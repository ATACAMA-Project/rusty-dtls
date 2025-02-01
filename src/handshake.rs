use core::panic;

use log::{debug, trace};

use crate::crypto::{PskTranscriptHash, TrafficSecret};
use crate::netqueue::{ClientResend, HandshakeHeader, NetQueue, NetQueueState, ServerResend};
use crate::parsing::{
    encode_encrypted_extensions, encode_finished, encode_pre_shared_key_client_binders,
    encode_server_hello, parse_encrypted_extensions, parse_finished, parse_server_hello, Cookie,
    EncodeHandshakeMessage, HandshakeType, ParseAck, ParseHandshakeMessage, ServerHelloVariant,
};
use crate::{
    crypto::{CipherDependentCryptoState, CipherSuite, Psk, PskTranscriptHashes},
    parsing::{encode_client_hello, ParseBuffer},
    record_parsing::RecordContentType,
    DtlsError, DtlsPoll,
};
use crate::{AlertDescription, DtlsConnection, EpochShort, EpochState, TimeStampMs};

pub struct HandshakeContext<'a> {
    pub recv_handshake_seq_num: u8,
    pub send_handshake_seq_num: u8,
    pub conn_id: usize,
    pub info: HandshakeInformation<'a>,
}

impl<'a> HandshakeContext<'a> {
    pub(crate) fn connection<'b, 'c>(
        &self,
        connections: &'b mut [Option<DtlsConnection<'c>>],
    ) -> &'b mut DtlsConnection<'c> {
        connections[self.conn_id].as_mut().unwrap()
    }

    pub fn next_send_seq_num(&mut self) -> u16 {
        self.send_handshake_seq_num += 1;
        (self.send_handshake_seq_num - 1) as u16
    }
}

pub struct HandshakeInformation<'a> {
    pub received_hello_retry_request: bool,
    pub crypto: CryptoInformation,
    pub selected_cipher_suite: Option<CipherSuite>,
    pub available_psks: &'a [Psk<'a>],
    pub selected_psk: Option<usize>,
}

pub enum CryptoInformation {
    PreServerHello(PskTranscriptHashes),
    PostHelloRetry(PskTranscriptHash),
    PostServerHello(CipherDependentCryptoState),
    None,
}

impl Default for CryptoInformation {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoInformation {
    pub fn new() -> Self {
        CryptoInformation::PreServerHello(PskTranscriptHashes::new())
    }

    pub fn psk_hashes_mut(&mut self) -> Result<&mut PskTranscriptHashes, DtlsError> {
        match self {
            CryptoInformation::PreServerHello(h) => Ok(h),
            _ => Err(DtlsError::IllegalInnerState),
        }
    }

    pub fn psk_hash_mut(&mut self) -> Result<&mut PskTranscriptHash, DtlsError> {
        match self {
            CryptoInformation::PostHelloRetry(h) => Ok(h),
            _ => Err(DtlsError::IllegalInnerState),
        }
    }

    pub fn crypto_state_mut(&mut self) -> Result<&mut CipherDependentCryptoState, DtlsError> {
        match self {
            CryptoInformation::PostServerHello(c) => Ok(c),
            _ => Err(DtlsError::IllegalInnerState),
        }
    }

    pub fn update_transcript_hash(&mut self, data: &[u8]) {
        match self {
            CryptoInformation::PreServerHello(hashes) => hashes.update(data),
            CryptoInformation::PostHelloRetry(hash) => hash.update(data),
            CryptoInformation::PostServerHello(crypto) => crypto.update_transcript_hash(data),
            CryptoInformation::None => panic!("Invalid inner state"),
        }
    }
}

impl<'a> HandshakeInformation<'a> {
    pub fn client_switch_to_post_hello_retry_hash(&mut self) {
        trace!("[Client] Switch to post hello_retry hash");
        let crypto = core::mem::replace(&mut self.crypto, CryptoInformation::None);
        if let (Some(cipher_suite), CryptoInformation::PreServerHello(hashes)) =
            (self.selected_cipher_suite, crypto)
        {
            self.crypto = CryptoInformation::PostHelloRetry(
                hashes.client_transition_to_single_hash(cipher_suite),
            );
        } else {
            panic!("Illegal inner state");
        }
    }

    pub fn server_switch_to_single_hash(&mut self) {
        let crypto = core::mem::replace(&mut self.crypto, CryptoInformation::None);
        if let (Some(cipher_suite), CryptoInformation::PreServerHello(_)) =
            (self.selected_cipher_suite, crypto)
        {
            self.crypto = CryptoInformation::PostHelloRetry(PskTranscriptHash::new(cipher_suite));
        } else {
            panic!("Illegal inner state");
        }
    }

    pub fn server_init_post_hello_retry_hash(&mut self, cookie: &[u8]) {
        trace!("[Server] Init post hello_retry hash");
        let Some(cipher_suite) = self.selected_cipher_suite else {
            panic!("Illegal inner state");
        };
        let mut hash = PskTranscriptHash::new(cipher_suite);
        hash.server_digest_cookie_hash(cookie);
        self.crypto = CryptoInformation::PostHelloRetry(hash);
    }

    pub fn initialize_crypto_state(&mut self, selected_psk_index: usize) -> Result<(), DtlsError> {
        if selected_psk_index >= self.available_psks.len() {
            return Err(DtlsError::Alert(AlertDescription::IllegalParameter));
        } else {
            self.selected_psk = Some(selected_psk_index);
        }

        let crypto = core::mem::replace(&mut self.crypto, CryptoInformation::None);
        self.crypto = CryptoInformation::PostServerHello(CipherDependentCryptoState::new(
            self.selected_cipher_suite.ok_or(DtlsError::ParseError)?,
            Some(self.available_psks[selected_psk_index].psk),
            crypto,
        )?);
        Ok(())
    }

    pub(crate) fn advance_to_epoch_two(
        &mut self,
        conn: &mut DtlsConnection,
        label_read: &str,
        label_write: &str,
    ) -> Result<(), DtlsError> {
        let crypto_state = self.crypto.crypto_state_mut()?;
        conn.current_epoch += 1;
        crypto_state.extract_new_hkdf_state(None)?;
        let err = conn
            .epochs
            .push(EpochState::new(TrafficSecret::None, TrafficSecret::None));
        debug_assert!(err.is_ok(), "Epoch should be 1");
        err.map_err(|_| DtlsError::IllegalInnerState)?;
        self.advance_epoch(conn, label_read, label_write)
    }

    pub(crate) fn advance_to_epoch_three(
        &mut self,
        conn: &mut DtlsConnection,
        label_read: &str,
        label_write: &str,
    ) -> Result<(), DtlsError> {
        let crypto_state = self.crypto.crypto_state_mut()?;
        crypto_state.extract_new_hkdf_state(None)?;
        self.advance_epoch(conn, label_read, label_write)
    }

    fn advance_epoch(
        &mut self,
        conn: &mut DtlsConnection,
        label_read: &str,
        label_write: &str,
    ) -> Result<(), DtlsError> {
        let crypto_state = self.crypto.crypto_state_mut()?;
        conn.current_epoch += 1;
        let index = (conn.current_epoch & 3) as usize;
        if index >= conn.epochs.len() {
            let err = conn.epochs.push(EpochState::new(
                crypto_state.derive_traffic_secret(label_read)?,
                crypto_state.derive_traffic_secret(label_write)?,
            ));
            debug_assert!(err.is_ok(), "EpochStates.len() >= 4");
            err.map_err(|_| DtlsError::IllegalInnerState)?;
        } else {
            conn.epochs[index] = EpochState::new(
                crypto_state.derive_traffic_secret(label_read)?,
                crypto_state.derive_traffic_secret(label_write)?,
            );
        }
        Ok(())
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    #[default]
    Start,
    ReceivedHelloRetry,
    WaitServerHello,
    WaitEncryptedExtensions,
    WaitFinished,
    SendFinished,
    WaitServerAck,
    FinishedHandshake,
}

pub struct SendTask {
    pub entry: usize,
    pub epoch: EpochShort,
}

impl SendTask {
    fn new(entry: usize, epoch: EpochShort) -> Self {
        Self { entry, epoch }
    }
}

pub fn process_client(
    state: &mut ClientState,
    now_ms: &TimeStampMs,
    ctx: &mut HandshakeContext,
    net_queue: &mut NetQueue,
    conn: &mut DtlsConnection,
    rng: &mut dyn rand_core::CryptoRngCore,
) -> Result<(DtlsPoll, Option<SendTask>), DtlsError> {
    let mut send_task = None;
    let poll = match state {
        ClientState::Start => {
            debug!("[Client] Send client_hello");
            net_queue.state =
                NetQueueState::ClientResend(ClientResend::ClientHello(Default::default()));
            alloc_client_hello(ctx, net_queue, rng, now_ms)?;
            send_task = Some(SendTask::new(0, 0));
            *state = ClientState::WaitServerHello;
            DtlsPoll::Wait
        }
        ClientState::ReceivedHelloRetry => {
            debug!("[Client] Send updated client_hello");
            alloc_client_hello(ctx, net_queue, rng, now_ms)?;
            send_task = Some(SendTask::new(0, 0));
            *state = ClientState::WaitServerHello;
            DtlsPoll::Wait
        }
        ClientState::WaitServerHello => {
            if ctx.info.crypto.crypto_state_mut().is_ok() {
                DtlsPoll::WaitTimeoutMs(1)
            } else {
                DtlsPoll::Wait
            }
        }
        ClientState::WaitEncryptedExtensions => DtlsPoll::Wait,
        ClientState::WaitFinished => DtlsPoll::Wait,
        ClientState::SendFinished => {
            net_queue.state =
                NetQueueState::ClientResend(ClientResend::Finished(Default::default()));
            ctx.info
                .advance_to_epoch_three(conn, "s ap traffic", "c ap traffic")?;
            debug!("[Client] Send finished");
            alloc_client_finish(ctx, net_queue, conn, now_ms)?;
            send_task = Some(SendTask::new(0, 2));
            *state = ClientState::WaitServerAck;
            DtlsPoll::Wait
        }
        ClientState::WaitServerAck => DtlsPoll::Wait,
        ClientState::FinishedHandshake => DtlsPoll::FinishedHandshake,
    };
    Ok((poll, send_task))
}

fn alloc_client_hello(
    ctx: &mut HandshakeContext,
    net_queue: &mut NetQueue,
    rng: &mut dyn rand_core::CryptoRngCore,
    now_ms: &TimeStampMs,
) -> Result<(), DtlsError> {
    let seq_num = ctx.next_send_seq_num();
    net_queue.alloc_client_hello_with_cookie(0, now_ms, &mut |buffer, cookie| {
        let mut handshake =
            EncodeHandshakeMessage::new(buffer, HandshakeType::ClientHello, seq_num)?;
        let (_, binders_len) = encode_client_hello(
            handshake.payload_buffer(),
            &mut ctx.info,
            CipherSuite::all(),
            now_ms,
            rng,
            cookie,
        )?;
        handshake.partial_transcript_hash(binders_len, &mut ctx.info.crypto);
        encode_pre_shared_key_client_binders(
            &mut handshake.binders_buffer(),
            ctx.info.selected_cipher_suite,
            ctx.info.available_psks,
            &mut ctx.info.crypto,
        )?;
        handshake.finish_partial_transcript_hash(&mut ctx.info.crypto);
        Ok(())
    })
}

fn alloc_client_finish(
    ctx: &mut HandshakeContext,
    net_queue: &mut NetQueue,
    conn: &mut DtlsConnection,
    now_ms: &u64,
) -> Result<(), DtlsError> {
    let seq_num = ctx.next_send_seq_num();
    let epoch_state = &mut conn.epochs[2];
    net_queue.alloc_client_finish(2, now_ms, &mut |buffer| -> Result<(), DtlsError> {
        let mut handshake = EncodeHandshakeMessage::new(buffer, HandshakeType::Finished, seq_num)?;
        encode_finished(
            handshake.payload_buffer(),
            &epoch_state.write_traffic_secret,
            ctx.info.crypto.crypto_state_mut()?,
        )?;
        handshake.finish(&mut ctx.info.crypto);
        Ok(())
    })
}

pub fn handle_handshake_message_client(
    state: &mut ClientState,
    ctx: &mut HandshakeContext,
    net_queue: &mut NetQueue,
    conn: &mut DtlsConnection,
    content_type: RecordContentType,
    message: ParseBuffer<&mut [u8]>,
) -> Result<(), DtlsError> {
    let mut cookie = None;
    let message = message.into_ref();
    let buf = message.clone();
    handle_handshake_message(
        ctx,
        net_queue,
        content_type,
        message,
        &mut |info, handshake_type, handshake| {
            cookie = receive_client(state, info, conn, handshake_type, handshake)?;
            Ok(())
        },
    )?;
    if *state == ClientState::WaitEncryptedExtensions
        && !matches!(net_queue.state, NetQueueState::ClientReorder(_))
    {
        net_queue.state = NetQueueState::ClientReorder(None);
    }
    if let Some(cookie) = cookie {
        net_queue
            .store_cookie(&buf.complete_inner_buffer()[cookie.index..cookie.index + cookie.len])?;
    }
    Ok(())
}

fn handle_handshake_message(
    ctx: &mut HandshakeContext,
    net_queue: &mut NetQueue,
    content_type: RecordContentType,
    message: ParseBuffer<&[u8]>,
    handle: &mut dyn FnMut(
        &mut HandshakeInformation,
        HandshakeType,
        ParseHandshakeMessage,
    ) -> Result<(), DtlsError>,
) -> Result<(), DtlsError> {
    let res = try_unpack_handshake_message(content_type, message, ctx, net_queue)?;
    if let Some((handshake, handshake_type)) = res {
        handle(&mut ctx.info, handshake_type, handshake)?;
        ctx.recv_handshake_seq_num += 1;
    }
    if let NetQueueState::ClientReorder(Some(fin)) = &net_queue.state {
        let message_seq: u16 = fin.hs_seq();
        if message_seq == ctx.recv_handshake_seq_num as u16 {
            let buffer = ParseBuffer::init(fin.as_bytes());
            let (handshake, handshake_type, _) = ParseHandshakeMessage::new(buffer)?;
            handle(&mut ctx.info, handshake_type, handshake)?;
            ctx.recv_handshake_seq_num += 1;
        }
    }
    Ok(())
}

fn try_unpack_handshake_message<'b>(
    content_type: RecordContentType,
    mut message: ParseBuffer<&'b [u8]>,
    ctx: &mut HandshakeContext,
    net_queue: &mut NetQueue,
) -> Result<Option<(ParseHandshakeMessage<'b>, HandshakeType)>, DtlsError> {
    if content_type == RecordContentType::Ack {
        let mut ack = ParseAck::new(&mut message)?;
        while let Some((epoch, seq_num)) = ack.next_entry() {
            net_queue.ack(&epoch, &seq_num);
        }
        net_queue.schedule_all_unacked_rt_entries();

        return Ok(None);
    }

    if !matches!(content_type, RecordContentType::DtlsHandshake) {
        return Err(DtlsError::ParseError);
    }
    let message_start = message.offset();
    let (handshake, handshake_type, seq_num) = ParseHandshakeMessage::new(message)?;

    let expected_seq_num = ctx.recv_handshake_seq_num;
    if seq_num != expected_seq_num as u16 {
        let message = handshake.abort_parsing();
        if seq_num > expected_seq_num as u16 {
            if handshake_type == HandshakeType::Finished {
                // would maybe be better to check for ClientState::WaitEncryptedExtensions, but it's not available here
                if let NetQueueState::ClientReorder(_) = &mut net_queue.state {
                    debug!(
                        "Saving finish message to record_queue with too new handshake_seq_num: {}",
                        seq_num
                    );
                    let res = net_queue.alloc_client_reorder(seq_num, &mut |buf| {
                        buf.expect_length(message.capacity())?;
                        buf.write_into(&message.complete_inner_buffer()[message_start..]);
                        Ok(())
                    });
                    match res {
                        Ok(()) | Err(DtlsError::OutOfMemory) => Ok(None),
                        Err(err) => Err(err),
                    }
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            debug!(
                "Dropped handshake message with too old handshake_seq_num: {}",
                seq_num
            );
            Ok(None)
        }
    } else {
        Ok(Some((handshake, handshake_type)))
    }
}

fn receive_client(
    state: &mut ClientState,
    info: &mut HandshakeInformation,
    conn: &mut DtlsConnection,
    handshake_type: HandshakeType,
    mut message: ParseHandshakeMessage<'_>,
) -> Result<Option<Cookie>, DtlsError> {
    match state {
        ClientState::WaitServerHello => {
            assert_handshake_type(handshake_type, HandshakeType::ServerHello)?;
            debug!("[Client] Received server_hello");
            let server_hello_variant = Some(parse_server_hello(
                message.payload_buffer(),
                CipherSuite::all(),
                info,
            )?);
            message.add_to_transcript_hash(&mut info.crypto);
            match server_hello_variant {
                Some(ServerHelloVariant::ServerHello) => {
                    *state = ClientState::WaitEncryptedExtensions;
                    info.advance_to_epoch_two(conn, "s hs traffic", "c hs traffic")?
                }
                Some(ServerHelloVariant::HelloRetry(cookie)) => {
                    *state = ClientState::ReceivedHelloRetry;
                    return Ok(cookie);
                }
                _ => return Err(DtlsError::ParseError),
            }
        }
        ClientState::WaitEncryptedExtensions => {
            assert_handshake_type(handshake_type, HandshakeType::EncryptedExtension)?;
            debug!("[Client] Received encrypted_extensions");
            parse_encrypted_extensions(message.payload_buffer())?;
            message.add_to_transcript_hash(&mut info.crypto);
            *state = ClientState::WaitFinished;
        }
        ClientState::WaitFinished => {
            assert_handshake_type(handshake_type, HandshakeType::Finished)?;
            debug!("[Client] Received finished");
            parse_finished(
                message.payload_buffer(),
                &conn.epochs[conn.current_epoch as usize & 3].read_traffic_secret,
                info.crypto.crypto_state_mut()?,
            )?;
            message.add_to_transcript_hash(&mut info.crypto);
            *state = ClientState::SendFinished;
        }
        _ => return Err(DtlsError::IllegalInnerState),
    }
    Ok(None)
}

fn assert_handshake_type(actual: HandshakeType, expected: HandshakeType) -> Result<(), DtlsError> {
    if actual != expected {
        Err(DtlsError::Alert(AlertDescription::UnexpectedMessage))
    } else {
        Ok(())
    }
}

#[derive(Default, Clone, Copy)]
pub enum ServerState {
    #[default]
    RecvdClientHello,
    Negotiated,
    WaitFinished,
    FinishedHandshake,
}

pub fn process_server(
    state: &mut ServerState,
    now_ms: &TimeStampMs,
    ctx: &mut HandshakeContext,
    net_queue: &mut NetQueue,
    conn: &mut DtlsConnection,
    rng: &mut dyn rand_core::CryptoRngCore,
) -> Result<(DtlsPoll, bool), DtlsError> {
    let mut send = false;
    let poll = match state {
        ServerState::RecvdClientHello => {
            debug!("[Server] Send server_hello");
            net_queue.state = NetQueueState::ServerResend(ServerResend::default());
            let seq_num = ctx.next_send_seq_num();
            net_queue.alloc_server_hello(0, now_ms, &mut |buffer| {
                let mut handshake =
                    EncodeHandshakeMessage::new(buffer, HandshakeType::ServerHello, seq_num)?;
                encode_server_hello(
                    handshake.payload_buffer(),
                    rng,
                    &[],
                    ctx.info
                        .selected_cipher_suite
                        .ok_or(DtlsError::IllegalInnerState)?,
                    0,
                )?;
                handshake.finish(&mut ctx.info.crypto);
                Ok(())
            })?;
            ctx.info
                .advance_to_epoch_two(conn, "c hs traffic", "s hs traffic")?;

            debug!("[Server] Send encrypted_extensions");
            let seq_num = ctx.next_send_seq_num();
            net_queue.alloc_encrypted_extensions(2, now_ms, &mut |buffer| {
                let mut handshake = EncodeHandshakeMessage::new(
                    buffer,
                    HandshakeType::EncryptedExtension,
                    seq_num,
                )?;
                encode_encrypted_extensions(handshake.payload_buffer())?;
                handshake.finish(&mut ctx.info.crypto);
                Ok(())
            })?;
            debug!("[Server] Send finished");
            let seq_num = ctx.next_send_seq_num();
            net_queue.alloc_server_finished(2, now_ms, &mut |buffer| {
                let epoch_state = &mut conn.epochs[(conn.current_epoch as usize) & 3];
                let mut handshake =
                    EncodeHandshakeMessage::new(buffer, HandshakeType::Finished, seq_num)?;
                encode_finished(
                    handshake.payload_buffer(),
                    &epoch_state.write_traffic_secret,
                    ctx.info.crypto.crypto_state_mut()?,
                )?;
                handshake.finish(&mut ctx.info.crypto);
                Ok(())
            })?;
            ctx.info
                .advance_to_epoch_three(conn, "c ap traffic", "s ap traffic")?;
            *state = ServerState::WaitFinished;
            send = true;
            DtlsPoll::Wait
        }
        ServerState::Negotiated => unreachable!(),
        ServerState::WaitFinished => DtlsPoll::Wait,
        ServerState::FinishedHandshake => DtlsPoll::FinishedHandshake,
    };
    Ok((poll, send))
}

pub fn handle_handshake_message_server(
    state: &mut ServerState,
    ctx: &mut HandshakeContext,
    net_queue: &mut NetQueue,
    conn: &mut DtlsConnection,
    content_type: RecordContentType,
    message: ParseBuffer<&mut [u8]>,
) -> Result<(), DtlsError> {
    handle_handshake_message(
        ctx,
        net_queue,
        content_type,
        message.into_ref(),
        &mut |info, handshake_type, handshake| {
            receive_server(state, info, conn, handshake_type, handshake)
        },
    )?;
    if matches!(*state, ServerState::FinishedHandshake) {
        net_queue.state = NetQueueState::Empty;
    }
    Ok(())
}

fn receive_server(
    state: &mut ServerState,
    info: &mut HandshakeInformation,
    conn: &mut DtlsConnection,
    handshake_type: HandshakeType,
    mut message: ParseHandshakeMessage<'_>,
) -> Result<(), DtlsError> {
    match state {
        ServerState::WaitFinished => {
            assert_handshake_type(handshake_type, HandshakeType::Finished)?;
            debug!("[Server] Received finished");
            parse_finished(
                message.payload_buffer(),
                &conn.epochs[2].read_traffic_secret,
                info.crypto.crypto_state_mut()?,
            )?;
            *state = ServerState::FinishedHandshake;
            message.add_to_transcript_hash(&mut info.crypto);
        }
        _ => return Err(DtlsError::IllegalInnerState),
    }
    Ok(())
}
