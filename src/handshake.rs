use log::{debug, trace};

use crate::crypto::{KeyShares, PskTranscriptHash};
use crate::parsing::{
    Cookie, EncodeHandshakeMessage, HandshakeMsgType, ParseAck, ParseHandshakeMessage,
    ServerHelloVariant, encode_encrypted_extensions, encode_finished,
    encode_pre_shared_key_client_binders, encode_server_hello, parse_encrypted_extensions,
    parse_finished, parse_server_hello,
};

#[cfg(feature = "_dhe")]
use crate::parsing::NamedGroup;

use crate::parsing_utility::ParseBuffer;
use crate::{
    AlertDescription, DtlsConnection, EpochShort, EpochState, HandshakeSlotIndex, RecordQueue,
    Milliseconds, UserSettings, illegal_state, parse_err,
};
use crate::{
    DtlsError, DtlsPoll,
    crypto::{CipherDependentCryptoState, CipherSuite, Psk, PskTranscriptHashes},
    parsing::encode_client_hello,
    record_parsing::RecordContentType,
};

pub struct HandshakeContext {
    pub recv_handshake_seq_num: u8,
    pub send_handshake_seq_num: u8,
    pub conn_id: usize,
    pub received_hello_retry_request: bool,
    pub crypto: CryptoInformation,
    pub selected_cipher_suite: Option<CipherSuite>,
    pub selected_psk_in_ch: u16,
    pub key_shares: KeyShares,
}

impl HandshakeContext {
    pub(crate) fn connection<'b, 'c>(
        &self,
        connections: &'b mut [Option<DtlsConnection<'c>>],
    ) -> &'b mut DtlsConnection<'c> {
        let l = self.conn_id.min(connections.len());
        connections[l].as_mut().unwrap()
    }

    pub fn next_send_seq_num(&mut self) -> u16 {
        self.send_handshake_seq_num += 1;
        (self.send_handshake_seq_num - 1) as u16
    }
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
            _ => Err(illegal_state!()),
        }
    }

    pub fn psk_hash_mut(&mut self) -> Result<&mut PskTranscriptHash, DtlsError> {
        match self {
            CryptoInformation::PostHelloRetry(h) => Ok(h),
            _ => Err(illegal_state!()),
        }
    }

    pub fn crypto_state_mut(&mut self) -> Result<&mut CipherDependentCryptoState, DtlsError> {
        match self {
            CryptoInformation::PostServerHello(c) => Ok(c),
            _ => Err(illegal_state!()),
        }
    }

    pub fn crypto_state_initialized(&self) -> bool {
        matches!(self, CryptoInformation::PostServerHello(_))
    }

    pub fn update_transcript_hash(&mut self, data: &[u8]) -> Result<(), DtlsError> {
        match self {
            CryptoInformation::PreServerHello(hashes) => hashes.update(data),
            CryptoInformation::PostHelloRetry(hash) => hash.update(data),
            CryptoInformation::PostServerHello(crypto) => crypto.update_transcript_hash(data),
            CryptoInformation::None => return Err(illegal_state!()),
        }
        Ok(())
    }
}

impl HandshakeContext {
    #[cfg(feature = "_dhe")]
    pub fn client_init_offered_key_shares(
        &mut self,
        offered_key_shares: &[NamedGroup],
        rng: &mut dyn rand_core::CryptoRngCore,
    ) -> Result<(), DtlsError> {
        trace!("[Client] Init offered key_shares");
        for group in offered_key_shares {
            self.key_shares.init_key_exchange(rng, *group)?;
        }
        Ok(())
    }

    pub fn client_switch_to_post_hello_retry_hash(&mut self) -> Result<(), DtlsError> {
        trace!("[Client] Switch to post hello_retry hash");
        let crypto = core::mem::replace(&mut self.crypto, CryptoInformation::None);
        if let (Some(cipher_suite), CryptoInformation::PreServerHello(hashes)) =
            (self.selected_cipher_suite, crypto)
        {
            self.crypto = CryptoInformation::PostHelloRetry(
                hashes.client_transition_to_single_hash(cipher_suite),
            );
            Ok(())
        } else {
            Err(illegal_state!())
        }
    }

    pub fn server_switch_to_single_hash(&mut self) -> Result<(), DtlsError> {
        trace!("[Server] Switch to single hash");
        let crypto = core::mem::replace(&mut self.crypto, CryptoInformation::None);
        if let (Some(cipher_suite), CryptoInformation::PreServerHello(_)) =
            (self.selected_cipher_suite, crypto)
        {
            self.crypto = CryptoInformation::PostHelloRetry(PskTranscriptHash::new(cipher_suite));
            Ok(())
        } else {
            Err(illegal_state!())
        }
    }

    pub fn server_init_post_hello_retry_hash(&mut self, cookie: &[u8]) -> Result<(), DtlsError> {
        trace!("[Server] Init post hello_retry hash");
        let Some(cipher_suite) = self.selected_cipher_suite else {
            return Err(illegal_state!());
        };
        let mut hash = PskTranscriptHash::new(cipher_suite);
        hash.server_digest_cookie_hash(cookie);
        self.crypto = CryptoInformation::PostHelloRetry(hash);
        Ok(())
    }

    pub fn initialize_crypto_state(
        &mut self,
        available_psks: &[Psk],
        selected_psk_index: usize,
        ecdhe: Option<&[u8]>,
    ) -> Result<(), DtlsError> {
        if selected_psk_index >= available_psks.len() {
            return Err(DtlsError::Alert(AlertDescription::IllegalParameter));
        }
        trace!(
            "Select psk {}, using dhe exch. {}",
            selected_psk_index,
            ecdhe.is_some()
        );
        let crypto = core::mem::replace(&mut self.crypto, CryptoInformation::None);
        self.crypto = CryptoInformation::PostServerHello(CipherDependentCryptoState::new(
            self.selected_cipher_suite.ok_or_else(|| parse_err!())?,
            Some(available_psks[selected_psk_index].psk),
            ecdhe,
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
        // Skip epoch 1
        conn.current_epoch += 1;
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
            // TODO epochs >= 4 are not supported atm
            return Err(illegal_state!());
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
    rng: &mut dyn rand_core::CryptoRngCore,
    index: HandshakeSlotIndex,
    ctx: &mut HandshakeContext,
    state: &mut ClientState,
    record_queue: &mut RecordQueue<'_>,
    set: &UserSettings,
    conn: &mut DtlsConnection,
    now_ms: &Milliseconds,
) -> Result<(DtlsPoll, Option<SendTask>), DtlsError> {
    let mut send_task = None;
    let poll = match state {
        ClientState::Start => {
            debug!("[Client] Send client_hello");
            let entry = alloc_client_hello(rng, ctx, record_queue, set, now_ms)?;
            send_task = Some(SendTask::new(entry, 0));
            *state = ClientState::WaitServerHello;
            DtlsPoll::Wait
        }
        ClientState::ReceivedHelloRetry => {
            debug!("[Client] Send updated client_hello");
            let entry = alloc_client_hello(rng, ctx, record_queue, set, now_ms)?;
            send_task = Some(SendTask::new(entry, 0));
            *state = ClientState::WaitServerHello;
            DtlsPoll::Wait
        }
        ClientState::WaitServerHello => {
            if ctx.crypto.crypto_state_initialized() {
                DtlsPoll::WaitTimeoutMs(1)
            } else {
                DtlsPoll::Wait
            }
        }
        ClientState::WaitEncryptedExtensions => DtlsPoll::Wait,
        ClientState::WaitFinished => DtlsPoll::Wait,
        ClientState::SendFinished => {
            record_queue.clear_record_queue();
            ctx.advance_to_epoch_three(conn, "s ap traffic", "c ap traffic")?;
            debug!("[Client] Send finished");
            let entry = alloc_client_finish(ctx, record_queue, conn, now_ms)?;
            send_task = Some(SendTask::new(entry, 2));
            *state = ClientState::WaitServerAck;
            DtlsPoll::Wait
        }
        ClientState::WaitServerAck => DtlsPoll::Wait,
        ClientState::FinishedHandshake => DtlsPoll::FinishedHandshake(index),
    };
    Ok((poll, send_task))
}

fn alloc_client_hello(
    rng: &mut dyn rand_core::CryptoRngCore,
    ctx: &mut HandshakeContext,
    record_queue: &mut RecordQueue<'_>,
    set: &UserSettings,
    now_ms: &Milliseconds,
) -> Result<usize, DtlsError> {
    let seq_num = ctx.next_send_seq_num();
    let (mut rt_buf, cookie) = record_queue.alloc_entry_with_cookie();
    let mut handshake =
        EncodeHandshakeMessage::new(&mut rt_buf, HandshakeMsgType::ClientHello, seq_num)?;
    let (_, binders_len) = encode_client_hello(
        handshake.payload_buffer(),
        ctx,
        set,
        CipherSuite::all(),
        now_ms,
        rng,
        cookie,
    )?;
    handshake.add_partial_transcript_hash(binders_len, &mut ctx.crypto)?;
    encode_pre_shared_key_client_binders(
        &mut handshake.binders_buffer(),
        ctx.selected_cipher_suite,
        set.psks,
        &mut ctx.crypto,
    )?;
    handshake.finish_after_partial_transcript_hash(&mut ctx.crypto)?;
    let offset = rt_buf.offset();
    record_queue.submit_rt_entry(0, now_ms, offset)
}

fn alloc_client_finish(
    ctx: &mut HandshakeContext,
    record_queue: &mut RecordQueue<'_>,
    conn: &mut DtlsConnection,
    now_ms: &Milliseconds,
) -> Result<usize, DtlsError> {
    let seq_num = ctx.next_send_seq_num();
    let epoch_state = &mut conn.epochs[2];
    let mut rt_buf = record_queue.alloc_entry();
    let mut handshake =
        EncodeHandshakeMessage::new(&mut rt_buf, HandshakeMsgType::Finished, seq_num)?;
    encode_finished(
        handshake.payload_buffer(),
        &epoch_state.write_traffic_secret,
        ctx.crypto.crypto_state_mut()?,
    )?;
    handshake.finish(&mut ctx.crypto)?;
    let offset = rt_buf.offset();
    record_queue.submit_rt_entry(2, now_ms, offset)
}

pub fn handle_handshake_message_client(
    rng: &mut dyn rand_core::CryptoRngCore,
    ctx: &mut HandshakeContext,
    state: &mut ClientState,
    record_queue: &mut RecordQueue<'_>,
    set: &UserSettings,
    conn: &mut DtlsConnection,
    content_type: RecordContentType,
    message: ParseBuffer<'_>,
) -> Result<(), DtlsError> {
    let mut cookie = None;
    let offset = message.offset();
    let message_buf = message.release_buffer();
    let message = ParseBuffer::init_with_offset(message_buf, offset);
    handle_handshake_message(
        ctx,
        record_queue,
        content_type,
        message,
        &mut |ctx, handshake_msg_type, handshake| {
            cookie = receive_client(rng, ctx, state, set, conn, handshake_msg_type, handshake)?;
            Ok(())
        },
    )?;

    let message = ParseBuffer::init_with_offset(message_buf, offset);
    if matches!(
        *state,
        ClientState::ReceivedHelloRetry | ClientState::WaitEncryptedExtensions
    ) {
        record_queue.clear_retransmission()?;
    }
    if let Some(cookie) = cookie {
        record_queue
            .store_cookie(message.access_slice_checked(cookie.index..cookie.index + cookie.len)?)?;
    }
    Ok(())
}

fn handle_handshake_message(
    ctx: &mut HandshakeContext,
    record_queue: &mut RecordQueue<'_>,
    content_type: RecordContentType,
    message: ParseBuffer<'_>,
    handle: &mut dyn FnMut(
        &mut HandshakeContext,
        HandshakeMsgType,
        ParseHandshakeMessage,
    ) -> Result<(), DtlsError>,
) -> Result<(), DtlsError> {
    let res = try_unpack_handshake_message(ctx, record_queue, content_type, message)?;
    if let Some((handshake, handshake_type)) = res {
        handle(ctx, handshake_type, handshake)?;
        ctx.recv_handshake_seq_num += 1;
    }
    loop {
        if let Some(msg) = record_queue.try_take_handshake_buffer(ctx.recv_handshake_seq_num as u16)
        {
            let message = msg;
            let (handshake, handshake_type, _) = ParseHandshakeMessage::new(message)?;
            handle(ctx, handshake_type, handshake)?;
            ctx.recv_handshake_seq_num += 1;
            continue;
        }
        record_queue.free_empty_entries();
        break;
    }
    Ok(())
}

fn try_unpack_handshake_message<'b>(
    ctx: &mut HandshakeContext,
    record_queue: &mut RecordQueue<'_>,
    content_type: RecordContentType,
    mut message: ParseBuffer<'b>,
) -> Result<Option<(ParseHandshakeMessage<'b>, HandshakeMsgType)>, DtlsError> {
    if content_type == RecordContentType::Ack {
        let mut ack = ParseAck::new(&mut message)?;
        while let Some((epoch, seq_num)) = ack.next_entry() {
            record_queue.ack(&epoch, &seq_num);
        }
        record_queue.schedule_all_unacked_rt_entries();
        return Ok(None);
    }

    if !matches!(content_type, RecordContentType::DtlsHandshake) {
        return Err(parse_err!());
    }
    let message_start = message.offset();
    let (handshake, handshake_type, seq_num) = ParseHandshakeMessage::new(message)?;

    let expected_seq_num = ctx.recv_handshake_seq_num;
    if seq_num != expected_seq_num as u16 {
        let message = handshake.abort_parsing();
        if seq_num > expected_seq_num as u16 {
            debug!(
                "Saving handshake message to record_queue with too new handshake_seq_num: {}",
                seq_num
            );
            let mut reorder_buf = record_queue.alloc_entry();
            let message_end = message.capacity();
            reorder_buf
                .write_slice_checked(message.access_slice_checked(message_start..message_end)?)?;
            let offset = reorder_buf.offset();
            let res = record_queue.submit_reordering_entry(seq_num, offset);

            match res {
                Ok(()) | Err(DtlsError::OutOfMemory) => Ok(None),
                Err(err) => Err(err),
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
    rng: &mut dyn rand_core::CryptoRngCore,
    ctx: &mut HandshakeContext,
    state: &mut ClientState,
    set: &UserSettings,
    conn: &mut DtlsConnection,
    message_type: HandshakeMsgType,
    mut message: ParseHandshakeMessage<'_>,
) -> Result<Option<Cookie>, DtlsError> {
    match state {
        ClientState::WaitServerHello => {
            assert_handshake_msg_type(message_type, HandshakeMsgType::ServerHello)?;
            debug!("[Client] Received server_hello");
            let server_hello_variant = Some(parse_server_hello(
                rng,
                ctx,
                set,
                CipherSuite::all(),
                message.payload_buffer(),
            )?);
            message.add_to_transcript_hash(&mut ctx.crypto)?;
            match server_hello_variant {
                Some(ServerHelloVariant::ServerHello) => {
                    *state = ClientState::WaitEncryptedExtensions;
                    ctx.advance_to_epoch_two(conn, "s hs traffic", "c hs traffic")?
                }
                Some(ServerHelloVariant::HelloRetry(cookie)) => {
                    *state = ClientState::ReceivedHelloRetry;
                    return Ok(cookie);
                }
                _ => return Err(parse_err!()),
            }
        }
        ClientState::WaitEncryptedExtensions => {
            assert_handshake_msg_type(message_type, HandshakeMsgType::EncryptedExtension)?;
            debug!("[Client] Received encrypted_extensions");
            parse_encrypted_extensions(message.payload_buffer())?;
            message.add_to_transcript_hash(&mut ctx.crypto)?;
            *state = ClientState::WaitFinished;
        }
        ClientState::WaitFinished => {
            assert_handshake_msg_type(message_type, HandshakeMsgType::Finished)?;
            debug!("[Client] Received finished");
            parse_finished(
                message.payload_buffer(),
                &conn.epochs[conn.current_epoch as usize & 3].read_traffic_secret,
                ctx.crypto.crypto_state_mut()?,
            )?;
            message.add_to_transcript_hash(&mut ctx.crypto)?;
            *state = ClientState::SendFinished;
        }
        _ => return Err(illegal_state!()),
    }
    Ok(None)
}

fn assert_handshake_msg_type(
    actual: HandshakeMsgType,
    expected: HandshakeMsgType,
) -> Result<(), DtlsError> {
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
    WaitFinished,
    FinishedHandshake,
}

pub fn process_server(
    rng: &mut dyn rand_core::CryptoRngCore,
    index: HandshakeSlotIndex,
    ctx: &mut HandshakeContext,
    state: &mut ServerState,
    record_queue: &mut RecordQueue<'_>,
    conn: &mut DtlsConnection,
    now_ms: &Milliseconds,
) -> Result<(DtlsPoll, bool), DtlsError> {
    let mut send = false;
    let poll = match state {
        ServerState::RecvdClientHello => {
            debug!("[Server] Send server_hello");
            record_queue.clear_record_queue();
            let seq_num = ctx.next_send_seq_num();
            let mut rt_buf = record_queue.alloc_entry();
            let mut handshake =
                EncodeHandshakeMessage::new(&mut rt_buf, HandshakeMsgType::ServerHello, seq_num)?;
            encode_server_hello(
                handshake.payload_buffer(),
                rng,
                &[],
                ctx.selected_cipher_suite.ok_or_else(|| illegal_state!())?,
                ctx.selected_psk_in_ch,
                #[cfg(feature = "_dhe")]
                &ctx.key_shares,
            )?;
            handshake.finish(&mut ctx.crypto)?;
            let offset = rt_buf.offset();
            record_queue.submit_rt_entry(0, now_ms, offset)?;

            ctx.advance_to_epoch_two(conn, "c hs traffic", "s hs traffic")?;

            debug!("[Server] Send encrypted_extensions");
            let seq_num = ctx.next_send_seq_num();
            let mut rt_buf = record_queue.alloc_entry();
            let mut handshake = EncodeHandshakeMessage::new(
                &mut rt_buf,
                HandshakeMsgType::EncryptedExtension,
                seq_num,
            )?;
            encode_encrypted_extensions(handshake.payload_buffer())?;
            handshake.finish(&mut ctx.crypto)?;
            let offset = rt_buf.offset();
            record_queue.submit_rt_entry(2, now_ms, offset)?;

            debug!("[Server] Send finished");
            let seq_num = ctx.next_send_seq_num();

            let mut rt_buf = record_queue.alloc_entry();
            let epoch_state = &mut conn.epochs[(conn.current_epoch as usize) & 3];
            let mut handshake =
                EncodeHandshakeMessage::new(&mut rt_buf, HandshakeMsgType::Finished, seq_num)?;
            encode_finished(
                handshake.payload_buffer(),
                &epoch_state.write_traffic_secret,
                ctx.crypto.crypto_state_mut()?,
            )?;
            handshake.finish(&mut ctx.crypto)?;
            let offset = rt_buf.offset();
            record_queue.submit_rt_entry(2, now_ms, offset)?;

            ctx.advance_to_epoch_three(conn, "c ap traffic", "s ap traffic")?;
            *state = ServerState::WaitFinished;
            send = true;
            DtlsPoll::Wait
        }
        ServerState::WaitFinished => DtlsPoll::Wait,
        ServerState::FinishedHandshake => DtlsPoll::FinishedHandshake(index),
    };
    Ok((poll, send))
}

pub fn handle_handshake_message_server(
    ctx: &mut HandshakeContext,
    state: &mut ServerState,
    record_queue: &mut RecordQueue<'_>,
    conn: &mut DtlsConnection,
    content_type: RecordContentType,
    message: ParseBuffer<'_>,
) -> Result<(), DtlsError> {
    handle_handshake_message(
        ctx,
        record_queue,
        content_type,
        message,
        &mut |ctx, handshake_type, handshake| {
            receive_server(state, ctx, conn, handshake_type, handshake)
        },
    )?;
    if matches!(*state, ServerState::FinishedHandshake) {
        record_queue.clear_retransmission()?;
    }
    Ok(())
}

fn receive_server(
    state: &mut ServerState,
    ctx: &mut HandshakeContext,
    conn: &mut DtlsConnection,
    handshake_type: HandshakeMsgType,
    mut message: ParseHandshakeMessage<'_>,
) -> Result<(), DtlsError> {
    match state {
        ServerState::WaitFinished => {
            assert_handshake_msg_type(handshake_type, HandshakeMsgType::Finished)?;
            debug!("[Server] Received finished");
            parse_finished(
                message.payload_buffer(),
                &conn.epochs[2].read_traffic_secret,
                ctx.crypto.crypto_state_mut()?,
            )?;
            *state = ServerState::FinishedHandshake;
            message.add_to_transcript_hash(&mut ctx.crypto)?;
        }
        _ => return Err(illegal_state!()),
    }
    Ok(())
}
