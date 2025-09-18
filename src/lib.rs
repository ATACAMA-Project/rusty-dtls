#![no_std]

use core::{borrow::BorrowMut, marker::PhantomData, mem, net::SocketAddr, ops::Range};

use crypto::TrafficSecret;
use handshake::{
    ClientState, CryptoInformation, HandshakeContext, ServerState, handle_handshake_message_client,
    handle_handshake_message_server,
};
use log::{debug, info, trace};
use parsing::{
    ClientHelloResult, EncodeHandshakeMessage, HandshakeMsgType, HelloRetryCookie,
    ParseHandshakeMessage, encode_alert, encode_hello_retry, parse_alert,
    parse_client_hello_first_pass, parse_client_hello_second_pass,
};

pub use crypto::{
    HashFunction, NamedGroupSelectInfo, Psk, SelectNamedGroup, default_select_named_group,
};
pub use parsing::NamedGroup;

use parsing_utility::ParseBuffer;
use record_parsing::{
    EncodeCiphertextRecord, EncodePlaintextRecord, RecordContentType, parse_plaintext_record,
    parse_record,
};

mod fmt;

#[cfg(feature = "async")]
mod asynchronous;
#[cfg(feature = "async")]
pub use asynchronous::{DtlsStackAsync, Event};

mod sync;
use sha2::{
    Sha256,
    digest::{OutputSizeUser, generic_array::GenericArray},
};
pub use sync::DtlsStack;

use crate::{
    parsing::{PSK_KE, PskExchangeModes},
    parsing_utility::Parser,
};

mod buffer_record_queue;
mod crypto;
mod handshake;
mod parsing;
mod parsing_utility;
mod record_parsing;

type Epoch = u64;
type EpochShort = u8;

#[cfg(not(any(feature = "time_size_u32", feature = "time_size_u64")))]
compile_error!("Enable exactly one: time_size_u32 or time_size_u64");
#[cfg(all(feature = "time_size_u32", feature = "time_size_u64"))]
compile_error!("Enable exactly one: time_size_u32 or time_size_u64");

#[cfg(feature = "time_size_u32")]
pub type Milliseconds = u32;
#[cfg(feature = "time_size_u64")]
pub type Milliseconds = u64;

type HandshakeSeqNum = u16;

type RecordSeqNum = u64;
type RecordSeqNumShort = u8;

type Connections<'a> = [Option<DtlsConnection<'a>>];
type RecordQueue<'a> = buffer_record_queue::BufferMessageQueue<'a>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    HandshakeFailure = 40,
    IllegalParameter = 47,
    DecodeError = 50,
    DecryptionError = 51,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    UnknownPskIdentity = 115,
    Unknown,
}

impl From<u8> for AlertDescription {
    fn from(value: u8) -> Self {
        match value {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            40 => Self::HandshakeFailure,
            47 => AlertDescription::IllegalParameter,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptionError,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            115 => Self::UnknownPskIdentity,
            _ => AlertDescription::Unknown,
        }
    }
}

impl AlertDescription {
    pub fn alert_level(&self) -> AlertLevel {
        match self {
            AlertDescription::UnexpectedMessage
            | AlertDescription::IllegalParameter
            | AlertDescription::DecodeError
            | AlertDescription::DecryptionError
            | AlertDescription::MissingExtension
            | AlertDescription::UnsupportedExtension
            | AlertDescription::CloseNotify
            | AlertDescription::UnknownPskIdentity
            | AlertDescription::HandshakeFailure
            | AlertDescription::Unknown => AlertLevel::Fatal,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
}

impl From<u8> for AlertLevel {
    fn from(value: u8) -> Self {
        match value {
            1 => AlertLevel::Warning,
            _ => AlertLevel::Fatal,
        }
    }
}

#[derive(Debug)]
pub enum DtlsError {
    MaximumConnectionsReached,
    UnknownConnection,
    MaximumRetransmissionsReached,
    HandshakeAlreadyRunning,
    OutOfMemory,
    /// Indicates a bug in the implementation
    IllegalInnerState,
    IoError,
    RngError,
    ParseError,
    CryptoError,
    NoMatchingEpoch,
    RejectedSequenceNumber,
    Alert(AlertDescription),
    MultipleRecordsPerPacketNotSupported,
    UnsupportedNamedGroup,
}

#[macro_export]
macro_rules! illegal_state {
    () => {{
        log::debug!("Illegal state at {}", line!());
        DtlsError::IllegalInnerState
    }};
}
#[macro_export]
macro_rules! parse_err {
    () => {{
        log::debug!("Parse error at {}", line!());
        DtlsError::ParseError
    }};
}

/// Common (async,sync) stack context information
struct StackContext<'a> {
    rng: &'a mut dyn rand_core::CryptoRngCore,
    staging_buffer: &'a mut [u8],
    select_group: SelectNamedGroup,
    require_cookie: bool,
    // In any case the minimal recommended length for K is L bytes (as the hash output
    // length) RFC 2104
    cookie_key: GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct ConnectionId(usize);

impl core::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

struct DtlsConnection<'a> {
    epochs: [EpochState; 4],
    current_epoch: Epoch,
    pub addr: SocketAddr,
    handshake_finished: bool,
    p: PhantomData<&'a ()>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DtlsPoll {
    /// Wait at most until a new message has arrived or the timeout has elapsed before
    /// calling [`poll`] again.
    WaitTimeoutMs(Milliseconds),
    /// Wait at most until a new message has arrived before calling [`poll`] again.
    Wait,
    /// Indicates a finished handshake.
    /// Poll should be called again immediately after resetting the handshake slot.
    FinishedHandshake(HandshakeSlotIndex),

    AbortedHandshake(HandshakeSlotIndex),
}

impl DtlsPoll {
    pub fn merge(self, other: Self) -> Self {
        match (self, other) {
            (DtlsPoll::FinishedHandshake(i), _) | (_, DtlsPoll::FinishedHandshake(i)) => {
                DtlsPoll::FinishedHandshake(i)
            }
            (DtlsPoll::AbortedHandshake(i), _) | (_, DtlsPoll::AbortedHandshake(i)) => {
                DtlsPoll::AbortedHandshake(i)
            }
            (DtlsPoll::WaitTimeoutMs(t1), DtlsPoll::WaitTimeoutMs(t2)) => {
                DtlsPoll::WaitTimeoutMs(t1.min(t2))
            }
            (DtlsPoll::WaitTimeoutMs(t), _) | (_, DtlsPoll::WaitTimeoutMs(t)) => {
                DtlsPoll::WaitTimeoutMs(t)
            }
            (DtlsPoll::Wait, DtlsPoll::Wait) => DtlsPoll::Wait,
        }
    }
}

enum DeferredAction<'a> {
    None,
    Send(&'a [u8]),
    AppData(ConnectionId, Range<usize>),
    Unhandled,
}

fn try_pass_packet_to_connection<'a>(
    staging_buffer: &'a mut [u8],
    connections: &mut [Option<DtlsConnection>],
    peer_addr: &SocketAddr,
    packet_len: usize,
) -> Result<DeferredAction<'a>, DtlsError> {
    for i in 0..connections.len() {
        let connection = match connections[i].as_mut() {
            Some(c) if &c.addr == peer_addr && c.handshake_finished => c,
            _ => continue,
        };
        let mut packet_buffer = ParseBuffer::init(&mut staging_buffer[..packet_len]);
        let res = parse_record(&mut packet_buffer, &mut connection.epochs);
        let action = match res {
            Ok(RecordContentType::ApplicationData) => DeferredAction::AppData(
                ConnectionId(i),
                packet_buffer.offset()..packet_buffer.capacity(),
            ),
            Ok(RecordContentType::DtlsHandshake) => {
                trace!("Received handshake message on existing connection");
                match ParseHandshakeMessage::retrieve_content_type(&mut packet_buffer) {
                    // The first ack might have gone lost
                    Ok(
                        HandshakeMsgType::ServerHello
                        | HandshakeMsgType::EncryptedExtension
                        | HandshakeMsgType::Finished,
                    ) if connection.current_epoch < 6 => {
                        debug!("Found retransmitted handshake message. Resending ack.");
                        DeferredAction::Send(stage_ack(
                            staging_buffer,
                            &mut connection.epochs,
                            &3,
                            &2,
                        )?)
                    }
                    _ => close_connection(staging_buffer, connections, ConnectionId(i)),
                }
            }
            Ok(RecordContentType::Ack) => DeferredAction::None,
            Ok(_) => close_connection(staging_buffer, connections, ConnectionId(i)),
            Err(err) => {
                trace!("Received broken record: {:?}", err);
                if let DtlsError::Alert(alert) = err {
                    DeferredAction::Send(stage_alert(
                        staging_buffer,
                        &mut connection.epochs,
                        &connection.current_epoch,
                        alert,
                    )?)
                } else {
                    DeferredAction::None
                }
            }
        };
        return Ok(action);
    }
    Ok(DeferredAction::Unhandled)
}

fn close_connection<'a>(
    staging_buffer: &'a mut [u8],
    connections: &mut [Option<DtlsConnection>],
    connection_id: ConnectionId,
) -> DeferredAction<'a> {
    debug_assert!(connection_id.0 < connections.len());
    let mut action = DeferredAction::None;
    if connection_id.0 < connections.len() {
        if let Some(c) = connections[connection_id.0].as_mut() {
            if !c.handshake_finished {
                return action;
            }
            if let Ok(buf) = stage_alert(
                staging_buffer,
                &mut c.epochs,
                &c.current_epoch,
                AlertDescription::CloseNotify,
            ) {
                action = DeferredAction::Send(buf);
            }
        }
        connections[connection_id.0] = None;
    }
    action
}

fn try_pass_packet_to_handshake<'a>(
    stk_ctx: &'a mut StackContext<'_>,
    handshakes: &mut [HandshakeSlot],
    connections: &mut [Option<DtlsConnection>],
    peer_addr: &SocketAddr,
    packet_len: usize,
) -> Result<DeferredAction<'a>, DtlsError> {
    for handshake in handshakes {
        if let HandshakeSlotState::Running {
            state,
            handshake: ctx,
        } = &mut handshake.state
        {
            let connection = ctx.connection(connections);
            if &connection.addr != peer_addr {
                continue;
            }
            let cur_epoch_bound =
                (connection.current_epoch as usize + 1).min(connection.epochs.len());
            let Some((content_type, mut packet)) = try_unpack_record(
                &mut stk_ctx.staging_buffer[..packet_len],
                &mut connection.epochs[..cur_epoch_bound],
            )?
            else {
                return Ok(DeferredAction::None);
            };
            let mut new_state = *state;
            if content_type == RecordContentType::Alert {
                let (level, desc) = parse_alert(&mut packet)?;
                info!("Received alert: {:?}, {:?}", level, desc);
                handshake.close(connections);
                handshake.state = HandshakeSlotState::Aborted(desc);
            }
            // Implicit way to ack the client finished
            else if content_type == RecordContentType::ApplicationData
                && matches!(state, HandshakeState::Client(ClientState::WaitServerAck))
            {
                debug!("[Client] Acked client finished through app data");
                let start = packet.offset();
                let end = packet.capacity();
                let id = ctx.conn_id;
                handshake.finish_handshake(connection);
                return Ok(DeferredAction::AppData(ConnectionId(id), start..end));
            } else {
                let res = match &mut new_state {
                    HandshakeState::Client(state) => handle_handshake_message_client(
                        stk_ctx.rng,
                        ctx,
                        state,
                        &mut handshake.rt_queue,
                        &handshake.settings,
                        connection,
                        content_type,
                        packet,
                    ),
                    HandshakeState::Server(state) => handle_handshake_message_server(
                        ctx,
                        state,
                        &mut handshake.rt_queue,
                        connection,
                        content_type,
                        packet,
                    ),
                };
                if let Err(DtlsError::Alert(alert)) = res {
                    let buf = stage_alert(
                        stk_ctx.staging_buffer,
                        &mut connection.epochs,
                        &connection.current_epoch,
                        alert,
                    )?;
                    return Ok(DeferredAction::Send(buf));
                }
                res?;
                *state = new_state;
                // Send ack for client finish
                if matches!(
                    state,
                    HandshakeState::Server(ServerState::FinishedHandshake)
                ) {
                    debug!("[Server] Send ACK for client finish");
                    return Ok(DeferredAction::Send(stage_ack(
                        stk_ctx.staging_buffer,
                        &mut connection.epochs,
                        &3,
                        &2,
                    )?));
                }
            }
            return Ok(DeferredAction::None);
        }
    }
    Ok(DeferredAction::Unhandled)
}

fn create_handshake_connection<'a, 'b>(
    connections: &'a mut [Option<DtlsConnection<'b>>],
    peer_addr: &SocketAddr,
) -> Result<(usize, &'a mut DtlsConnection<'b>), DtlsError> {
    let slot = find_empty_connection_slot(connections);
    if let Some(slot) = slot {
        let slot = slot.min(connections.len() - 1);
        let c = &mut connections[slot];
        let c = c.insert(DtlsConnection {
            epochs: [
                EpochState::empty(),
                EpochState::empty(),
                EpochState::empty(),
                EpochState::empty(),
            ],
            current_epoch: 0,
            addr: *peer_addr,
            handshake_finished: false,
            p: PhantomData,
        });
        Ok((slot, c))
    } else {
        Err(DtlsError::MaximumConnectionsReached)
    }
}

fn open_connection(
    slot: &mut HandshakeSlot,
    connections: &mut Connections,
    peer_addr: &SocketAddr,
) -> bool {
    let Ok((conn_id, _)) = create_handshake_connection(connections, peer_addr) else {
        return false;
    };

    let HandshakeSlotState::Empty = slot.state else {
        return false;
    };
    slot.state = HandshakeSlotState::Running {
        state: HandshakeState::Client(ClientState::default()),
        handshake: HandshakeContext {
            recv_handshake_seq_num: 0,
            send_handshake_seq_num: 0,
            conn_id,
            selected_psk_in_ch: 0,
            crypto: CryptoInformation::new(),
            selected_cipher_suite: None,
            received_hello_retry_request: false,
            key_shares: Default::default(),
        },
    };

    true
}

fn accept_connection(slot: &mut HandshakeSlot) -> bool {
    let HandshakeSlotState::Empty = slot.state else {
        return false;
    };
    slot.state = HandshakeSlotState::AcceptConnection;
    true
}

fn find_empty_connection_slot(connections: &mut [Option<DtlsConnection>]) -> Option<usize> {
    for (i, c) in connections.iter().enumerate() {
        if c.is_none() {
            return Some(i);
        }
    }
    None
}

// #[inline(never)]
fn try_open_new_handshake<'a>(
    stk_ctx: &'a mut StackContext,
    handshakes: &mut [HandshakeSlot],
    connections: &mut [Option<DtlsConnection>],
    peer_addr: &SocketAddr,
    packet_len: usize,
) -> Result<Option<&'a [u8]>, DtlsError> {
    let mut epoch_states = [EpochState::empty()];
    let mut packet_buffer = ParseBuffer::init(&mut stk_ctx.staging_buffer[..packet_len]);
    let res = parse_plaintext_record(&mut packet_buffer, &mut epoch_states);
    let Ok(RecordContentType::DtlsHandshake) = res else {
        return Ok(None);
    };

    let result: Result<usize, DtlsError>;

    let mut handshake_slot_indx = 0;
    for slot in handshakes.iter() {
        if matches!(slot.state, HandshakeSlotState::AcceptConnection) {
            break;
        }
        handshake_slot_indx += 1
    }
    if handshake_slot_indx >= handshakes.len() {
        // TODO maybe sent alert that we are full?
        return Ok(None);
    }

    let Ok((mut client_hello, HandshakeMsgType::ClientHello, client_hello_seq_num @ (0 | 1))) =
        ParseHandshakeMessage::new(packet_buffer)
    else {
        return Ok(None);
    };

    let handshake_slot = &mut handshakes[handshake_slot_indx];

    let conn_len = connections.len();
    let Ok((conn_id, conn)) = create_handshake_connection(connections, peer_addr) else {
        return Ok(None);
    };
    let conn_id = conn_id.min(conn_len - 1);

    conn.epochs[0] = epoch_states.into_iter().next().unwrap();
    handshake_slot.fill_server(conn_id);

    let HandshakeSlotState::Running {
        state: _,
        handshake: ctx,
    } = &mut handshake_slot.state
    else {
        unreachable!()
    };

    'close: {
        let client_hello_start = client_hello.payload_buffer().offset();
        let ch_res = parse_client_hello_first_pass(
            stk_ctx.require_cookie,
            &stk_ctx.cookie_key,
            stk_ctx.select_group,
            ctx,
            &mut handshake_slot.rt_queue,
            handshake_slot.settings.psk_exchange_modes,
            peer_addr,
            client_hello.payload_buffer(),
        );

        match ch_res {
            Ok(ClientHelloResult::HelloRetry { request_key_share }) => {
                debug!(
                    "[Server] Didn't find valid cookie: {}. Requesting key_share: {}. Sending hello_retry",
                    stk_ctx.require_cookie,
                    request_key_share.is_some()
                );
                client_hello.add_to_transcript_hash(&mut ctx.crypto)?;
                result = stage_hello_retry_message(stk_ctx, ctx, peer_addr, request_key_share);
            }
            Ok(ClientHelloResult::Ok { dhe_group }) => {
                debug!("[Server] Found valid CH opening handshake");
                let res = parse_client_hello_second_pass(
                    stk_ctx.rng,
                    ctx,
                    handshake_slot.settings.psks,
                    client_hello.payload_buffer(),
                    dhe_group,
                    client_hello_start,
                );
                if let Err(e) = res {
                    result = Err(e);
                    break 'close;
                }

                client_hello.add_to_transcript_hash(&mut ctx.crypto)?;
                conn.epochs[0].send_record_seq_num = client_hello_seq_num as u64;
                ctx.send_handshake_seq_num = client_hello_seq_num as u8;
                ctx.recv_handshake_seq_num = client_hello_seq_num as u8 + 1;
                return Ok(None);
            }
            Err(err) => {
                debug!("[Server] Error parsing client_hello: {err:?}");
                result = Err(err);
            }
        }
    }

    let result = match result {
        Err(DtlsError::Alert(desc)) => {
            conn.epochs[0].send_record_seq_num += client_hello_seq_num as u64;
            stage_alert(
                stk_ctx.staging_buffer,
                &mut conn.epochs,
                &conn.current_epoch,
                desc,
            )
            .map(Some)
        }
        Err(e) => Err(e),
        Ok(len) => Ok(Some(&stk_ctx.staging_buffer[..len])),
    };
    handshake_slot.close(connections);
    accept_connection(handshake_slot);
    connections[conn_id] = None;
    result
}

fn stage_hello_retry_message(
    stk_ctx: &mut StackContext,
    ctx: &mut HandshakeContext,
    peer_addr: &SocketAddr,
    request_key_share: Option<NamedGroup>,
) -> Result<usize, DtlsError> {
    let mut buffer = ParseBuffer::init(stk_ctx.staging_buffer.borrow_mut());
    let mut record = EncodePlaintextRecord::new(&mut buffer, RecordContentType::DtlsHandshake, 0)?;
    let mut handshake =
        EncodeHandshakeMessage::new(record.payload_buffer(), HandshakeMsgType::ServerHello, 0)?;
    encode_hello_retry(
        handshake.payload_buffer(),
        &[],
        ctx.selected_cipher_suite.ok_or_else(|| illegal_state!())?,
        HelloRetryCookie::calculate(ctx.crypto.psk_hash_mut()?, &stk_ctx.cookie_key, peer_addr),
        request_key_share,
    )?;
    handshake.finish(&mut ctx.crypto)?;
    record.finish()?;
    let offset = buffer.offset();
    Ok(offset)
}

fn stage_ack<'a>(
    staging_buffer: &'a mut [u8],
    epoch_states: &mut [EpochState],
    epoch: &u64,
    ack_epoch: &u64,
) -> Result<&'a [u8], DtlsError> {
    let mut buffer = ParseBuffer::init(staging_buffer);
    let send_epoch_index = *epoch as usize & 3;
    let ack_epoch_index = *ack_epoch as usize & 3;
    let max_entries = (buffer.capacity() as u64 - 2) / 16;
    let mut record =
        EncodeCiphertextRecord::new(&mut buffer, &epoch_states[send_epoch_index], epoch)?;
    let w = &epoch_states[ack_epoch_index].sliding_window;
    let r = &epoch_states[ack_epoch_index].receive_record_seq_num;

    let len_pos = record.payload_buffer().prepend_len_u16();
    let mut index = 1;
    for i in 0..64.min(max_entries) {
        if w & index > 0 {
            let s = r - i;
            Parser::new(record.payload_buffer())?
                .write_u64(ack_epoch)
                .write_u64(&s)
                .end();
        }
        index <<= 1;
    }
    record.payload_buffer().submit_prepend_len_u16(len_pos)?;
    record.finish(&mut epoch_states[send_epoch_index], RecordContentType::Ack)?;
    let offset = buffer.offset();
    Ok(&buffer.release_buffer()[..offset])
}

fn stage_alert<'a>(
    staging_buffer: &'a mut [u8],
    epoch_states: &mut [EpochState],
    epoch: &u64,
    alert: AlertDescription,
) -> Result<&'a [u8], DtlsError> {
    info!("Sending alert: {:?}", alert);
    let epoch_index = *epoch as usize & 3;
    let mut buffer = ParseBuffer::init(staging_buffer);
    if epoch < &2 {
        let mut record = EncodePlaintextRecord::new(
            &mut buffer,
            RecordContentType::Alert,
            epoch_states[epoch_index].send_record_seq_num,
        )?;
        encode_alert(record.payload_buffer(), alert, alert.alert_level())?;
        record.finish()?;
    } else {
        let mut record =
            EncodeCiphertextRecord::new(&mut buffer, &epoch_states[epoch_index], epoch)?;
        encode_alert(record.payload_buffer(), alert, alert.alert_level())?;
        record.finish(&mut epoch_states[epoch_index], RecordContentType::Alert)?;
    }
    let offset = buffer.offset();
    Ok(&buffer.release_buffer()[..offset])
}

pub type HandshakeSlotIndex = usize;

pub struct HandshakeSlot<'a> {
    rt_queue: RecordQueue<'a>,
    settings: UserSettings<'a>,
    state: HandshakeSlotState,
}

pub struct UserSettings<'a> {
    psks: &'a [Psk<'a>],
    psk_exchange_modes: PskExchangeModes,
    #[allow(unused)]
    offered_key_shares: &'a [NamedGroup],
}

#[derive(Default)]
pub enum HandshakeSlotState {
    Running {
        state: HandshakeState,
        handshake: HandshakeContext,
    },
    AcceptConnection,
    #[default]
    Empty,
    Finished(ConnectionId),
    Aborted(AlertDescription),
}

#[derive(Clone, Copy)]
pub enum HandshakeState {
    Client(ClientState),
    Server(ServerState),
}

impl<'a> HandshakeSlot<'a> {
    ///
    /// **offered_key_shares:** Keyshares that are generated and sent with the first
    /// client_hello. Can be left empty to request selection from the server.
    /// Supported_groups will still contain all enabled groups.
    /// This setting is ignored server side or if no dhe
    /// group feature is enabled.
    pub fn new(
        available_psks: &'a [Psk<'a>],
        offered_key_shares: &'a [NamedGroup],
        buffer: &'a mut [u8],
    ) -> Self {
        HandshakeSlot {
            rt_queue: RecordQueue::new(buffer),
            settings: UserSettings {
                psks: available_psks,
                #[cfg(feature = "_dhe")]
                psk_exchange_modes: PSK_KE | crate::parsing::PSK_DHE_KE,
                #[cfg(not(feature = "_dhe"))]
                psk_exchange_modes: PSK_KE,
                offered_key_shares,
            },
            state: HandshakeSlotState::Empty,
        }
    }

    #[cfg(feature = "_dhe")]
    pub fn set_psk_exchange_modes(&mut self, support_psk_ex: bool, support_psk_dhe_ex: bool) {
        let mut m = 0;
        m |= support_psk_ex as u8 * PSK_KE;
        {
            m |= support_psk_dhe_ex as u8 * crate::parsing::PSK_DHE_KE;
        }
        self.settings.psk_exchange_modes = m;
    }

    fn fill_server(&mut self, conn_id: usize) {
        if let HandshakeSlotState::AcceptConnection = self.state {
            self.state = HandshakeSlotState::Running {
                state: HandshakeState::Server(ServerState::default()),
                handshake: HandshakeContext {
                    recv_handshake_seq_num: 0,
                    send_handshake_seq_num: 0,
                    conn_id,
                    received_hello_retry_request: false,
                    selected_psk_in_ch: 0,
                    crypto: CryptoInformation::new(),
                    selected_cipher_suite: None,
                    key_shares: Default::default(),
                },
            }
        }
    }

    pub fn try_take_connection_id(&mut self) -> Option<ConnectionId> {
        if let HandshakeSlotState::Finished(cid) = self.state {
            self.state = HandshakeSlotState::Empty;
            Some(cid)
        } else {
            None
        }
    }

    pub fn try_take_abort_reason(&mut self) -> Option<AlertDescription> {
        if let HandshakeSlotState::Aborted(desc) = self.state {
            self.state = HandshakeSlotState::Empty;
            Some(desc)
        } else {
            None
        }
    }

    fn finish_handshake(&mut self, conn: &mut DtlsConnection) {
        if let HandshakeSlotState::Running {
            state: _,
            handshake: ctx,
        } = mem::take(&mut self.state)
        {
            conn.handshake_finished = true;
            self.rt_queue.reset();
            let id = ctx.conn_id;
            self.state = HandshakeSlotState::Finished(ConnectionId(id));
        }
    }

    fn close(&mut self, connections: &mut [Option<DtlsConnection>]) {
        debug!("Closing handshake prematurely");
        match mem::take(&mut self.state) {
            HandshakeSlotState::Running {
                state: _,
                handshake: c,
            } => {
                connections[c.conn_id] = None;
            }
            HandshakeSlotState::Empty
            | HandshakeSlotState::Aborted(_)
            | HandshakeSlotState::AcceptConnection
            | HandshakeSlotState::Finished(_) => {}
        }
        self.rt_queue.reset();
    }
}

fn try_unpack_record<'a>(
    packet: &'a mut [u8],
    viable_epochs: &mut [EpochState],
) -> Result<Option<(RecordContentType, ParseBuffer<'a>)>, DtlsError> {
    let mut packet_buffer = ParseBuffer::init(packet);
    let res = parse_record(&mut packet_buffer, viable_epochs);

    match res {
        Err(DtlsError::NoMatchingEpoch) => {
            trace!("Rejected record because no cipher state was present for its epoch");
            Ok(None)
        }
        Err(DtlsError::RejectedSequenceNumber) => {
            trace!("Rejected record because it was already received");
            Ok(None)
        }
        Err(DtlsError::ParseError | DtlsError::CryptoError) => {
            trace!("Rejected record because it was broken");
            Ok(None)
        }
        Err(err) => Err(err),
        Ok(content_type) => Ok(Some((content_type, packet_buffer))),
    }
}

struct EpochState {
    send_record_seq_num: RecordSeqNum,
    receive_record_seq_num: RecordSeqNum,
    read_traffic_secret: TrafficSecret,
    write_traffic_secret: TrafficSecret,
    sliding_window: u64,
}

impl EpochState {
    pub const fn new(
        read_traffic_secret: TrafficSecret,
        write_traffic_secret: TrafficSecret,
    ) -> Self {
        Self {
            send_record_seq_num: 0,
            receive_record_seq_num: 0,
            read_traffic_secret,
            write_traffic_secret,
            sliding_window: 0,
        }
    }

    pub const fn empty() -> Self {
        Self::new(TrafficSecret::None, TrafficSecret::None)
    }

    pub(crate) fn check_seq_num(&self, seq_num: &u64) -> Result<(), DtlsError> {
        const WINDOW_MAX_SHIFT_BITS: u64 = 64 - 1;
        let highest_seq_num = self.receive_record_seq_num;

        if highest_seq_num > *seq_num {
            let diff = highest_seq_num - seq_num;
            if diff > WINDOW_MAX_SHIFT_BITS {
                return Err(DtlsError::RejectedSequenceNumber);
            }
            let window_index = 1u64 << diff;
            if self.sliding_window & window_index > 0 {
                // Record already present
                return Err(DtlsError::RejectedSequenceNumber);
            }
        } else {
            let shift = seq_num - highest_seq_num;
            if shift == 0 && self.sliding_window & 1 == 1 {
                // We already received this record
                return Err(DtlsError::RejectedSequenceNumber);
            }
        }
        Ok(())
    }

    pub(crate) fn mark_received(&mut self, seq_num: &u64) {
        let highest_seq_num = &self.receive_record_seq_num;
        if highest_seq_num > seq_num {
            let diff = highest_seq_num - seq_num;
            let window_index = 1u64 << diff;
            debug_assert!(self.sliding_window & window_index == 0);
            self.sliding_window |= window_index;
        } else {
            let shift = seq_num - highest_seq_num;
            if shift >= 64 {
                self.sliding_window = 0;
            } else {
                self.sliding_window <<= shift;
            }
            self.receive_record_seq_num = *seq_num;
            debug_assert!(self.sliding_window & 1 == 0);
            self.sliding_window |= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{DtlsError, EpochState, crypto::TrafficSecret};

    #[test]
    pub fn reject_double_receive() {
        let mut state = EpochState::new(TrafficSecret::None, TrafficSecret::None);
        state.check_seq_num(&2).unwrap();
        state.mark_received(&2);
        assert!(matches!(
            state.check_seq_num(&2),
            Err(DtlsError::RejectedSequenceNumber)
        ));
    }
    #[test]
    pub fn reject_too_old_receive() {
        let mut state = EpochState::new(TrafficSecret::None, TrafficSecret::None);
        state.mark_received(&64);
        assert!(matches!(
            state.check_seq_num(&0),
            Err(DtlsError::RejectedSequenceNumber)
        ));
    }
    #[test]
    pub fn correctly_check_after_shift() {
        let mut state = EpochState::new(TrafficSecret::None, TrafficSecret::None);
        state.mark_received(&20);
        state.mark_received(&64);
        assert!(matches!(
            state.check_seq_num(&20),
            Err(DtlsError::RejectedSequenceNumber)
        ));
    }
}
