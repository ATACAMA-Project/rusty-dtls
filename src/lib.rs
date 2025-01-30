#![no_std]

use core::{borrow::BorrowMut, marker::PhantomData, mem, net::SocketAddr, ops::Range};

use crypto::TrafficSecret;
use handshake::{
    handle_handshake_message_client, handle_handshake_message_server, ClientState,
    CryptoInformation, HandshakeContext, HandshakeInformation, ServerState,
};
use log::{debug, info, trace};
use parsing::{
    encode_alert, encode_hello_retry, parse_alert, parse_client_hello_first_pass,
    parse_client_hello_second_pass, ClientHelloResult, EncodeAck, EncodeHandshakeMessage,
    HandshakeType, HelloRetryCookie, ParseBuffer, ParseHandshakeMessage,
};

pub use crypto::{HashFunction, Psk};

use record_parsing::{
    parse_plaintext_record, parse_record, EncodeCiphertextRecord, EncodePlaintextRecord,
    RecordContentType,
};

mod fmt;

#[cfg(feature = "async")]
mod asynchronous;
#[cfg(feature = "async")]
pub use asynchronous::{DtlsStackAsync, Event};

mod sync;
pub use sync::DtlsStack;
pub use netqueue::NetQueue;

mod netqueue;
mod crypto;
mod handshake;
mod parsing;
mod record_parsing;

type Epoch = u64;
type EpochShort = u8;

type TimeStampMs = u64;

type HandshakeSeqNum = u16;

type RecordSeqNum = u64;
type RecordSeqNumShort = u8;

type Connections<'a> = [Option<DtlsConnection<'a>>];

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0,
    UnexpectedMessage = 10,
    IllegalParameter = 47,
    DecodeError = 50,
    DecryptionError = 51,
    MissingExtension = 109,
    UnsupportedExtension = 110,
    Unknown,
}

impl From<u8> for AlertDescription {
    fn from(value: u8) -> Self {
        match value {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            47 => AlertDescription::IllegalParameter,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptionError,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
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
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct ConnectionId(usize);

impl core::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

struct DtlsConnection<'a> {
    epochs: heapless::Vec<EpochState, 4>,
    current_epoch: Epoch,
    pub addr: SocketAddr,
    handshake_finished: bool,
    p: PhantomData<&'a ()>,
}

#[derive(PartialEq, Eq)]
pub enum DtlsPoll {
    /// Wait at most until a new message has arrived or the timeout has elapsed before
    /// calling [`poll`] again.
    WaitTimeoutMs(u32),
    /// Wait at most until a new message has arrived before calling [`poll`] again.
    Wait,
    /// Indicates a finished handshake.
    /// Poll should be called again immediately after resetting the handshake slot.
    FinishedHandshake,
}

impl DtlsPoll {
    pub fn merge(self, other: Self) -> Self {
        match (self, other) {
            (DtlsPoll::FinishedHandshake, _) | (_, DtlsPoll::FinishedHandshake) => {
                DtlsPoll::FinishedHandshake
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
    addr: &SocketAddr,
    packet_len: usize,
) -> Result<DeferredAction<'a>, DtlsError> {
    for i in 0..connections.len() {
        let connection = match connections[i].as_mut() {
            Some(c) if &c.addr == addr && c.handshake_finished => c,
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
                trace!("Already established connection received handshake message");
                match ParseHandshakeMessage::retrieve_content_type(&mut packet_buffer) {
                    // The first ack might have gone lost
                    Ok(
                        HandshakeType::ServerHello
                        | HandshakeType::EncryptedExtension
                        | HandshakeType::Finished,
                    ) if connection.current_epoch < 6 => {
                        trace!("Found retransmitted handshake message. Resending ack.");
                        DeferredAction::Send(stage_ack(
                            staging_buffer,
                            &mut connection.epochs,
                            &3,
                            &2,
                        )?)
                    }
                    _ => close_connection(ConnectionId(i), staging_buffer, connections),
                }
            }
            Ok(RecordContentType::Ack) => DeferredAction::None,
            Ok(_) => close_connection(ConnectionId(i), staging_buffer, connections),
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
    connection_id: ConnectionId,
    staging_buffer: &'a mut [u8],
    connections: &mut [Option<DtlsConnection>],
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
    staging_buffer: &'a mut [u8],
    connections: &mut [Option<DtlsConnection>],
    handshakes: &mut [HandshakeSlot],
    addr: &SocketAddr,
    packet_len: usize,
) -> Result<DeferredAction<'a>, DtlsError> {
    for handshake in handshakes {
        if let HandshakeSlotState::Running {
            state,
            handshake: ctx,
        } = &mut handshake.state
        {
            let connection = ctx.connection(connections);
            if &connection.addr != addr {
                continue;
            }
            let Some((content_type, mut packet)) =
                try_unpack_record(&mut staging_buffer[..packet_len], &mut connection.epochs)?
            else {
                return Ok(DeferredAction::None);
            };
            let mut new_state = *state;
            if content_type == RecordContentType::Alert {
                let (level, desc) = parse_alert(&mut packet)?;
                info!("Received alert: {:?}, {:?}", level, desc);
                handshake.close(connections);
                continue;
            }
            // Implicit way to ack the client finished
            else if content_type == RecordContentType::ApplicationData
                && matches!(state, HandshakeState::Client(ClientState::WaitServerAck))
            {
                trace!("[Client] Acked client finished through app data");
                let start = packet.offset();
                let end = packet.capacity();
                let id = ctx.conn_id;
                handshake.finish_handshake(connection);
                return Ok(DeferredAction::AppData(ConnectionId(id), start..end));
            } else {
                let res = match &mut new_state {
                    HandshakeState::Client(state) => handle_handshake_message_client(
                        state,
                        ctx,
                        &mut handshake.net_queue,
                        connection,
                        content_type,
                        packet,
                    ),
                    HandshakeState::Server(state) => handle_handshake_message_server(
                        state,
                        ctx,
                        &mut handshake.net_queue,
                        connection,
                        content_type,
                        packet,
                    ),
                };
                if let Err(DtlsError::Alert(alert)) = res {
                    let buf = stage_alert(
                        staging_buffer,
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
                    return Ok(DeferredAction::Send(stage_ack(
                        staging_buffer,
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
    addr: &SocketAddr,
) -> Result<(usize, &'a mut DtlsConnection<'b>), DtlsError> {
    let slot = find_empty_connection_slot(connections);
    if let Some(slot) = slot {
        connections[slot] = Some(DtlsConnection {
            epochs: heapless::Vec::new(),
            current_epoch: 0,
            addr: *addr,
            handshake_finished: false,
            p: PhantomData,
        });
        let _ = connections[slot]
            .as_mut()
            .unwrap()
            .epochs
            .push(EpochState::empty());
        Ok((slot, connections[slot].as_mut().unwrap()))
    } else {
        Err(DtlsError::MaximumConnectionsReached)
    }
}

fn open_connection(
    connections: &mut Connections,
    slot: &mut HandshakeSlot,
    addr: &SocketAddr,
) -> bool {
    let Ok((conn_id, _)) = create_handshake_connection(connections, addr) else {
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
            info: HandshakeInformation {
                available_psks: slot.psks,
                selected_psk: None,
                crypto: CryptoInformation::new(),
                selected_cipher_suite: None,
                received_hello_retry_request: false,
            },
        },
    };

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

fn try_open_new_handshake<'a>(
    staging_buffer: &'a mut [u8],
    require_cookie: bool,
    cookie_key: &[u8],
    handshakes: &mut [HandshakeSlot],
    connections: &mut [Option<DtlsConnection>],
    addr: &SocketAddr,
    packet_len: usize,
) -> Result<Option<&'a [u8]>, DtlsError> {
    let mut packet_buffer = ParseBuffer::init(&mut staging_buffer[..packet_len]);
    let mut epoch_states = [EpochState::empty()];
    let res = parse_plaintext_record(&mut packet_buffer, &mut epoch_states);
    let Ok(RecordContentType::DtlsHandshake) = res else {
        return Ok(None);
    };
    let mut send_buf = None;
    for handshake_slot in handshakes {
        if !matches!(handshake_slot.state, HandshakeSlotState::Empty) {
            continue;
        }
        let Ok((conn_id, conn)) = create_handshake_connection(connections, addr) else {
            return Ok(None);
        };
        conn.epochs[0] = epoch_states.into_iter().next().unwrap();

        handshake_slot.fill(conn_id);
        let HandshakeSlotState::Running {
            state: _,
            handshake: ctx,
        } = &mut handshake_slot.state
        else {
            unreachable!()
        };
        let Ok((mut client_hello, HandshakeType::ClientHello, client_hello_seq_num @ (0 | 1))) =
            ParseHandshakeMessage::new(packet_buffer.into_ref())
        else {
            break;
        };
        let client_hello_start = client_hello.payload_buffer().offset();
        match parse_client_hello_first_pass(
            client_hello.payload_buffer(),
            require_cookie,
            cookie_key,
            addr,
            ctx,
            &mut handshake_slot.net_queue,
        ) {
            Ok(ClientHelloResult::MissingCookie) => {
                trace!("Did not found valid cookie. Sending hello_retry");
                client_hello.add_to_transcript_hash(&mut ctx.info.crypto);
                send_buf = Some(stage_hello_retry_message(
                    staging_buffer,
                    cookie_key,
                    addr,
                    &mut ctx.info,
                )?);
            }
            Ok(ClientHelloResult::Ok) => {
                if require_cookie {
                    trace!("Found valid cookie opening handshake");
                }
                parse_client_hello_second_pass(
                    client_hello.payload_buffer(),
                    &mut ctx.info,
                    client_hello_start,
                )?;
                client_hello.add_to_transcript_hash(&mut ctx.info.crypto);
                conn.epochs[0].send_record_seq_num = client_hello_seq_num as u64;
                ctx.send_handshake_seq_num = client_hello_seq_num as u8;
                ctx.recv_handshake_seq_num = client_hello_seq_num as u8 + 1;
                break;
            }
            Err(err) => {
                trace!("Error parsing client_hello: {err:?}");
            }
        }
        handshake_slot.close(connections);
        connections[conn_id] = None;
        break;
    }
    Ok(send_buf)
}

fn stage_hello_retry_message<'a>(
    staging_buffer: &'a mut [u8],
    cookie_key: &[u8],
    addr: &SocketAddr,
    info: &mut HandshakeInformation,
) -> Result<&'a [u8], DtlsError> {
    let mut buffer = ParseBuffer::init(staging_buffer.borrow_mut());
    let mut record = EncodePlaintextRecord::new(&mut buffer, RecordContentType::DtlsHandshake, 0)?;
    let mut handshake =
        EncodeHandshakeMessage::new(record.payload_buffer(), HandshakeType::ServerHello, 0)?;
    encode_hello_retry(
        handshake.payload_buffer(),
        &[],
        info.selected_cipher_suite
            .ok_or(DtlsError::IllegalInnerState)?,
        HelloRetryCookie::calculate(info.crypto.psk_hash_mut()?, cookie_key, addr),
    )?;
    handshake.finish(&mut info.crypto);
    record.finish();
    let offset = buffer.offset();
    Ok(&buffer.release_buffer()[..offset])
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
    let mut ack = EncodeAck::new(record.payload_buffer())?;
    let w = &epoch_states[ack_epoch_index].sliding_window;
    let r = &epoch_states[ack_epoch_index].receive_record_seq_num;
    let mut index = 1;
    for i in 0..64.min(max_entries) {
        if w & index > 0 {
            let s = r - i;
            ack.add_entry(ack_epoch, &s)?;
        }
        index <<= 1;
    }
    ack.finish();
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
        record.finish();
    } else {
        let mut record =
            EncodeCiphertextRecord::new(&mut buffer, &epoch_states[epoch_index], epoch)?;
        encode_alert(record.payload_buffer(), alert, alert.alert_level())?;
        record.finish(&mut epoch_states[epoch_index], RecordContentType::Alert)?;
    }
    let offset = buffer.offset();
    Ok(&buffer.release_buffer()[..offset])
}

pub struct HandshakeSlot<'a> {
    net_queue: &'a mut NetQueue,
    psks: &'a [Psk<'a>],
    state: HandshakeSlotState<'a>,
}

#[derive(Default)]
pub enum HandshakeSlotState<'a> {
    Running {
        state: HandshakeState,
        handshake: HandshakeContext<'a>,
    },
    #[default]
    Empty,
    Finished(ConnectionId),
}

#[derive(Clone, Copy)]
pub enum HandshakeState {
    Client(ClientState),
    Server(ServerState),
}

// pub enum HandshakeSlot<'a> {
//     Client(ClientState, HandshakeContext<'a>),
//     Server(ServerState, HandshakeContext<'a>),
//     Finished(ConnectionId, &'a mut [u8], &'a [Psk<'a>]),
//     Empty(&'a mut [u8], &'a [Psk<'a>]),
// }

impl<'a> HandshakeSlot<'a> {
    pub fn new(available_psks: &'a [Psk<'a>], net_queue: &'a mut NetQueue) -> Self {
        HandshakeSlot {
            net_queue,
            psks: available_psks,
            state: HandshakeSlotState::Empty,
        }
    }

    fn fill(&mut self, conn_id: usize) {
        if let HandshakeSlotState::Empty = self.state {
            self.state = HandshakeSlotState::Running {
                state: HandshakeState::Server(ServerState::default()),
                handshake: HandshakeContext {
                    recv_handshake_seq_num: 0,
                    send_handshake_seq_num: 0,
                    conn_id,
                    info: HandshakeInformation {
                        received_hello_retry_request: false,
                        available_psks: self.psks,
                        selected_psk: None,
                        crypto: CryptoInformation::new(),
                        selected_cipher_suite: None,
                    },
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

    fn finish_handshake(&mut self, conn: &mut DtlsConnection) {
        if let HandshakeSlotState::Running {
            state: _,
            handshake: ctx,
        } = mem::take(&mut self.state)
        {
            conn.handshake_finished = true;
            self.net_queue.reset();
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
            HandshakeSlotState::Empty | HandshakeSlotState::Finished(_) => {}
        }
        self.net_queue.reset();
    }
}

fn try_unpack_record<'a>(
    packet: &'a mut [u8],
    viable_epochs: &mut [EpochState],
) -> Result<Option<(RecordContentType, ParseBuffer<&'a mut [u8]>)>, DtlsError> {
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

    use crate::{crypto::TrafficSecret, DtlsError, EpochState};

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
