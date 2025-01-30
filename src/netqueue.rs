use log::{error, info, trace};

use crate::{
    parsing::ParseBuffer,
    record_parsing::{EncodeCiphertextRecord, EncodePlaintextRecord, RecordContentType},
    DtlsError, DtlsPoll, Epoch, EpochShort, EpochState, HandshakeSeqNum, RecordSeqNum, TimeStampMs
};

const LEGACY_VERSION: usize = 2;
const RANDOM: usize = 32;
const LEGACY_SESSION: usize = 1;
const LEGACY_COOKIE: usize = 1;
const CIPHER_SUITES: usize = 2;
const LEGACY_COMPRESSION_METHODS: usize = 2;

const EXTENSION_HEADER: usize = 2;
const SUPPORTED_VERSIONS_CLIENT: usize = 3;
const COOKIE: usize = 2 + 100;

const CLIENT_HELLO_LEN: usize = LEGACY_VERSION
    + RANDOM
    + LEGACY_SESSION
    + LEGACY_COOKIE
    + CIPHER_SUITES
    + LEGACY_COMPRESSION_METHODS
    + 2 * EXTENSION_HEADER
    + SUPPORTED_VERSIONS_CLIENT
    + COOKIE
    + 30; // FIXME: padding

const SERVER_HELLO_LEN: usize = 38 + 6 + COOKIE;

const HS_HDR_LEN: usize = 12;

pub struct NetQueue {
    pub(crate) state: NetQueueState,
}

pub(crate) enum NetQueueState {
    Empty,
    ClientResend(ClientResend),
    ServerResend(ServerResend),
    ClientReorder(Option<Finished>),
}

pub struct Cookie {
    len: usize,
    data: [u8; COOKIE],
}

impl Default for Cookie {
    fn default() -> Self {
        Self { len: 0, data: [0u8; COOKIE] }
    }
}

#[derive(Default)]
pub struct Retransmission<T: Default> {
    rt_timestamp_ms: u64,
    rt_count: u8,
    seq_num: u64,
    epoch: EpochShort,
    acked: bool,
    msg: T,
}

pub enum ClientResend {
    ClientHello(Retransmission<ClientHello>),
    Finished(Retransmission<Finished>),
}

#[derive(Default)]
pub struct ServerResend {
    pub sh: Retransmission<ServerHello>,
    pub ee: Retransmission<EncryptedExtensions>,
    pub fin: Retransmission<Finished>,
}

pub trait HandshakeHeader {
    fn hs_length(&self) -> u32 {
        let mut bytes: [u8; 4] = [0u8; 4];
        bytes[1..4].copy_from_slice(&self.as_bytes()[1..4]);
        u32::from_be_bytes(bytes)
    }
    fn hs_seq(&self) -> u16 {
        let mut bytes: [u8; 2] = [0u8; 2];
        bytes.copy_from_slice(&self.as_bytes()[4..6]);
        u16::from_be_bytes(bytes)
    }

    fn as_bytes(&self) -> &[u8];

    /// length of header + message
    fn len(&self) -> usize {
        let hs_len = self.hs_length();
        HS_HDR_LEN + hs_len as usize
    }
}

pub struct ServerHello {
    data: [u8; HS_HDR_LEN + SERVER_HELLO_LEN],
}

impl HandshakeHeader for ServerHello {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl core::default::Default for ServerHello {
    fn default() -> Self {
        Self { data: [0; HS_HDR_LEN + SERVER_HELLO_LEN] }
    }
}

#[derive(Default)]
pub struct EncryptedExtensions {
    data: [u8; HS_HDR_LEN + 2],
}

impl HandshakeHeader for EncryptedExtensions {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

pub struct ClientHello {
    data: [u8; HS_HDR_LEN + CLIENT_HELLO_LEN],
    // avoids saving cookie on stack
    cookie: Cookie,
}

impl HandshakeHeader for ClientHello {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl core::default::Default for ClientHello {
    fn default() -> Self {
        Self {
            data: [0; HS_HDR_LEN + CLIENT_HELLO_LEN],
            cookie: Cookie::default(),
        }
    }
}

pub struct Finished {
    data: [u8; HS_HDR_LEN + 32 + 5], // FIXME: padding
}

impl HandshakeHeader for Finished {
    fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl Default for Finished {
    fn default() -> Self {
        Self { data: [0u8; HS_HDR_LEN + 32 + 5] }
    }
}

impl<T: Default + HandshakeHeader> Retransmission<T> {

    fn init(&mut self, epoch: EpochShort, now_ms: &TimeStampMs) {
        self.rt_timestamp_ms = *now_ms + 1000;
        self.rt_count = 0;
        self.epoch = epoch;
        self.seq_num = 0;
        self.acked = false;
    }

    fn send_entry<'a>(
        &mut self,
        stage_buffer: &'a mut [u8],
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
    ) -> Result<&'a [u8], DtlsError> {
        let message_buffer = self.msg.as_bytes();
        let mut buffer = ParseBuffer::init(stage_buffer);
        debug_assert!(epoch >= self.epoch && epoch - self.epoch < 4);
        let epoch_state = &mut epoch_states[self.epoch as usize & 3];
        self.seq_num = epoch_state
            .send_record_seq_num
            .try_into()
            .map_err(|_| DtlsError::IllegalInnerState)?;
        if self.epoch > 1 {
            let mut record =
                EncodeCiphertextRecord::new(&mut buffer, epoch_state, &(self.epoch as u64))?;
            record.payload_buffer().expect_length(self.msg.len())?;
            record.payload_buffer().write_into(&message_buffer[..self.msg.len()]);
            record.finish(epoch_state, RecordContentType::DtlsHandshake)?;
        } else {
            let mut record = EncodePlaintextRecord::new(
                &mut buffer,
                RecordContentType::DtlsHandshake,
                epoch_state.send_record_seq_num,
            )?;
            record.payload_buffer().expect_length(self.msg.len())?;
            record.payload_buffer().write_into(&message_buffer[..self.msg.len()]);
            record.finish();
            epoch_state.send_record_seq_num += 1;
        }
        let offset = buffer.offset();
        Ok(&buffer.release_buffer()[..offset])
    }

    fn run_retransmission(
        &mut self,
        now_ms: &TimeStampMs,
        stage_buffer: &mut [u8],
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        send_bytes: &mut dyn FnMut(&[u8])
    ) -> Result<u64, DtlsError>
    {
        trace!("Entry: epoch: {}, seq_num: {}, acked: {}",
            self.epoch, self.seq_num, self.acked
        );

        if self.acked {
            return Ok(0);
        }
        if self.rt_timestamp_ms > *now_ms {
            return Ok(self.rt_timestamp_ms);
        }
        trace!(
            "Retransmitting entry: epoch: {}, last_record_seq_num: {}",
            self.epoch,
            self.seq_num,
        );
        debug_assert!(epoch >= self.epoch && epoch - self.epoch < 4);

        // implementations SHOULD use an initial timer value of 1000 ms and double the value at
        // each retransmission, up to no less than 60 seconds
        self.rt_count += 1;
        self.rt_timestamp_ms = *now_ms + 1000 * (1u64 << self.rt_count);
        if self.rt_count >= 7 {
            return Err(DtlsError::MaximumRetransmissionsReached);
        }

        let buf = self.send_entry(stage_buffer, epoch_states, epoch)?;
        send_bytes(buf);
        Ok(self.rt_timestamp_ms)
    }

    fn ack(&mut self, ack_epoch: &Epoch, ack_seq_num: &RecordSeqNum) {
        if self.epoch as Epoch == *ack_epoch && self.seq_num == *ack_seq_num {
            trace!("Acked: epoch: {}, seq_num: {}", ack_epoch, ack_seq_num);
            self.acked = true;
        }
    }

    fn schedule(&mut self) {
        if !self.acked {
            self.rt_timestamp_ms = 0;
        }
    }
}

type EncodeData<'a> = &'a mut dyn FnMut(&mut ParseBuffer<&mut [u8]>) -> Result<(), DtlsError>;

impl NetQueue {
    pub fn new() -> Self {
        NetQueue { state: NetQueueState::Empty }
    }

    pub(crate) fn run_retransmission(
        &mut self,
        now_ms: &TimeStampMs,
        staging_buffer: &mut [u8],
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        send_bytes: &mut dyn FnMut(&[u8]),
    ) -> Result<DtlsPoll, DtlsError>
    {
        let mut next_rt_timestamp = 0;
        if let NetQueueState::ClientResend(resend) = &mut self.state {
            let timestamp_ms = match resend {
                ClientResend::ClientHello(rt) => {
                    rt.run_retransmission(now_ms, staging_buffer, epoch_states, epoch, send_bytes)?
                },
                ClientResend::Finished(rt) => {
                    rt.run_retransmission(now_ms, staging_buffer, epoch_states, epoch, send_bytes)?
                },
            };
            next_rt_timestamp = next_rt_timestamp.max(timestamp_ms);
        } else if let NetQueueState::ServerResend(resend) = &mut self.state {
            next_rt_timestamp = next_rt_timestamp.max(resend.sh.run_retransmission(now_ms, staging_buffer, epoch_states, epoch, send_bytes)?);
            next_rt_timestamp = next_rt_timestamp.max(resend.ee.run_retransmission(now_ms, staging_buffer, epoch_states, epoch, send_bytes)?);
            next_rt_timestamp = next_rt_timestamp.max(resend.fin.run_retransmission(now_ms, staging_buffer, epoch_states, epoch, send_bytes)?);
        }
        if next_rt_timestamp == 0 {
            Ok(DtlsPoll::Wait)
        } else {
            Ok(DtlsPoll::WaitTimeoutMs((next_rt_timestamp - now_ms) as u32))
        }
    }

    pub fn ack(&mut self, ack_epoch: &u64, ack_seq_num: &u64) {
        match &mut self.state {
            NetQueueState::ClientResend(ClientResend::ClientHello(rt)) => rt.ack(ack_epoch, ack_seq_num),
            NetQueueState::ClientResend(ClientResend::Finished(rt)) => rt.ack(ack_epoch, ack_seq_num),
            NetQueueState::ServerResend(server_resend) => {
                server_resend.sh.ack(ack_epoch, ack_seq_num);
                server_resend.ee.ack(ack_epoch, ack_seq_num);
                server_resend.fin.ack(ack_epoch, ack_seq_num);
            },
            _ => (),
        }
    }

    pub fn schedule_all_unacked_rt_entries(&mut self) {
        match &mut self.state {
            NetQueueState::ClientResend(ClientResend::ClientHello(rt)) => rt.schedule(),
            NetQueueState::ClientResend(ClientResend::Finished(rt)) => rt.schedule(),
            NetQueueState::ServerResend(server_resend) => {
                server_resend.sh.schedule();
                server_resend.ee.schedule();
                server_resend.fin.schedule();
            },
            _ => (),
        }
    }

    pub(crate) fn reset(&mut self) {
        self.state = NetQueueState::Empty;
    }

    pub(crate) fn send_rt_entry(
        &mut self,
        index: usize,
        stage_buffer: &mut [u8],
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        send_bytes: &mut dyn FnMut(&[u8]),
    ) -> Result<(), DtlsError> {
        let buf = match &mut self.state {
            NetQueueState::Empty => {
                error!("[NetQueue] send_rt_entry: in state Empty");
                return Err(DtlsError::IllegalInnerState);
            },
            NetQueueState::ClientResend(client_resend) => {
                match client_resend {
                    ClientResend::ClientHello(rt) => {
                        rt.send_entry(stage_buffer, epoch_states, epoch)?
                    },
                    ClientResend::Finished(rt) => {
                        rt.send_entry(stage_buffer, epoch_states, epoch)?
                    },
                }
            },
            NetQueueState::ServerResend(server_resend) => {
                match index {
                    0 => server_resend.sh.send_entry(stage_buffer, epoch_states, epoch)?,
                    1 => server_resend.ee.send_entry(stage_buffer, epoch_states, epoch)?,
                    2 => server_resend.fin.send_entry(stage_buffer, epoch_states, epoch)?,
                    _ => {
                        error!("[NetQueue] send_rt_entry: invalid index {}", index);
                        return Err(DtlsError::IllegalInnerState);
                    },
                }
            },
            NetQueueState::ClientReorder(_) => { return Ok(()) },
        };
        send_bytes(buf);
        Ok(())
    }

    pub fn store_cookie(&mut self, cookie: &[u8]) -> Result<(), DtlsError> {
        let NetQueueState::ClientResend(ClientResend::ClientHello(rt)) = &mut self.state else { 
            error!("[NetQueue] in not in state ClientResend ClientHello");
            return Err(DtlsError::IllegalInnerState);
        };
        let len = alloc_data(&mut rt.msg.cookie.data, &mut |b| {
            b.expect_length(cookie.len())?;
            b.write_into(cookie);
            Ok(())
        })?;
        rt.msg.cookie.len = len;
        Ok(())
    }

    pub fn alloc_client_hello_with_cookie(
        &mut self,
        epoch: EpochShort,
        now_ms: &TimeStampMs,
        encode_data: &mut dyn FnMut(
            &mut ParseBuffer<&mut [u8]>,
            Option<&[u8]>,
        ) -> Result<(), DtlsError>,
    ) -> Result<(), DtlsError> {
        let NetQueueState::ClientResend(ClientResend::ClientHello(rt)) = &mut self.state else { 
            error!("[NetQueue] in not in state ClientResend ClientHello");
            return Err(DtlsError::IllegalInnerState);
        };

        rt.init(epoch, now_ms);

        let buffer = &mut rt.msg.data;
        let mut cookie_buffer: Option<&[u8]> = None;
        let cookie_len = rt.msg.cookie.len;
        if cookie_len > 0 {
            cookie_buffer = Some(&rt.msg.cookie.data[..cookie_len]);
        }

        alloc_data(buffer, &mut |b| {
            encode_data(b, cookie_buffer)
        })?;
        Ok(())
    }

    pub fn alloc_client_finish(
        &mut self,
        epoch: EpochShort,
        now_ms: &TimeStampMs,
        encode_data: EncodeData,
    ) -> Result<(), DtlsError> {
        let NetQueueState::ClientResend(ClientResend::Finished(rt)) = &mut self.state else { 
            error!("[NetQueue] in not in state ClientResend Finished");
            return Err(DtlsError::IllegalInnerState);
        };

        rt.init(epoch, now_ms);

        let buffer = &mut rt.msg.data;
        alloc_data(buffer, encode_data)?;
        Ok(())
    }

    pub fn alloc_client_reorder(
        &mut self,
        handshake_seq_num: HandshakeSeqNum,
        encode_data: EncodeData,
    ) -> Result<(), DtlsError> {
        let NetQueueState::ClientReorder(option) = &mut self.state else { 
            error!("[NetQueue] in not in state ClientReorder");
            return Err(DtlsError::IllegalInnerState);
        };

        if matches!(option, Some(_)) {
            info!("[NetQueue] replace client reorder message");
        }

        // FIXME: handshake_seq_num

        self.state = NetQueueState::ClientReorder(Some(Finished::default()));
        let NetQueueState::ClientReorder(Some(fin)) = &mut self.state else { unreachable!() };

        let buffer = &mut fin.data;
        alloc_data(buffer, encode_data)?;
        Ok(())
    }

    pub fn alloc_server_hello(
        &mut self,
        epoch: EpochShort,
        now_ms: &TimeStampMs,
        encode_data: EncodeData,
    ) -> Result<usize, DtlsError> {
        let NetQueueState::ServerResend(resend) = &mut self.state else { 
            error!("[NetQueue] in not in state ServerResend");
            return Err(DtlsError::IllegalInnerState);
        };
        resend.sh.init(epoch, now_ms);
        let buffer = &mut resend.sh.msg.data;
        alloc_data(buffer, encode_data)?;
        Ok(0)
    }

    pub fn alloc_encrypted_extensions(
        &mut self,
        epoch: EpochShort,
        now_ms: &TimeStampMs,
        encode_data: EncodeData,
    ) -> Result<usize, DtlsError> {
        let NetQueueState::ServerResend(resend) = &mut self.state else { 
            error!("[NetQueue] in not in state ServerResend");
            return Err(DtlsError::IllegalInnerState);
        };
        resend.ee.init(epoch, now_ms);
        let buffer = &mut resend.ee.msg.data;
        alloc_data(buffer, encode_data)?;
        Ok(1)
    }

    pub fn alloc_server_finished(
        &mut self,
        epoch: EpochShort,
        now_ms: &TimeStampMs,
        encode_data: EncodeData,
    ) -> Result<usize, DtlsError> {
        let NetQueueState::ServerResend(resend) = &mut self.state else { 
            error!("[NetQueue] in not in state ServerResend");
            return Err(DtlsError::IllegalInnerState);
        };
        resend.fin.init(epoch, now_ms);
        let buffer = &mut resend.fin.msg.data;
        alloc_data(buffer, encode_data)?;
        Ok(2)
    }

}

fn alloc_data(
    buffer: &mut [u8],
    encode_data: EncodeData,
) -> Result<usize, DtlsError> {
    let mut space = ParseBuffer::init(buffer);
    encode_data(&mut space)?;
    let len = space.offset();
    Ok(len)
}
