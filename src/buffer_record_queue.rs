use core::{borrow::BorrowMut, mem::size_of};

use log::{debug, error, trace, warn};

#[cfg(feature = "async")]
use crate::asynchronous::SocketAndAddr;

type EncodeData<'a> = &'a mut dyn FnMut(&mut ParseBuffer<&mut [u8]>) -> Result<(), DtlsError>;

use crate::{
    parsing::ParseBuffer,
    record_parsing::{EncodeCiphertextRecord, EncodePlaintextRecord, RecordContentType},
    DtlsError, DtlsPoll, Epoch, EpochShort, EpochState, HandshakeSeqNum, RecordSeqNum,
    RecordSeqNumShort, TimeStampMs,
};

struct EntryIterator<'a> {
    entries: <&'a mut heapless::Deque<Entry, 3> as IntoIterator>::IntoIter,
    now_ms: &'a u64,
    next_rt_timestamp: u64,
}

impl<'a> EntryIterator<'a> {
    fn new(
        entries: <&'a mut heapless::Deque<Entry, 3> as IntoIterator>::IntoIter,
        now_ms: &'a u64,
    ) -> Self {
        Self {
            entries,
            now_ms,
            next_rt_timestamp: u64::MAX,
        }
    }

    fn timeout(&self) -> DtlsPoll {
        if self.next_rt_timestamp == u64::MAX {
            DtlsPoll::Wait
        } else {
            DtlsPoll::WaitTimeoutMs((self.next_rt_timestamp - self.now_ms) as u32)
        }
    }

    fn try_next(&mut self) -> Result<Option<&mut RetransmissionEntry>, DtlsError> {
        for entry in &mut self.entries {
            if let Entry::Retransmission(rt) = entry {
                if rt.acked {
                    continue;
                }
                if &rt.rt_timestamp_ms <= self.now_ms {
                    debug!(
                        "Retransmitting record: epoch: {}, last sent with record_seq_num: {}",
                        rt.epoch, rt.seq_num,
                    );
                    rt.tick_rt_count(self.now_ms)?;
                    self.next_rt_timestamp = self.next_rt_timestamp.min(rt.rt_timestamp_ms);

                    return Ok(Some(rt));
                } else {
                    self.next_rt_timestamp = self.next_rt_timestamp.min(rt.rt_timestamp_ms);
                }
            }
        }
        Ok(None)
    }
}

pub struct BufferMessageQueue<'a> {
    buffer: &'a mut [u8],
    pub buffer_pos: usize,
    cookie: Option<Slice>,
    message_queue: heapless::Deque<Entry, 3>,
}

impl<'a> BufferMessageQueue<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            buffer_pos: 0,
            cookie: None,
            message_queue: heapless::Deque::new(),
        }
    }

    pub(crate) fn run_retransmission(
        &mut self,
        now_ms: &TimeStampMs,
        stage_buffer: &mut [u8],
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        send_bytes: &mut dyn FnMut(&[u8]),
    ) -> Result<DtlsPoll, DtlsError> {
        let mut iter = EntryIterator::new(self.message_queue.iter_mut(), now_ms);
        while let Some(rt) = iter.try_next()? {
            let buf = send_entry(self.buffer, rt, stage_buffer, epoch_states, epoch)?;
            send_bytes(buf);
        }
        Ok(iter.timeout())
    }

    #[cfg(feature = "async")]
    pub(crate) async fn run_retransmission_async<Socket: embedded_nal_async::UnconnectedUdp>(
        &mut self,
        now_ms: &TimeStampMs,
        stage_buffer: &mut [u8],
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        socket: &mut SocketAndAddr<'_, Socket>,
    ) -> Result<DtlsPoll, DtlsError> {
        let mut iter = EntryIterator::new(self.message_queue.iter_mut(), now_ms);
        while let Some(rt) = iter.try_next()? {
            let buf = send_entry(self.buffer, rt, stage_buffer, epoch_states, epoch)?;
            socket.send(buf).await?;
        }
        Ok(iter.timeout())
    }

    pub fn alloc_rt_entry_with_cookie(
        &mut self,
        epoch: EpochShort,
        now_ms: &TimeStampMs,
        encode_data: &mut dyn FnMut(
            &mut ParseBuffer<&mut [u8]>,
            Option<&[u8]>,
        ) -> Result<(), DtlsError>,
    ) -> Result<usize, DtlsError> {
        if let Some(cookie) = self.cookie.take() {
            let len_size = size_of::<usize>();
            let buffer = self.buffer.borrow_mut();
            let (cookie_buf, buf) = buffer.split_at_mut(cookie.index + cookie.len + len_size + 1);
            self.buffer_pos -= cookie_buf.len();
            let mut handshake_data = alloc_data(buf, &mut self.buffer_pos, &mut |b| {
                encode_data(
                    b,
                    Some(&cookie_buf[cookie.index..cookie.index + cookie.len]),
                )
            })?;
            handshake_data.index += cookie_buf.len();
            self.buffer_pos += cookie_buf.len();

            self.message_queue
                .push_back(Entry::Retransmission(RetransmissionEntry::new(
                    handshake_data,
                    epoch,
                    now_ms,
                )))
                .map_err(|_| DtlsError::OutOfMemory)?;
            Ok(self.message_queue.len() - 1)
        } else {
            self.alloc_rt_entry(epoch, now_ms, &mut |b| encode_data(b, None))
        }
    }

    pub fn alloc_rt_entry(
        &mut self,
        epoch: EpochShort,
        now_ms: &TimeStampMs,
        encode_data: EncodeData,
    ) -> Result<usize, DtlsError> {
        let handshake_data = self.alloc_data(encode_data)?;
        self.message_queue
            .push_back(Entry::Retransmission(RetransmissionEntry::new(
                handshake_data,
                epoch,
                now_ms,
            )))
            .map_err(|_| DtlsError::OutOfMemory)?;
        Ok(self.message_queue.len() - 1)
    }

    pub(crate) fn send_rt_entry(
        &mut self,
        index: usize,
        stage_buffer: &mut [u8],
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        send_bytes: &mut dyn FnMut(&[u8]),
    ) -> Result<(), DtlsError> {
        let Some(Entry::Retransmission(rt)) = self.message_queue.iter_mut().nth(index) else {
            return Err(DtlsError::IllegalInnerState);
        };
        let buf = send_entry(self.buffer, rt, stage_buffer, epoch_states, epoch)?;
        send_bytes(buf);
        Ok(())
    }

    #[cfg(feature = "async")]
    pub(crate) async fn send_rt_entry_async<Socket: embedded_nal_async::UnconnectedUdp>(
        &mut self,
        index: usize,
        stage_buffer: &mut [u8],
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        socket: &mut SocketAndAddr<'_, Socket>,
    ) -> Result<(), DtlsError> {
        let Some(Entry::Retransmission(rt)) = self.message_queue.iter_mut().nth(index) else {
            return Err(DtlsError::IllegalInnerState);
        };
        let buf = send_entry(self.buffer, rt, stage_buffer, epoch_states, epoch)?;
        socket.send(buf).await
    }

    pub fn alloc_reordering_entry(
        &mut self,
        handshake_seq_num: HandshakeSeqNum,
        encode_data: EncodeData,
    ) -> Result<(), DtlsError> {
        let record_data = self.alloc_data(encode_data)?;
        self.message_queue
            .push_back(Entry::Reordering(ReorderingEntry {
                handshake_data: record_data,
                seq_num: handshake_seq_num,
            }))
            .map_err(|_| DtlsError::OutOfMemory)?;
        Ok(())
    }

    pub fn try_find_handshake_message_index(&self, handshake_seq_num: u16) -> Option<usize> {
        for (i, record) in self.message_queue.iter().enumerate() {
            match record {
                Entry::Reordering(ReorderingEntry {
                    handshake_data: _,
                    seq_num,
                }) if seq_num == &handshake_seq_num => return Some(i),
                _ => {}
            }
        }
        None
    }

    pub fn get_handshake_buffer(&self, index: usize) -> Result<ParseBuffer<&[u8]>, DtlsError> {
        let Some(Entry::Reordering(ReorderingEntry {
            handshake_data: record_data,
            seq_num: _,
        })) = &self.message_queue.iter().nth(index)
        else {
            error!("Used invalid index!");
            return Err(DtlsError::IllegalInnerState);
        };
        Ok(ParseBuffer::init(record_data.to_slice(self.buffer)))
    }

    pub fn free_entry_by_index(&mut self, index: usize) {
        let Some(entry) = self.message_queue.iter_mut().nth(index) else {
            warn!("Used invalid index!");
            return;
        };
        let entry = entry.take();
        self.free_entry(&entry);
    }

    fn free_entry(&mut self, entry: &Entry) {
        self.free_data(entry.record_data_raw());
        self.clean_entries();
    }

    fn clean_entries(&mut self) {
        while let Some(Entry::Empty) = self.message_queue.front() {
            self.message_queue.pop_front();
        }
        while let Some(Entry::Empty) = self.message_queue.back() {
            self.message_queue.pop_back();
        }
    }

    pub fn store_cookie(&mut self, cookie: &[u8]) -> Result<(), DtlsError> {
        print_bytes!("Store Cookie:", cookie);
        self.cookie = Some(self.alloc_data(&mut |b| {
            b.expect_length(cookie.len())?;
            b.write_into(cookie);
            Ok(())
        })?);
        Ok(())
    }

    fn alloc_data(&mut self, encode_data: EncodeData) -> Result<Slice, DtlsError> {
        alloc_data(self.buffer, &mut self.buffer_pos, encode_data)
    }

    fn free_data(&mut self, data: &Slice) {
        let Slice { index, len } = data;

        if self.buffer_pos == index + len {
            self.buffer_pos = *index;
            let len_size = size_of::<usize>();
            while self.buffer_pos > len_size + 1 && self.buffer[self.buffer_pos - 1] == 0 {
                let len = usize::from_be_bytes(
                    self.buffer[self.buffer_pos - size_of::<usize>() - 1..self.buffer_pos - 1]
                        .try_into()
                        .expect("size_of works"),
                );
                self.buffer_pos -= (len + size_of::<usize>() + 1).min(self.buffer_pos);
            }
        } else {
            self.buffer[index + len] = 0;
        }
    }

    pub fn clear_record_queue(&mut self) {
        self.message_queue.clear();
        self.buffer_pos = 0;
    }

    pub fn clear_retransmission(&mut self) {
        let mut i = 0usize;
        while i < self.message_queue.len() {
            let entry = self.message_queue.iter_mut().nth(i).unwrap();
            if matches!(entry, Entry::Retransmission(_)) {
                let entry = &entry.take();
                self.free_entry(entry);
            }
            i += 1;
        }
    }

    pub fn reset(&mut self) {
        self.clear_record_queue();
        self.cookie = None;
    }

    pub fn ack(&mut self, ack_epoch: &Epoch, ack_seq_num: &RecordSeqNum) {
        for entry in &mut self.message_queue {
            match entry {
                Entry::Retransmission(RetransmissionEntry {
                    handshake_data: _,
                    rt_timestamp_ms: _,
                    rt_count: _,
                    epoch,
                    seq_num,
                    acked,
                }) if *ack_epoch < u8::MAX as u64
                    && *epoch == *ack_epoch as u8
                    && *ack_seq_num < u8::MAX as u64
                    && *seq_num == *ack_seq_num as u8 =>
                {
                    trace!(
                        "Acked: epoch: {}, record_seq_num: {}",
                        ack_epoch,
                        ack_seq_num
                    );
                    *acked = true;
                    return;
                }
                _ => {}
            }
        }
    }

    pub fn schedule_all_unacked_rt_entries(&mut self) {
        for entry in &mut self.message_queue {
            match entry {
                Entry::Retransmission(RetransmissionEntry {
                    handshake_data: _,
                    rt_timestamp_ms,
                    rt_count: _,
                    epoch: _,
                    seq_num: _,
                    acked,
                }) if !*acked => {
                    *rt_timestamp_ms = 0;
                }
                _ => {}
            }
        }
    }
}

fn alloc_data(
    buffer: &mut [u8],
    buffer_pos: &mut usize,
    encode_data: EncodeData,
) -> Result<Slice, DtlsError> {
    let mut space = ParseBuffer::init(&mut buffer[*buffer_pos..]);
    encode_data(&mut space)?;

    let index = *buffer_pos;
    let len = space.offset();
    let len_size = size_of::<usize>();

    if len + len_size + 1 > (buffer.len() - *buffer_pos) {
        return Err(DtlsError::OutOfMemory);
    }

    *buffer_pos += len;

    buffer[*buffer_pos..*buffer_pos + len_size].copy_from_slice(&len.to_be_bytes());
    *buffer_pos += len_size;

    buffer[*buffer_pos] = 1;
    *buffer_pos += 1;

    Ok(Slice { index, len })
}

fn send_entry<'a>(
    message_buffer: &[u8],
    entry: &mut RetransmissionEntry,
    stage_buffer: &'a mut [u8],
    epoch_states: &mut [EpochState],
    epoch: EpochShort,
) -> Result<&'a [u8], DtlsError> {
    let mut buffer = ParseBuffer::init(stage_buffer);
    let slice = entry.handshake_data.to_slice(message_buffer);
    debug_assert!(epoch >= entry.epoch && epoch - entry.epoch < 4);
    let epoch_state = &mut epoch_states[entry.epoch as usize & 3];
    entry.seq_num = epoch_state
        .send_record_seq_num
        .try_into()
        .map_err(|_| DtlsError::IllegalInnerState)?;
    if entry.epoch > 1 {
        let mut record =
            EncodeCiphertextRecord::new(&mut buffer, epoch_state, &(entry.epoch as u64))?;
        record.payload_buffer().expect_length(slice.len())?;
        record.payload_buffer().write_into(slice);
        record.finish(epoch_state, RecordContentType::DtlsHandshake)?;
    } else {
        let mut record = EncodePlaintextRecord::new(
            &mut buffer,
            RecordContentType::DtlsHandshake,
            epoch_state.send_record_seq_num,
        )?;
        record.payload_buffer().expect_length(slice.len())?;
        record.payload_buffer().write_into(slice);
        record.finish();
        epoch_state.send_record_seq_num += 1;
    }
    let offset = buffer.offset();
    Ok(&buffer.release_buffer()[..offset])
}

enum Entry {
    Reordering(ReorderingEntry),
    Retransmission(RetransmissionEntry),
    Empty,
}

impl Entry {
    fn take(&mut self) -> Entry {
        core::mem::replace(self, Entry::Empty)
    }

    fn record_data_raw(&self) -> &Slice {
        match self {
            Entry::Reordering(ReorderingEntry {
                handshake_data: record_data,
                seq_num: _,
            }) => record_data,
            Entry::Retransmission(retransmit) => &retransmit.handshake_data,
            Entry::Empty => panic!("Can not access record data of empty record entry"),
        }
    }
}

#[derive(Clone, Copy)]
struct Slice {
    index: usize,
    len: usize,
}

impl Slice {
    fn to_slice(self, buffer: &[u8]) -> &[u8] {
        &buffer[self.index..self.index + self.len]
    }
}

struct ReorderingEntry {
    handshake_data: Slice,
    seq_num: HandshakeSeqNum,
}

struct RetransmissionEntry {
    pub handshake_data: Slice,
    rt_timestamp_ms: TimeStampMs,
    rt_count: u8,
    seq_num: RecordSeqNumShort,
    epoch: EpochShort,
    acked: bool,
}

impl RetransmissionEntry {
    pub fn new(data: Slice, epoch: EpochShort, now_ms: &TimeStampMs) -> Self {
        RetransmissionEntry {
            handshake_data: data,
            rt_timestamp_ms: *now_ms + 1000,
            rt_count: 0,
            epoch,
            seq_num: 0,
            acked: false,
        }
    }

    pub fn tick_rt_count(&mut self, now_ms: &u64) -> Result<(), DtlsError> {
        // implementations SHOULD use an initial timer value of 1000 ms and double the value at
        // each retransmission, up to no less than 60 seconds
        self.rt_count += 1;
        self.rt_timestamp_ms = *now_ms + 1000 * (1u64 << self.rt_count);
        if self.rt_count >= 7 {
            Err(DtlsError::MaximumRetransmissionsReached)
        } else {
            Ok(())
        }
    }
}
