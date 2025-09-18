use core::slice;

use log::{debug, trace};

#[cfg(feature = "async")]
use crate::asynchronous::SocketAndAddr;

use crate::{
    DtlsError, DtlsPoll, Epoch, EpochShort, EpochState, HandshakeSeqNum, Milliseconds,
    RecordSeqNum, RecordSeqNumShort, illegal_state,
    parsing_utility::ParseBuffer,
    record_parsing::{EncodeCiphertextRecord, EncodePlaintextRecord, RecordContentType},
};

struct EntryIterator<'a> {
    entries: slice::IterMut<'a, Entry>,
    now_ms: &'a Milliseconds,
    next_rt_timestamp: Milliseconds,
}

impl<'a> EntryIterator<'a> {
    fn new(entries: slice::IterMut<'a, Entry>, now_ms: &'a Milliseconds) -> Self {
        Self {
            entries,
            now_ms,
            next_rt_timestamp: Milliseconds::MAX,
        }
    }

    fn timeout(&self) -> DtlsPoll {
        if self.next_rt_timestamp == Milliseconds::MAX {
            DtlsPoll::Wait
        } else {
            DtlsPoll::WaitTimeoutMs(self.next_rt_timestamp - self.now_ms)
        }
    }

    fn try_next(&mut self) -> Result<Option<&mut RetransmissionEntry>, DtlsError> {
        for rt in &mut self.entries {
            if let Entry::Retransmission(rt) = rt {
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
    message_queue: [Entry; 3],
}

impl<'a> BufferMessageQueue<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            buffer_pos: 0,
            cookie: None,
            message_queue: [Entry::Empty, Entry::Empty, Entry::Empty],
        }
    }

    pub(crate) fn run_retransmission(
        &mut self,
        stage_buffer: &mut [u8],
        send_bytes: &mut dyn FnMut(&[u8]),
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        now_ms: &Milliseconds,
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
        stage_buffer: &mut [u8],
        socket: &mut SocketAndAddr<'_, Socket>,
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        now_ms: &Milliseconds,
    ) -> Result<DtlsPoll, DtlsError> {
        let mut iter = EntryIterator::new(self.message_queue.iter_mut(), now_ms);
        while let Some(rt) = iter.try_next()? {
            let buf = send_entry(self.buffer, rt, stage_buffer, epoch_states, epoch)?;
            socket.send(buf).await?;
        }
        Ok(iter.timeout())
    }

    pub fn alloc_entry_with_cookie(&mut self) -> (ParseBuffer<'_>, Option<&[u8]>) {
        let cookie = self.cookie.take().unwrap_or(Slice { index: 0, len: 0 });
        let len_size = size_of::<u16>();
        let extra = if cookie.len > 0 {
            cookie.len + len_size + 1
        } else {
            0
        };
        let (cookie_buf, buffer) = self.buffer.split_at_mut(cookie.index + extra);
        let b = get_alloc_space(buffer, self.buffer_pos - cookie_buf.len());
        (
            b,
            (cookie.len > 0).then_some(&cookie_buf[cookie.index..cookie.index + cookie.len]),
        )
    }

    pub fn alloc_entry(&mut self) -> ParseBuffer<'_> {
        get_alloc_space(self.buffer, self.buffer_pos)
    }

    pub fn submit_rt_entry(
        &mut self,
        epoch: EpochShort,
        now_ms: &Milliseconds,
        offset: usize,
    ) -> Result<usize, DtlsError> {
        let handshake_data = submit_alloc_space(&mut self.buffer_pos, self.buffer, offset)?;
        let slot = self.find_empty_slot()?;
        self.message_queue[slot] =
            Entry::Retransmission(RetransmissionEntry::new(handshake_data, epoch, now_ms));
        Ok(slot)
    }

    fn find_empty_slot(&self) -> Result<usize, DtlsError> {
        for i in 0..self.message_queue.len() {
            if matches!(self.message_queue[i], Entry::Empty) {
                return Ok(i);
            }
        }
        Err(DtlsError::OutOfMemory)
    }

    pub(crate) fn send_rt_entry(
        &mut self,
        index: usize,
        stage_buffer: &mut [u8],
        epoch_states: &mut [EpochState],
        epoch: EpochShort,
        send_bytes: &mut dyn FnMut(&[u8]),
    ) -> Result<(), DtlsError> {
        let Some(Entry::Retransmission(rt)) = self.message_queue.get_mut(index) else {
            return Err(illegal_state!());
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
        let Some(Entry::Retransmission(rt)) = self.message_queue.get_mut(index) else {
            return Err(illegal_state!());
        };
        let buf = send_entry(self.buffer, rt, stage_buffer, epoch_states, epoch)?;
        socket.send(buf).await
    }

    pub fn submit_reordering_entry(
        &mut self,
        handshake_seq_num: HandshakeSeqNum,
        offset: usize,
    ) -> Result<(), DtlsError> {
        let record_data = submit_alloc_space(&mut self.buffer_pos, self.buffer, offset)?;
        let slot = self.find_empty_slot()?;
        self.message_queue[slot] = Entry::Reordering(ReorderingEntry {
            handshake_data: record_data,
            seq_num: handshake_seq_num,
        });
        Ok(())
    }

    pub fn try_take_handshake_buffer(&mut self, handshake_seq_num: u16) -> Option<ParseBuffer<'_>> {
        for record in self.message_queue.iter_mut() {
            match record {
                Entry::Reordering(ReorderingEntry {
                    handshake_data: record_data,
                    seq_num,
                }) if seq_num == &handshake_seq_num => {
                    clear_flag(self.buffer, record_data);
                    let buf = ParseBuffer::init(record_data.into_slice_mut(self.buffer));
                    record.take();
                    return Some(buf);
                }
                _ => {}
            }
        }
        None
    }

    pub fn free_empty_entries(&mut self) {
        self.free_data();
    }

    pub fn store_cookie(&mut self, cookie: &[u8]) -> Result<(), DtlsError> {
        print_bytes!("Store Cookie:", cookie);
        let mut b = get_alloc_space(self.buffer, self.buffer_pos);
        b.write_slice_checked(cookie)?;
        let offset = b.offset();
        self.cookie = Some(submit_alloc_space(
            &mut self.buffer_pos,
            self.buffer,
            offset,
        )?);
        Ok(())
    }

    fn free_data(&mut self) {
        let len_size = size_of::<u16>();
        let flag_size = 1;
        while self.buffer_pos > len_size + 1 && self.buffer[self.buffer_pos - 1] == 0 {
            let len = u16::from_be_bytes(
                self.buffer[self.buffer_pos - len_size - 1..self.buffer_pos - 1]
                    .try_into()
                    .expect("size_of works"),
            ) as usize;
            self.buffer_pos -= (len + len_size + flag_size).min(self.buffer_pos);
        }
    }

    pub fn clear_record_queue(&mut self) {
        self.message_queue = [Entry::Empty, Entry::Empty, Entry::Empty];
        self.buffer_pos = 0;
    }

    pub fn clear_retransmission(&mut self) -> Result<(), DtlsError> {
        for e in self.message_queue.iter_mut() {
            if matches!(e, Entry::Retransmission(_)) {
                let data = *e.take().record_data_raw()?;
                clear_flag(self.buffer, &data);
            }
        }
        self.free_data();
        Ok(())
    }

    pub fn reset(&mut self) {
        self.clear_record_queue();
        self.cookie = None;
    }

    pub fn ack(&mut self, ack_epoch: &Epoch, ack_seq_num: &RecordSeqNum) {
        if *ack_epoch >= u8::MAX as u64 || *ack_seq_num >= u8::MAX as u64 {
            return;
        }
        for entry in &mut self.message_queue {
            match entry {
                Entry::Retransmission(RetransmissionEntry {
                    handshake_data: _,
                    rt_timestamp_ms: _,
                    rt_count: _,
                    epoch,
                    seq_num,
                    acked,
                }) if *epoch == *ack_epoch as u8 && *seq_num == *ack_seq_num as u8 => {
                    trace!(
                        "Acked: epoch: {}, record_seq_num: {}",
                        ack_epoch, ack_seq_num
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

#[inline(always)]
fn clear_flag(buffer: &mut [u8], data: &Slice) {
    let len_size = size_of::<u16>();
    buffer[data.index + data.len + len_size] = 0;
}

fn get_alloc_space(buffer: &mut [u8], buffer_pos: usize) -> ParseBuffer<'_> {
    ParseBuffer::init(&mut buffer[buffer_pos..])
}

fn submit_alloc_space(
    buffer_pos: &mut usize,
    buffer: &mut [u8],
    offset: usize,
) -> Result<Slice, DtlsError> {
    let len = offset;

    let index = *buffer_pos;
    let len_size = size_of::<u16>();

    if len + len_size + 1 > buffer.len() - *buffer_pos {
        return Err(DtlsError::OutOfMemory);
    }

    buffer[index + len..index + len + len_size].copy_from_slice(&(len as u16).to_be_bytes());
    buffer[index + len + len_size] = 1;

    *buffer_pos += len;
    *buffer_pos += len_size;
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
        .map_err(|_| illegal_state!())?;
    if entry.epoch > 1 {
        let mut record =
            EncodeCiphertextRecord::new(&mut buffer, epoch_state, &(entry.epoch as u64))?;
        record.payload_buffer().write_slice_checked(slice)?;
        record.finish(epoch_state, RecordContentType::DtlsHandshake)?;
    } else {
        let mut record = EncodePlaintextRecord::new(
            &mut buffer,
            RecordContentType::DtlsHandshake,
            epoch_state.send_record_seq_num,
        )?;
        record.payload_buffer().write_slice_checked(slice)?;
        record.finish()?;
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

    fn record_data_raw(&self) -> Result<&Slice, DtlsError> {
        match self {
            Entry::Reordering(ReorderingEntry {
                handshake_data: record_data,
                seq_num: _,
            }) => Ok(record_data),
            Entry::Retransmission(retransmit) => Ok(&retransmit.handshake_data),
            Entry::Empty => Err(illegal_state!()),
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

    fn into_slice_mut(self, buffer: &mut [u8]) -> &mut [u8] {
        &mut buffer[self.index..self.index + self.len]
    }
}

struct ReorderingEntry {
    handshake_data: Slice,
    seq_num: HandshakeSeqNum,
}

struct RetransmissionEntry {
    pub handshake_data: Slice,
    rt_timestamp_ms: Milliseconds,
    rt_count: u8,
    seq_num: RecordSeqNumShort,
    epoch: EpochShort,
    acked: bool,
}

impl RetransmissionEntry {
    pub fn new(data: Slice, epoch: EpochShort, now_ms: &Milliseconds) -> Self {
        RetransmissionEntry {
            handshake_data: data,
            rt_timestamp_ms: *now_ms + 1000,
            rt_count: 0,
            epoch,
            seq_num: 0,
            acked: false,
        }
    }

    pub fn tick_rt_count(&mut self, now_ms: &Milliseconds) -> Result<(), DtlsError> {
        // implementations SHOULD use an initial timer value of 1000 ms and double the value at
        // each retransmission, up to no less than 60 seconds
        self.rt_count += 1;
        self.rt_timestamp_ms = *now_ms + 1000 * (1 << self.rt_count);
        if self.rt_count >= 7 {
            Err(DtlsError::MaximumRetransmissionsReached)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::buffer_record_queue::{clear_flag, get_alloc_space, submit_alloc_space};

    use super::BufferMessageQueue;

    #[test]
    fn test_alloc_and_free() {
        let _ = simple_logger::SimpleLogger::new().init();
        let mut b = [0; 20 + 18];
        let mut bq = BufferMessageQueue::new(&mut b);

        let mut b = get_alloc_space(bq.buffer, bq.buffer_pos);
        b.expect_length(10).unwrap();
        b.add_offset(10);
        let offset = b.offset();
        let slice1 = submit_alloc_space(&mut bq.buffer_pos, bq.buffer, offset).unwrap();

        let mut b = get_alloc_space(bq.buffer, bq.buffer_pos);
        b.expect_length(10).unwrap();
        b.add_offset(10);
        let offset = b.offset();
        let slice2 = submit_alloc_space(&mut bq.buffer_pos, bq.buffer, offset).unwrap();

        clear_flag(bq.buffer, &slice1);
        clear_flag(bq.buffer, &slice2);
        bq.free_data();
        let mut b = get_alloc_space(bq.buffer, bq.buffer_pos);
        b.write_slice_checked(&[42; 10]).unwrap();
        let offset = b.offset();
        let slice = submit_alloc_space(&mut bq.buffer_pos, bq.buffer, offset).unwrap();
        assert_eq!(slice.index, 0);
        assert_eq!(slice.len, 10);
        assert_eq!(bq.buffer[slice.index..slice.index + slice.len], [42; 10])
    }
}
