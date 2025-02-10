use log::{debug, trace};

use crate::{
    crypto::{aead_decrypt_in_place, aead_encrypt_in_place, mac_length, xor_sequence_number},
    parsing::LEGACY_PROTOCOL_VERSION,
    parsing_utility::{parse_expect, ParseBuffer, Parser},
    DtlsError, EpochState,
};

#[repr(u8)]
#[derive(PartialEq, Eq)]
pub enum RecordContentType {
    Alert = 21,
    DtlsHandshake = 22,
    ApplicationData = 23,
    Ack = 26,
}

impl TryFrom<u8> for RecordContentType {
    type Error = DtlsError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            21 => Ok(RecordContentType::Alert),
            22 => Ok(RecordContentType::DtlsHandshake),
            23 => Ok(RecordContentType::ApplicationData),
            26 => Ok(RecordContentType::Ack),
            v => {
                debug!("Received unknown content type: {}", v);
                Err(DtlsError::ParseError)
            }
        }
    }
}

pub struct EncodePlaintextRecord<'a, 'b> {
    buffer: &'a mut ParseBuffer<'b>,
    len_pos: usize,
}

impl<'a, 'b> EncodePlaintextRecord<'a, 'b> {
    pub fn new(
        buffer: &'a mut ParseBuffer<'b>,
        content_type: RecordContentType,
        record_sequence_number: u64,
    ) -> Result<Self, DtlsError> {
        let len_pos = buffer.offset() + 11;
        Parser::new(buffer)?
            .write_u8(content_type as u8)
            .write_u16(LEGACY_PROTOCOL_VERSION)
            .write_u16(0) // Epoch
            .write_u48(&record_sequence_number)
            .write_u16(0) // Length
            .end();

        Ok(Self { buffer, len_pos })
    }

    pub fn payload_buffer<'c>(&'c mut self) -> &'c mut ParseBuffer<'b> {
        self.buffer
    }

    pub fn finish(self) {
        let payload_len = self.buffer.offset() - self.len_pos - 2;
        // TLS 1.3 5.1 the length MUST no exceed 2^14 bytes.
        debug_assert!(payload_len < 2 << 14);
        let mut buf = self.buffer.with_offset(self.len_pos);
        Parser::new(&mut buf)
            .expect("Checked in new")
            .write_u16(payload_len as u16)
            .end();
    }
}

pub fn parse_record(
    buffer: &mut ParseBuffer<'_>,
    viable_epochs: &mut [EpochState],
) -> Result<RecordContentType, DtlsError> {
    let b = buffer.access_slice_checked(buffer.offset()..buffer.offset() + 1)?[0];
    if b >> 5 == 1 {
        parse_ciphertext_record(buffer, viable_epochs)
    } else {
        parse_plaintext_record(buffer, viable_epochs)
    }
}

pub fn parse_plaintext_record(
    buffer: &mut ParseBuffer<'_>,
    viable_epochs: &mut [EpochState],
) -> Result<RecordContentType, DtlsError> {
    trace!("Parse plaintext record");
    let (content_type, r) = Parser::new(buffer)?.read_u8();
    let content_type = TryInto::<RecordContentType>::try_into(content_type)?;
    let (legacy_version, r) = r.read_u16();
    parse_expect(
        legacy_version == LEGACY_PROTOCOL_VERSION,
        DtlsError::ParseError,
    )?;
    let (epoch, r) = r.read_u16();
    parse_expect(epoch == 0, DtlsError::ParseError)?;
    let epoch_state = &mut viable_epochs[0];
    let (record_sequence_number, r) = r.read_u48();
    epoch_state.check_seq_num(&record_sequence_number)?;
    let (length, r) = r.read_u16();
    r.end();
    let length = length as usize;
    parse_expect(length < 2usize << 14, DtlsError::ParseError)?;
    buffer.expect_length(length)?;
    epoch_state.mark_received(&record_sequence_number);
    parse_expect(
        buffer.offset() + length == buffer.capacity(),
        DtlsError::MultipleRecordsPerPacketNotSupported,
    )?;

    Ok(content_type)
}

const MINIMUM_PAYLOAD_LENGTH: usize = 16;

pub struct EncodeCiphertextRecord<'a, 'b> {
    buffer: &'a mut ParseBuffer<'b>,
    seq_num_pos: usize,
    inner_record_len_pos: usize,
}

const CIPHERTEXT_HEADER_LEN: usize = 5;

impl<'a, 'b> EncodeCiphertextRecord<'a, 'b> {
    pub fn new(
        buffer: &'a mut ParseBuffer<'b>,
        epoch_state: &EpochState,
        current_epoch: &u64,
    ) -> Result<Self, DtlsError> {
        let seq_num_pos = buffer.offset() + 1;
        let inner_record_len_pos = buffer.offset() + 3;
        Parser::new(buffer)?
            .write_u8(0b00101100 + ((*current_epoch as u8) & 3))
            .write_u16(epoch_state.send_record_seq_num as u16)
            .write_u16(0)
            .end();
        Ok(Self {
            buffer,
            seq_num_pos,
            inner_record_len_pos,
        })
    }
    pub fn payload_buffer<'c>(&'c mut self) -> &'c mut ParseBuffer<'b> {
        self.buffer
    }

    pub fn finish(
        self,
        epoch_state: &mut EpochState,
        content_type: RecordContentType,
    ) -> Result<(), DtlsError> {
        let payload_len = self.buffer.offset() - self.inner_record_len_pos - 2;
        let mac_length = mac_length(&epoch_state.write_traffic_secret);
        let padding_len = MINIMUM_PAYLOAD_LENGTH.saturating_sub(1 + payload_len + mac_length);

        let r = Parser::new_dyn(self.buffer, padding_len)?;
        let mut r = r.write_u8(content_type as u8);
        while let Some(r) = r.next() {
            r.write_u8(0).end();
        }
        r.done().end();

        let to_encrypt_data_len = self.buffer.offset() - CIPHERTEXT_HEADER_LEN;
        let mut buf = self.buffer.with_offset(self.inner_record_len_pos);
        Parser::new(&mut buf)?
            .write_u16((to_encrypt_data_len + mac_length) as u16)
            .end();

        let (header, remaining_buffer) = self.buffer.split_at_mut_checked(CIPHERTEXT_HEADER_LEN)?;
        let mut payload = ParseBuffer::init_with_offset(remaining_buffer, to_encrypt_data_len);
        aead_encrypt_in_place(
            &epoch_state.write_traffic_secret,
            &epoch_state.send_record_seq_num,
            header,
            &mut payload,
        )?;
        xor_sequence_number(
            &epoch_state.write_traffic_secret,
            &mut header[self.seq_num_pos..self.seq_num_pos + 2],
            payload.access_slice_checked(0..16)?.try_into().unwrap(),
        )?;
        self.buffer.add_offset(mac_length);

        epoch_state.send_record_seq_num += 1;
        Ok(())
    }
}

pub fn parse_ciphertext_record(
    buffer: &mut ParseBuffer<'_>,
    viable_epochs: &mut [EpochState],
) -> Result<RecordContentType, DtlsError> {
    trace!("Parse ciphertext record");
    let header_start = buffer.offset();
    let header_descriptor = Parser::read_single_u8(buffer)?;
    parse_expect((header_descriptor >> 5) == 1, DtlsError::ParseError)?;
    let connection_id_present = (header_descriptor >> 4) & 1 == 1;
    parse_expect(!connection_id_present, DtlsError::ParseError)?;

    let two_byte_seq_num = (header_descriptor >> 3) & 1 == 1;
    let len_present = (header_descriptor >> 2) & 1 == 1;
    let epoch_bits = header_descriptor & 3;
    let epoch_state = select_viable_epoch(epoch_bits, viable_epochs)?;

    let seq_num_len = if two_byte_seq_num { 2 } else { 1 };
    let length_field_len = if len_present { 2 } else { 0 };

    let (header, payload) = buffer.split_at_mut_checked(1 + seq_num_len + length_field_len)?;
    xor_sequence_number(
        &epoch_state.read_traffic_secret,
        &mut header[1..1 + seq_num_len],
        &payload[..16].try_into().unwrap(),
    )?;
    let sequence_number_bytes = if two_byte_seq_num {
        Parser::read_single_u16(buffer)?
    } else {
        Parser::read_single_u8(buffer)? as u16
    };
    let encrypted_plaintext_len = if len_present {
        Parser::read_single_u16(buffer)?
    } else {
        (buffer.capacity() - buffer.offset()) as u16
    };
    let header_end = buffer.offset();

    let reconstructed_sequence_num = reconstruct_seq_num(
        epoch_state.receive_record_seq_num,
        sequence_number_bytes,
        two_byte_seq_num,
    );
    epoch_state.check_seq_num(&reconstructed_sequence_num)?;

    buffer.expect_length(encrypted_plaintext_len as usize)?;
    buffer.add_offset(encrypted_plaintext_len as usize);
    let (header, payload) = buffer.as_mut().split_at_mut(header_end - header_start);
    aead_decrypt_in_place(
        &epoch_state.read_traffic_secret,
        &reconstructed_sequence_num,
        header,
        &mut payload[..encrypted_plaintext_len as usize],
    )?;

    let mac_length = mac_length(&epoch_state.read_traffic_secret);
    let padding_bytes_count = payload[..encrypted_plaintext_len as usize - mac_length]
        .iter()
        .rev()
        .take_while(|b| **b == 0)
        .count();
    let payload_len = encrypted_plaintext_len as usize - 1 - padding_bytes_count - mac_length;
    let content_type: RecordContentType = payload[payload_len].try_into()?;

    epoch_state.mark_received(&reconstructed_sequence_num);
    let payload_start = header_end;
    buffer.set_offset(payload_start);
    parse_expect(
        buffer.offset() + encrypted_plaintext_len as usize == buffer.capacity(),
        DtlsError::MultipleRecordsPerPacketNotSupported,
    )?;
    buffer.truncate(buffer.offset() + payload_len);

    Ok(content_type)
}

pub fn select_viable_epoch(
    epoch_bits: u8,
    viable_epochs: &mut [EpochState],
) -> Result<&mut EpochState, DtlsError> {
    for (i, epoch_state) in viable_epochs.iter_mut().enumerate() {
        if (i & 3) as u8 == epoch_bits {
            return Ok(epoch_state);
        }
    }
    Err(DtlsError::NoMatchingEpoch)
}

fn reconstruct_seq_num(
    expected_seq_num: u64,
    received_seq_num_bytes: u16,
    two_bytes_seq_num: bool,
) -> u64 {
    let mask = if two_bytes_seq_num { 0xFFFF } else { 0xFF };
    let expected_seq_num_bytes = expected_seq_num as u16 & mask;

    let mut possible_seq_num =
        (expected_seq_num & (!(mask as u64))) + received_seq_num_bytes as u64;
    let mask_width = mask as u64 + 1;
    if expected_seq_num_bytes > received_seq_num_bytes {
        let diff = expected_seq_num_bytes - received_seq_num_bytes;
        if diff as u64 > mask_width / 2 && u64::MAX - possible_seq_num >= mask_width {
            possible_seq_num += mask_width;
        }
    } else {
        let diff = received_seq_num_bytes - expected_seq_num_bytes;
        if diff as u64 > mask_width / 2 && possible_seq_num >= mask_width {
            possible_seq_num -= mask_width;
        }
    }
    trace!("\tReconstructed record_seq_num: {}", possible_seq_num);
    possible_seq_num
}

#[cfg(test)]
mod tests {
    extern crate std;

    use crate::{
        parsing_utility::ParseBuffer,
        record_parsing::{EncodePlaintextRecord, RecordContentType},
    };

    use super::{parse_plaintext_record, reconstruct_seq_num};
    use crate::{crypto::TrafficSecret, record_parsing::parse_ciphertext_record, EpochState};
    use sha2::digest::generic_array::GenericArray;

    #[test]
    fn test_plaintext() {
        let _ = simple_logger::SimpleLogger::new().init();

        let mut buf = [0; 128];
        let mut buffer = ParseBuffer::init(&mut buf[..]);
        let mut record =
            EncodePlaintextRecord::new(&mut buffer, RecordContentType::DtlsHandshake, 1).unwrap();
        record
            .payload_buffer()
            .write_slice_checked(b"Hello World")
            .unwrap();
        record.finish();

        let epoch_state = EpochState {
            send_record_seq_num: 0,
            receive_record_seq_num: 0,
            read_traffic_secret: TrafficSecret::Aes128GcmSha256 {
                key: GenericArray::default(),
                iv: GenericArray::default(),
                sn: GenericArray::default(),
                traffic_secret: GenericArray::default(),
            },
            write_traffic_secret: TrafficSecret::Aes128GcmSha256 {
                key: GenericArray::default(),
                iv: GenericArray::default(),
                sn: GenericArray::default(),
                traffic_secret: GenericArray::default(),
            },
            sliding_window: 0,
        };
        let len = buffer.offset();
        let mut buffer = ParseBuffer::init(&mut buf[..len]);
        let rt = parse_plaintext_record(&mut buffer, &mut [epoch_state]).unwrap();
        assert!(rt == RecordContentType::DtlsHandshake);
        assert_eq!(
            &buffer.complete_inner_buffer()[buffer.offset()..],
            b"Hello World"
        );
    }

    #[test]
    #[cfg(feature = "aes128gcm_sha256")]
    fn test_ciphertext() {
        use crate::record_parsing::EncodeCiphertextRecord;

        let _ = simple_logger::SimpleLogger::new().init();

        let mut buf = [0; 128];
        let mut buffer = ParseBuffer::init(&mut buf[..]);
        let mut epoch_state = EpochState {
            send_record_seq_num: 0,
            receive_record_seq_num: 0,
            read_traffic_secret: TrafficSecret::Aes128GcmSha256 {
                key: GenericArray::default(),
                iv: GenericArray::default(),
                sn: GenericArray::default(),
                traffic_secret: GenericArray::default(),
            },
            write_traffic_secret: TrafficSecret::Aes128GcmSha256 {
                key: GenericArray::default(),
                iv: GenericArray::default(),
                sn: GenericArray::default(),
                traffic_secret: GenericArray::default(),
            },
            sliding_window: 0,
        };
        let mut record = EncodeCiphertextRecord::new(&mut buffer, &epoch_state, &0).unwrap();
        record
            .payload_buffer()
            .write_slice_checked(b"Hello World")
            .unwrap();
        record
            .finish(&mut epoch_state, RecordContentType::DtlsHandshake)
            .unwrap();
        let len = buffer.offset();
        let mut buffer = ParseBuffer::init(&mut buf[..len]);
        let rt = parse_ciphertext_record(&mut buffer, &mut [epoch_state]).unwrap();
        assert!(rt == RecordContentType::DtlsHandshake);
        assert_eq!(
            &buffer.complete_inner_buffer()[buffer.offset()..],
            b"Hello World"
        );
    }

    #[test]
    fn test_reconstruct_seq_num_lower() {
        assert_eq!(reconstruct_seq_num(250, 100, false), 100 + (1 << 8))
    }
    #[test]
    fn test_reconstruct_seq_num_lower_near_max() {
        assert_eq!(
            reconstruct_seq_num(u64::MAX, 2, false),
            (u64::MAX & (!0xFF)) + 2
        )
    }
    #[test]
    fn test_reconstruct_seq_num_higher() {
        assert_eq!(reconstruct_seq_num((1 << 8) + 2, 200, false), 200)
    }
    #[test]
    fn test_reconstruct_seq_num_higher_near_zero() {
        assert_eq!(reconstruct_seq_num(2, 200, false), 200)
    }
    #[test]
    fn test_reconstruct_seq_num_eq() {
        assert_eq!(reconstruct_seq_num((1 << 8) + 2, 2, false), (1 << 8) + 2)
    }
}
