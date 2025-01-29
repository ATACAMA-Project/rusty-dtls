use crate::buffer_record_queue::BufferMessageQueue;
use crate::crypto::{
    self, encode_binder_entry, validate_binder, CipherDependentCryptoState, CipherSuite, Psk,
    PskTranscriptHash, TrafficSecret,
};
use crate::handshake::{CryptoInformation, HandshakeContext, HandshakeInformation};
use crate::{AlertDescription, AlertLevel, DtlsError, Epoch, HandshakeSeqNum, RecordSeqNum};
use aes_gcm::aead::Buffer;
use core::mem;
use core::net::SocketAddr;

pub struct ParseBuffer<T> {
    buf: T,
    offset: usize,
}
impl<T: AsMut<[u8]>> ParseBuffer<T> {
    pub fn complete_inner_buffer_mut(&mut self) -> &mut [u8] {
        self.buf.as_mut()
    }

    pub fn write_u8(&mut self, b: u8) {
        self.write_into(&b.to_be_bytes());
    }

    pub fn write_u16(&mut self, b: u16) {
        self.write_into(&b.to_be_bytes());
    }

    pub fn set_u16(&mut self, index: usize, b: u16) {
        self.buf.as_mut()[index..index + 2].copy_from_slice(&b.to_be_bytes())
    }

    pub fn write_u32(&mut self, b: u32) {
        self.write_into(&b.to_be_bytes());
    }

    pub fn write_u64(&mut self, b: u64) {
        self.write_into(&b.to_be_bytes());
    }

    pub fn write_u24(&mut self, b: u32) {
        self.write_into(&b.to_be_bytes()[1..4]);
    }

    pub fn set_u24(&mut self, index: usize, b: u32) {
        self.buf.as_mut()[index..index + 3].copy_from_slice(&b.to_be_bytes()[1..])
    }

    pub fn write_u48(&mut self, b: u64) {
        self.write_into(&b.to_be_bytes()[2..8]);
    }

    pub fn write_into(&mut self, src: &[u8]) {
        self.buf.as_mut()[self.offset..self.offset + src.len()].copy_from_slice(src);
        self.offset += src.len();
    }

    pub fn write_prepend_length(
        &mut self,
        length_field_length: usize,
        variable_content: &mut dyn FnMut(&mut Self) -> Result<(), DtlsError>,
    ) -> Result<usize, DtlsError> {
        debug_assert!(length_field_length <= core::mem::size_of::<usize>());
        self.offset += length_field_length;

        let offset_begin = self.offset;
        variable_content(self)?;
        let length = self.offset - offset_begin;
        debug_assert!(
            length.leading_zeros() as usize
                >= (core::mem::size_of::<usize>() - length_field_length)
        );
        self.buf.as_mut()[offset_begin - length_field_length..offset_begin].copy_from_slice(
            &length.to_be_bytes()[core::mem::size_of::<usize>() - length_field_length..],
        );
        Ok(length)
    }
}

impl<T: AsRef<[u8]>> ParseBuffer<T> {
    pub fn init(buf: T) -> Self {
        ParseBuffer { buf, offset: 0 }
    }

    pub fn release_buffer(self) -> T {
        self.buf
    }

    pub fn init_with_offset(buf: T, offset: usize) -> Self {
        debug_assert!(buf.as_ref().len() >= offset);
        ParseBuffer { buf, offset }
    }

    pub fn set_offset(&mut self, offset: usize) {
        debug_assert!(offset < self.buf.as_ref().len());
        self.offset = offset;
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn capacity(&self) -> usize {
        self.buf.as_ref().len()
    }

    pub fn complete_inner_buffer(&self) -> &[u8] {
        self.buf.as_ref()
    }

    pub fn expect_length(&self, len: usize) -> Result<(), DtlsError> {
        if self.buf.as_ref().len() - self.offset >= len {
            Ok(())
        } else {
            Err(DtlsError::ParseError)
        }
    }

    pub fn read_u8(&mut self) -> u8 {
        let v = self.buf.as_ref()[self.offset];
        self.offset += 1;
        v
    }
    pub fn read_u16(&mut self) -> u16 {
        let v = u16::from_be_bytes(
            self.buf.as_ref()[self.offset..self.offset + 2]
                .try_into()
                .unwrap(),
        );
        self.offset += 2;
        v
    }

    pub fn read_u32(&mut self) -> u32 {
        let v = u32::from_be_bytes(
            self.buf.as_ref()[self.offset..self.offset + 4]
                .try_into()
                .unwrap(),
        );
        self.offset += 4;
        v
    }

    pub fn read_u64(&mut self) -> u64 {
        let v = u64::from_be_bytes(
            self.buf.as_ref()[self.offset..self.offset + 8]
                .try_into()
                .unwrap(),
        );
        self.offset += 8;
        v
    }

    pub fn read_u24(&mut self) -> u32 {
        let mut buf = [0; 4];
        buf[1..4].copy_from_slice(&self.buf.as_ref()[self.offset..self.offset + 3]);
        let v = u32::from_be_bytes(buf);
        self.offset += 3;
        v
    }

    pub fn read_u48(&mut self) -> u64 {
        let mut buf = [0; 8];
        buf[2..8].copy_from_slice(&self.buf.as_ref()[self.offset..self.offset + 6]);
        let v = u64::from_be_bytes(buf);
        self.offset += 6;
        v
    }
    pub fn read_as_reference(&mut self, length: usize) -> &[u8] {
        let begin = self.offset;
        self.offset += length;
        return &self.buf.as_ref()[begin..self.offset];
    }

    pub fn read_exactly_n(&mut self, written_into: &mut [u8], n: usize) {
        written_into.copy_from_slice(&self.buf.as_ref()[self.offset..self.offset + n]);
        self.offset += n;
    }

    pub fn read_into<const SZ: usize>(&mut self, written_into: &mut [u8; SZ]) {
        written_into.copy_from_slice(&self.buf.as_ref()[self.offset..self.offset + SZ]);
        self.offset += SZ;
    }

    /// Increases offset but does not write anything.
    pub fn add_offset(&mut self, len: usize) {
        debug_assert!(self.buf.as_ref().len() >= len + self.offset);
        self.offset += len;
    }
}

impl<T: AsMut<[u8]>> AsMut<[u8]> for ParseBuffer<T> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[..self.offset]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for ParseBuffer<T> {
    fn as_ref(&self) -> &[u8] {
        &self.buf.as_ref()[..self.offset]
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> Buffer for ParseBuffer<T> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        self.write_into(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.offset = len;
    }
}

impl<'a> ParseBuffer<&'a mut [u8]> {
    pub fn into_ref(self) -> ParseBuffer<&'a [u8]> {
        ParseBuffer::init_with_offset(self.buf, self.offset)
    }

    pub fn truncate(&mut self, len: usize) {
        let offset = self.offset;
        let buf = core::mem::take(&mut self.buf);
        *self = ParseBuffer::init_with_offset(&mut buf[..len], offset);
    }
}

impl Clone for ParseBuffer<&[u8]> {
    fn clone(&self) -> Self {
        ParseBuffer::init_with_offset(self.buf, self.offset)
    }
}

pub fn parse_expect(expect: bool, err: DtlsError) -> Result<(), DtlsError> {
    if expect {
        Ok(())
    } else {
        Err(err)
    }
}

pub const LEGACY_PROTOCOL_VERSION: u16 = u16::from_be_bytes([254, 253]);
pub const DTLS_1_3: u16 = 0xfefc;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtension = 8,
    Finished = 20,
    MessageHash = 254,
}

impl HandshakeType {
    pub fn from_num(val: u8) -> Option<Self> {
        match val {
            1 => Some(HandshakeType::ClientHello),
            2 => Some(HandshakeType::ServerHello),
            8 => Some(HandshakeType::EncryptedExtension),
            20 => Some(HandshakeType::Finished),
            _ => None,
        }
    }
}

pub struct EncodeHandshakeMessage<'a, 'b> {
    buffer: &'a mut ParseBuffer<&'b mut [u8]>,
    len_pos: usize,
    binders_len: usize,
}

impl<'a, 'b> EncodeHandshakeMessage<'a, 'b> {
    pub fn new(
        buffer: &'a mut ParseBuffer<&'b mut [u8]>,
        handshake_type: HandshakeType,
        handshake_seq_num: u16,
    ) -> Result<Self, DtlsError> {
        buffer.expect_length(12)?;
        buffer.write_u8(handshake_type as u8);
        let len_pos = buffer.offset();
        buffer.add_offset(3);
        buffer.write_u16(handshake_seq_num);
        buffer.write_u24(0);
        buffer.add_offset(3);
        Ok(Self {
            buffer,
            len_pos,
            binders_len: 0,
        })
    }

    pub fn payload_buffer<'c>(&'c mut self) -> &'c mut ParseBuffer<&'b mut [u8]> {
        self.buffer
    }

    pub fn partial_transcript_hash(
        &mut self,
        binders_len: usize,
        transcript_hash: &mut CryptoInformation,
    ) {
        let payload_len = self.buffer.offset - self.len_pos - 11;
        self.buffer.set_u24(self.len_pos, payload_len as u32);
        self.buffer.set_u24(self.len_pos + 8, payload_len as u32);
        self.binders_len = binders_len;
        let msg_start = self.len_pos - 1;

        transcript_hash.update_transcript_hash(&self.buffer.as_ref()[msg_start..msg_start + 4]);

        let binders_len_field_size = 2;
        transcript_hash.update_transcript_hash(
            &self.buffer.as_ref()
                [msg_start + 12..self.buffer.offset() - binders_len_field_size - binders_len],
        );
    }

    pub fn binders_buffer(&mut self) -> ParseBuffer<&mut [u8]> {
        let offset = self.buffer.offset();
        ParseBuffer::init(&mut self.buffer.as_mut()[offset - self.binders_len..])
    }

    pub fn finish_partial_transcript_hash(&mut self, transcript_hash: &mut CryptoInformation) {
        let binders_len_field_size = 2;
        transcript_hash.update_transcript_hash(
            &self.buffer.as_ref()
                [self.buffer.offset() - binders_len_field_size - self.binders_len..],
        );
    }

    pub fn finish(self, transcript_hash: &mut CryptoInformation) {
        debug_assert_eq!(self.binders_len, 0);
        let payload_len = self.buffer.offset - self.len_pos - 11;
        self.buffer.set_u24(self.len_pos, payload_len as u32);
        self.buffer.set_u24(self.len_pos + 8, payload_len as u32);

        let msg_start = self.len_pos - 1;
        let buf = self.buffer.as_ref();
        transcript_hash.update_transcript_hash(&buf[msg_start..msg_start + 4]);
        transcript_hash.update_transcript_hash(&buf[msg_start + 12..]);
    }
}

pub fn encode_client_hello(
    buffer: &mut ParseBuffer<&mut [u8]>,
    info: &mut HandshakeInformation,
    cipher_suites: &[CipherSuite],
    now_ms: &u64,
    rng: &mut dyn rand_core::CryptoRngCore,
    cookie: Option<&[u8]>,
) -> Result<(HandshakeType, usize), DtlsError> {
    buffer.expect_length(4 + 32)?;
    buffer.write_u16(LEGACY_PROTOCOL_VERSION);

    let mut random = [0; 32];
    rng.try_fill_bytes(&mut random)
        .map_err(|_| DtlsError::RngError)?;
    buffer.write_into(&random);

    buffer.write_u8(0); // Session
    buffer.write_u8(0); // Cookie
    buffer.write_prepend_length(2, &mut |buffer| {
        buffer.expect_length(cipher_suites.len() * mem::size_of::<u16>())?;
        for cipher_suite in cipher_suites {
            buffer.write_u16(*cipher_suite as u16);
        }
        Ok(())
    })?;
    buffer.write_u8(1); // Compression Length
    buffer.write_u8(0); // Compression

    buffer.expect_length(2)?;
    let mut binders_len: usize = 0;
    buffer.write_prepend_length(2, &mut |buffer| {
        encode_extension(buffer, &mut encode_supported_versions_client)?;
        if let Some(cookie) = cookie {
            encode_extension(buffer, &mut |buffer| encode_cookie(buffer, cookie))?;
        }
        encode_extension(buffer, &mut encode_pre_shared_key_exchange_modes)?;
        encode_extension(buffer, &mut |buffer| {
            let (ext_type, binders_l) = encode_pre_shared_key_client_with_empty_binders(
                buffer,
                info.available_psks,
                now_ms,
            )?;
            binders_len = binders_l;
            Ok(ext_type)
        })?;
        Ok(())
    })?;
    debug_assert_ne!(binders_len, 0);

    Ok((HandshakeType::ClientHello, binders_len))
}

pub fn encode_server_hello(
    buffer: &mut ParseBuffer<&mut [u8]>,
    rng: &mut dyn rand_core::CryptoRngCore,
    client_hello_session_id: &[u8],
    selected_cipher_suite: CipherSuite,
    selected_psk_id_idx: u16,
) -> Result<HandshakeType, DtlsError> {
    buffer.write_u16(LEGACY_PROTOCOL_VERSION);

    // new random
    let mut random = [0; 32];
    rng.try_fill_bytes(&mut random)
        .map_err(|_| DtlsError::RngError)?;
    buffer.write_into(&random);

    // echo whatever was sent in the client hello
    buffer.write_prepend_length(1, &mut |b| {
        b.write_into(client_hello_session_id);
        Ok(())
    })?;

    // cipher suite
    buffer.write_u16(selected_cipher_suite as u16);

    // Compression
    buffer.write_u8(0);

    //extensions
    buffer.write_prepend_length(2, &mut |buffer| {
        // needs supported version ext
        encode_extension(buffer, &mut encode_supported_versions_server)?;
        // psk identity index selection
        encode_extension(buffer, &mut |buffer| {
            buffer.write_u16(selected_psk_id_idx);
            Ok(ExtensionType::PreSharedKey)
        })?;

        Ok(())
    })?;

    Ok(HandshakeType::ServerHello)
}

pub enum HelloRetryCookie<'a> {
    Calculate {
        client_hello_hash: &'a PskTranscriptHash,
        cookie_key: &'a [u8],
        peer_addr: &'a SocketAddr,
    },
    Existing(&'a [u8]),
}

impl<'a> HelloRetryCookie<'a> {
    pub fn calculate(
        client_hello_hash: &'a PskTranscriptHash,
        cookie_key: &'a [u8],
        peer_addr: &'a SocketAddr,
    ) -> Self {
        Self::Calculate {
            client_hello_hash,
            peer_addr,
            cookie_key,
        }
    }
    pub fn existing(cookie: &'a [u8]) -> Self {
        Self::Existing(cookie)
    }
}

pub fn encode_hello_retry(
    buffer: &mut ParseBuffer<&mut [u8]>,
    client_hello_session_id: &[u8],
    cipher_suite: CipherSuite,
    cookie: HelloRetryCookie<'_>,
) -> Result<HandshakeType, DtlsError> {
    buffer.write_u16(LEGACY_PROTOCOL_VERSION);

    buffer.write_into(&HELLO_RETRY_RANDOM);

    // echo whatever was sent in the client hello
    buffer.write_prepend_length(1, &mut |b| {
        b.write_into(client_hello_session_id);
        Ok(())
    })?;

    // cipher suite
    buffer.write_u16(cipher_suite as u16);

    // Compression
    buffer.write_u8(0);

    //extensions
    buffer.write_prepend_length(2, &mut |buffer| {
        // needs supported version ext
        encode_extension(buffer, &mut encode_supported_versions_server)?;
        encode_extension(buffer, &mut |b| match cookie {
            HelloRetryCookie::Calculate {
                client_hello_hash,
                peer_addr,
                cookie_key,
            } => create_and_encode_cookie(b, cookie_key, peer_addr, client_hello_hash),
            HelloRetryCookie::Existing(cookie) => encode_cookie(b, cookie),
        })?;
        Ok(())
    })?;

    Ok(HandshakeType::ServerHello)
}

pub fn encode_encrypted_extensions(buffer: &mut ParseBuffer<&mut [u8]>) -> Result<(), DtlsError> {
    buffer.write_u16(0);
    Ok(())
}

pub fn encode_finished(
    buffer: &mut ParseBuffer<&mut [u8]>,
    secret: &TrafficSecret,
    crypto_state: &mut CipherDependentCryptoState,
) -> Result<HandshakeType, DtlsError> {
    crypto_state.encode_verify_data(buffer, secret)?;
    Ok(HandshakeType::Finished)
}

#[repr(u16)]
pub enum ExtensionType {
    PreSharedKey = 41,
    SupportedVersions = 43,
    Cookie = 44,
    PskKeyExchangeModes = 45,
    KeyShare = 51,
}

impl TryFrom<u16> for ExtensionType {
    type Error = DtlsError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            41 => Ok(ExtensionType::PreSharedKey),
            43 => Ok(ExtensionType::SupportedVersions),
            44 => Ok(ExtensionType::Cookie),
            45 => Ok(ExtensionType::PskKeyExchangeModes),
            51 => Ok(ExtensionType::KeyShare),
            _ => Err(DtlsError::ParseError),
        }
    }
}

pub fn encode_extension(
    buffer: &mut ParseBuffer<&mut [u8]>,
    encode_extension_data: &mut dyn FnMut(
        &mut ParseBuffer<&mut [u8]>,
    ) -> Result<ExtensionType, DtlsError>,
) -> Result<(), DtlsError> {
    let type_pos = buffer.offset();
    buffer.expect_length(2)?;
    buffer.add_offset(2);
    let mut extension_type = None;
    buffer.write_prepend_length(2, &mut |buffer| {
        extension_type = Some(encode_extension_data(buffer)?);
        Ok(())
    })?;
    buffer.as_mut()[type_pos..type_pos + 2]
        .copy_from_slice(&(extension_type.unwrap() as u16).to_be_bytes());
    Ok(())
}

pub fn encode_supported_versions_client(
    buffer: &mut ParseBuffer<&mut [u8]>,
) -> Result<ExtensionType, DtlsError> {
    buffer.expect_length(3)?;
    buffer.write_u8(2);
    buffer.write_u16(DTLS_1_3);
    Ok(ExtensionType::SupportedVersions)
}

pub fn encode_supported_versions_server(
    buffer: &mut ParseBuffer<&mut [u8]>,
) -> Result<ExtensionType, DtlsError> {
    buffer.expect_length(3)?;
    buffer.write_u16(DTLS_1_3);
    Ok(ExtensionType::SupportedVersions)
}

pub fn encode_pre_shared_key_client_with_empty_binders(
    buffer: &mut ParseBuffer<&mut [u8]>,
    psks: &[Psk<'_>],
    now_ms: &u64,
) -> Result<(ExtensionType, usize), DtlsError> {
    buffer.write_prepend_length(2, &mut |buffer| {
        for psk in psks {
            buffer.expect_length(2 + psk.identity.len() + mem::size_of::<u32>())?;
            buffer.write_prepend_length(2, &mut |buffer| {
                buffer.write_into(psk.identity);
                Ok(())
            })?;

            match psk.key_type {
                crate::crypto::PskType::Resumption {
                    ticket_creation_timestamp_ms,
                } => buffer.write_u32((now_ms - ticket_creation_timestamp_ms).try_into().unwrap()),
                crate::crypto::PskType::External => buffer.write_u32(0),
            }
        }
        Ok(())
    })?;
    let mut binders_space_len = 0;
    buffer.write_prepend_length(2, &mut |buffer| {
        for psk in psks {
            let binder_space_len = 1 + psk.hash_function.output_size();
            buffer.expect_length(binder_space_len)?;
            // Add empty offset here so lengths are calculated correctly
            buffer.add_offset(binder_space_len);
            binders_space_len += binder_space_len;
        }
        Ok(())
    })?;

    Ok((ExtensionType::PreSharedKey, binders_space_len))
}

pub fn encode_pre_shared_key_client_binders(
    binders_buffer: &mut ParseBuffer<&mut [u8]>,
    cipher_suite: Option<CipherSuite>,
    psks: &[Psk<'_>],
    transcript_hash: &mut CryptoInformation,
) -> Result<(), DtlsError> {
    if let Some(cipher_suite) = cipher_suite {
        // Partial client hello was already added to transcript hashes.
        let transcript_hash = transcript_hash.psk_hash_mut()?.finalize(&[]);
        let hash_fn = cipher_suite.hash_function();
        for psk in psks.iter().filter(|p| p.hash_function == hash_fn) {
            encode_binder_entry(binders_buffer, psk, transcript_hash.as_ref())?;
        }
    } else {
        // Partial client hello was already added to transcript hashes.
        let finalized_hashes = transcript_hash.psk_hashes_mut()?.finalize(&[]);
        for psk in psks.iter() {
            encode_binder_entry(binders_buffer, psk, finalized_hashes.get(psk.hash_function))?;
        }
    }
    Ok(())
}

pub fn encode_pre_shared_key_exchange_modes(
    buffer: &mut ParseBuffer<&mut [u8]>,
) -> Result<ExtensionType, DtlsError> {
    buffer.expect_length(2)?;
    buffer.write_u8(1);
    // psk_ke only
    buffer.write_u8(0);
    Ok(ExtensionType::PskKeyExchangeModes)
}

pub fn encode_cookie(
    buffer: &mut ParseBuffer<&mut [u8]>,
    cookie: &[u8],
) -> Result<ExtensionType, DtlsError> {
    buffer.expect_length(2 + cookie.len())?;
    buffer.write_u16(cookie.len() as u16);
    buffer.write_into(cookie);
    Ok(ExtensionType::Cookie)
}

pub fn create_and_encode_cookie(
    buffer: &mut ParseBuffer<&mut [u8]>,
    key: &[u8],
    peer_addr: &SocketAddr,
    client_hello_hash: &PskTranscriptHash,
) -> Result<ExtensionType, DtlsError> {
    buffer.write_prepend_length(2, &mut |buffer| {
        crypto::encode_cookie(buffer, key, client_hello_hash, peer_addr)
    })?;
    Ok(ExtensionType::Cookie)
}

pub fn encode_alert(
    buffer: &mut ParseBuffer<&mut [u8]>,
    description: AlertDescription,
    level: AlertLevel,
) -> Result<(), DtlsError> {
    buffer.expect_length(2)?;
    buffer.write_u8(level as u8);
    buffer.write_u8(description as u8);
    Ok(())
}

pub struct EncodeAck<'a, 'b> {
    message_start: usize,
    buffer: &'a mut ParseBuffer<&'b mut [u8]>,
}

impl<'a, 'b> EncodeAck<'a, 'b> {
    pub fn new(buffer: &'a mut ParseBuffer<&'b mut [u8]>) -> Result<Self, DtlsError> {
        buffer.expect_length(2)?;
        let message_start = buffer.offset;
        buffer.write_u16(0);
        Ok(Self {
            message_start,
            buffer,
        })
    }

    pub fn add_entry(&mut self, epoch: &Epoch, seq_num: &RecordSeqNum) -> Result<(), DtlsError> {
        self.buffer.expect_length(8 + 8)?;
        self.buffer.write_u64(*epoch);
        self.buffer.write_u64(*seq_num);
        Ok(())
    }

    pub fn finish(self) {
        let len = self.buffer.offset() - self.message_start - 2;
        self.buffer.set_u16(self.message_start, len as u16);
    }
}

// ##########################
// ##### === DECODE === #####
// ##########################

pub struct ParseHandshakeMessage<'a> {
    buffer: ParseBuffer<&'a [u8]>,
    message_start: usize,
}

impl<'a> ParseHandshakeMessage<'a> {
    pub fn new(
        mut buffer: ParseBuffer<&'a [u8]>,
    ) -> Result<(Self, HandshakeType, HandshakeSeqNum), DtlsError> {
        buffer.expect_length(12)?;
        let start = buffer.offset();

        let handshake_type =
            HandshakeType::from_num(buffer.read_u8()).ok_or(DtlsError::ParseError)?;
        let length = buffer.read_u24();
        let seq_num = buffer.read_u16();
        parse_expect(buffer.read_u24() == 0, DtlsError::ParseError)?;
        parse_expect(buffer.read_u24() == length, DtlsError::ParseError)?;
        Ok((
            ParseHandshakeMessage {
                buffer,
                message_start: start,
            },
            handshake_type,
            seq_num,
        ))
    }

    pub fn retrieve_content_type(
        buffer: &mut ParseBuffer<&'a mut [u8]>,
    ) -> Result<HandshakeType, DtlsError> {
        buffer.expect_length(1)?;
        HandshakeType::from_num(buffer.read_u8()).ok_or(DtlsError::ParseError)
    }

    pub fn payload_buffer<'c>(&'c mut self) -> &'c mut ParseBuffer<&'a [u8]> {
        &mut self.buffer
    }

    pub fn add_to_transcript_hash(&self, transcript_hash: &mut CryptoInformation) {
        transcript_hash.update_transcript_hash(
            &self.buffer.as_ref()[self.message_start..self.message_start + 4],
        );
        transcript_hash.update_transcript_hash(&self.buffer.as_ref()[self.message_start + 12..]);
    }

    pub fn abort_parsing(self) -> ParseBuffer<&'a [u8]> {
        self.buffer
    }
}

pub enum ClientHelloResult {
    Ok,
    MissingCookie,
}

pub fn parse_client_hello_first_pass(
    buffer: &mut ParseBuffer<&[u8]>,
    require_cookie: bool,
    cookie_key: &[u8],
    peer_addr: &SocketAddr,
    ctx: &mut HandshakeContext,
    record_queue: &mut BufferMessageQueue<'_>,
) -> Result<ClientHelloResult, DtlsError> {
    // legacy version field ignored on server side (my way of understanding)
    buffer.add_offset(2);

    // TODO: check if random is individually needed later
    buffer.add_offset(32);

    // if we ignore cached sessions we could ignore this field...
    let legacy_session_len = buffer.read_u8() as usize;
    let mut legacy_session = [0u8; 32];
    buffer.read_exactly_n(
        &mut legacy_session[0..legacy_session_len],
        legacy_session_len,
    );

    let cookie_len = buffer.read_u8();
    parse_expect(
        cookie_len == 0,
        DtlsError::Alert(AlertDescription::IllegalParameter),
    )?;

    let cipher_suites_len = buffer.read_u16();
    buffer.expect_length(cipher_suites_len as usize)?;
    let supported_suites = CipherSuite::all();
    for _ in 0..cipher_suites_len / 2 {
        let suite = CipherSuite::try_from(buffer.read_u16())?;
        if ctx.info.selected_cipher_suite.is_none() && supported_suites.contains(&suite) {
            ctx.info.selected_cipher_suite = Some(suite);
        }
    }

    // skip compression
    let compression_len = buffer.read_u8();
    let compression_method = buffer.read_u8();
    parse_expect(
        compression_len == 1 && compression_method == 0,
        DtlsError::Alert(AlertDescription::IllegalParameter),
    )?;

    let extension_start = buffer.offset();
    let mut found_valid_cookie = false;
    parse_extensions(
        buffer,
        &mut |extension_type, mut buffer| match extension_type {
            ExtensionType::Cookie => {
                let cookie = parse_cookie(&mut buffer)?;
                let cookie = &buffer.as_ref()[cookie.index..cookie.index + cookie.len];
                let true = crypto::verify_cookie(cookie, cookie_key, peer_addr)? else {
                    return Ok(());
                };
                // Set transcript hash to message_hash + HelloRetry
                ctx.info.server_init_post_hello_retry_hash(cookie);
                // Using space in the record queue to keep staging buffer valid.
                record_queue.alloc_rt_entry(0, &0, &mut |buffer| {
                    let mut hs =
                        EncodeHandshakeMessage::new(buffer, HandshakeType::ServerHello, 0)?;
                    encode_hello_retry(
                        hs.payload_buffer(),
                        &[],
                        ctx.info
                            .selected_cipher_suite
                            .expect("Is set if parsing was successful"),
                        HelloRetryCookie::existing(cookie),
                    )?;
                    // This adds the hello retry to the transcript hash
                    hs.finish(&mut ctx.info.crypto);
                    Ok(())
                })?;
                record_queue.clear_record_queue();
                found_valid_cookie = true;
                Ok(())
            }
            _ => Ok(()),
        },
    )?;
    if !found_valid_cookie {
        // We selected a single cipher suite and can narrow the
        // amount of available hashes for further calculations.
        ctx.info.server_switch_to_single_hash();
        if require_cookie {
            return Ok(ClientHelloResult::MissingCookie);
        }
    }
    // Second pass will pick up from here.
    buffer.set_offset(extension_start);
    Ok(ClientHelloResult::Ok)
}

pub fn parse_client_hello_second_pass(
    buffer: &mut ParseBuffer<&[u8]>,
    info: &mut HandshakeInformation,
    client_hello_start: usize,
) -> Result<(), DtlsError> {
    let mut found_supported_version = false;
    let mut found_psk = false;
    let mut found_psk_em = false;
    parse_extensions(
        buffer,
        &mut |extension_type, mut buffer| match extension_type {
            ExtensionType::SupportedVersions => {
                parse_expect(
                    !found_psk,
                    DtlsError::Alert(AlertDescription::IllegalParameter),
                )?;
                found_supported_version = true;
                parse_supported_versions_client(&mut buffer)
            }
            ExtensionType::Cookie => Ok(()),
            ExtensionType::PreSharedKey => {
                found_psk = true;
                parse_pre_shared_key_client(&mut buffer, client_hello_start, info)
            }
            ExtensionType::PskKeyExchangeModes => {
                parse_expect(
                    !found_psk,
                    DtlsError::Alert(AlertDescription::IllegalParameter),
                )?;
                found_psk_em = parse_ch_key_exchange_modes(&mut buffer);
                Ok(())
            }
            _ => {
                if found_psk {
                    return Err(DtlsError::Alert(AlertDescription::IllegalParameter));
                }

                Ok(())
            }
        },
    )?;

    if !found_psk_em || !found_supported_version {
        return Err(DtlsError::Alert(AlertDescription::MissingExtension));
    }

    Ok(())
}
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

pub enum ServerHelloVariant {
    ServerHello,
    HelloRetry(Option<Cookie>),
}

pub fn parse_server_hello(
    buffer: &mut ParseBuffer<&[u8]>,
    allowed_cipher_suites: &[CipherSuite],
    info: &mut HandshakeInformation,
) -> Result<ServerHelloVariant, DtlsError> {
    buffer.expect_length(3 + 32)?;

    parse_expect(
        buffer.read_u16() == LEGACY_PROTOCOL_VERSION,
        DtlsError::ParseError,
    )?;

    let mut variant = if buffer.read_as_reference(32) == HELLO_RETRY_RANDOM {
        /*
        If a client receives a second
        HelloRetryRequest in the same connection (i.e., where the ClientHello
        was itself in response to a HelloRetryRequest), it MUST abort the
        handshake with an "unexpected_message" alert.
        */
        if info.received_hello_retry_request {
            Err(DtlsError::Alert(AlertDescription::UnexpectedMessage))?;
        }
        info.received_hello_retry_request = true;
        ServerHelloVariant::HelloRetry(None)
    } else {
        ServerHelloVariant::ServerHello
    };
    // session id echo
    parse_expect(buffer.read_u8() == 0, DtlsError::ParseError)?;
    let cipher_suite = CipherSuite::try_from(buffer.read_u16())?;
    if !allowed_cipher_suites.contains(&cipher_suite) {
        /*
        A client which receives a cipher suite that was not offered MUST
        abort the handshake.
        */
        return Err(DtlsError::Alert(crate::AlertDescription::IllegalParameter));
    }

    if info.selected_cipher_suite.is_none() {
        info.selected_cipher_suite = Some(cipher_suite);
        if matches!(variant, ServerHelloVariant::HelloRetry(_)) {
            // Throw away all unnecessary hashes and replace client_hello hash
            info.client_switch_to_post_hello_retry_hash();
        }
    } else {
        /*
        clients MUST check that the cipher suite supplied in
        the ServerHello is the same as that in the HelloRetryRequest and
        otherwise abort the handshake with an "illegal_parameter" alert.
        */
        parse_expect(
            info.selected_cipher_suite == Some(cipher_suite),
            DtlsError::Alert(AlertDescription::IllegalParameter),
        )?;
    }
    // legacy compression method
    parse_expect(buffer.read_u8() == 0, DtlsError::ParseError)?;

    let mut found_supported_version = false;
    let mut found_psk = false;
    parse_extensions(
        buffer,
        &mut |extension_type, mut buffer| match extension_type {
            ExtensionType::SupportedVersions => {
                found_supported_version = true;
                parse_supported_versions_server(&mut buffer)
            }
            ExtensionType::PreSharedKey => {
                found_psk = true;
                info.initialize_crypto_state(parse_pre_shared_key_server(&mut buffer)? as usize)
            }
            ExtensionType::KeyShare => {
                Err(DtlsError::Alert(AlertDescription::UnsupportedExtension))
            }
            ExtensionType::Cookie => {
                variant = ServerHelloVariant::HelloRetry(Some(parse_cookie(&mut buffer)?));
                Ok(())
            }
            _ => Err(DtlsError::ParseError),
        },
    )?;

    match &variant {
        ServerHelloVariant::ServerHello => {
            parse_expect(
                found_psk && found_supported_version,
                DtlsError::Alert(AlertDescription::MissingExtension),
            )?;
        }
        // We expect to find a cookie in a hello retry request.
        ServerHelloVariant::HelloRetry(cookie) => {
            parse_expect(
                found_supported_version,
                DtlsError::Alert(AlertDescription::MissingExtension),
            )?;
            if cookie.is_none() {
                // Clients MUST abort the handshake with an
                //"illegal_parameter" alert if the HelloRetryRequest would not result
                //in any change in the ClientHello.
                Err(DtlsError::Alert(AlertDescription::IllegalParameter))?
            }
        }
    }

    Ok(variant)
}

pub fn parse_encrypted_extensions(buffer: &mut ParseBuffer<&[u8]>) -> Result<(), DtlsError> {
    parse_extensions(buffer, &mut |_, _| {
        Err(DtlsError::Alert(AlertDescription::UnsupportedExtension))
    })?;
    Ok(())
}

pub fn parse_finished(
    buffer: &mut ParseBuffer<&[u8]>,
    secret: &TrafficSecret,
    crypto_state: &mut CipherDependentCryptoState,
) -> Result<(), DtlsError> {
    if !crypto_state.check_verify_data(buffer, secret)? {
        Err(DtlsError::Alert(AlertDescription::DecryptionError))
    } else {
        Ok(())
    }
}

pub fn parse_alert(
    buffer: &mut ParseBuffer<&mut [u8]>,
) -> Result<(AlertLevel, AlertDescription), DtlsError> {
    buffer.expect_length(2)?;
    Ok((
        AlertLevel::from(buffer.read_u8()),
        AlertDescription::from(buffer.read_u8()),
    ))
}

pub fn parse_extensions(
    buffer: &mut ParseBuffer<&[u8]>,
    handle_extension_data: &mut dyn FnMut(
        ExtensionType,
        ParseBuffer<&[u8]>,
    ) -> Result<(), DtlsError>,
) -> Result<(), DtlsError> {
    buffer.expect_length(2)?;
    let extensions_len = buffer.read_u16() as usize;
    buffer.expect_length(extensions_len)?;

    let start = buffer.offset();
    while buffer.offset() < start + extensions_len {
        buffer.expect_length(4)?;
        let extension_type = ExtensionType::try_from(buffer.read_u16())?;
        let extension_data_len = buffer.read_u16() as usize;
        buffer.expect_length(extension_data_len)?;
        buffer.add_offset(extension_data_len);
        let sub_buffer =
            ParseBuffer::init_with_offset(buffer.as_ref(), buffer.offset() - extension_data_len);
        handle_extension_data(extension_type, sub_buffer)?;
    }

    Ok(())
}

fn parse_supported_versions_client(buffer: &mut ParseBuffer<&[u8]>) -> Result<(), DtlsError> {
    let mut len = buffer.read_u8();
    buffer.expect_length(len as usize)?;

    while len > 1 {
        len -= 2;
        let v = buffer.read_u16();
        if v == DTLS_1_3 {
            buffer.add_offset(len as usize);
            return Ok(());
        }
    }

    Err(DtlsError::Alert(AlertDescription::IllegalParameter))
}

pub fn parse_supported_versions_server(buffer: &mut ParseBuffer<&[u8]>) -> Result<(), DtlsError> {
    buffer.expect_length(2)?;
    parse_expect(buffer.read_u16() == DTLS_1_3, DtlsError::ParseError)
}

pub fn parse_pre_shared_key_server(buffer: &mut ParseBuffer<&[u8]>) -> Result<u16, DtlsError> {
    buffer.expect_length(2)?;
    Ok(buffer.read_u16())
}

fn parse_pre_shared_key_client(
    buffer: &mut ParseBuffer<&[u8]>,
    client_hello_start: usize,
    info: &mut HandshakeInformation,
) -> Result<(), DtlsError> {
    let mut psk_ids_len_left = buffer.read_u16() as usize;
    parse_expect(
        psk_ids_len_left > 0,
        DtlsError::Alert(AlertDescription::MissingExtension),
    )?;
    let cipher_suite_hash_fn = info.selected_cipher_suite.unwrap().hash_function();
    let mut selected_psk_index = 0;
    while psk_ids_len_left > 0 {
        let psk_id_len = buffer.read_u16() as usize;
        buffer.expect_length(2 + psk_id_len + 4)?;
        psk_ids_len_left -= 2 + psk_id_len;
        let id = buffer.read_as_reference(psk_id_len);
        if info
            .available_psks
            .iter()
            .any(|c| c.identity == id && c.hash_function == cipher_suite_hash_fn)
        {
            buffer.add_offset(psk_ids_len_left);
            break;
        }
        psk_ids_len_left -= 4;
        let _ = buffer.read_u32();
        selected_psk_index += 1;
    }
    let binder_start = buffer.offset;

    let mut binders_len_left = buffer.read_u16();
    let mut binder_index = 0;
    while binders_len_left > 0 {
        let binder_len = buffer.read_u8();
        buffer.add_offset(binder_len as usize);
        let bind_entry = &buffer.as_ref()[buffer.offset - binder_len as usize..buffer.offset];
        binders_len_left -= 1 + binder_len as u16;

        if selected_psk_index == binder_index {
            let partial_client_hello =
                &buffer.complete_inner_buffer()[client_hello_start - 12..binder_start];
            let (header, client_hello) = partial_client_hello.split_at(12);
            let transcript_hash: &mut PskTranscriptHash = info.crypto.psk_hash_mut()?;
            let finalized_hash = transcript_hash.finalize(&[&header[0..4], client_hello]);

            if validate_binder(
                bind_entry,
                &info.available_psks[selected_psk_index],
                finalized_hash.as_ref(),
            )
            .is_ok_and(|b| b)
            {
                info.initialize_crypto_state(selected_psk_index)?;
            } else {
                return Err(DtlsError::Alert(AlertDescription::DecryptionError));
            }
        }
        binder_index += 1;
    }

    Ok(())
}

fn parse_ch_key_exchange_modes(buffer: &mut ParseBuffer<&[u8]>) -> bool {
    let modes = buffer.read_u8();
    let mut found_psk_em = false;
    for _ in 0..modes {
        let mode = buffer.read_u8();
        if mode == 0 {
            found_psk_em = true;
        }
    }
    found_psk_em
}

pub struct Cookie {
    pub index: usize,
    pub len: usize,
}

pub fn parse_cookie(buffer: &mut ParseBuffer<&[u8]>) -> Result<Cookie, DtlsError> {
    buffer.expect_length(2)?;
    let len = buffer.read_u16() as usize;
    let index = buffer.offset();
    buffer.expect_length(len)?;
    buffer.add_offset(len);
    Ok(Cookie { index, len })
}

pub struct ParseAck<'a, 'b> {
    buffer: &'a mut ParseBuffer<&'b [u8]>,
    left_entries: u16,
}

impl<'a, 'b> ParseAck<'a, 'b> {
    pub fn new(buffer: &'a mut ParseBuffer<&'b [u8]>) -> Result<Self, DtlsError> {
        buffer.expect_length(2)?;
        let len = buffer.read_u16();
        parse_expect(len % 16 == 0, DtlsError::ParseError)?;
        buffer.expect_length(len as usize)?;
        let left_entries = len / 16;
        Ok(Self {
            buffer,
            left_entries,
        })
    }

    pub fn next_entry(&mut self) -> Option<(u64, u64)> {
        if self.left_entries > 0 {
            self.left_entries -= 1;
            Some((self.buffer.read_u64(), self.buffer.read_u64()))
        } else {
            None
        }
    }
}
