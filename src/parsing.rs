use crate::buffer_record_queue::BufferMessageQueue;
use crate::crypto::{
    self, encode_binder_entry, validate_binder, CipherDependentCryptoState, CipherSuite, Psk,
    PskTranscriptHash, TrafficSecret,
};
use crate::handshake::{CryptoInformation, HandshakeContext, HandshakeInformation};
use crate::parsing_utility::{parse_expect, Itr, ParseBuffer, Parser, S};
use crate::{AlertDescription, AlertLevel, DtlsError, Epoch, HandshakeSeqNum, RecordSeqNum};
use core::mem;
use core::net::SocketAddr;

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
    buffer: &'a mut ParseBuffer<'b>,
    len_pos: usize,
    binders_len: usize,
}

impl<'a, 'b> EncodeHandshakeMessage<'a, 'b> {
    pub fn new(
        buffer: &'a mut ParseBuffer<'b>,
        handshake_type: HandshakeType,
        handshake_seq_num: u16,
    ) -> Result<Self, DtlsError> {
        let len_pos = buffer.offset() + 1;
        let r = Parser::new(buffer)?;
        let r = r.write_u8(handshake_type as u8);

        let r = r.write_u24(0); // Skip len
        let r = r.write_u16(handshake_seq_num);
        let r = r.write_u24(0); // fragment offset
        r.write_u24(0).end(); // Skip fragment length

        Ok(Self {
            buffer,
            len_pos,
            binders_len: 0,
        })
    }

    pub fn payload_buffer<'c>(&'c mut self) -> &'c mut ParseBuffer<'b> {
        self.buffer
    }

    pub fn add_partial_transcript_hash(
        &mut self,
        binders_len: usize,
        transcript_hash: &mut CryptoInformation,
    ) -> Result<(), DtlsError> {
        let payload_len = self.buffer.offset() - self.len_pos - 11;

        let mut buf = self.buffer.with_offset(self.len_pos);
        Parser::<S<3, S<5, S<3, ()>>>>::new(&mut buf)
            .expect("Checked in new")
            .write_u24(payload_len as u32)
            .add_offset()
            .write_u24(payload_len as u32)
            .end();
        self.binders_len = binders_len;
        let msg_start = self.len_pos - 1;

        transcript_hash
            .update_transcript_hash(self.buffer.access_slice_checked(msg_start..msg_start + 4)?);

        let binders_len_field_size = 2;
        transcript_hash.update_transcript_hash(self.buffer.access_slice_checked(
            msg_start + 12..self.buffer.offset() - binders_len_field_size - binders_len,
        )?);
        Ok(())
    }

    pub fn binders_buffer(&mut self) -> ParseBuffer<'_> {
        let offset = self.buffer.offset();
        ParseBuffer::init(&mut self.buffer.as_mut()[offset - self.binders_len..])
    }

    pub fn finish_after_partial_transcript_hash(
        &mut self,
        transcript_hash: &mut CryptoInformation,
    ) -> Result<(), DtlsError> {
        let binders_len_field_size = 2;
        transcript_hash.update_transcript_hash(self.buffer.access_slice_checked(
            self.buffer.offset() - binders_len_field_size - self.binders_len..self.buffer.offset(),
        )?);
        Ok(())
    }

    pub fn finish(self, transcript_hash: &mut CryptoInformation) {
        debug_assert_eq!(self.binders_len, 0);
        let payload_len = self.buffer.offset() - self.len_pos - 11;

        let mut buf = self.buffer.with_offset(self.len_pos);
        Parser::<S<3, S<5, S<3, ()>>>>::new(&mut buf)
            .expect("Checked in new")
            .write_u24(payload_len as u32)
            .add_offset()
            .write_u24(payload_len as u32)
            .end();

        let msg_start = self.len_pos - 1;
        let buf = self.buffer.as_ref();
        transcript_hash.update_transcript_hash(&buf[msg_start..msg_start + 4]);
        transcript_hash.update_transcript_hash(&buf[msg_start + 12..]);
    }
}

pub fn encode_client_hello(
    buffer: &mut ParseBuffer<'_>,
    info: &mut HandshakeInformation,
    cipher_suites: &[CipherSuite],
    now_ms: &u64,
    rng: &mut dyn rand_core::CryptoRngCore,
    cookie: Option<&[u8]>,
) -> Result<(HandshakeType, usize), DtlsError> {
    let mut r = Parser::new(buffer)?.write_u16(LEGACY_PROTOCOL_VERSION);
    let slice: &mut [u8; 32] = r.read_static_slice();
    rng.try_fill_bytes(slice).map_err(|_| DtlsError::RngError)?;
    r.done()
        .write_u8(0) // Session
        .write_u8(0) // Cookie
        .end();

    buffer.write_prepend_length_u16(&mut |buffer| {
        let mut r = Parser::new_dyn(buffer, cipher_suites.len() * mem::size_of::<u16>())?;
        let mut i = 0;
        while let Some(r) = r.next() {
            r.write_u16(cipher_suites[i] as u16).end();
            i += 1
        }
        r.done().end();
        Ok(())
    })?;

    Parser::new(buffer)?
        .write_u8(1) // Compression length
        .write_u8(0) // Compression type
        .end();

    let mut binders_len: usize = 0;
    buffer.write_prepend_length_u16(&mut |buffer| {
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
    buffer: &mut ParseBuffer<'_>,
    rng: &mut dyn rand_core::CryptoRngCore,
    client_hello_session_id: &[u8],
    selected_cipher_suite: CipherSuite,
    selected_psk_id_idx: u16,
) -> Result<HandshakeType, DtlsError> {
    let mut r =
        Parser::new_mut_slice(buffer, client_hello_session_id)?.write_u16(LEGACY_PROTOCOL_VERSION);

    let slice: &mut [u8; 32] = r.read_static_slice();
    rng.try_fill_bytes(slice).map_err(|_| DtlsError::RngError)?;
    r.done()
        .write_len_u8()
        .write_slice() // echo whatever was sent in the client hello
        .write_u16(selected_cipher_suite as u16) // Cipher suite
        .write_u8(0) // Compression
        .end();

    buffer.write_prepend_length_u16(&mut |buffer| {
        // needs supported version ext
        encode_extension(buffer, &mut encode_supported_versions_server)?;
        // psk identity index selection
        encode_extension(buffer, &mut |buffer| {
            Parser::new(buffer)?.write_u16(selected_psk_id_idx).end();
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
    buffer: &mut ParseBuffer<'_>,
    client_hello_session_id: &[u8],
    cipher_suite: CipherSuite,
    cookie: HelloRetryCookie<'_>,
) -> Result<HandshakeType, DtlsError> {
    Parser::new_mut_slice(buffer, client_hello_session_id)?
        .write_u16(LEGACY_PROTOCOL_VERSION)
        .write_static_slice(&HELLO_RETRY_RANDOM)
        .write_len_u8()
        .write_slice() // echo whatever was sent in the client hello
        .write_u16(cipher_suite as u16) // Cipher suite
        .write_u8(0) // Compression
        .end();

    buffer.write_prepend_length_u16(&mut |buffer| {
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

pub fn encode_encrypted_extensions(buffer: &mut ParseBuffer<'_>) -> Result<(), DtlsError> {
    Parser::new(buffer)?.write_u16(0).end();
    Ok(())
}

pub fn encode_finished(
    buffer: &mut ParseBuffer<'_>,
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
    buffer: &mut ParseBuffer<'_>,
    encode_extension_data: &mut dyn FnMut(&mut ParseBuffer<'_>) -> Result<ExtensionType, DtlsError>,
) -> Result<(), DtlsError> {
    let type_pos = buffer.offset();
    buffer.expect_length(2)?;
    buffer.add_offset(2);
    let mut extension_type = None;
    buffer.write_prepend_length_u16(&mut |buffer| {
        extension_type = Some(encode_extension_data(buffer)?);
        Ok(())
    })?;
    buffer.as_mut()[type_pos..type_pos + 2]
        .copy_from_slice(&(extension_type.unwrap() as u16).to_be_bytes());
    Ok(())
}

pub fn encode_supported_versions_client(
    buffer: &mut ParseBuffer<'_>,
) -> Result<ExtensionType, DtlsError> {
    Parser::new(buffer)?.write_u8(2).write_u16(DTLS_1_3).end();
    Ok(ExtensionType::SupportedVersions)
}

pub fn encode_supported_versions_server(
    buffer: &mut ParseBuffer<'_>,
) -> Result<ExtensionType, DtlsError> {
    Parser::new(buffer)?.write_u16(DTLS_1_3).end();
    Ok(ExtensionType::SupportedVersions)
}

pub fn encode_pre_shared_key_client_with_empty_binders(
    buffer: &mut ParseBuffer<'_>,
    psks: &[Psk<'_>],
    now_ms: &u64,
) -> Result<(ExtensionType, usize), DtlsError> {
    buffer.write_prepend_length_u16(&mut |buffer| {
        for psk in psks {
            let r = Parser::new_mut_slice(buffer, psk.identity)?
                .write_len_u16()
                .write_slice();

            match psk.key_type {
                crate::crypto::PskType::Resumption {
                    ticket_creation_timestamp_ms,
                } => r
                    .write_u32((now_ms - ticket_creation_timestamp_ms).try_into().unwrap())
                    .end(),
                crate::crypto::PskType::External => r.write_u32(0).end(),
            }
        }
        Ok(())
    })?;
    let mut binders_space_len = 0;
    buffer.write_prepend_length_u16(&mut |buffer| {
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
    binders_buffer: &mut ParseBuffer<'_>,
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
    buffer: &mut ParseBuffer<'_>,
) -> Result<ExtensionType, DtlsError> {
    Parser::new(buffer)?
        .write_u8(1)
        .write_u8(0) // psk_ke only
        .end();
    Ok(ExtensionType::PskKeyExchangeModes)
}

pub fn encode_cookie(
    buffer: &mut ParseBuffer<'_>,
    cookie: &[u8],
) -> Result<ExtensionType, DtlsError> {
    Parser::new_mut_slice(buffer, cookie)?
        .write_len_u16()
        .write_slice()
        .end();
    Ok(ExtensionType::Cookie)
}

pub fn create_and_encode_cookie(
    buffer: &mut ParseBuffer<'_>,
    key: &[u8],
    peer_addr: &SocketAddr,
    client_hello_hash: &PskTranscriptHash,
) -> Result<ExtensionType, DtlsError> {
    buffer.write_prepend_length_u16(&mut |buffer| {
        crypto::encode_cookie(buffer, key, client_hello_hash, peer_addr)
    })?;
    Ok(ExtensionType::Cookie)
}

pub fn encode_alert(
    buffer: &mut ParseBuffer<'_>,
    description: AlertDescription,
    level: AlertLevel,
) -> Result<(), DtlsError> {
    Parser::new(buffer)?
        .write_u8(level as u8)
        .write_u8(description as u8)
        .end();
    Ok(())
}

pub struct EncodeAck<'a, 'b> {
    message_start: usize,
    buffer: &'a mut ParseBuffer<'b>,
}

impl<'a, 'b> EncodeAck<'a, 'b> {
    pub fn new(buffer: &'a mut ParseBuffer<'b>) -> Result<Self, DtlsError> {
        let message_start = buffer.offset();
        Parser::new(buffer)?.write_u16(0).end();
        Ok(Self {
            message_start,
            buffer,
        })
    }

    pub fn add_entry(&mut self, epoch: &Epoch, seq_num: &RecordSeqNum) -> Result<(), DtlsError> {
        Parser::new(self.buffer)?
            .write_u64(epoch)
            .write_u64(seq_num)
            .end();
        Ok(())
    }

    pub fn finish(self) {
        let len = self.buffer.offset() - self.message_start - 2;
        let mut buf = self.buffer.with_offset(self.message_start);
        Parser::new(&mut buf)
            .expect("Checked in new")
            .write_u16(len as u16)
            .end();
    }
}

// ##########################
// ##### === DECODE === #####
// ##########################

pub struct ParseHandshakeMessage<'a> {
    buffer: ParseBuffer<'a>,
    message_start: usize,
}

impl<'a> ParseHandshakeMessage<'a> {
    pub fn new(
        mut buffer: ParseBuffer<'a>,
    ) -> Result<(Self, HandshakeType, HandshakeSeqNum), DtlsError> {
        let start = buffer.offset();

        let r = Parser::new(&mut buffer)?;
        let (hs_type, r) = r.read_u8();
        let handshake_type = HandshakeType::from_num(hs_type).ok_or(DtlsError::ParseError)?;
        let (length, r) = r.read_u24();
        let (seq_num, r) = r.read_u16();
        let (frag_off, r) = r.read_u24();
        parse_expect(frag_off == 0, DtlsError::ParseError)?;
        let (frag_len, r) = r.read_u24();
        r.end();
        parse_expect(frag_len == length, DtlsError::ParseError)?;
        Ok((
            ParseHandshakeMessage {
                buffer,
                message_start: start,
            },
            handshake_type,
            seq_num,
        ))
    }

    pub fn retrieve_content_type(buffer: &mut ParseBuffer<'a>) -> Result<HandshakeType, DtlsError> {
        let (content_type, r) = Parser::new(buffer)?.read_u8();
        r.end();
        HandshakeType::from_num(content_type).ok_or(DtlsError::ParseError)
    }

    pub fn payload_buffer<'c>(&'c mut self) -> &'c mut ParseBuffer<'a> {
        &mut self.buffer
    }

    pub fn add_to_transcript_hash(&self, transcript_hash: &mut CryptoInformation) {
        transcript_hash.update_transcript_hash(
            &self.buffer.as_ref()[self.message_start..self.message_start + 4],
        );
        transcript_hash.update_transcript_hash(&self.buffer.as_ref()[self.message_start + 12..]);
    }

    pub fn abort_parsing(self) -> ParseBuffer<'a> {
        self.buffer
    }
}

pub enum ClientHelloResult {
    Ok,
    MissingCookie,
}

pub fn parse_client_hello_first_pass(
    buffer: &mut ParseBuffer<'_>,
    require_cookie: bool,
    cookie_key: &[u8],
    peer_addr: &SocketAddr,
    ctx: &mut HandshakeContext,
    record_queue: &mut BufferMessageQueue<'_>,
) -> Result<ClientHelloResult, DtlsError> {
    // legacy version field ignored on server side (my way of understanding)
    buffer.add_offset(2);

    buffer.add_offset(32);

    // if we ignore cached sessions we could ignore this field...
    let (legacy_session_len, r) = Parser::new(buffer)?.read_u8();
    r.end();
    buffer.add_offset(legacy_session_len as usize);

    let (cookie_len, r) = Parser::new(buffer)?.read_u8();
    parse_expect(
        cookie_len == 0,
        DtlsError::Alert(AlertDescription::IllegalParameter),
    )
    .unwrap();
    let (cipher_suites_len, r) = r.read_u16();
    r.end();
    let supported_suites = CipherSuite::all();

    let mut r = Parser::new_dyn(buffer, cipher_suites_len as usize)?;
    while let Some(r) = r.next() {
        let (suite, r) = r.read_u16();
        r.end();
        let suite = CipherSuite::try_from(suite)?;
        if ctx.info.selected_cipher_suite.is_none() && supported_suites.contains(&suite) {
            ctx.info.selected_cipher_suite = Some(suite);
        }
    }
    let (compression_len, r) = r.done().read_u8();
    let (compression_method, r) = r.read_u8();
    r.end();
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
                let cookie =
                    buffer.access_slice_checked(cookie.index..cookie.index + cookie.len)?;
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
    buffer: &mut ParseBuffer<'_>,
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
                found_psk_em = parse_ch_key_exchange_modes(&mut buffer)?;
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
    buffer: &mut ParseBuffer<'_>,
    allowed_cipher_suites: &[CipherSuite],
    info: &mut HandshakeInformation,
) -> Result<ServerHelloVariant, DtlsError> {
    let (legacy_protocol_ver, mut r) = Parser::new(buffer)?.read_u16();
    parse_expect(
        legacy_protocol_ver == LEGACY_PROTOCOL_VERSION,
        DtlsError::ParseError,
    )?;

    let mut variant = if r.read_static_slice() == &HELLO_RETRY_RANDOM {
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
    let (session_id_echo, r) = r.done().read_u8();
    parse_expect(session_id_echo == 0, DtlsError::ParseError)?;

    let (cipher_suite, r) = r.read_u16();
    let cipher_suite = CipherSuite::try_from(cipher_suite)?;
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
    let (legacy_compression_method, r) = r.read_u8();
    r.end();
    parse_expect(legacy_compression_method == 0, DtlsError::ParseError)?;

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

pub fn parse_encrypted_extensions(buffer: &mut ParseBuffer<'_>) -> Result<(), DtlsError> {
    parse_extensions(buffer, &mut |_, _| {
        Err(DtlsError::Alert(AlertDescription::UnsupportedExtension))
    })?;
    Ok(())
}

pub fn parse_finished(
    buffer: &mut ParseBuffer<'_>,
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
    buffer: &mut ParseBuffer<'_>,
) -> Result<(AlertLevel, AlertDescription), DtlsError> {
    let (level, r) = Parser::new(buffer)?.read_u8();
    let (desc, r) = r.read_u8();
    r.end();
    Ok((AlertLevel::from(level), AlertDescription::from(desc)))
}

pub fn parse_extensions(
    buffer: &mut ParseBuffer<'_>,
    handle_extension_data: &mut dyn FnMut(ExtensionType, ParseBuffer<'_>) -> Result<(), DtlsError>,
) -> Result<(), DtlsError> {
    let extensions_len = Parser::read_single_u16(buffer)? as usize;

    buffer.expect_length(extensions_len)?;

    let start = buffer.offset();
    while buffer.offset() < start + extensions_len {
        let (extension_type, r) = Parser::new(buffer)?.read_u16();
        let extension_type = ExtensionType::try_from(extension_type)?;
        let (extension_data_len, r) = r.read_u16();
        r.end();
        let extension_data_len = extension_data_len as usize;
        buffer.expect_length(extension_data_len)?;
        buffer.add_offset(extension_data_len);
        let offset = buffer.offset();
        let sub_buffer =
            ParseBuffer::init_with_offset(buffer.as_mut(), offset - extension_data_len);
        handle_extension_data(extension_type, sub_buffer)?;
    }

    Ok(())
}

fn parse_supported_versions_client(buffer: &mut ParseBuffer<'_>) -> Result<(), DtlsError> {
    let len = Parser::read_single_u8(buffer)?;
    let mut r = Parser::new_dyn(buffer, len as usize)?;
    while let Some(r) = r.next() {
        let (v, r) = r.read_u16();
        r.end();
        if v == DTLS_1_3 {
            return Ok(());
        }
    }
    r.done().end();
    Err(DtlsError::Alert(AlertDescription::IllegalParameter))
}

pub fn parse_supported_versions_server(buffer: &mut ParseBuffer<'_>) -> Result<(), DtlsError> {
    let (supported_version, r) = Parser::new(buffer)?.read_u16();
    r.end();
    parse_expect(supported_version == DTLS_1_3, DtlsError::ParseError)
}

pub fn parse_pre_shared_key_server(buffer: &mut ParseBuffer<'_>) -> Result<u16, DtlsError> {
    let (psk_index, r) = Parser::new(buffer)?.read_u16();
    r.end();
    Ok(psk_index)
}

fn parse_pre_shared_key_client(
    buffer: &mut ParseBuffer<'_>,
    client_hello_start: usize,
    info: &mut HandshakeInformation,
) -> Result<(), DtlsError> {
    let mut psk_ids_len_left = Parser::read_single_u16(buffer)? as usize;
    parse_expect(
        psk_ids_len_left > 0,
        DtlsError::Alert(AlertDescription::MissingExtension),
    )?;
    let cipher_suite_hash_fn = info.selected_cipher_suite.unwrap().hash_function();
    let mut selected_psk_index = 0;

    while psk_ids_len_left > 0 {
        let psk_id_len = Parser::read_single_u16(buffer)? as usize;
        psk_ids_len_left -= 2 + psk_id_len;
        let mut r = Parser::new_dyn(buffer, psk_id_len)?;
        let id = r.read_slice();
        if info
            .available_psks
            .iter()
            .any(|c| c.identity == id && c.hash_function == cipher_suite_hash_fn)
        {
            buffer.add_offset(psk_ids_len_left);
            break;
        }
        psk_ids_len_left -= 4;
        let (_obfuscated_ticked_age, r) = r.done().read_u32();
        r.end();
        selected_psk_index += 1;
    }
    let binder_start = buffer.offset();

    let mut binders_len_left = Parser::read_single_u16(buffer)?;
    let mut binder_index = 0;
    while binders_len_left > 0 {
        let binder_len = Parser::read_single_u8(buffer)? as usize;
        buffer.add_offset(binder_len);
        let bind_entry =
            buffer.access_slice_checked(buffer.offset() - binder_len..buffer.offset())?;
        binders_len_left -= 1 + binder_len as u16;

        if selected_psk_index == binder_index {
            let partial_client_hello =
                &buffer.access_slice_checked(client_hello_start - 12..binder_start)?;
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

fn parse_ch_key_exchange_modes(buffer: &mut ParseBuffer<'_>) -> Result<bool, DtlsError> {
    let modes_len = Parser::read_single_u8(buffer)?;
    let mut found_psk_em = false;
    let mut r = Parser::new_dyn(buffer, modes_len as usize)?;
    while let Some(r) = r.next() {
        let (mode, r) = r.read_u8();
        r.end();
        if mode == 0 {
            found_psk_em = true;
        }
    }
    r.done().end();
    Ok(found_psk_em)
}

pub struct Cookie {
    pub index: usize,
    pub len: usize,
}

pub fn parse_cookie(buffer: &mut ParseBuffer<'_>) -> Result<Cookie, DtlsError> {
    let len = Parser::read_single_u16(buffer)? as usize;
    let index = buffer.offset();
    buffer.expect_length(len)?;
    buffer.add_offset(len);
    Ok(Cookie { index, len })
}

pub struct ParseAck<'a, 'b> {
    reader: Parser<'a, 'b, Itr<S<8, S<8, ()>>>>,
}

impl<'a, 'b> ParseAck<'a, 'b> {
    pub fn new(buffer: &'a mut ParseBuffer<'b>) -> Result<Self, DtlsError> {
        let len = Parser::read_single_u16(buffer)?;
        Ok(Self {
            reader: Parser::new_dyn(buffer, len as usize)?,
        })
    }

    pub fn next_entry(&mut self) -> Option<(u64, u64)> {
        let r = self.reader.next()?;
        let (epoch, r) = r.read_u64();
        let (seq_num, r) = r.read_u64();
        r.end();
        Some((epoch, seq_num))
    }
}
