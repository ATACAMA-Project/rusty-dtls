use crate::buffer_record_queue::BufferMessageQueue;
use crate::crypto::{
    self, CipherDependentCryptoState, CipherSuite, EcdheSharedKey, Psk, PskTranscriptHash,
    TrafficSecret, encode_binder_entry, validate_binder,
};

#[cfg(feature = "_dhe")]
use {
    crate::crypto::{
        KeyShares, NamedGroupSelectInfo, gather_available_key_share_entries, parse_key_share,
    },
    core::ops::Range,
};

use crate::handshake::{CryptoInformation, HandshakeContext};
use crate::parsing_utility::{C, Itr, ParseBuffer, Parser, parse_expect, parse_expect_with};
use crate::{
    AlertDescription, AlertLevel, DtlsError, HandshakeSeqNum, Milliseconds, SelectNamedGroup,
    UserSettings, illegal_state, parse_err,
};
use core::net::SocketAddr;

pub const LEGACY_PROTOCOL_VERSION: u16 = u16::from_be_bytes([254, 253]);
pub const DTLS_1_3: u16 = 0xfefc;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeMsgType {
    ClientHello = 1,
    ServerHello = 2,
    EncryptedExtension = 8,
    Finished = 20,
    MessageHash = 254,
}

impl HandshakeMsgType {
    pub fn from_num(val: u8) -> Option<Self> {
        match val {
            1 => Some(HandshakeMsgType::ClientHello),
            2 => Some(HandshakeMsgType::ServerHello),
            8 => Some(HandshakeMsgType::EncryptedExtension),
            20 => Some(HandshakeMsgType::Finished),
            _ => None,
        }
    }
}

#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001D,
    X448 = 0x001E,

    /* Finite Field Groups (DHE) */
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
}

impl NamedGroup {
    pub fn from_num(val: u16) -> Option<Self> {
        match val {
            0x0017 => Some(NamedGroup::Secp256r1),
            0x0018 => Some(NamedGroup::Secp384r1),
            0x0019 => Some(NamedGroup::Secp521r1),
            0x001D => Some(NamedGroup::X25519),
            0x001E => Some(NamedGroup::X448),
            0x0100 => Some(NamedGroup::Ffdhe2048),
            0x0101 => Some(NamedGroup::Ffdhe3072),
            0x0102 => Some(NamedGroup::Ffdhe4096),
            0x0103 => Some(NamedGroup::Ffdhe6144),
            0x0104 => Some(NamedGroup::Ffdhe8192),
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
        handshake_type: HandshakeMsgType,
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
        Parser::<C<3, C<5, C<3, ()>>>>::new(&mut buf)
            .expect("Checked in new")
            .write_u24(payload_len as u32)
            .add_offset()
            .write_u24(payload_len as u32)
            .end();
        self.binders_len = binders_len;
        let msg_start = self.len_pos - 1;

        transcript_hash
            .update_transcript_hash(self.buffer.access_slice_checked(msg_start..msg_start + 4)?)?;

        let binders_len_field_size = 2;
        transcript_hash.update_transcript_hash(self.buffer.access_slice_checked(
            msg_start + 12..self.buffer.offset() - binders_len_field_size - binders_len,
        )?)?;
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
        )?)?;
        Ok(())
    }

    pub fn finish(self, transcript_hash: &mut CryptoInformation) -> Result<(), DtlsError> {
        debug_assert_eq!(self.binders_len, 0);
        let payload_len = self.buffer.offset() - self.len_pos - 11;

        let mut buf = self.buffer.with_offset(self.len_pos);
        Parser::<C<3, C<5, C<3, ()>>>>::new(&mut buf)
            .expect("Checked in new")
            .write_u24(payload_len as u32)
            .add_offset()
            .write_u24(payload_len as u32)
            .end();

        let msg_start = self.len_pos - 1;
        let buf = self.buffer.as_ref();
        transcript_hash.update_transcript_hash(&buf[msg_start..msg_start + 4])?;
        transcript_hash.update_transcript_hash(&buf[msg_start + 12..])
    }
}

pub fn encode_client_hello(
    buffer: &mut ParseBuffer<'_>,
    #[allow(unused)] ctx: &mut HandshakeContext,
    set: &UserSettings,
    cipher_suites: &[CipherSuite],
    now_ms: &Milliseconds,
    rng: &mut dyn rand_core::CryptoRngCore,
    cookie: Option<&[u8]>,
) -> Result<(HandshakeMsgType, usize), DtlsError> {
    let mut r = Parser::new_dyn(buffer, size_of_val(cipher_suites))?
        .write_u16(LEGACY_PROTOCOL_VERSION)
        .access_static_slice();
    rng.try_fill_bytes(r.slice_mut() as &mut [u8; 32])
        .map_err(|_| DtlsError::RngError)?;
    let mut r = r
        .done()
        .write_u8(0) // Session
        .write_u8(0) // Cookie
        .write_dyn_len_u16();
    let mut i = 0;
    while let Some(r) = r.next() {
        r.write_u16(cipher_suites[i] as u16).end();
        i += 1
    }
    r.done().end();

    Parser::new(buffer)?
        .write_u8(1) // Compression length
        .write_u8(0) // Compression type
        .end();

    let binders_len: usize;
    let len_pos = buffer.prepend_len_u16();
    {
        {
            let ext_pos = encode_extension(buffer);
            let ext = encode_supported_versions_client(buffer)?;
            submit_encode_extension(buffer, ext, ext_pos);
        }
        {
            let ext_pos = encode_extension(buffer);
            let ext = encode_supported_versions_client(buffer)?;
            submit_encode_extension(buffer, ext, ext_pos);
        }
        if let Some(cookie) = cookie {
            let ext_pos = encode_extension(buffer);
            let ext = encode_cookie(buffer, cookie)?;
            submit_encode_extension(buffer, ext, ext_pos);
        }

        // first client hello?
        #[cfg(feature = "_dhe")]
        {
            if ctx.key_shares.is_empty() && set.psk_exchange_modes & PSK_DHE_KE > 0 {
                ctx.client_init_offered_key_shares(set.offered_key_shares, rng)?;
            }
            if set.psk_exchange_modes & PSK_DHE_KE > 0 {
                let ext_pos = encode_extension(buffer);
                let ext = encode_supported_groups(buffer)?;
                submit_encode_extension(buffer, ext, ext_pos);
            }
            if !ctx.key_shares.is_empty() {
                {
                    let ext_pos = encode_extension(buffer);
                    let ext = encode_key_share_client(buffer, &ctx.key_shares)?;
                    submit_encode_extension(buffer, ext, ext_pos);
                }
            }
        }

        {
            let ext_pos = encode_extension(buffer);
            let ext = encode_pre_shared_key_exchange_modes(buffer, set.psk_exchange_modes)?;
            submit_encode_extension(buffer, ext, ext_pos);
        }
        {
            let ext_pos = encode_extension(buffer);
            let (ext, binders_l) =
                encode_pre_shared_key_client_with_empty_binders(buffer, set.psks, now_ms)?;
            binders_len = binders_l;
            submit_encode_extension(buffer, ext, ext_pos);
        }
    }
    buffer.submit_prepend_len_u16(len_pos)?;

    debug_assert_ne!(binders_len, 0);

    Ok((HandshakeMsgType::ClientHello, binders_len))
}

pub fn encode_server_hello(
    buffer: &mut ParseBuffer<'_>,
    rng: &mut dyn rand_core::CryptoRngCore,
    client_hello_session_id: &[u8],
    selected_cipher_suite: CipherSuite,
    selected_psk_id_idx: u16,
    #[cfg(feature = "_dhe")] key_shares: &KeyShares,
) -> Result<HandshakeMsgType, DtlsError> {
    let mut r = Parser::new_mut_slice(buffer, client_hello_session_id)?
        .write_u16(LEGACY_PROTOCOL_VERSION)
        .access_static_slice();

    let slice: &mut [u8; 32] = r.slice_mut();
    rng.try_fill_bytes(slice).map_err(|_| DtlsError::RngError)?;
    r.done()
        .write_slice_with_u8_len() // echo whatever was sent in the client hello
        .write_u16(selected_cipher_suite as u16) // Cipher suite
        .write_u8(0) // Compression
        .end();

    let len_pos = buffer.prepend_len_u16();
    {
        let ext_pos = encode_extension(buffer);
        let ext = encode_supported_versions_server(buffer)?;
        submit_encode_extension(buffer, ext, ext_pos);
    }

    #[cfg(feature = "_dhe")]
    if !key_shares.is_empty() {
        {
            let ext_pos = encode_extension(buffer);
            let ext = encode_key_share_server(buffer, key_shares)?;
            submit_encode_extension(buffer, ext, ext_pos);
        }
    }
    {
        let ext_pos = encode_extension(buffer);
        Parser::new(buffer)?.write_u16(selected_psk_id_idx).end();
        submit_encode_extension(buffer, ExtensionType::PreSharedKey, ext_pos);
    }
    buffer.submit_prepend_len_u16(len_pos)?;

    Ok(HandshakeMsgType::ServerHello)
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
    #[allow(unused)] request_key_share: Option<NamedGroup>,
) -> Result<HandshakeMsgType, DtlsError> {
    Parser::new_mut_slice(buffer, client_hello_session_id)?
        .write_u16(LEGACY_PROTOCOL_VERSION)
        .write_static_slice(&HELLO_RETRY_RANDOM)
        .write_slice_with_u8_len() // echo whatever was sent in the client hello
        .write_u16(cipher_suite as u16) // Cipher suite
        .write_u8(0) // Compression
        .end();

    {
        let len_pos = buffer.prepend_len_u16();
        {
            let ext_pos = encode_extension(buffer);
            let ext = encode_supported_versions_server(buffer)?;
            submit_encode_extension(buffer, ext, ext_pos);
        }

        #[cfg(feature = "_dhe")]
        if let Some(group) = &request_key_share {
            {
                let ext_pos = encode_extension(buffer);
                let ext = encode_key_share_hello_rt(buffer, *group)?;
                submit_encode_extension(buffer, ext, ext_pos);
            }
        }
        {
            let ext_pos = encode_extension(buffer);
            let ext = match cookie {
                HelloRetryCookie::Calculate {
                    client_hello_hash,
                    peer_addr,
                    cookie_key,
                } => create_and_encode_cookie(buffer, cookie_key, peer_addr, client_hello_hash),
                HelloRetryCookie::Existing(cookie) => encode_cookie(buffer, cookie),
            }?;
            submit_encode_extension(buffer, ext, ext_pos);
        }

        buffer.submit_prepend_len_u16(len_pos)?;
    }
    Ok(HandshakeMsgType::ServerHello)
}

pub fn encode_encrypted_extensions(buffer: &mut ParseBuffer<'_>) -> Result<(), DtlsError> {
    Parser::new(buffer)?.write_u16(0).end();
    Ok(())
}

pub fn encode_finished(
    buffer: &mut ParseBuffer<'_>,
    secret: &TrafficSecret,
    crypto_state: &mut CipherDependentCryptoState,
) -> Result<HandshakeMsgType, DtlsError> {
    crypto_state.encode_verify_data(buffer, secret)?;
    Ok(HandshakeMsgType::Finished)
}

#[repr(u16)]
pub enum ExtensionType {
    SupportedGroups = 10,
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
            10 => Ok(ExtensionType::SupportedGroups),
            41 => Ok(ExtensionType::PreSharedKey),
            43 => Ok(ExtensionType::SupportedVersions),
            44 => Ok(ExtensionType::Cookie),
            45 => Ok(ExtensionType::PskKeyExchangeModes),
            51 => Ok(ExtensionType::KeyShare),
            _ => Err(parse_err!()),
        }
    }
}

pub fn encode_extension(buffer: &mut ParseBuffer<'_>) -> usize {
    buffer.add_offset(4);
    buffer.offset()
}

pub fn submit_encode_extension(
    buffer: &mut ParseBuffer<'_>,
    extension_type: ExtensionType,
    offset: usize,
) {
    let o = buffer.offset();
    let b: &mut [u8; 4] = buffer
        .as_mut()
        .get_mut(offset - 4..offset)
        .and_then(|b| b.try_into().ok())
        .unwrap();

    *b.split_last_chunk_mut::<2>().unwrap().1 = ((o - offset) as u16).to_be_bytes();
    *b.split_first_chunk_mut::<2>().unwrap().0 = (extension_type as u16).to_be_bytes();
}

#[cfg(feature = "_dhe")]
pub fn encode_supported_groups(buffer: &mut ParseBuffer<'_>) -> Result<ExtensionType, DtlsError> {
    let groups = crypto::supported_groups();
    let len = size_of_val(groups);
    let mut r = Parser::new_dyn(buffer, len)?.write_dyn_len_u16();

    let mut i = 0;
    while let Some(r) = r.next() {
        r.write_u16(groups[i] as u16).end();
        i += 1;
    }
    r.done().end();

    Ok(ExtensionType::SupportedGroups)
}

pub fn encode_pre_shared_key_client_with_empty_binders(
    buffer: &mut ParseBuffer<'_>,
    psks: &[Psk<'_>],
    now_ms: &Milliseconds,
) -> Result<(ExtensionType, usize), DtlsError> {
    let len_pos = buffer.prepend_len_u16();
    for psk in psks {
        let r = Parser::new_mut_slice(buffer, psk.identity)?.write_slice_with_u16_len();

        #[allow(clippy::unnecessary_cast)]
        match psk.key_type {
            crate::crypto::PskType::Resumption {
                ticket_creation_timestamp_ms,
            } => r
                .write_u32((now_ms - ticket_creation_timestamp_ms) as u32)
                .end(),
            crate::crypto::PskType::External => r.write_u32(0).end(),
        }
    }
    buffer.submit_prepend_len_u16(len_pos)?;
    let mut binders_space_len = 0;

    let len_pos = buffer.prepend_len_u16();
    for psk in psks {
        let binder_space_len = 1 + psk.hash_function.output_size();
        buffer.expect_length(binder_space_len)?;
        // Add empty offset here so lengths are calculated correctly
        buffer.add_offset(binder_space_len);
        binders_space_len += binder_space_len;
    }
    buffer.submit_prepend_len_u16(len_pos)?;

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

pub fn encode_cookie(
    buffer: &mut ParseBuffer<'_>,
    cookie: &[u8],
) -> Result<ExtensionType, DtlsError> {
    Parser::new_mut_slice(buffer, cookie)?
        .write_slice_with_u16_len()
        .end();
    Ok(ExtensionType::Cookie)
}

pub fn create_and_encode_cookie(
    buffer: &mut ParseBuffer<'_>,
    key: &[u8],
    peer_addr: &SocketAddr,
    client_hello_hash: &PskTranscriptHash,
) -> Result<ExtensionType, DtlsError> {
    let len_pos = buffer.prepend_len_u16();
    crypto::encode_cookie(buffer, key, client_hello_hash, peer_addr)?;
    buffer.submit_prepend_len_u16(len_pos)?;
    Ok(ExtensionType::Cookie)
}

pub fn encode_pre_shared_key_exchange_modes(
    buffer: &mut ParseBuffer<'_>,
    psk_modes: PskExchangeModes,
) -> Result<ExtensionType, DtlsError> {
    if psk_modes == 3 {
        Parser::new(buffer)?
            .write_u8(2)
            .write_u8(0)
            .write_u8(1)
            .end();
    } else {
        Parser::new(buffer)?
            .write_u8(1)
            .write_u8(psk_modes >> 1)
            .end();
    }
    Ok(ExtensionType::PskKeyExchangeModes)
}

#[cfg(feature = "_dhe")]
pub fn encode_key_share_client(
    buffer: &mut ParseBuffer<'_>,
    key_shares: &KeyShares,
) -> Result<ExtensionType, DtlsError> {
    let len_pos = buffer.prepend_len_u16();
    key_shares.encode_available_key_share_entries(buffer)?;
    buffer.submit_prepend_len_u16(len_pos)?;
    Ok(ExtensionType::KeyShare)
}

#[cfg(feature = "_dhe")]
pub fn encode_key_share_hello_rt(
    buffer: &mut ParseBuffer<'_>,
    group: NamedGroup,
) -> Result<ExtensionType, DtlsError> {
    Parser::new(buffer)?.write_u16(group as u16).end();
    Ok(ExtensionType::KeyShare)
}

#[cfg(feature = "_dhe")]
pub fn encode_key_share_server(
    buffer: &mut ParseBuffer<'_>,
    key_shares: &KeyShares,
) -> Result<ExtensionType, DtlsError> {
    key_shares.encode_available_key_share_entries(buffer)?;
    Ok(ExtensionType::KeyShare)
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
    ) -> Result<(Self, HandshakeMsgType, HandshakeSeqNum), DtlsError> {
        let start = buffer.offset();

        let r = Parser::new(&mut buffer)?;
        let (hs_type, r) = r.read_u8();
        let handshake_type = HandshakeMsgType::from_num(hs_type).ok_or_else(|| parse_err!())?;
        let (length, r) = r.read_u24();
        let (seq_num, r) = r.read_u16();
        let (frag_off, r) = r.read_u24();
        parse_expect_with(frag_off == 0, || parse_err!())?;
        let (frag_len, r) = r.read_u24();
        r.end();
        parse_expect_with(frag_len == length, || parse_err!())?;
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
        buffer: &mut ParseBuffer<'a>,
    ) -> Result<HandshakeMsgType, DtlsError> {
        let (content_type, r) = Parser::new(buffer)?.read_u8();
        r.end();
        HandshakeMsgType::from_num(content_type).ok_or_else(|| parse_err!())
    }

    pub fn payload_buffer<'c>(&'c mut self) -> &'c mut ParseBuffer<'a> {
        &mut self.buffer
    }

    pub fn add_to_transcript_hash(
        &self,
        transcript_hash: &mut CryptoInformation,
    ) -> Result<(), DtlsError> {
        transcript_hash.update_transcript_hash(
            &self.buffer.as_ref()[self.message_start..self.message_start + 4],
        )?;
        transcript_hash.update_transcript_hash(&self.buffer.as_ref()[self.message_start + 12..])
    }

    pub fn abort_parsing(self) -> ParseBuffer<'a> {
        self.buffer
    }
}

pub enum ClientHelloResult {
    Ok {
        dhe_group: Option<NamedGroup>,
    },
    HelloRetry {
        request_key_share: Option<NamedGroup>,
    },
}

pub fn parse_client_hello_first_pass(
    require_cookie: bool,
    cookie_key: &[u8],
    #[allow(unused)] select_group: SelectNamedGroup,
    #[allow(unused)] ctx: &mut HandshakeContext,
    record_queue: &mut BufferMessageQueue<'_>,
    psk_exch_modes: PskExchangeModes,
    peer_addr: &SocketAddr,
    buffer: &mut ParseBuffer<'_>,
) -> Result<ClientHelloResult, DtlsError> {
    // legacy version field ignored on server side (my way of understanding)
    buffer.add_offset(2);

    buffer.add_offset(32);

    // if we ignore cached sessions we could ignore this field...
    let legacy_session_len = Parser::read_single_u8(buffer)?;
    buffer.add_offset(legacy_session_len as usize);

    let (cookie_len, r) = Parser::new(buffer)?.read_u8();
    parse_expect(
        cookie_len == 0,
        DtlsError::Alert(AlertDescription::IllegalParameter),
    )?;
    let (cipher_suites_len, r) = r.read_u16();
    r.end();
    let supported_suites = CipherSuite::all();

    let mut r = Parser::new_dyn(buffer, cipher_suites_len as usize)?;
    while let Some(r) = r.next() {
        let (suite, r) = r.read_u16();
        r.end();
        let suite = CipherSuite::try_from(suite)?;
        if ctx.selected_cipher_suite.is_none() && supported_suites.contains(&suite) {
            ctx.selected_cipher_suite = Some(suite);
        }
    }
    let (compression_len, r) = r.done().read_u8();
    let (compression_method, r) = r.read_u8();
    r.end();
    parse_expect(
        compression_len == 1 && compression_method == 0,
        DtlsError::Alert(AlertDescription::IllegalParameter),
    )?;

    #[cfg(feature = "_dhe")]
    let mut ng = NamedGroupSelectInfo { v: 0 };
    let extension_start = buffer.offset();
    let mut found_supported_version = false;
    let mut psk_exchange_modes = 0;
    let mut cookie = None;
    let mut extensions = ParseExtensions::new(buffer)?;
    while extensions.has_next() {
        let (extension_type, mut buffer) = extensions.next()?;
        match extension_type {
            ExtensionType::SupportedVersions => {
                found_supported_version = true;
                parse_supported_versions_client(&mut buffer)
            }
            #[cfg(feature = "_dhe")]
            ExtensionType::SupportedGroups => parse_supported_groups(&mut buffer, &mut ng),
            #[cfg(feature = "_dhe")]
            ExtensionType::KeyShare => gather_available_key_share_entries(&mut buffer, &mut ng),
            ExtensionType::Cookie => {
                cookie = Some(parse_cookie(&mut buffer)?);
                Ok(())
            }
            ExtensionType::PskKeyExchangeModes => {
                psk_exchange_modes = psk_exch_modes & parse_ch_key_exchange_modes(&mut buffer)?;
                Ok(())
            }
            _ => Ok(()),
        }?;
    }

    if !found_supported_version {
        return Err(DtlsError::Alert(AlertDescription::MissingExtension));
    }

    #[cfg(not(feature = "_dhe"))]
    if psk_exchange_modes & (!PSK_DHE_KE) == 0 {
        return Err(DtlsError::Alert(AlertDescription::HandshakeFailure));
    }

    #[allow(unused_mut)]
    let mut selected_group = None;
    #[cfg(feature = "_dhe")]
    if psk_exchange_modes & PSK_DHE_KE == 0 {
        // Clear supported groups
        ng.v = 0;
    } else {
        ng.check()?;
        selected_group = select_group(&ng);

        if selected_group.is_none() {
            psk_exchange_modes &= !PSK_DHE_KE;
        }
    };

    if psk_exchange_modes == 0 {
        return Err(DtlsError::Alert(AlertDescription::HandshakeFailure));
    }

    let mut found_valid_cookie = false;
    let mut cookie_data = None;
    if let Some(c) = cookie {
        'cookie: {
            let cookie_slice = buffer.access_slice_checked(c.index..c.index + c.len)?;
            let true = crypto::verify_cookie(cookie_slice, cookie_key, peer_addr)? else {
                break 'cookie;
            };
            found_valid_cookie = true;
            cookie_data = Some(cookie_slice);
            // Set transcript hash to message_hash + HelloRetry
            ctx.server_init_post_hello_retry_hash(cookie_slice)?;
        }
    } else {
        // We selected a single cipher suite and can narrow the
        // amount of available hashes.
        ctx.server_switch_to_single_hash()?;
    }

    #[allow(unused_mut)]
    let mut request_key_share = None;
    #[cfg(feature = "_dhe")]
    if let Some(group) = selected_group {
        if (found_valid_cookie || !require_cookie) && ng.key_share_available(group) {
            ctx.key_shares.discard_unused_key_shares(group);
        } else if found_valid_cookie {
            // Client refused to send requested group
            return Err(DtlsError::Alert(AlertDescription::HandshakeFailure));
        } else {
            // If we arrive here we either didn't find a cookie or a key_share.
            // In either case a HelloRetry needs to be sent.
            request_key_share = Some(group);
        }
    }

    if !found_valid_cookie && require_cookie || request_key_share.is_some() {
        return Ok(ClientHelloResult::HelloRetry { request_key_share });
    }

    // Only encode HelloRetry if one was sent
    if let Some(cookie_data) = cookie_data {
        // Using space in the record queue to keep staging buffer valid.
        let mut rt_buf = record_queue.alloc_entry();
        // record_queue.alloc_rt_entry(0, &0, &mut |buffer| {
        let mut hs = EncodeHandshakeMessage::new(&mut rt_buf, HandshakeMsgType::ServerHello, 0)?;
        encode_hello_retry(
            hs.payload_buffer(),
            &[],
            ctx.selected_cipher_suite
                .expect("Is set if parsing was successful"),
            HelloRetryCookie::existing(cookie_data),
            selected_group,
        )?;
        // This adds the HelloRetry to the transcript hash
        hs.finish(&mut ctx.crypto)?;
        let offset = rt_buf.offset();
        record_queue.submit_rt_entry(0, &0, offset)?;
        record_queue.clear_record_queue();
    }
    // Second pass will pick up from here.
    buffer.set_offset(extension_start);
    Ok(ClientHelloResult::Ok {
        dhe_group: selected_group,
    })
}

pub fn parse_client_hello_second_pass(
    #[allow(unused)] rng: &mut dyn rand_core::CryptoRngCore,
    ctx: &mut HandshakeContext,
    available_psks: &[Psk<'_>],
    buffer: &mut ParseBuffer<'_>,
    #[allow(unused)] dhe_group: Option<NamedGroup>,
    client_hello_start: usize,
) -> Result<(), DtlsError> {
    #[cfg(feature = "_dhe")]
    let mut key_share_slice = None;

    let mut extensions = ParseExtensions::new(buffer)?;
    while extensions.has_next() {
        let (extension_type, mut buffer) = extensions.next()?;
        match extension_type {
            #[cfg(feature = "_dhe")]
            ExtensionType::KeyShare => {
                key_share_slice = Some(buffer.offset()..buffer.capacity());
            }
            ExtensionType::PreSharedKey => {
                #[allow(unused_mut)]
                let mut ecdhe_key: Option<EcdheSharedKey> = None;
                #[cfg(feature = "_dhe")]
                if let (Some(key_share_slice), Some(dhe_group)) =
                    (key_share_slice.take(), dhe_group)
                {
                    let mut b = ParseBuffer::init_with_offset(
                        &mut buffer.as_mut()[..key_share_slice.end],
                        key_share_slice.start + 2, // Skip len field
                    );
                    ctx.key_shares.init_key_exchange(rng, dhe_group)?;
                    let key_exch_slice = parse_key_share(dhe_group, &mut b)?;
                    ecdhe_key = Some(ctx.key_shares.calculate_ecdhe_key(
                        dhe_group,
                        buffer.access_slice_checked(key_exch_slice)?,
                    )?)
                }
                let psk_index = parse_pre_shared_key_client(
                    &mut buffer,
                    client_hello_start,
                    ctx,
                    available_psks,
                )?;
                ctx.initialize_crypto_state(
                    available_psks,
                    psk_index,
                    ecdhe_key.as_ref().map(|e| e.as_ref()),
                )?;
            }
            _ => {}
        }
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
    #[allow(unused)] rng: &mut dyn rand_core::CryptoRngCore,
    ctx: &mut HandshakeContext,
    set: &UserSettings,
    allowed_cipher_suites: &[CipherSuite],
    buffer: &mut ParseBuffer<'_>,
) -> Result<ServerHelloVariant, DtlsError> {
    let (legacy_protocol_ver, r) = Parser::new(buffer)?.read_u16();
    parse_expect_with(
        legacy_protocol_ver == LEGACY_PROTOCOL_VERSION,
        || parse_err!(),
    )?;
    let mut r = r.access_static_slice();
    let mut variant = if r.slice_mut() == &HELLO_RETRY_RANDOM {
        /*
        If a client receives a second
        HelloRetryRequest in the same connection (i.e., where the ClientHello
        was itself in response to a HelloRetryRequest), it MUST abort the
        handshake with an "unexpected_message" alert.
        */
        if ctx.received_hello_retry_request {
            Err(DtlsError::Alert(AlertDescription::UnexpectedMessage))?;
        }
        ctx.received_hello_retry_request = true;
        ServerHelloVariant::HelloRetry(None)
    } else {
        ServerHelloVariant::ServerHello
    };
    let (session_id_echo, r) = r.done().read_u8();
    parse_expect_with(session_id_echo == 0, || parse_err!())?;

    let (cipher_suite, r) = r.read_u16();
    let cipher_suite = CipherSuite::try_from(cipher_suite)?;
    if !allowed_cipher_suites.contains(&cipher_suite) {
        /*
        A client which receives a cipher suite that was not offered MUST
        abort the handshake.
        */
        return Err(DtlsError::Alert(crate::AlertDescription::IllegalParameter));
    }

    if ctx.selected_cipher_suite.is_none() {
        ctx.selected_cipher_suite = Some(cipher_suite);
        if matches!(variant, ServerHelloVariant::HelloRetry(_)) {
            // Throw away all unnecessary hashes and replace client_hello hash
            ctx.client_switch_to_post_hello_retry_hash()?;
        }
    } else {
        /*
        clients MUST check that the cipher suite supplied in
        the ServerHello is the same as that in the HelloRetryRequest and
        otherwise abort the handshake with an "illegal_parameter" alert.
        */
        parse_expect(
            ctx.selected_cipher_suite == Some(cipher_suite),
            DtlsError::Alert(AlertDescription::IllegalParameter),
        )?;
    }
    let (legacy_compression_method, r) = r.read_u8();
    r.end();
    parse_expect(legacy_compression_method == 0, DtlsError::ParseError)?;

    let mut found_supported_version = false;

    #[allow(unused_mut)]
    let mut found_missing_group_request = false;
    let mut found_psk = false;
    #[cfg(feature = "_dhe")]
    let mut ecdhe_slice: Option<(NamedGroup, Range<usize>)> = None;
    let mut extensions = ParseExtensions::new(buffer)?;
    while extensions.has_next() {
        let (extension_type, mut buffer) = extensions.next()?;
        match extension_type {
            ExtensionType::SupportedVersions => {
                found_supported_version = true;
                parse_supported_versions_server(&mut buffer)?;
            }
            ExtensionType::PreSharedKey => {
                found_psk = true;
                let psk_index = parse_pre_shared_key_server(&mut buffer)? as usize;

                #[allow(unused_mut)]
                let mut ecdhe_key: Option<EcdheSharedKey> = None;
                #[cfg(feature = "_dhe")]
                if let Some((g, r)) = &ecdhe_slice {
                    ecdhe_key = Some(
                        ctx.key_shares
                            .calculate_ecdhe_key(*g, buffer.access_slice_checked(r.clone())?)?,
                    )
                }
                ctx.initialize_crypto_state(
                    set.psks,
                    psk_index,
                    ecdhe_key.as_ref().map(|e| e.as_ref()),
                )?;
            }
            #[cfg(feature = "_dhe")]
            ExtensionType::KeyShare => {
                if set.psk_exchange_modes & PSK_DHE_KE == 0 {
                    // Server selected illegal exchange_mode
                    return Err(DtlsError::Alert(AlertDescription::IllegalParameter));
                }
                if matches!(variant, ServerHelloVariant::ServerHello) {
                    ecdhe_slice = Some(parse_key_share_server_hello(&mut buffer, &ctx.key_shares)?);
                } else {
                    let group = parse_key_share_hello_retry(&mut buffer)?;
                    ctx.key_shares.discard_unused_key_shares(group);
                    if !ctx.key_shares.key_exchange_initialized(group) {
                        found_missing_group_request = true;
                        ctx.key_shares.init_key_exchange(rng, group)?;
                    }
                }
            }
            ExtensionType::Cookie => {
                variant = ServerHelloVariant::HelloRetry(Some(parse_cookie(&mut buffer)?));
            }
            _ => {
                Err(parse_err!())?;
            }
        }
    }

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
            if cookie.is_none() && !found_missing_group_request {
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
    let extension = ParseExtensions::new(buffer)?;
    if extension.has_next() {
        return Err(DtlsError::Alert(AlertDescription::UnsupportedExtension));
    }
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

pub struct ParseExtensions<'a, 'b> {
    buffer: &'a mut ParseBuffer<'b>,
    end: usize,
}

impl<'a, 'b> ParseExtensions<'a, 'b> {
    pub fn new(buffer: &'a mut ParseBuffer<'b>) -> Result<Self, DtlsError> {
        let extensions_len = Parser::read_single_u16(buffer)? as usize;
        buffer.expect_length(extensions_len)?;
        let start = buffer.offset();
        Ok(Self {
            buffer,
            end: start + extensions_len,
        })
    }

    pub fn has_next(&self) -> bool {
        self.buffer.offset() < self.end
    }

    pub fn next<'c>(&'c mut self) -> Result<(ExtensionType, ParseBuffer<'c>), DtlsError> {
        let (extension_type, r) = Parser::new(self.buffer)?.read_u16();
        log::trace!("Parse extension {}", extension_type);
        let extension_type = ExtensionType::try_from(extension_type)?;
        let (extension_data_len, r) = r.read_u16();
        r.end();
        let extension_data_len = extension_data_len as usize;
        self.buffer.expect_length(extension_data_len)?;
        self.buffer.add_offset(extension_data_len);
        let offset = self.buffer.offset();

        if matches!(extension_type, ExtensionType::PreSharedKey) && offset < self.end {
            return Err(DtlsError::Alert(AlertDescription::IllegalParameter));
        }

        let sub_buffer =
            ParseBuffer::init_with_offset(self.buffer.as_mut(), offset - extension_data_len);
        Ok((extension_type, sub_buffer))
    }
}

#[cfg(feature = "_dhe")]
fn parse_supported_groups(
    buffer: &mut ParseBuffer<'_>,
    ng: &mut NamedGroupSelectInfo,
) -> Result<(), DtlsError> {
    let groups_len = Parser::read_single_u16(buffer)?;
    let mut r = Parser::new_dyn(buffer, groups_len as usize)?;
    while let Some(r) = r.next() {
        let (group, r) = r.read_u16();
        let group =
            NamedGroup::from_num(group).ok_or(DtlsError::Alert(AlertDescription::DecodeError))?;
        ng.add_offered_group(group);

        r.end();
    }
    r.done().end();
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
    ctx: &mut HandshakeContext,
    available_psks: &[Psk<'_>],
) -> Result<usize, DtlsError> {
    let mut psk_ids_len_left = Parser::read_single_u16(buffer)? as usize;
    parse_expect(
        psk_ids_len_left > 0,
        DtlsError::Alert(AlertDescription::MissingExtension),
    )?;
    let Some(cipher_suite) = ctx.selected_cipher_suite else {
        return Err(illegal_state!());
    };
    let cipher_suite_hash_fn = cipher_suite.hash_function();
    let mut selected_psk_index = 0;
    let mut avail_psk_index = 0;
    let mut found_psk = false;

    'outer: while psk_ids_len_left > 0 {
        let psk_id_len = Parser::read_single_u16(buffer)? as usize;
        psk_ids_len_left -= 2 + psk_id_len;
        let r = Parser::new_dyn(buffer, psk_id_len)?.access_dyn_slice();
        let id = r.slice();
        parse_expect(
            !id.is_empty(),
            DtlsError::Alert(AlertDescription::DecodeError),
        )?;

        for (i, psk) in available_psks.iter().enumerate() {
            if psk.hash_function == cipher_suite_hash_fn && psk.identity == id {
                found_psk = true;
                avail_psk_index = i;
                buffer.add_offset(psk_ids_len_left);
                break 'outer;
            }
        }
        psk_ids_len_left -= 4;
        let (_obfuscated_ticked_age, r) = r.done().read_u32();
        r.end();
        selected_psk_index += 1;
    }

    if !found_psk {
        return Err(DtlsError::Alert(AlertDescription::UnknownPskIdentity));
    }

    let binder_start = buffer.offset();

    let mut binders_len_left = Parser::read_single_u16(buffer)?;
    let mut binder_index = 0;
    while binders_len_left > 0 {
        let binder_len = Parser::read_single_u8(buffer)? as usize;
        buffer.add_offset(binder_len);
        parse_expect(
            binder_len >= 32,
            DtlsError::Alert(AlertDescription::DecodeError),
        )?;
        let bind_entry =
            buffer.access_slice_checked(buffer.offset() - binder_len..buffer.offset())?;
        binders_len_left -= 1 + binder_len as u16;

        if selected_psk_index == binder_index {
            let partial_client_hello =
                &buffer.access_slice_checked(client_hello_start - 12..binder_start)?;
            let (header, client_hello) = partial_client_hello.split_at(12);
            let transcript_hash: &mut PskTranscriptHash = ctx.crypto.psk_hash_mut()?;
            let finalized_hash = transcript_hash.finalize(&[&header[0..4], client_hello]);

            if validate_binder(
                bind_entry,
                &available_psks[avail_psk_index],
                finalized_hash.as_ref(),
            )
            .is_ok_and(|b| b)
            {
                buffer.add_offset(binders_len_left as usize);
                ctx.selected_psk_in_ch = selected_psk_index as u16;
                return Ok(avail_psk_index);
            } else {
                return Err(DtlsError::Alert(AlertDescription::DecryptionError));
            }
        }
        binder_index += 1;
    }
    // Binders are not correctly encoded
    Err(DtlsError::Alert(AlertDescription::DecodeError))
}

pub type PskExchangeModes = u8;
pub const PSK_KE: u8 = 1;
pub const PSK_DHE_KE: u8 = 2;

fn parse_ch_key_exchange_modes(
    buffer: &mut ParseBuffer<'_>,
) -> Result<PskExchangeModes, DtlsError> {
    let modes_len = Parser::read_single_u8(buffer)?;
    let mut modes = 0;
    let mut r = Parser::new_dyn(buffer, modes_len as usize)?;
    while let Some(r) = r.next() {
        let (mode, r) = r.read_u8();
        r.end();
        if mode > 1 {
            return Err(DtlsError::Alert(AlertDescription::DecodeError));
        }
        modes |= 1 << mode;
    }
    r.done().end();
    Ok(modes)
}

#[cfg(feature = "_dhe")]
pub fn parse_key_share_hello_retry(buffer: &mut ParseBuffer<'_>) -> Result<NamedGroup, DtlsError> {
    let group = Parser::read_single_u16(buffer)?;
    NamedGroup::from_num(group).ok_or(DtlsError::Alert(AlertDescription::IllegalParameter))
}

#[cfg(feature = "_dhe")]
pub fn parse_key_share_server_hello(
    buffer: &mut ParseBuffer<'_>,
    key_shares: &KeyShares,
) -> Result<(NamedGroup, Range<usize>), DtlsError> {
    let (group, r) = Parser::new(buffer)?.read_u16();
    let (k_e_len, r) = r.read_u16();
    r.end();
    let group =
        NamedGroup::from_num(group).ok_or(DtlsError::Alert(AlertDescription::IllegalParameter))?;
    parse_expect(
        key_shares.key_exchange_initialized(group),
        DtlsError::Alert(AlertDescription::IllegalParameter),
    )?;
    crypto::parse_key_exchange(group, k_e_len, buffer).map(|r| (group, r))
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
    reader: Parser<'a, 'b, Itr<C<8, C<8, ()>>>>,
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
