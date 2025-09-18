use core::net::{IpAddr, SocketAddr};

use crate::handshake::CryptoInformation;
use crate::parsing::{HandshakeMsgType, NamedGroup};
use crate::parsing_utility::{ParseBuffer, Parser};
use crate::{DtlsError, Milliseconds, illegal_state, parse_err};

#[cfg(feature = "aes128gcm_sha256")]
use {aes_gcm::Aes128Gcm, sha2::digest::generic_array::typenum::Unsigned};

#[cfg(feature = "_dhe")]
use {
    crate::AlertDescription,
    crate::parsing_utility::{C, parse_expect_with},
    core::ops::Range,
};

use aes_gcm::{
    AeadCore, AeadInPlace, KeyInit, KeySizeUser,
    aes::{
        Aes128,
        cipher::{BlockEncrypt, BlockSizeUser},
    },
};
use hkdf::hmac::Mac;
use hkdf::{Hkdf, hmac::SimpleHmac};
use log::trace;
use sha2::digest::Update;
use sha2::{
    Digest, Sha256,
    digest::{FixedOutput, OutputSizeUser, generic_array::GenericArray},
};

pub struct PskTranscriptHashes {
    #[cfg(feature = "aes128gcm_sha256")]
    pub(crate) sha256: Sha256,
}

impl Default for PskTranscriptHashes {
    fn default() -> Self {
        Self::new()
    }
}

impl PskTranscriptHashes {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "aes128gcm_sha256")]
            sha256: <Sha256 as Digest>::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        print_bytes!("TranscriptHash Update", data);
        #[cfg(feature = "aes128gcm_sha256")]
        Digest::update(&mut self.sha256, data);
    }

    pub fn finalize(&self, partial_client_hello: &[&[u8]]) -> FinalizedPskTranscriptHashes {
        FinalizedPskTranscriptHashes {
            #[cfg(feature = "aes128gcm_sha256")]
            sha256: {
                let mut hash = self.sha256.clone();
                partial_client_hello.iter().for_each(|part| {
                    Digest::update(&mut hash, part);
                });
                hash.finalize()
            },
        }
    }

    pub fn client_transition_to_single_hash(self, cipher_suite: CipherSuite) -> PskTranscriptHash {
        // When the server responds to a
        // ClientHello with a HelloRetryRequest, the value of ClientHello1 is
        // replaced with a special synthetic handshake message of handshake type
        // "message_hash" containing Hash(ClientHello1).
        match cipher_suite {
            #[cfg(feature = "aes128gcm_sha256")]
            CipherSuite::Aes128GcmSha256 => {
                let client_hello_1 = self.sha256.finalize();
                let hash = calculate_hello_retry_transcript_hash::<Sha256>(&client_hello_1);
                PskTranscriptHash::Sha256(hash)
            }
        }
    }
}

pub struct FinalizedPskTranscriptHashes {
    #[cfg(feature = "aes128gcm_sha256")]
    pub(crate) sha256: GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
}

impl FinalizedPskTranscriptHashes {
    pub fn get(&self, hash_fn: HashFunction) -> &[u8] {
        match hash_fn {
            #[cfg(feature = "aes128gcm_sha256")]
            HashFunction::Sha256 => &self.sha256,
        }
    }
}

pub enum PskTranscriptHash {
    Sha256(Sha256),
}

impl PskTranscriptHash {
    pub fn new(cipher_suite: CipherSuite) -> Self {
        match cipher_suite {
            #[cfg(feature = "aes128gcm_sha256")]
            CipherSuite::Aes128GcmSha256 => Self::Sha256(<Sha256 as Digest>::new()),
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        print_bytes!("TranscriptHash Update", data);
        match self {
            PskTranscriptHash::Sha256(h) => Digest::update(h, data),
        }
    }

    pub fn server_digest_cookie_hash(&mut self, cookie: &[u8]) {
        match self {
            PskTranscriptHash::Sha256(h) => {
                digest_client_hello_1_hash(h, &cookie[..<Sha256 as OutputSizeUser>::output_size()])
            }
        }
    }

    pub fn finalize(&self, partial_client_hello: &[&[u8]]) -> FinalizedPskTranscriptHash {
        match self {
            PskTranscriptHash::Sha256(h) => {
                let mut h = h.clone();
                partial_client_hello.iter().for_each(|part| {
                    print_bytes!("TranscriptHash Update", part);
                    Digest::update(&mut h, part);
                });
                FinalizedPskTranscriptHash::Sha256(h.finalize())
            }
        }
    }
}

pub enum FinalizedPskTranscriptHash {
    Sha256(GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>),
}

impl AsRef<[u8]> for FinalizedPskTranscriptHash {
    fn as_ref(&self) -> &[u8] {
        match self {
            FinalizedPskTranscriptHash::Sha256(h) => h,
        }
    }
}

pub fn supported_groups() -> &'static [NamedGroup] {
    &[NamedGroup::Secp256r1]
}

pub struct NamedGroupSelectInfo {
    pub(crate) v: u32,
}

impl NamedGroupSelectInfo {
    const SECP256R1: u32 = 1;

    /// Groups supported by this implementation
    pub fn supported_groups(&self) -> &'static [NamedGroup] {
        supported_groups()
    }

    pub fn group_offered(&self, group: NamedGroup) -> bool {
        match group {
            NamedGroup::Secp256r1 => self.v & Self::SECP256R1 > 0,
            _ => false,
        }
    }

    pub fn key_share_available(&self, group: NamedGroup) -> bool {
        match group {
            NamedGroup::Secp256r1 => self.v & (Self::SECP256R1 << 16) > 0,
            _ => false,
        }
    }

    #[cfg(feature = "_dhe")]
    pub(crate) fn add_offered_group(&mut self, group: NamedGroup) {
        match group {
            NamedGroup::Secp256r1 => self.v |= Self::SECP256R1,
            _ => {}
        }
    }

    #[cfg(feature = "_dhe")]
    pub(crate) fn check(&self) -> Result<(), DtlsError> {
        if (self.v >> 16) & !(self.v & 0xFFFF) > 0 {
            Err(DtlsError::Alert(AlertDescription::IllegalParameter))
        } else {
            Ok(())
        }
    }
}

pub type SelectNamedGroup = fn(&NamedGroupSelectInfo) -> Option<NamedGroup>;

pub fn default_select_named_group(
    #[allow(unused)] ngi: &NamedGroupSelectInfo,
) -> Option<NamedGroup> {
    #[cfg(feature = "_dhe")]
    {
        for g in ngi.supported_groups() {
            if ngi.key_share_available(*g) {
                return Some(*g);
            }
        }
        for g in ngi.supported_groups() {
            if ngi.group_offered(*g) {
                return Some(*g);
            }
        }
    }
    None
}

pub enum EcdheSharedKey {
    #[cfg(feature = "secp256r1")]
    Secp256r1(p256::ecdh::SharedSecret),
}

impl AsRef<[u8]> for EcdheSharedKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            #[cfg(feature = "secp256r1")]
            EcdheSharedKey::Secp256r1(shared_secret) => shared_secret.raw_secret_bytes(),
            #[cfg(not(any(feature = "secp256r1")))]
            _ => &[],
        }
    }
}

#[derive(Default)]
pub struct KeyShares {
    #[cfg(feature = "secp256r1")]
    pub secp256r1: Option<p256::ecdh::EphemeralSecret>,
}

/// Glue for rust_crypto since it is generic about the rng
/// instead of using dynamic dispatch as rusty-dlts is.
#[cfg(feature = "_dhe")]
struct RngWrapper<'a> {
    rng: &'a mut dyn rand_core::CryptoRngCore,
}

#[cfg(feature = "_dhe")]
impl<'a> rand_core::CryptoRng for RngWrapper<'a> {}

#[cfg(feature = "_dhe")]
impl<'a> rand_core::RngCore for RngWrapper<'a> {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.rng.try_fill_bytes(dest)
    }
}

#[cfg(feature = "_dhe")]
impl KeyShares {
    pub fn init_key_exchange(
        &mut self,
        rng: &mut dyn rand_core::CryptoRngCore,
        group: NamedGroup,
    ) -> Result<(), DtlsError> {
        let mut rng = RngWrapper { rng };
        match group {
            #[cfg(feature = "secp256r1")]
            NamedGroup::Secp256r1 => {
                self.secp256r1 = Some(p256::ecdh::EphemeralSecret::random(&mut rng));
                Ok(())
            }
            _ => Err(DtlsError::UnsupportedNamedGroup),
        }
    }

    /// Does not encode the length of the encoded entries!
    pub fn encode_available_key_share_entries(
        &self,
        buf: &mut ParseBuffer<'_>,
    ) -> Result<(), DtlsError> {
        #[cfg(feature = "secp256r1")]
        if let Some(secp256r1) = &self.secp256r1 {
            use p256::elliptic_curve::sec1::ToEncodedPoint as _;
            let p = secp256r1.public_key();
            let mut r = Parser::new(buf)?
                .write_u16(NamedGroup::Secp256r1 as u16)
                .write_u16(1 + 32 * 2)
                .access_static_slice();
            let ep = p.as_affine().to_encoded_point(false);
            let s: &mut [u8; 1 + 32 * 2] = r.slice_mut();
            s.copy_from_slice(ep.as_bytes());
            r.done().end();
        }
        Ok(())
    }

    pub fn calculate_ecdhe_key(
        &self,
        selected_group: NamedGroup,
        buf: &[u8],
    ) -> Result<EcdheSharedKey, DtlsError> {
        match selected_group {
            #[cfg(feature = "secp256r1")]
            NamedGroup::Secp256r1 => {
                print_bytes!("Public key", buf);
                let p = p256::PublicKey::from_sec1_bytes(buf)
                    .map_err(|_| DtlsError::Alert(AlertDescription::IllegalParameter))?;
                let sc = self.secp256r1.as_ref().unwrap().diffie_hellman(&p);
                Ok(EcdheSharedKey::Secp256r1(sc))
            }
            _ => unreachable!(),
        }
    }

    pub fn key_exchange_initialized(&self, group: NamedGroup) -> bool {
        match group {
            #[cfg(feature = "secp256r1")]
            NamedGroup::Secp256r1 => self.secp256r1.is_some(),
            _ => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        let mut r = true;
        #[cfg(feature = "secp256r1")]
        {
            r &= self.secp256r1.is_none()
        }
        r
    }

    pub fn discard_unused_key_shares(&mut self, used_group: NamedGroup) {
        #[cfg(feature = "secp256r1")]
        if used_group != NamedGroup::Secp256r1 {
            self.secp256r1 = None;
        }
    }
}

#[cfg(feature = "_dhe")]
pub fn gather_available_key_share_entries(
    buf: &mut ParseBuffer<'_>,
    ng: &mut NamedGroupSelectInfo,
) -> Result<(), DtlsError> {
    let mut key_share_len = Parser::read_single_u16(buf)?;
    buf.expect_length(key_share_len as usize)?;
    while key_share_len > 0 {
        let (group, r) = Parser::new(buf)?.read_u16();
        let Some(group) = NamedGroup::from_num(group) else {
            return Err(DtlsError::Alert(AlertDescription::IllegalParameter));
        };
        match group {
            #[cfg(feature = "secp256r1")]
            NamedGroup::Secp256r1 => {
                ng.v |= NamedGroupSelectInfo::SECP256R1 << 16;
            }
            _ => {}
        }
        let (k_e_len, r) = r.read_u16();
        r.end();
        buf.add_offset(k_e_len as usize);
        key_share_len -= 4 + k_e_len;
    }
    Ok(())
}

/// Expects the entire remaining
/// buffer consists of key_shares
/// and searches it for the selected group.
///
/// This just returns when the group is found
/// and leaves the offset be.
#[cfg(feature = "_dhe")]
pub fn parse_key_share(
    selected_group: NamedGroup,
    buf: &mut ParseBuffer<'_>,
) -> Result<Range<usize>, DtlsError> {
    let end = buf.capacity();
    while buf.offset() < end {
        let (group, r) = Parser::new(buf)?.read_u16();
        let Some(group) = NamedGroup::from_num(group) else {
            return Err(illegal_state!());
        };
        let (k_e_len, r) = r.read_u16();
        r.end();
        if group == selected_group {
            let r = parse_key_exchange(group, k_e_len, buf)?;
            buf.set_offset(end);
            return Ok(r);
        } else {
            buf.add_offset(k_e_len as usize);
        }
    }

    Err(DtlsError::Alert(AlertDescription::HandshakeFailure))
}

/// Parses the content of the key_exchange field
/// exluding the length field.
/// This also validates the provided k_e_len.
#[cfg(feature = "_dhe")]
pub fn parse_key_exchange(
    group: NamedGroup,
    k_e_len: u16,
    buf: &mut ParseBuffer<'_>,
) -> Result<Range<usize>, DtlsError> {
    match group {
        #[cfg(feature = "secp256r1")]
        NamedGroup::Secp256r1 => {
            parse_expect_with(k_e_len == 1 + 64, || parse_err!())?;
            let k_e = buf.offset()..buf.offset() + 1 + 64;
            Parser::<C<{ 64 + 1 }, ()>>::new(buf)?.add_offset().end();
            Ok(k_e)
        }
        _ => Err(DtlsError::Alert(AlertDescription::DecodeError)),
    }
}

pub fn encode_cookie(
    buffer: &mut ParseBuffer<'_>,
    key: &[u8],
    hash: &PskTranscriptHash,
    peer_addr: &SocketAddr,
) -> Result<(), DtlsError> {
    let hash = hash.finalize(&[]);
    #[allow(unused)]
    let start = buffer.offset();
    buffer.write_slice_checked(hash.as_ref())?;
    let mut hmac =
        <SimpleHmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| DtlsError::CryptoError)?;
    Mac::update(&mut hmac, hash.as_ref());
    match &peer_addr.ip() {
        IpAddr::V4(i) => Mac::update(&mut hmac, &i.to_bits().to_be_bytes()),
        IpAddr::V6(i) => Mac::update(&mut hmac, &i.to_bits().to_be_bytes()),
    }
    let s = <Sha256 as OutputSizeUser>::output_size();
    buffer.add_offset(s);
    let slice = buffer.access_slice_mut_checked(buffer.offset() - s..buffer.offset())?;
    hmac.finalize_into(slice.into());
    print_bytes!("Cookie", &buffer.as_ref()[start..]);
    Ok(())
}

pub fn verify_cookie(cookie: &[u8], key: &[u8], peer_addr: &SocketAddr) -> Result<bool, DtlsError> {
    print_bytes!("Cookie", cookie);
    let mut hmac =
        <SimpleHmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| DtlsError::CryptoError)?;
    let tag_len = <SimpleHmac<Sha256> as OutputSizeUser>::output_size();
    Mac::update(&mut hmac, &cookie[..cookie.len() - tag_len]);
    match peer_addr.ip() {
        IpAddr::V4(i) => Mac::update(&mut hmac, &i.to_bits().to_be_bytes()),
        IpAddr::V6(i) => Mac::update(&mut hmac, &i.to_bits().to_be_bytes()),
    }
    Ok(hmac.verify_slice(&cookie[cookie.len() - tag_len..]).is_ok())
}

#[derive(Clone)]
pub struct Psk<'a> {
    pub(crate) identity: &'a [u8],
    pub(crate) psk: &'a [u8],
    pub(crate) hash_function: HashFunction,
    pub(crate) key_type: PskType,
}

impl<'a> Psk<'a> {
    pub fn new(identity: &'a [u8], psk: &'a [u8], hash_function: HashFunction) -> Self {
        Self {
            identity,
            psk,
            hash_function,
            key_type: PskType::External,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HashFunction {
    #[cfg(feature = "aes128gcm_sha256")]
    Sha256,
}

impl HashFunction {
    pub fn output_size(self) -> usize {
        match self {
            #[cfg(feature = "aes128gcm_sha256")]
            HashFunction::Sha256 => <Sha256 as OutputSizeUser>::output_size(),
        }
    }
}

#[derive(Clone)]
pub(crate) enum PskType {
    #[allow(unused)]
    Resumption {
        ticket_creation_timestamp_ms: Milliseconds,
    },
    External,
}

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    #[cfg(feature = "aes128gcm_sha256")]
    Aes128GcmSha256 = 0x1301,
}

impl CipherSuite {
    pub const fn all() -> &'static [CipherSuite] {
        &[
            #[cfg(feature = "aes128gcm_sha256")]
            CipherSuite::Aes128GcmSha256,
        ]
    }

    pub fn hash_function(&self) -> HashFunction {
        match self {
            #[cfg(feature = "aes128gcm_sha256")]
            CipherSuite::Aes128GcmSha256 => HashFunction::Sha256,
        }
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = DtlsError;
    fn try_from(value: u16) -> Result<Self, DtlsError> {
        match value {
            #[cfg(feature = "aes128gcm_sha256")]
            0x1301 => Ok(Self::Aes128GcmSha256),
            _ => Err(parse_err!()),
        }
    }
}

pub enum TrafficSecret {
    None,
    #[cfg(feature = "aes128gcm_sha256")]
    Aes128GcmSha256 {
        traffic_secret: GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
        key: GenericArray<u8, <Aes128Gcm as KeySizeUser>::KeySize>,
        iv: GenericArray<u8, <Aes128Gcm as AeadCore>::NonceSize>,
        sn: GenericArray<u8, <Aes128Gcm as KeySizeUser>::KeySize>,
    },
}

pub fn mac_length(secret: &TrafficSecret) -> usize {
    match secret {
        #[cfg(feature = "aes128gcm_sha256")]
        TrafficSecret::Aes128GcmSha256 {
            traffic_secret: _,
            key: _,
            iv: _,
            sn: _,
        } => <Aes128Gcm as AeadCore>::TagSize::to_usize(),
        _ => unreachable!("Invalid cipher suite"), // Rust requires this branch for references
    }
}

pub fn aead_encrypt_in_place(
    secret: &TrafficSecret,
    record_seq_num: &u64,
    additional_data: &[u8],
    plaintext: &mut ParseBuffer<'_>,
) -> Result<(), DtlsError> {
    match secret {
        #[cfg(feature = "aes128gcm_sha256")]
        TrafficSecret::Aes128GcmSha256 {
            traffic_secret: _,
            key,
            iv,
            sn: _,
        } => {
            encrypt_in_place::<Aes128Gcm>(key, iv, record_seq_num, additional_data, plaintext)?;
        }
        TrafficSecret::None => return Err(illegal_state!()),
    }
    Ok(())
}

fn generate_nonce(record_seq_num: &u64, iv: &[u8], nonce: &mut [u8]) {
    let nonce_len = nonce.len();
    nonce[nonce_len - 8..].copy_from_slice(&record_seq_num.to_be_bytes());
    nonce
        .iter_mut()
        .zip(iv.iter())
        .for_each(|(nonce_byte, iv_byte)| *nonce_byte ^= iv_byte);
}

pub fn aead_decrypt_in_place(
    secret: &TrafficSecret,
    record_seq_num: &u64,
    additional_data: &[u8],
    ciphertext: &mut [u8],
) -> Result<(), DtlsError> {
    match secret {
        #[cfg(feature = "aes128gcm_sha256")]
        TrafficSecret::Aes128GcmSha256 {
            traffic_secret: _,
            key,
            iv,
            sn: _,
        } => {
            decrypt_in_place::<Aes128Gcm>(key, iv, record_seq_num, additional_data, ciphertext)?;
        }
        TrafficSecret::None => return Err(illegal_state!()),
    }
    Ok(())
}

pub fn xor_sequence_number(
    secret: &TrafficSecret,
    record_seq_num: &mut [u8],
    cipher_text: &[u8; 16],
) -> Result<(), DtlsError> {
    debug_assert!(record_seq_num.len() == 1 || record_seq_num.len() == 2);
    trace!("xor_seq_num: seq_num: {record_seq_num:x?}");
    print_bytes!("cipher_text", cipher_text);
    match secret {
        #[cfg(feature = "aes128gcm_sha256")]
        TrafficSecret::Aes128GcmSha256 {
            traffic_secret: _,
            key: _,
            iv: _,
            sn,
        } => {
            print_bytes!("sn", sn);
            xor_seq_num_aes128(sn, record_seq_num, cipher_text);
        }
        TrafficSecret::None => return Err(illegal_state!()),
    };
    Ok(())
}

fn xor_seq_num_aes128(
    sn: &GenericArray<u8, <Aes128 as KeySizeUser>::KeySize>,
    record_seq_num: &mut [u8],
    cipher_text: &[u8; 16],
) {
    let mut mask = GenericArray::clone_from_slice(cipher_text);
    Aes128::new(sn).encrypt_block(&mut mask);
    let seq_num_len = record_seq_num.len();
    record_seq_num
        .iter_mut()
        .zip(&mask[0..seq_num_len])
        .for_each(|(record_bytem, mask_byte)| *record_bytem ^= mask_byte);
}

pub enum CipherDependentCryptoState {
    #[cfg(feature = "aes128gcm_sha256")]
    Aes128GcmSha256 {
        transcript_hash: Sha256,
        hkdf_state: Hkdf<Sha256, SimpleHmac<Sha256>>,
    },
}

impl CipherDependentCryptoState {
    pub fn new(
        cipher_suite: CipherSuite,
        psk: Option<&[u8]>,
        ecdhe_key: Option<&[u8]>,
        hashes: CryptoInformation,
    ) -> Result<CipherDependentCryptoState, DtlsError> {
        use crate::illegal_state;
        match cipher_suite {
            #[cfg(feature = "aes128gcm_sha256")]
            CipherSuite::Aes128GcmSha256 => {
                let empty_psk =
                    GenericArray::<u8, <Sha256 as OutputSizeUser>::OutputSize>::default();
                let psk = if let Some(psk) = psk {
                    psk
                } else {
                    empty_psk.as_slice()
                };

                let mut hkdf = Hkdf::<Sha256, SimpleHmac<Sha256>>::new(None, psk);
                if let Some(ecdhe) = ecdhe_key {
                    print_bytes!("Shared Secret", ecdhe);
                }
                extract_new_hkdf_state(&mut hkdf, ecdhe_key)?;
                let hash = match hashes {
                    CryptoInformation::PreServerHello(hashes) => hashes.sha256,
                    CryptoInformation::PostHelloRetry(PskTranscriptHash::Sha256(h)) => h,
                    _ => Err(illegal_state!())?,
                };
                Ok(CipherDependentCryptoState::Aes128GcmSha256 {
                    transcript_hash: hash,
                    hkdf_state: hkdf,
                })
            }
        }
    }

    pub fn update_transcript_hash(&mut self, data: &[u8]) {
        print_bytes!("TranscriptHash Update", data);
        match self {
            #[cfg(feature = "aes128gcm_sha256")]
            CipherDependentCryptoState::Aes128GcmSha256 {
                transcript_hash,
                hkdf_state: _,
            } => {
                Digest::update(transcript_hash, data);
            }
        }
    }

    pub fn extract_new_hkdf_state(&mut self, ikm: Option<&[u8]>) -> Result<(), DtlsError> {
        match self {
            #[cfg(feature = "aes128gcm_sha256")]
            CipherDependentCryptoState::Aes128GcmSha256 {
                transcript_hash: _,
                hkdf_state,
            } => {
                extract_new_hkdf_state::<Sha256>(hkdf_state, ikm)?;
            }
        }
        Ok(())
    }

    pub fn derive_traffic_secret(&self, label: &str) -> Result<TrafficSecret, DtlsError> {
        match &self {
            #[cfg(feature = "aes128gcm_sha256")]
            CipherDependentCryptoState::Aes128GcmSha256 {
                transcript_hash,
                hkdf_state,
            } => {
                let (traffic_secret, key, iv, sn) =
                    derive_traffic_secret::<Aes128Gcm, Sha256>(hkdf_state, transcript_hash, label)?;
                Ok(TrafficSecret::Aes128GcmSha256 {
                    traffic_secret,
                    key,
                    iv,
                    sn,
                })
            }
        }
    }

    pub fn encode_verify_data(
        &mut self,
        buffer: &mut ParseBuffer<'_>,
        secret: &TrafficSecret,
    ) -> Result<(), DtlsError> {
        match (self, secret) {
            #[cfg(feature = "aes128gcm_sha256")]
            (
                CipherDependentCryptoState::Aes128GcmSha256 {
                    transcript_hash,
                    hkdf_state: _,
                },
                TrafficSecret::Aes128GcmSha256 {
                    traffic_secret,
                    key: _,
                    iv: _,
                    sn: _,
                },
            ) => encode_verify_data::<Sha256>(
                buffer,
                traffic_secret,
                &transcript_hash.clone().finalize(),
            ),
            (_, TrafficSecret::None) => Err(illegal_state!()),
        }
    }

    pub fn check_verify_data(
        &mut self,
        buffer: &mut ParseBuffer<'_>,
        secret: &TrafficSecret,
    ) -> Result<bool, DtlsError> {
        match (self, secret) {
            #[cfg(feature = "aes128gcm_sha256")]
            (
                CipherDependentCryptoState::Aes128GcmSha256 {
                    transcript_hash,
                    hkdf_state: _,
                },
                TrafficSecret::Aes128GcmSha256 {
                    traffic_secret,
                    key: _,
                    iv: _,
                    sn: _,
                },
            ) => check_verify_data::<Sha256>(
                buffer,
                traffic_secret,
                &transcript_hash.clone().finalize(),
            ),
            (_, TrafficSecret::None) => Err(illegal_state!()),
        }
    }
}

trait HkdfExt {
    fn hkdf_expand(&self, info_components: &[&[u8]], okm: &mut [u8]) -> Result<(), DtlsError>;
}

impl<H> HkdfExt for Hkdf<H, SimpleHmac<H>>
where
    H: Digest + Clone + OutputSizeUser + BlockSizeUser,
{
    fn hkdf_expand(&self, info_components: &[&[u8]], okm: &mut [u8]) -> Result<(), DtlsError> {
        self.expand_multi_info(info_components, okm)
            .map_err(|_| DtlsError::CryptoError)
    }
}

fn hkdf_expand_label(
    hkdf: &dyn HkdfExt,
    label: &str,
    context: &[u8],
    okm: &mut [u8],
) -> Result<(), DtlsError> {
    let okm_len = okm.len() as u16;
    trace!("Hkdf_expand_label: {:?}", label);
    let label_len = 6 + label.len() as u8;
    hkdf.hkdf_expand(
        &[
            &okm_len.to_be_bytes(),
            &label_len.to_be_bytes(),
            b"dtls13",
            label.as_bytes(),
            &(context.len() as u8).to_be_bytes(),
            context,
        ],
        okm,
    )
    .map_err(|_| DtlsError::CryptoError)?;
    print_bytes!("Context", context);
    print_bytes!("OKM", okm);
    Ok(())
}

fn calculate_hello_retry_transcript_hash<H: Digest + Update>(client_hello_1_hash: &[u8]) -> H {
    let mut hash = <H as Digest>::new();
    digest_client_hello_1_hash(&mut hash, client_hello_1_hash);
    hash
}

fn digest_client_hello_1_hash(hash: &mut dyn Update, client_hello_1_hash: &[u8]) {
    print_bytes!("Client Hello 1 Hash", client_hello_1_hash);
    hash.update(&[
        HandshakeMsgType::MessageHash as u8,
        0,
        0,
        client_hello_1_hash.len() as u8,
    ]);
    hash.update(client_hello_1_hash);
}

fn encode_verify_data<H: Digest + BlockSizeUser + OutputSizeUser + Clone>(
    buffer: &mut ParseBuffer<'_>,
    traffic_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<(), DtlsError> {
    let verify_data = calculate_verify_data::<H>(traffic_secret, transcript_hash)?;
    buffer.write_slice_checked(&verify_data)
}

fn check_verify_data<H: Digest + BlockSizeUser + OutputSizeUser + Clone>(
    buffer: &mut ParseBuffer<'_>,
    traffic_secret: &[u8],
    transcript_hash: &[u8],
) -> Result<bool, DtlsError> {
    let verify_data = calculate_verify_data::<H>(traffic_secret, transcript_hash)?;
    let hash_len = transcript_hash.len();
    Ok(buffer.read_slice_checked(hash_len)? == verify_data.as_slice())
}

fn extract_new_hkdf_state<H: Digest + BlockSizeUser + OutputSizeUser + Clone>(
    hkdf_state: &mut Hkdf<H, SimpleHmac<H>>,
    ikm: Option<&[u8]>,
) -> Result<(), DtlsError> {
    let mut derived = GenericArray::<u8, <H as OutputSizeUser>::OutputSize>::default();
    hkdf_expand_label(hkdf_state, "derived", &empty_hash::<H>(), &mut derived)?;
    let hkdf = if let Some(ikm) = ikm {
        Hkdf::<H, SimpleHmac<H>>::new(Some(derived.as_slice()), ikm)
    } else {
        let ikm = GenericArray::<u8, <H as OutputSizeUser>::OutputSize>::default();
        Hkdf::<H, SimpleHmac<H>>::new(Some(derived.as_slice()), &ikm)
    };
    *hkdf_state = hkdf;
    Ok(())
}

pub fn validate_binder(
    received_binder: &[u8],
    psk: &Psk,
    transcript_hash: &[u8],
) -> Result<bool, DtlsError> {
    trace!("Validating binder entry");
    print_bytes!("received_binder", received_binder);
    print_bytes!("transcript_hash", transcript_hash);
    let valid = match psk.hash_function {
        #[cfg(feature = "aes128gcm_sha256")]
        HashFunction::Sha256 => {
            received_binder == calculate_binder_value::<Sha256>(psk, transcript_hash)?.as_slice()
        }
    };
    Ok(valid)
}

pub fn encode_binder_entry(
    buffer: &mut ParseBuffer<'_>,
    psk: &Psk,
    transcript_hash: &[u8],
) -> Result<(), DtlsError> {
    trace!("Encode binder entry");
    print_bytes!("transcript_hash", transcript_hash);
    let binder: &[u8] = match psk.hash_function {
        #[cfg(feature = "aes128gcm_sha256")]
        HashFunction::Sha256 => &calculate_binder_value::<Sha256>(psk, transcript_hash)?,
    };
    Parser::new_mut_slice(buffer, binder)?
        .write_slice_with_u8_len()
        .end();
    Ok(())
}

fn calculate_binder_value<H: Clone + OutputSizeUser + FixedOutput + Digest + BlockSizeUser>(
    psk: &Psk,
    transcript_hash: &[u8],
) -> Result<GenericArray<u8, <H as OutputSizeUser>::OutputSize>, DtlsError> {
    let hkdf = Hkdf::<H, SimpleHmac<H>>::new(None, psk.psk);
    let label = match psk.key_type {
        PskType::Resumption {
            ticket_creation_timestamp_ms: _,
        } => "res binder",
        PskType::External => "ext binder",
    };
    let mut binder_key = GenericArray::<u8, <H as OutputSizeUser>::OutputSize>::default();
    hkdf_expand_label(&hkdf, label, &empty_hash::<H>(), &mut binder_key)?;
    calculate_verify_data::<H>(&binder_key, transcript_hash)
}

fn empty_hash<D: Digest + OutputSizeUser>() -> GenericArray<u8, <D as OutputSizeUser>::OutputSize> {
    let mut h = <D as Digest>::new();
    Digest::update(&mut h, []);
    h.finalize()
}

pub fn calculate_verify_data<H: Digest + BlockSizeUser + OutputSizeUser + Clone>(
    base_key: &[u8],
    data: &[u8],
) -> Result<GenericArray<u8, H::OutputSize>, DtlsError> {
    let hkdf = Hkdf::<H, SimpleHmac<H>>::from_prk(base_key).map_err(|_| DtlsError::CryptoError)?;
    print_bytes!("PRK", base_key);
    let mut finished_key = GenericArray::<u8, <H as OutputSizeUser>::OutputSize>::default();
    hkdf_expand_label(&hkdf, "finished", &[], &mut finished_key)?;
    let mut hmac = <SimpleHmac<H> as KeyInit>::new_from_slice(&finished_key)
        .map_err(|_| DtlsError::CryptoError)?;
    Mac::update(&mut hmac, data);
    Ok(hmac.finalize_fixed())
}

fn encrypt_in_place<A: KeyInit + AeadInPlace>(
    key: &GenericArray<u8, A::KeySize>,
    iv: &[u8],
    record_seq_num: &u64,
    additional_data: &[u8],
    plaintext: &mut ParseBuffer<'_>,
) -> Result<(), DtlsError> {
    let mut nonce = GenericArray::default();
    generate_nonce(record_seq_num, iv, nonce.as_mut_slice());
    A::new(key)
        .encrypt_in_place(&nonce, additional_data, plaintext)
        .map_err(|_| DtlsError::CryptoError)?;
    Ok(())
}

fn decrypt_in_place<A: KeyInit + AeadInPlace>(
    key: &GenericArray<u8, A::KeySize>,
    iv: &[u8],
    record_seq_num: &u64,
    additional_data: &[u8],
    ciphertext: &mut [u8],
) -> Result<(), DtlsError> {
    let mut nonce = GenericArray::default();
    generate_nonce(record_seq_num, iv, nonce.as_mut_slice());
    let len = ciphertext.len();
    let mut ciphertext = ParseBuffer::init_with_offset(ciphertext, len);
    A::new(key)
        .decrypt_in_place(&nonce, additional_data, &mut ciphertext)
        .map_err(|_| DtlsError::CryptoError)?;
    Ok(())
}

fn derive_traffic_secret<
    A: KeySizeUser + AeadCore,
    H: Digest + Clone + OutputSizeUser + BlockSizeUser,
>(
    hkdf: &Hkdf<H, SimpleHmac<H>>,
    hash: &H,
    label: &str,
) -> Result<
    (
        GenericArray<u8, <H as OutputSizeUser>::OutputSize>,
        GenericArray<u8, <A as KeySizeUser>::KeySize>,
        GenericArray<u8, <A as AeadCore>::NonceSize>,
        GenericArray<u8, <A as KeySizeUser>::KeySize>,
    ),
    DtlsError,
> {
    let hash = <H as Digest>::finalize(hash.clone());
    let mut traffic_secret = GenericArray::<u8, <H as OutputSizeUser>::OutputSize>::default();
    hkdf_expand_label(hkdf, label, &hash, &mut traffic_secret)?;

    let hkdf =
        Hkdf::<H, SimpleHmac<H>>::from_prk(&traffic_secret).map_err(|_| DtlsError::CryptoError)?;
    let mut key = GenericArray::default();
    hkdf_expand_label(&hkdf, "key", &[], &mut key)?;
    let mut iv = GenericArray::default();
    hkdf_expand_label(&hkdf, "iv", &[], &mut iv)?;
    let mut sn = GenericArray::default();
    hkdf_expand_label(&hkdf, "sn", &[], &mut sn)?;
    Ok((traffic_secret, key, iv, sn))
}
