use core::net::{IpAddr, SocketAddr};
use core::panic;

use crate::handshake::CryptoInformation;
use crate::parsing::HandshakeType;
use crate::parsing_utility::{ParseBuffer, Parser};
use crate::DtlsError;

#[cfg(feature = "aes128gcm_sha256")]
use {aes_gcm::Aes128Gcm, sha2::digest::generic_array::typenum::Unsigned};

use aes_gcm::{
    aes::{
        cipher::{BlockEncrypt, BlockSizeUser},
        Aes128,
    },
    AeadCore, AeadInPlace, KeyInit, KeySizeUser,
};
use hkdf::hmac::Mac;
use hkdf::{hmac::SimpleHmac, Hkdf};
use log::trace;
use sha2::digest::Update;
use sha2::{
    digest::{generic_array::GenericArray, FixedOutput, OutputSizeUser},
    Digest, Sha256,
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
            CipherSuite::NullCipherSuite => todo!(),
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
            CipherSuite::NullCipherSuite => panic!(),
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

pub fn encode_cookie(
    buffer: &mut ParseBuffer<'_>,
    key: &[u8],
    hash: &PskTranscriptHash,
    peer_addr: &SocketAddr,
) -> Result<(), DtlsError> {
    let hash = hash.finalize(&[]);
    let start = buffer.offset();
    buffer.write_slice_checked(hash.as_ref())?;
    let mut hmac =
        <SimpleHmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| DtlsError::CryptoError)?;
    Mac::update(&mut hmac, hash.as_ref());
    match peer_addr.ip() {
        IpAddr::V4(i) => Mac::update(&mut hmac, &i.to_bits().to_be_bytes()),
        IpAddr::V6(i) => Mac::update(&mut hmac, &i.to_bits().to_be_bytes()),
    }
    let mac = hmac.finalize_fixed();
    buffer.write_slice_checked(&mac)?;
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

pub(crate) enum PskType {
    #[allow(unused)]
    Resumption {
        ticket_creation_timestamp_ms: u64,
    },
    External,
}

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    NullCipherSuite = 0x0,
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
            CipherSuite::NullCipherSuite => panic!(),
        }
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = DtlsError;
    fn try_from(value: u16) -> Result<Self, DtlsError> {
        match value {
            0x0 => Ok(Self::NullCipherSuite),
            #[cfg(feature = "aes128gcm_sha256")]
            0x1301 => Ok(Self::Aes128GcmSha256),
            _ => Err(DtlsError::ParseError),
        }
    }
}

pub enum TrafficSecret {
    #[cfg(feature = "aes128gcm_sha256")]
    Aes128GcmSha256 {
        traffic_secret: GenericArray<u8, <Sha256 as OutputSizeUser>::OutputSize>,
        key: GenericArray<u8, <Aes128Gcm as KeySizeUser>::KeySize>,
        iv: GenericArray<u8, <Aes128Gcm as AeadCore>::NonceSize>,
        sn: GenericArray<u8, <Aes128Gcm as KeySizeUser>::KeySize>,
    },
    None,
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
        TrafficSecret::None => panic!(),
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
        TrafficSecret::None => panic!(),
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
        TrafficSecret::None => panic!(),
    };
    Ok(())
}

fn xor_seq_num_aes128(sn: &[u8], record_seq_num: &mut [u8], cipher_text: &[u8; 16]) {
    let mut mask = GenericArray::clone_from_slice(cipher_text);
    Aes128::new_from_slice(sn).unwrap().encrypt_block(&mut mask);
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
    None,
}

impl CipherDependentCryptoState {
    pub fn new(
        cipher_suite: CipherSuite,
        psk: Option<&[u8]>,
        hashes: CryptoInformation,
    ) -> Result<CipherDependentCryptoState, DtlsError> {
        let empty_psk = GenericArray::<u8, <Sha256 as OutputSizeUser>::OutputSize>::default();
        let psk = if let Some(psk) = psk {
            psk
        } else {
            empty_psk.as_slice()
        };
        match cipher_suite {
            #[cfg(feature = "aes128gcm_sha256")]
            CipherSuite::Aes128GcmSha256 => {
                let hkdf = Hkdf::<Sha256, SimpleHmac<Sha256>>::new(None, psk);
                let hash = match hashes {
                    CryptoInformation::PreServerHello(hashes) => hashes.sha256,
                    CryptoInformation::PostHelloRetry(PskTranscriptHash::Sha256(h)) => h,
                    _ => Err(DtlsError::IllegalInnerState)?,
                };
                Ok(CipherDependentCryptoState::Aes128GcmSha256 {
                    transcript_hash: hash,
                    hkdf_state: hkdf,
                })
            }
            CipherSuite::NullCipherSuite => panic!(),
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
            CipherDependentCryptoState::None => panic!(),
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
            CipherDependentCryptoState::None => panic!(),
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
            CipherDependentCryptoState::None => panic!(),
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
            (CipherDependentCryptoState::None, _) => panic!(),
            (_, TrafficSecret::None) => panic!(),
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
            (CipherDependentCryptoState::None, _) => panic!(),
            (_, TrafficSecret::None) => panic!(),
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
        HandshakeType::MessageHash as u8,
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
        .write_len_u8()
        .write_slice()
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
    key: &[u8],
    iv: &[u8],
    record_seq_num: &u64,
    additional_data: &[u8],
    plaintext: &mut ParseBuffer<'_>,
) -> Result<(), DtlsError> {
    let mut nonce = GenericArray::default();
    generate_nonce(record_seq_num, iv, nonce.as_mut_slice());
    A::new_from_slice(key)
        .unwrap()
        .encrypt_in_place(&nonce, additional_data, plaintext)
        .map_err(|_| DtlsError::CryptoError)?;
    Ok(())
}

fn decrypt_in_place<A: KeyInit + AeadInPlace>(
    key: &[u8],
    iv: &[u8],
    record_seq_num: &u64,
    additional_data: &[u8],
    ciphertext: &mut [u8],
) -> Result<(), DtlsError> {
    let mut nonce = GenericArray::default();
    generate_nonce(record_seq_num, iv, nonce.as_mut_slice());
    let len = ciphertext.len();
    let mut ciphertext = ParseBuffer::init_with_offset(ciphertext, len);
    A::new_from_slice(key)
        .unwrap()
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
