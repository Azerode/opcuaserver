//! Security policies (Part 7 profiles, Part 6 §6.7) on top of aws-lc-rs.
//!
//! Supported policies are the ones the OPC Foundation currently recommends
//! for RSA: Basic256Sha256, Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss.
//! Basic128Rsa15 and Basic256 (SHA-1) are deprecated by the specification and
//! intentionally not offered.

use aws_lc_rs::cipher::{
    DecryptingKey, DecryptionContext, EncryptingKey, EncryptionContext, UnboundCipherKey, AES_128, AES_256,
};
use aws_lc_rs::iv::FixedLength;
use aws_lc_rs::rsa::{
    OaepAlgorithm, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey, PublicEncryptingKey,
    OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256,
};
use aws_lc_rs::signature::{self, KeyPair as _, RsaKeyPair, UnparsedPublicKey};
use aws_lc_rs::{digest, hmac};

pub const URI_NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";
pub const URI_BASIC256SHA256: &str = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256";
pub const URI_AES128_SHA256_RSAOAEP: &str = "http://opcfoundation.org/UA/SecurityPolicy#Aes128_Sha256_RsaOaep";
pub const URI_AES256_SHA256_RSAPSS: &str = "http://opcfoundation.org/UA/SecurityPolicy#Aes256_Sha256_RsaPss";

pub const ALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const ALG_RSA_PSS_SHA256: &str = "http://opcfoundation.org/UA/security/rsa-pss-sha2-256";
pub const ALG_RSA_OAEP: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep";
pub const ALG_RSA_OAEP_SHA256: &str = "http://opcfoundation.org/UA/security/rsa-oaep-sha2-256";

pub const NONCE_LEN: usize = 32;
pub const SYM_SIGNATURE_LEN: usize = 32;
pub const AES_BLOCK: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    None,
    Basic256Sha256,
    Aes128Sha256RsaOaep,
    Aes256Sha256RsaPss,
}

/// MessageSecurityMode (Part 4 §7.20).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    None = 1,
    Sign = 2,
    SignAndEncrypt = 3,
}

impl Mode {
    pub fn from_u32(v: u32) -> Option<Mode> {
        match v {
            1 => Some(Mode::None),
            2 => Some(Mode::Sign),
            3 => Some(Mode::SignAndEncrypt),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError;

impl From<aws_lc_rs::error::Unspecified> for CryptoError {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        CryptoError
    }
}

pub type CResult<T> = Result<T, CryptoError>;

impl Policy {
    pub const SECURE: [Policy; 3] = [Policy::Basic256Sha256, Policy::Aes128Sha256RsaOaep, Policy::Aes256Sha256RsaPss];

    pub fn from_uri(uri: &str) -> Option<Policy> {
        Some(match uri {
            URI_NONE => Policy::None,
            URI_BASIC256SHA256 => Policy::Basic256Sha256,
            URI_AES128_SHA256_RSAOAEP => Policy::Aes128Sha256RsaOaep,
            URI_AES256_SHA256_RSAPSS => Policy::Aes256Sha256RsaPss,
            _ => return None,
        })
    }

    pub fn uri(self) -> &'static str {
        match self {
            Policy::None => URI_NONE,
            Policy::Basic256Sha256 => URI_BASIC256SHA256,
            Policy::Aes128Sha256RsaOaep => URI_AES128_SHA256_RSAOAEP,
            Policy::Aes256Sha256RsaPss => URI_AES256_SHA256_RSAPSS,
        }
    }

    /// Relative strength advertised in EndpointDescription.securityLevel.
    pub fn security_level(self, mode: Mode) -> u8 {
        let base = match self {
            Policy::None => 0,
            Policy::Basic256Sha256 => 10,
            Policy::Aes128Sha256RsaOaep => 20,
            Policy::Aes256Sha256RsaPss => 30,
        };
        match mode {
            Mode::None => 0,
            Mode::Sign => base,
            Mode::SignAndEncrypt => base + 1,
        }
    }

    pub fn asym_signature_uri(self) -> &'static str {
        match self {
            Policy::Aes256Sha256RsaPss => ALG_RSA_PSS_SHA256,
            _ => ALG_RSA_SHA256,
        }
    }

    pub fn asym_encryption_uri(self) -> &'static str {
        match self {
            Policy::Aes256Sha256RsaPss => ALG_RSA_OAEP_SHA256,
            _ => ALG_RSA_OAEP,
        }
    }

    fn oaep(self) -> &'static OaepAlgorithm {
        match self {
            Policy::Aes256Sha256RsaPss => &OAEP_SHA256_MGF1SHA256,
            _ => &OAEP_SHA1_MGF1SHA1,
        }
    }

    /// Bytes lost to OAEP padding per RSA block.
    pub fn oaep_overhead(self) -> usize {
        match self {
            Policy::Aes256Sha256RsaPss => 66,
            _ => 42,
        }
    }

    pub fn sym_encryption_key_len(self) -> usize {
        match self {
            Policy::Aes128Sha256RsaOaep => 16,
            _ => 32,
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Policy::None => 0,
            _ => NONCE_LEN,
        }
    }

    pub fn min_key_bits(self) -> usize {
        2048
    }

    pub fn max_key_bits(self) -> usize {
        4096
    }

    /// Signs `data` with the private key (RSA PKCS#1 v1.5 or PSS, SHA-256).
    pub fn asym_sign(self, key: &RsaKeyPair, data: &[u8]) -> CResult<Vec<u8>> {
        let mut sig = vec![0u8; key.public_modulus_len()];
        let alg: &'static dyn signature::RsaEncoding = match self {
            Policy::Aes256Sha256RsaPss => &signature::RSA_PSS_SHA256,
            _ => &signature::RSA_PKCS1_SHA256,
        };
        key.sign(alg, &aws_lc_rs::rand::SystemRandom::new(), data, &mut sig)?;
        Ok(sig)
    }

    /// Verifies a signature made with the public key `rsa_public_key`
    /// (PKCS#1 RSAPublicKey DER, as found in a certificate).
    pub fn asym_verify(self, rsa_public_key: &[u8], data: &[u8], sig: &[u8]) -> CResult<()> {
        let alg: &'static signature::RsaParameters = match self {
            Policy::Aes256Sha256RsaPss => &signature::RSA_PSS_2048_8192_SHA256,
            _ => &signature::RSA_PKCS1_2048_8192_SHA256,
        };
        UnparsedPublicKey::new(alg, rsa_public_key).verify(data, sig)?;
        Ok(())
    }

    /// RSA-OAEP encryption of `plain` in as many blocks as needed.
    pub fn asym_encrypt(self, spki: &[u8], plain: &[u8], out: &mut Vec<u8>) -> CResult<()> {
        let key = OaepPublicEncryptingKey::new(PublicEncryptingKey::from_der(spki).map_err(|_| CryptoError)?)?;
        let block_in = key.key_size_bytes() - self.oaep_overhead();
        let block_out = key.key_size_bytes();
        for chunk in plain.chunks(block_in) {
            let at = out.len();
            out.resize(at + block_out, 0);
            let written = key.encrypt(self.oaep(), chunk, &mut out[at..], None)?.len();
            if written != block_out {
                return Err(CryptoError);
            }
        }
        Ok(())
    }

    /// RSA-OAEP decryption of whole blocks.
    pub fn asym_decrypt(self, key: &PrivateDecryptingKey, cipher: &[u8], out: &mut Vec<u8>) -> CResult<()> {
        let key = OaepPrivateDecryptingKey::new(key.clone())?;
        let block = key.key_size_bytes();
        if cipher.is_empty() || cipher.len() % block != 0 {
            return Err(CryptoError);
        }
        let mut buf = vec![0u8; block];
        for chunk in cipher.chunks(block) {
            let plain = key.decrypt(self.oaep(), chunk, &mut buf, None)?;
            out.extend_from_slice(plain);
        }
        Ok(())
    }
}

/// SHA-1 thumbprint of a DER certificate (Part 6 §6.7.2.3).
pub fn thumbprint(cert_der: &[u8]) -> [u8; 20] {
    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, cert_der).as_ref().try_into().unwrap()
}

/// P_SHA256 (RFC 5246 §5).
pub fn p_sha256(secret: &[u8], seed: &[u8], len: usize) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut out = Vec::with_capacity(len + 32);
    let mut a = hmac::sign(&key, seed);
    while out.len() < len {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(a.as_ref());
        ctx.update(seed);
        out.extend_from_slice(ctx.sign().as_ref());
        a = hmac::sign(&key, a.as_ref());
    }
    out.truncate(len);
    out
}

/// One direction's symmetric keys, with AES key schedules prepared once.
pub struct SymKeys {
    signing: hmac::Key,
    encrypt: EncryptingKey,
    decrypt: DecryptingKey,
    iv: [u8; AES_BLOCK],
}

impl SymKeys {
    /// Derives keys from (secret, seed) as in Part 6 §6.7.5.
    pub fn derive(policy: Policy, secret: &[u8], seed: &[u8]) -> CResult<SymKeys> {
        let ek = policy.sym_encryption_key_len();
        let material = p_sha256(secret, seed, 32 + ek + AES_BLOCK);
        let alg = if ek == 16 { &AES_128 } else { &AES_256 };
        let enc_key = &material[32..32 + ek];
        Ok(SymKeys {
            signing: hmac::Key::new(hmac::HMAC_SHA256, &material[..32]),
            encrypt: EncryptingKey::cbc(UnboundCipherKey::new(alg, enc_key)?)?,
            decrypt: DecryptingKey::cbc(UnboundCipherKey::new(alg, enc_key)?)?,
            iv: material[32 + ek..].try_into().unwrap(),
        })
    }

    #[inline]
    pub fn sign(&self, data: &[u8]) -> [u8; SYM_SIGNATURE_LEN] {
        hmac::sign(&self.signing, data).as_ref().try_into().unwrap()
    }

    /// Constant-time HMAC check.
    #[inline]
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        hmac::verify(&self.signing, data, sig).is_ok()
    }

    /// HMAC over the concatenation of `parts`.
    #[inline]
    pub fn sign_parts(&self, parts: &[&[u8]]) -> [u8; SYM_SIGNATURE_LEN] {
        let mut ctx = hmac::Context::with_key(&self.signing);
        for p in parts {
            ctx.update(p);
        }
        ctx.sign().as_ref().try_into().unwrap()
    }

    /// Constant-time check of an HMAC over the concatenation of `parts`.
    #[inline]
    pub fn verify_parts(&self, parts: &[&[u8]], sig: &[u8]) -> bool {
        let expected = self.sign_parts(parts);
        sig.len() == SYM_SIGNATURE_LEN && aws_lc_rs::constant_time::verify_slices_are_equal(&expected, sig).is_ok()
    }

    /// In-place AES-CBC; `data.len()` must be a multiple of 16.
    #[inline]
    pub fn encrypt(&self, data: &mut [u8]) -> CResult<()> {
        self.encrypt.less_safe_encrypt(data, EncryptionContext::Iv128(FixedLength::from(self.iv)))?;
        Ok(())
    }

    #[inline]
    pub fn decrypt(&self, data: &mut [u8]) -> CResult<()> {
        if data.len() % AES_BLOCK != 0 {
            return Err(CryptoError);
        }
        self.decrypt.decrypt(data, DecryptionContext::Iv128(FixedLength::from(self.iv)))?;
        Ok(())
    }
}

/// Keys of both directions of a secure channel, from the server's view.
pub struct ChannelKeys {
    /// Keys the client uses to secure what it sends (we verify / decrypt).
    pub remote: SymKeys,
    /// Keys we use to secure what we send.
    pub local: SymKeys,
}

impl ChannelKeys {
    pub fn derive(policy: Policy, client_nonce: &[u8], server_nonce: &[u8]) -> CResult<ChannelKeys> {
        Ok(ChannelKeys {
            remote: SymKeys::derive(policy, server_nonce, client_nonce)?,
            local: SymKeys::derive(policy, client_nonce, server_nonce)?,
        })
    }
}

/// The RSA key of the server application instance certificate.
pub struct PrivateKey {
    pub sign: RsaKeyPair,
    pub decrypt: PrivateDecryptingKey,
}

impl PrivateKey {
    pub fn from_pkcs8(der: &[u8]) -> CResult<PrivateKey> {
        Ok(PrivateKey {
            sign: RsaKeyPair::from_pkcs8(der).map_err(|_| CryptoError)?,
            decrypt: PrivateDecryptingKey::from_pkcs8(der).map_err(|_| CryptoError)?,
        })
    }

    pub fn size_bytes(&self) -> usize {
        self.sign.public_modulus_len()
    }

    pub fn public_key_der(&self) -> &[u8] {
        self.sign.public_key().as_ref()
    }
}

/// Bytes of padding (including the PaddingSize byte(s)) so that
/// `plain_len + padding + signature_len` is a multiple of `block`.
/// Returns (padding byte value, total padding bytes, extra padding byte?).
pub fn padding(plain_len: usize, signature_len: usize, block: usize, extra: bool) -> (usize, usize) {
    let header = if extra { 2 } else { 1 };
    let rem = (plain_len + header + signature_len) % block;
    let pad = if rem == 0 { 0 } else { block - rem };
    (pad, pad + header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::KeySize;

    #[test]
    fn p_sha256_vector() {
        // Test vector from the TLS 1.2 PRF (P_SHA256 with an empty label folded into the seed).
        let secret = [0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17, 0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35];
        let mut seed = b"test label".to_vec();
        seed.extend_from_slice(&[
            0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18, 0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c,
        ]);
        let out = p_sha256(&secret, &seed, 16);
        assert_eq!(
            out,
            [0xe3, 0xf2, 0x29, 0xba, 0x72, 0x7b, 0xe1, 0x7b, 0x8d, 0x12, 0x26, 0x20, 0x55, 0x7c, 0xd4, 0x53]
        );
    }

    #[test]
    fn symmetric_roundtrip_and_direction() {
        let (c, s) = ([1u8; 32], [2u8; 32]);
        for p in Policy::SECURE {
            let server = ChannelKeys::derive(p, &c, &s).unwrap();
            // The client derives the mirror image.
            let client_local = SymKeys::derive(p, &s, &c).unwrap();
            let mut msg = [7u8; 64];
            client_local.encrypt(&mut msg).unwrap();
            assert_ne!(msg, [7u8; 64]);
            server.remote.decrypt(&mut msg).unwrap();
            assert_eq!(msg, [7u8; 64]);
            let sig = client_local.sign(b"abc");
            assert!(server.remote.verify(b"abc", &sig));
            assert!(!server.local.verify(b"abc", &sig));
        }
    }

    #[test]
    fn asymmetric_roundtrip() {
        let kp = aws_lc_rs::rsa::KeyPair::generate(KeySize::Rsa2048).unwrap();
        let pkcs8 = kp.as_der().unwrap();
        let key = PrivateKey::from_pkcs8(pkcs8.as_ref()).unwrap();
        let spki = key.decrypt.public_key().as_der().unwrap();
        for p in Policy::SECURE {
            let plain: Vec<u8> = (0..700).map(|i| i as u8).collect();
            let mut cipher = Vec::new();
            p.asym_encrypt(spki.as_ref(), &plain, &mut cipher).unwrap();
            assert_eq!(cipher.len() % 256, 0);
            let mut back = Vec::new();
            p.asym_decrypt(&key.decrypt, &cipher, &mut back).unwrap();
            assert_eq!(back, plain);

            let sig = p.asym_sign(&key.sign, b"hello").unwrap();
            p.asym_verify(key.public_key_der(), b"hello", &sig).unwrap();
            assert!(p.asym_verify(key.public_key_der(), b"hellO", &sig).is_err());
        }
    }

    #[test]
    fn padding_sizes() {
        // 100 bytes + 1 + 32 = 133 -> pad to 144
        assert_eq!(padding(100, 32, 16, false), (11, 12));
        assert_eq!(padding(111, 32, 16, false), (0, 1));
    }
}
