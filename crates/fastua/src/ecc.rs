//! ECC security policies (Part 7, OPC UA 1.05.04 and later): ephemeral key
//! agreement in the OpenSecureChannel nonces, HKDF key derivation, ECDSA /
//! EdDSA asymmetric signatures and AEAD symmetric security (AES-GCM or
//! ChaCha20-Poly1305), with the SecureChannelEnhancements.
//!
//! The deprecated ECC_* policies (AES-CBC + HMAC) are not offered.

use crate::crypto::{CResult, CryptoError};
use aws_lc_rs::{aead, agreement, digest, hkdf, rand, signature};

/// Length of the AEAD IV (nonce) and of the authentication tag.
pub const IV_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Curve {
    NistP256,
    NistP384,
    Curve25519,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Cipher {
    AesGcm,
    ChaChaPoly,
}

/// One ECC AEAD security policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Suite {
    pub curve: Curve,
    pub cipher: Cipher,
}

impl Suite {
    pub const ALL: [Suite; 6] = [
        Suite { curve: Curve::NistP256, cipher: Cipher::AesGcm },
        Suite { curve: Curve::NistP256, cipher: Cipher::ChaChaPoly },
        Suite { curve: Curve::NistP384, cipher: Cipher::AesGcm },
        Suite { curve: Curve::NistP384, cipher: Cipher::ChaChaPoly },
        Suite { curve: Curve::Curve25519, cipher: Cipher::AesGcm },
        Suite { curve: Curve::Curve25519, cipher: Cipher::ChaChaPoly },
    ];

    pub fn uri(self) -> &'static str {
        use {Cipher::*, Curve::*};
        match (self.curve, self.cipher) {
            (NistP256, AesGcm) => "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_AesGcm",
            (NistP256, ChaChaPoly) => "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP256_ChaChaPoly",
            (NistP384, AesGcm) => "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384_AesGcm",
            (NistP384, ChaChaPoly) => "http://opcfoundation.org/UA/SecurityPolicy#ECC_nistP384_ChaChaPoly",
            (Curve25519, AesGcm) => "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519_AesGcm",
            (Curve25519, ChaChaPoly) => "http://opcfoundation.org/UA/SecurityPolicy#ECC_curve25519_ChaChaPoly",
        }
    }

    pub fn from_uri(uri: &str) -> Option<Suite> {
        Suite::ALL.into_iter().find(|s| s.uri() == uri)
    }

    /// Ephemeral public key on the wire (the OpenSecureChannel nonce): the
    /// uncompressed point without its 0x04 prefix, or the X25519 key.
    pub fn nonce_len(self) -> usize {
        match self.curve {
            Curve::NistP256 => 64,
            Curve::NistP384 => 96,
            Curve::Curve25519 => 32,
        }
    }

    /// Shared secret length: the width of the IKM accumulator.
    pub fn secret_len(self) -> usize {
        match self.curve {
            Curve::NistP384 => 48,
            _ => 32,
        }
    }

    /// Asymmetric signature: raw r || s for ECDSA, 64 bytes for Ed25519.
    pub fn signature_len(self) -> usize {
        match self.curve {
            Curve::NistP384 => 96,
            _ => 64,
        }
    }

    pub fn sym_key_len(self) -> usize {
        match (self.curve, self.cipher) {
            (Curve::NistP384, _) | (_, Cipher::ChaChaPoly) => 32,
            _ => 16,
        }
    }

    /// Base of EndpointDescription.securityLevel (Part 7: the 384-bit tier
    /// rates like Aes256_Sha256_RsaPss).
    pub fn security_level(self) -> u8 {
        match self.curve {
            Curve::NistP384 => 30,
            _ => 10,
        }
    }

    pub fn symmetric_uri(self) -> &'static str {
        match (self.cipher, self.sym_key_len()) {
            (Cipher::ChaChaPoly, _) => "http://opcfoundation.org/UA/security/chacha20-poly1305",
            (Cipher::AesGcm, 16) => "http://opcfoundation.org/UA/security/aes128-gcm",
            _ => "http://opcfoundation.org/UA/security/aes256-gcm",
        }
    }

    fn agreement(self) -> &'static agreement::Algorithm {
        match self.curve {
            Curve::NistP256 => &agreement::ECDH_P256,
            Curve::NistP384 => &agreement::ECDH_P384,
            Curve::Curve25519 => &agreement::X25519,
        }
    }

    fn hkdf(self) -> hkdf::Algorithm {
        match self.curve {
            Curve::NistP384 => hkdf::HKDF_SHA384,
            _ => hkdf::HKDF_SHA256,
        }
    }

    fn aead(self) -> &'static aead::Algorithm {
        match (self.cipher, self.sym_key_len()) {
            (Cipher::ChaChaPoly, _) => &aead::CHACHA20_POLY1305,
            (Cipher::AesGcm, 16) => &aead::AES_128_GCM,
            _ => &aead::AES_256_GCM,
        }
    }

    /// Hash of a certificate in channel-bound signatures (thumbprints of the
    /// SecureChannelEnhancements).
    pub fn certificate_hash(self, der: &[u8]) -> Vec<u8> {
        let alg = match self.curve {
            Curve::NistP384 => &digest::SHA384,
            _ => &digest::SHA256,
        };
        digest::digest(alg, der).as_ref().to_vec()
    }

    fn is_ec(self) -> bool {
        self.curve != Curve::Curve25519
    }

    /// Verifies an asymmetric signature with the public key of a
    /// certificate (`public_key`: the SubjectPublicKeyInfo key bits).
    pub fn verify(self, public_key: &[u8], data: &[u8], sig: &[u8]) -> CResult<()> {
        let alg: &'static dyn signature::VerificationAlgorithm = match self.curve {
            Curve::NistP256 => &signature::ECDSA_P256_SHA256_FIXED,
            Curve::NistP384 => &signature::ECDSA_P384_SHA384_FIXED,
            Curve::Curve25519 => &signature::ED25519,
        };
        signature::UnparsedPublicKey::new(alg, public_key).verify(data, sig).map_err(|_| CryptoError)
    }
}

/// The private key of an ECC application instance certificate.
pub enum SigningKey {
    Ecdsa(signature::EcdsaKeyPair),
    Ed25519(signature::Ed25519KeyPair),
}

impl SigningKey {
    pub fn from_pkcs8(curve: Curve, der: &[u8]) -> CResult<SigningKey> {
        Ok(match curve {
            Curve::NistP256 => SigningKey::Ecdsa(
                signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, der)
                    .map_err(|_| CryptoError)?,
            ),
            Curve::NistP384 => SigningKey::Ecdsa(
                signature::EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, der)
                    .map_err(|_| CryptoError)?,
            ),
            Curve::Curve25519 => SigningKey::Ed25519(
                signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der).map_err(|_| CryptoError)?,
            ),
        })
    }

    pub fn sign(&self, data: &[u8]) -> CResult<Vec<u8>> {
        match self {
            SigningKey::Ecdsa(k) => Ok(k.sign(&rand::SystemRandom::new(), data)?.as_ref().to_vec()),
            SigningKey::Ed25519(k) => Ok(k.sign(data).as_ref().to_vec()),
        }
    }
}

/// Our ephemeral key of one OpenSecureChannel exchange.
pub struct Ephemeral {
    key: agreement::EphemeralPrivateKey,
    /// The nonce we send.
    pub public: Vec<u8>,
}

impl Ephemeral {
    pub fn generate(suite: Suite) -> CResult<Ephemeral> {
        let key = agreement::EphemeralPrivateKey::generate(suite.agreement(), &rand::SystemRandom::new())?;
        let pk = key.compute_public_key()?;
        let bytes = pk.as_ref();
        let public = if suite.is_ec() { bytes[1..].to_vec() } else { bytes.to_vec() };
        Ok(Ephemeral { key, public })
    }

    /// ECDH / X25519 with the peer's nonce: the shared secret.
    pub fn agree(self, suite: Suite, peer_nonce: &[u8]) -> CResult<Vec<u8>> {
        if peer_nonce.len() != suite.nonce_len() {
            return Err(CryptoError);
        }
        let mut point = Vec::with_capacity(peer_nonce.len() + 1);
        if suite.is_ec() {
            point.push(0x04);
        }
        point.extend_from_slice(peer_nonce);
        let peer = agreement::UnparsedPublicKey::new(suite.agreement(), &point);
        agreement::agree_ephemeral(self.key, peer, CryptoError, |s| Ok(s.to_vec()))
    }
}

/// Key material of one direction (Part 6 §6.8.1): HKDF over the IKM with
/// salt = info = L (UInt16) | label | sender nonce | receiver nonce.
pub fn derive(suite: Suite, ikm: &[u8], label: &[u8], sender: &[u8], receiver: &[u8], len: usize) -> Vec<u8> {
    let mut salt = Vec::with_capacity(2 + label.len() + sender.len() + receiver.len());
    salt.extend_from_slice(&(len as u16).to_le_bytes());
    salt.extend_from_slice(label);
    salt.extend_from_slice(sender);
    salt.extend_from_slice(receiver);
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let prk = hkdf::Salt::new(suite.hkdf(), &salt).extract(ikm);
    let mut out = vec![0u8; len];
    prk.expand(&[&salt], Len(len)).and_then(|okm| okm.fill(&mut out)).expect("HKDF length within limits");
    out
}

/// AEAD keys of one direction.
pub struct AeadKeys {
    key: aead::LessSafeKey,
    iv: [u8; IV_LEN],
}

impl AeadKeys {
    fn new(suite: Suite, material: &[u8]) -> CResult<AeadKeys> {
        let k = suite.sym_key_len();
        Ok(AeadKeys {
            key: aead::LessSafeKey::new(aead::UnboundKey::new(suite.aead(), &material[..k])?),
            iv: material[k..k + IV_LEN].try_into().map_err(|_| CryptoError)?,
        })
    }

    /// Message IV: the base IV with the TokenId and the previous sequence
    /// number XORed into its first 8 bytes (little endian).
    #[inline]
    fn nonce(&self, token: u32, prev_seq: u32) -> aead::Nonce {
        let mut iv = self.iv;
        for (b, x) in iv[..4].iter_mut().zip(token.to_le_bytes()) {
            *b ^= x;
        }
        for (b, x) in iv[4..8].iter_mut().zip(prev_seq.to_le_bytes()) {
            *b ^= x;
        }
        aead::Nonce::assume_unique_for_key(iv)
    }

    /// Encrypts `data` in place and returns the tag (SignAndEncrypt), or
    /// authenticates `aad` alone with an empty `data` (Sign).
    #[inline]
    pub fn seal(&self, token: u32, prev_seq: u32, aad: &[u8], data: &mut [u8]) -> CResult<[u8; TAG_LEN]> {
        let tag = self.key.seal_in_place_separate_tag(self.nonce(token, prev_seq), aead::Aad::from(aad), data)?;
        tag.as_ref().try_into().map_err(|_| CryptoError)
    }

    /// Checks the tag and decrypts `data` in place.
    #[inline]
    pub fn open(&self, token: u32, prev_seq: u32, aad: &[u8], data: &mut [u8], tag: &[u8]) -> CResult<()> {
        self.key.open_in_place_separate_tag(self.nonce(token, prev_seq), aead::Aad::from(aad), tag, data)?;
        Ok(())
    }
}

/// Both directions of an ECC secure channel, from the server's view.
pub struct EccKeys {
    /// What the client sends (we open).
    pub remote: AeadKeys,
    /// What we send.
    pub local: AeadKeys,
}

impl EccKeys {
    /// Keys of one OpenSecureChannel exchange. `ikm` is the channel's IKM
    /// accumulator (zeros before the first exchange): IKM_n = IKM_n-1 XOR
    /// shared secret, kept for the next renewal.
    pub fn derive(suite: Suite, ikm: &mut [u8], secret: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> CResult<EccKeys> {
        if ikm.len() != secret.len() {
            return Err(CryptoError);
        }
        for (a, b) in ikm.iter_mut().zip(secret) {
            *a ^= b;
        }
        let len = suite.sym_key_len() + IV_LEN;
        let local = derive(suite, ikm, b"opcua-server", server_nonce, client_nonce, len);
        let remote = derive(suite, ikm, b"opcua-client", client_nonce, server_nonce, len);
        Ok(EccKeys { remote: AeadKeys::new(suite, &remote)?, local: AeadKeys::new(suite, &local)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_case1() {
        // RFC 5869 A.1 checks the primitive.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        struct L;
        impl hkdf::KeyType for L {
            fn len(&self) -> usize {
                42
            }
        }
        let mut out = [0u8; 42];
        hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&ikm).expand(&[&info], L).unwrap().fill(&mut out).unwrap();
        let want = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, want);
        // salt == info, length prefix and label, as Part 6 §6.8.1 lays out.
        let a = derive(Suite::ALL[0], &ikm, b"opcua-server", b"S", b"C", 48);
        let mut s = vec![48, 0];
        s.extend_from_slice(b"opcua-serverSC");
        let mut b = [0u8; 48];
        struct L48;
        impl hkdf::KeyType for L48 {
            fn len(&self) -> usize {
                48
            }
        }
        hkdf::Salt::new(hkdf::HKDF_SHA256, &s).extract(&ikm).expand(&[&s], L48).unwrap().fill(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn both_sides_agree_and_roundtrip() {
        for suite in Suite::ALL {
            let server = Ephemeral::generate(suite).unwrap();
            let client = Ephemeral::generate(suite).unwrap();
            assert_eq!(server.public.len(), suite.nonce_len());
            let (sn, cn) = (server.public.clone(), client.public.clone());
            let s_secret = server.agree(suite, &cn).unwrap();
            let c_secret = client.agree(suite, &sn).unwrap();
            assert_eq!(s_secret, c_secret);
            assert_eq!(s_secret.len(), suite.secret_len());
            let mut ikm = vec![0u8; suite.secret_len()];
            let keys = EccKeys::derive(suite, &mut ikm, &s_secret, &cn, &sn).unwrap();
            // The client's sending keys: label opcua-client, client nonce first.
            let len = suite.sym_key_len() + IV_LEN;
            let client_local =
                AeadKeys::new(suite, &derive(suite, &ikm, b"opcua-client", &cn, &sn, len)).unwrap();
            let mut msg = *b"hello secure channel";
            let tag = client_local.seal(7, 41, b"header", &mut msg).unwrap();
            assert_ne!(&msg, b"hello secure channel");
            keys.remote.open(7, 41, b"header", &mut msg, &tag).unwrap();
            assert_eq!(&msg, b"hello secure channel");
            // Wrong sequence number, AAD or direction: rejected.
            let mut again = *b"hello secure channel";
            let tag = client_local.seal(7, 41, b"header", &mut again).unwrap();
            assert!(keys.remote.open(7, 42, b"header", &mut again.clone(), &tag).is_err());
            assert!(keys.remote.open(7, 41, b"headeR", &mut again.clone(), &tag).is_err());
            assert!(keys.local.open(7, 41, b"header", &mut again.clone(), &tag).is_err());
            // Sign only: tag over the AAD.
            let tag = client_local.seal(1, 0, b"whole message", &mut []).unwrap();
            keys.remote.open(1, 0, b"whole message", &mut [], &tag).unwrap();
            // IKM chaining: a renewal with the same secret gives other keys.
            let first = ikm.clone();
            let _ = EccKeys::derive(suite, &mut ikm, &s_secret, &cn, &sn).unwrap();
            assert_eq!(ikm, vec![0u8; suite.secret_len()]);
            assert_ne!(first, ikm);
        }
    }

    #[test]
    fn rejects_bad_peer_keys() {
        for suite in Suite::ALL {
            let e = Ephemeral::generate(suite).unwrap();
            assert!(e.agree(suite, &[1u8; 3]).is_err());
            if suite.curve != Curve::Curve25519 {
                // Not a point on the curve.
                let e = Ephemeral::generate(suite).unwrap();
                assert!(e.agree(suite, &vec![1u8; suite.nonce_len()]).is_err());
            }
        }
    }
}
