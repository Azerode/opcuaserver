//! Certificate store and validation (Part 4 §6.1.3, Part 12 §7.3 layout).
//!
//! ```text
//! pki/
//!   own/certs/fastua.der        server application instance certificate
//!   own/private/fastua.pk8      its RSA private key (PKCS#8 DER, mode 0600)
//!   own/certs/fastua_<curve>.der, own/private/fastua_<curve>.pk8
//!                               ECC certificates (nistP256, nistP384, curve25519)
//!   trusted/certs, trusted/crl  trusted application certificates / CAs, and CRLs
//!   issuers/certs, issuers/crl  CAs used only to build chains, and their CRLs
//!   rejected/certs              certificates that failed the trust check
//!   users/{trusted,issuers}/... same layout, for X.509 user identity tokens
//! ```
//!
//! An unknown client certificate is copied to `rejected/certs`; an
//! administrator trusts it by moving the file to `trusted/certs`. Trust lists
//! are re-read automatically when their directories change.

use crate::crypto::{thumbprint, CryptoError, PrivateKey};
use crate::types::status;
use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use x509_parser::prelude::*;

pub mod codes {
    pub const BAD_CERTIFICATE_INVALID: u32 = 0x8012_0000;
    pub const BAD_CERTIFICATE_TIME_INVALID: u32 = 0x8014_0000;
    pub const BAD_CERTIFICATE_ISSUER_TIME_INVALID: u32 = 0x8015_0000;
    pub const BAD_CERTIFICATE_URI_INVALID: u32 = 0x8017_0000;
    pub const BAD_CERTIFICATE_USE_NOT_ALLOWED: u32 = 0x8018_0000;
    pub const BAD_CERTIFICATE_ISSUER_USE_NOT_ALLOWED: u32 = 0x8019_0000;
    pub const BAD_CERTIFICATE_UNTRUSTED: u32 = 0x801A_0000;
    pub const BAD_CERTIFICATE_REVOCATION_UNKNOWN: u32 = 0x801B_0000;
    pub const BAD_CERTIFICATE_ISSUER_REVOCATION_UNKNOWN: u32 = 0x801C_0000;
    pub const BAD_CERTIFICATE_REVOKED: u32 = 0x801D_0000;
    pub const BAD_CERTIFICATE_ISSUER_REVOKED: u32 = 0x801E_0000;
    pub const BAD_CERTIFICATE_CHAIN_INCOMPLETE: u32 = 0x810D_0000;
}
use codes::*;

/// Splits a concatenation of DER certificates (SenderCertificate may carry a chain).
pub fn split_chain(mut der: &[u8]) -> Result<Vec<&[u8]>, u32> {
    let mut out = Vec::new();
    while !der.is_empty() {
        let len = der_len(der).ok_or(BAD_CERTIFICATE_INVALID)?;
        if len > der.len() {
            return Err(BAD_CERTIFICATE_INVALID);
        }
        out.push(&der[..len]);
        der = &der[len..];
        if out.len() > 16 {
            return Err(BAD_CERTIFICATE_INVALID);
        }
    }
    if out.is_empty() {
        return Err(BAD_CERTIFICATE_INVALID);
    }
    Ok(out)
}

/// Total length of the outer DER SEQUENCE.
fn der_len(d: &[u8]) -> Option<usize> {
    if d.len() < 2 || d[0] != 0x30 {
        return None;
    }
    let l = d[1] as usize;
    if l < 0x80 {
        return Some(2 + l);
    }
    let n = l & 0x7F;
    if n == 0 || n > 4 || d.len() < 2 + n {
        return None;
    }
    let mut len = 0usize;
    for b in &d[2..2 + n] {
        len = (len << 8) | *b as usize;
    }
    Some(2 + n + len)
}

/// Facts about a validated certificate that later checks need.
#[derive(Clone, Debug)]
pub struct CertInfo {
    pub der: Vec<u8>,
    pub application_uri: Option<String>,
    /// The SubjectPublicKey bits: PKCS#1 RSAPublicKey, uncompressed EC
    /// point or Ed25519 key (for signature verification).
    pub rsa_public_key: Vec<u8>,
    /// SubjectPublicKeyInfo (for encryption).
    pub spki: Vec<u8>,
    /// RSA modulus size; 0 for ECC keys.
    pub key_bits: usize,
    /// Curve of an ECC key.
    pub curve: Option<crate::ecc::Curve>,
    pub thumbprint: [u8; 20],
}

pub fn inspect(der: &[u8]) -> Result<CertInfo, u32> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| BAD_CERTIFICATE_INVALID)?;
    let pk = cert.public_key();
    let spki = pk.raw.to_vec();
    let curve = key_curve(&cert);
    let key_bits = match curve {
        Some(_) => 0,
        None => aws_lc_rs::rsa::PublicEncryptingKey::from_der(&spki)
            .map_err(|_| BAD_CERTIFICATE_INVALID)?
            .key_size_bits(),
    };
    let application_uri = cert.subject_alternative_name().ok().flatten().and_then(|san| {
        san.value.general_names.iter().find_map(|g| match g {
            GeneralName::URI(u) => Some(u.to_string()),
            _ => None,
        })
    });
    Ok(CertInfo {
        der: der.to_vec(),
        application_uri,
        rsa_public_key: pk.subject_public_key.data.to_vec(),
        spki,
        key_bits,
        curve,
        thumbprint: thumbprint(der),
    })
}

/// The curve of an EC (P-256, P-384) or Ed25519 public key.
fn key_curve(cert: &X509Certificate) -> Option<crate::ecc::Curve> {
    use crate::ecc::Curve;
    let alg = &cert.public_key().algorithm;
    match alg.algorithm.to_id_string().as_str() {
        "1.3.101.112" => Some(Curve::Curve25519),
        "1.2.840.10045.2.1" => match alg.parameters.as_ref()?.as_oid().ok()?.to_id_string().as_str() {
            "1.2.840.10045.3.1.7" => Some(Curve::NistP256),
            "1.3.132.0.34" => Some(Curve::NistP384),
            _ => None,
        },
        _ => None,
    }
}

fn verification_alg(oid: &str) -> Option<&'static [&'static dyn VerificationAlgorithm]> {
    Some(match oid {
        "1.2.840.113549.1.1.11" => &[&signature::RSA_PKCS1_2048_8192_SHA256],
        "1.2.840.113549.1.1.12" => &[&signature::RSA_PKCS1_2048_8192_SHA384],
        "1.2.840.113549.1.1.13" => &[&signature::RSA_PKCS1_2048_8192_SHA512],
        "1.2.840.113549.1.1.10" => &[
            &signature::RSA_PSS_2048_8192_SHA256,
            &signature::RSA_PSS_2048_8192_SHA384,
            &signature::RSA_PSS_2048_8192_SHA512,
        ],
        "1.2.840.10045.4.3.2" => &[&signature::ECDSA_P256_SHA256_ASN1, &signature::ECDSA_P384_SHA256_ASN1],
        "1.2.840.10045.4.3.3" => &[&signature::ECDSA_P384_SHA384_ASN1, &signature::ECDSA_P256_SHA384_ASN1],
        "1.3.101.112" => &[&signature::ED25519],
        // SHA-1 and MD5 signatures are rejected (not allowed by the supported policies).
        _ => return None,
    })
}

fn verify_signed(issuer: &X509Certificate, tbs: &[u8], oid: &str, sig: &[u8]) -> bool {
    let Some(algs) = verification_alg(oid) else { return false };
    let key = &issuer.public_key().subject_public_key.data;
    algs.iter().any(|alg| UnparsedPublicKey::new(*alg, key.as_ref()).verify(tbs, sig).is_ok())
}

fn signed_by(cert: &X509Certificate, issuer: &X509Certificate) -> bool {
    cert.issuer().as_raw() == issuer.subject().as_raw()
        && verify_signed(
            issuer,
            cert.tbs_certificate.as_ref(),
            &cert.signature_algorithm.algorithm.to_id_string(),
            &cert.signature_value.data,
        )
}

#[derive(Default)]
struct Lists {
    stamp: Vec<Option<SystemTime>>,
    trusted: Vec<Vec<u8>>,
    issuers: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
}

/// One trust list directory tree (`trusted`, `issuers`, `rejected`).
pub struct TrustStore {
    root: PathBuf,
    lists: Mutex<Arc<Lists>>,
}

fn read_dir_files(dir: &Path) -> Vec<Vec<u8>> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_file()).collect())
        .unwrap_or_default();
    files.sort();
    files.iter().filter_map(|p| std::fs::read(p).ok()).map(|b| pem_to_der(&b).unwrap_or(b)).collect()
}

/// Accepts PEM files too (first block only).
fn pem_to_der(b: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(b).ok()?;
    let start = text.find("-----BEGIN ")?;
    let body_start = text[start..].find('\n')? + start + 1;
    let end = text[body_start..].find("-----END ")? + body_start;
    let b64: String = text[body_start..end].chars().filter(|c| !c.is_whitespace()).collect();
    crate::types::decode_base64(&b64)
}

impl TrustStore {
    pub fn new(root: &Path) -> std::io::Result<TrustStore> {
        for d in ["trusted/certs", "trusted/crl", "issuers/certs", "issuers/crl", "rejected/certs"] {
            std::fs::create_dir_all(root.join(d))?;
        }
        Ok(TrustStore { root: root.to_path_buf(), lists: Mutex::new(Arc::new(Lists::default())) })
    }

    fn dirs(&self) -> [PathBuf; 4] {
        [
            self.root.join("trusted/certs"),
            self.root.join("issuers/certs"),
            self.root.join("trusted/crl"),
            self.root.join("issuers/crl"),
        ]
    }

    /// Current lists, re-read if any directory changed.
    fn lists(&self) -> Arc<Lists> {
        let dirs = self.dirs();
        let stamp: Vec<_> = dirs.iter().map(|d| std::fs::metadata(d).and_then(|m| m.modified()).ok()).collect();
        let mut guard = self.lists.lock().unwrap_or_else(|e| e.into_inner());
        if guard.stamp != stamp || guard.stamp.is_empty() {
            let mut crls = read_dir_files(&dirs[2]);
            crls.extend(read_dir_files(&dirs[3]));
            *guard =
                Arc::new(Lists { stamp, trusted: read_dir_files(&dirs[0]), issuers: read_dir_files(&dirs[1]), crls });
        }
        guard.clone()
    }

    fn reject(&self, der: &[u8]) {
        let name = format!("{}.der", hex(&thumbprint(der)));
        let _ = std::fs::write(self.root.join("rejected/certs").join(name), der);
    }

    /// Full validation of a certificate chain (leaf first). `application`
    /// selects the key usage rules for application instance certificates.
    pub fn validate(&self, chain_der: &[&[u8]], application: bool) -> Result<(), u32> {
        let lists = self.lists();
        let leaf_der = chain_der[0];
        let mut pool: Vec<&[u8]> = chain_der[1..].to_vec();
        pool.extend(lists.trusted.iter().map(Vec::as_slice));
        pool.extend(lists.issuers.iter().map(Vec::as_slice));
        let parsed_pool: Vec<X509Certificate> =
            pool.iter().filter_map(|d| X509Certificate::from_der(d).ok().map(|(_, c)| c)).collect();

        let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(|_| BAD_CERTIFICATE_INVALID)?;

        // Build the chain up to a self-signed certificate.
        let mut chain: Vec<&X509Certificate> = Vec::new();
        let mut current = &leaf;
        loop {
            if current.issuer().as_raw() == current.subject().as_raw() {
                if !signed_by(current, current) {
                    return Err(BAD_CERTIFICATE_INVALID);
                }
                break;
            }
            let issuer = parsed_pool.iter().find(|c| signed_by(current, c));
            match issuer {
                Some(i) if chain.len() < 8 => {
                    chain.push(i);
                    current = i;
                }
                _ => return Err(BAD_CERTIFICATE_CHAIN_INCOMPLETE),
            }
        }

        // Trust: the leaf itself, or any CA of its chain, is in the trusted list.
        let trusted = lists.trusted.iter().any(|t| t.as_slice() == leaf_der)
            || chain.iter().any(|c| lists.trusted.iter().any(|t| t.as_slice() == c.as_ref()));
        if !trusted {
            self.reject(leaf_der);
            return Err(BAD_CERTIFICATE_UNTRUSTED);
        }

        // Validity periods.
        if !leaf.validity().is_valid() {
            return Err(BAD_CERTIFICATE_TIME_INVALID);
        }
        if chain.iter().any(|c| !c.validity().is_valid()) {
            return Err(BAD_CERTIFICATE_ISSUER_TIME_INVALID);
        }

        // Usage.
        if application {
            let ku = leaf.key_usage().map_err(|_| BAD_CERTIFICATE_INVALID)?;
            // ECC keys sign and agree on keys: they do not encipher.
            let ecc = key_curve(&leaf).is_some();
            if let Some(ku) = ku {
                let k = ku.value;
                if !k.digital_signature() || !ecc && !k.key_encipherment() && !k.data_encipherment() {
                    return Err(BAD_CERTIFICATE_USE_NOT_ALLOWED);
                }
            }
        }
        for ca in &chain {
            let is_ca = ca.basic_constraints().ok().flatten().is_some_and(|b| b.value.ca);
            let can_sign = ca.key_usage().ok().flatten().is_none_or(|k| k.value.key_cert_sign());
            if !is_ca || !can_sign {
                return Err(BAD_CERTIFICATE_ISSUER_USE_NOT_ALLOWED);
            }
        }

        // Revocation: every CA-issued certificate needs its issuer's CRL.
        let mut subject: &X509Certificate = &leaf;
        for (depth, issuer) in chain.iter().enumerate() {
            let (unknown, revoked) = if depth == 0 {
                (BAD_CERTIFICATE_REVOCATION_UNKNOWN, BAD_CERTIFICATE_REVOKED)
            } else {
                (BAD_CERTIFICATE_ISSUER_REVOCATION_UNKNOWN, BAD_CERTIFICATE_ISSUER_REVOKED)
            };
            let crl = lists.crls.iter().find_map(|d| {
                let (_, crl) = CertificateRevocationList::from_der(d).ok()?;
                let ok = crl.issuer().as_raw() == issuer.subject().as_raw()
                    && verify_signed(
                        issuer,
                        crl.tbs_cert_list.as_ref(),
                        &crl.signature_algorithm.algorithm.to_id_string(),
                        &crl.signature_value.data,
                    );
                ok.then_some(crl)
            });
            let Some(crl) = crl else { return Err(unknown) };
            if crl.iter_revoked_certificates().any(|r| r.raw_serial() == subject.raw_serial()) {
                return Err(revoked);
            }
            subject = issuer;
        }
        Ok(())
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The server's own certificate and key, plus the trust stores.
pub struct Pki {
    pub cert_der: Vec<u8>,
    pub key: PrivateKey,
    pub thumbprint: [u8; 20],
    pub applications: TrustStore,
    pub users: TrustStore,
    /// Development switch: accept any well-formed client certificate.
    pub trust_all: bool,
    /// One ECC certificate per curve (ECC security policies).
    pub ecc: Vec<EccOwn>,
}

/// An ECC application instance certificate and its key.
pub struct EccOwn {
    pub curve: crate::ecc::Curve,
    pub cert_der: Vec<u8>,
    pub key: crate::ecc::SigningKey,
    pub thumbprint: [u8; 20],
}

impl Pki {
    /// Our certificate for an ECC curve.
    pub fn ecc_own(&self, curve: crate::ecc::Curve) -> Option<&EccOwn> {
        self.ecc.iter().find(|e| e.curve == curve)
    }
}

fn curve_name(curve: crate::ecc::Curve) -> &'static str {
    match curve {
        crate::ecc::Curve::NistP256 => "nistP256",
        crate::ecc::Curve::NistP384 => "nistP384",
        crate::ecc::Curve::Curve25519 => "curve25519",
    }
}

/// Loads (or creates) the ECC certificate of `curve` in `root/own`.
fn load_ecc(root: &Path, curve: crate::ecc::Curve, application_uri: &str, hostname: &str) -> Result<EccOwn, String> {
    let name = curve_name(curve);
    let cert_path = root.join(format!("own/certs/fastua_{name}.der"));
    let key_path = root.join(format!("own/private/fastua_{name}.pk8"));
    let io = |e: std::io::Error| format!("{}: {e}", root.display());
    if !cert_path.exists() || !key_path.exists() {
        let (cert, key) =
            generate_self_signed_ecc(curve, application_uri, hostname).map_err(|e| format!("{e:?}"))?;
        write_private(&key_path, &key).map_err(io)?;
        std::fs::write(&cert_path, &cert).map_err(io)?;
        crate::log!("generated self-signed certificate {}", cert_path.display());
    }
    let cert_der = std::fs::read(&cert_path).map_err(io)?;
    let key_der = std::fs::read(&key_path).map_err(io)?;
    let info = inspect(&cert_der).map_err(|c| format!("{}: invalid certificate (0x{c:08X})", cert_path.display()))?;
    if info.curve != Some(curve) {
        return Err(format!("{}: not a {name} certificate", cert_path.display()));
    }
    let key = crate::ecc::SigningKey::from_pkcs8(curve, &key_der)
        .map_err(|_| format!("{}: invalid private key", key_path.display()))?;
    // The key must be the certificate's: sign and verify.
    let probe = key.sign(b"fastua").map_err(|_| format!("{}: unusable key", key_path.display()))?;
    let suite = crate::ecc::Suite { curve, cipher: crate::ecc::Cipher::AesGcm };
    if suite.verify(&info.rsa_public_key, b"fastua", &probe).is_err() {
        return Err(format!("{} does not match {}", cert_path.display(), key_path.display()));
    }
    Ok(EccOwn { curve, thumbprint: thumbprint(&cert_der), cert_der, key })
}

impl Pki {
    /// Loads `root/own`, generating a self-signed certificate on first start.
    pub fn open(root: &Path, application_uri: &str, hostname: &str, trust_all: bool) -> Result<Arc<Pki>, String> {
        let cert_path = root.join("own/certs/fastua.der");
        let key_path = root.join("own/private/fastua.pk8");
        let io = |e: std::io::Error| format!("{}: {e}", root.display());
        std::fs::create_dir_all(root.join("own/certs")).map_err(io)?;
        std::fs::create_dir_all(root.join("own/private")).map_err(io)?;
        if !cert_path.exists() || !key_path.exists() {
            let (cert, key) = generate_self_signed(application_uri, hostname).map_err(|e| format!("{e:?}"))?;
            write_private(&key_path, &key).map_err(io)?;
            std::fs::write(&cert_path, &cert).map_err(io)?;
            crate::log!("generated self-signed certificate {}", cert_path.display());
        }
        let cert_der = std::fs::read(&cert_path).map_err(io)?;
        let key_der = std::fs::read(&key_path).map_err(io)?;
        let key =
            PrivateKey::from_pkcs8(&key_der).map_err(|_| format!("{}: invalid private key", key_path.display()))?;
        let info =
            inspect(&cert_der).map_err(|c| format!("{}: invalid certificate (0x{c:08X})", cert_path.display()))?;
        if info.rsa_public_key != key.public_key_der() {
            return Err(format!("{} does not match {}", cert_path.display(), key_path.display()));
        }
        if info.application_uri.as_deref() != Some(application_uri) {
            crate::log!(
                "warning: certificate URI {:?} differs from ApplicationUri {application_uri}",
                info.application_uri
            );
        }
        Ok(Arc::new(Pki {
            thumbprint: thumbprint(&cert_der),
            cert_der,
            key,
            applications: TrustStore::new(root).map_err(io)?,
            users: TrustStore::new(&root.join("users")).map_err(io)?,
            trust_all,
            ecc: [crate::ecc::Curve::NistP256, crate::ecc::Curve::NistP384, crate::ecc::Curve::Curve25519]
                .into_iter()
                .map(|c| load_ecc(root, c, application_uri, hostname))
                .collect::<Result<_, _>>()?,
        }))
    }

    /// Validates a client application certificate (chain).
    pub fn validate_application(&self, chain: &[u8]) -> Result<CertInfo, u32> {
        let parts = split_chain(chain)?;
        let info = inspect(parts[0])?;
        if !self.trust_all {
            self.applications.validate(&parts, true)?;
        }
        Ok(info)
    }

    pub fn validate_user(&self, chain: &[u8]) -> Result<CertInfo, u32> {
        let parts = split_chain(chain)?;
        let info = inspect(parts[0])?;
        self.users.validate(&parts, false)?;
        Ok(info)
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

/// RSA-2048 / SHA-256 application instance certificate (Part 6 §6.2.2).
pub fn generate_self_signed(application_uri: &str, hostname: &str) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use aws_lc_rs::encoding::AsDer;
    use rcgen::*;
    let kp = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)?;
    let pkcs8 = kp.as_der()?.as_ref().to_vec();
    let key =
        KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8.as_slice().into(), &PKCS_RSA_SHA256).map_err(|_| CryptoError)?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "fastua");
    dn.push(DnType::OrganizationName, "fastua");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        SanType::URI(application_uri.try_into().map_err(|_| CryptoError)?),
        SanType::DnsName(hostname.try_into().map_err(|_| CryptoError)?),
    ];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::DataEncipherment,
        KeyUsagePurpose::KeyCertSign,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    params.is_ca = IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = true;
    let mut serial = [0u8; 16];
    crate::server::random_bytes(&mut serial);
    serial[0] &= 0x7F;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now - ::time::Duration::days(1);
    params.not_after = now + ::time::Duration::days(5 * 365);
    let cert = params.self_signed(&key).map_err(|_| CryptoError)?;
    Ok((cert.der().to_vec(), pkcs8))
}

/// ECC application instance certificate (ECDSA P-256 / P-384 with SHA-256 /
/// SHA-384, or Ed25519).
pub fn generate_self_signed_ecc(
    curve: crate::ecc::Curve,
    application_uri: &str,
    hostname: &str,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    use rcgen::*;
    let alg = match curve {
        crate::ecc::Curve::NistP256 => &PKCS_ECDSA_P256_SHA256,
        crate::ecc::Curve::NistP384 => &PKCS_ECDSA_P384_SHA384,
        crate::ecc::Curve::Curve25519 => &PKCS_ED25519,
    };
    let key = KeyPair::generate_for(alg).map_err(|_| CryptoError)?;
    let pkcs8 = key.serialize_der();
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("fastua {}", curve_name(curve)));
    dn.push(DnType::OrganizationName, "fastua");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![
        SanType::URI(application_uri.try_into().map_err(|_| CryptoError)?),
        SanType::DnsName(hostname.try_into().map_err(|_| CryptoError)?),
    ];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
        KeyUsagePurpose::KeyCertSign,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    params.is_ca = IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = true;
    let mut serial = [0u8; 16];
    crate::server::random_bytes(&mut serial);
    serial[0] &= 0x7F;
    params.serial_number = Some(SerialNumber::from_slice(&serial));
    let now = ::time::OffsetDateTime::now_utc();
    params.not_before = now - ::time::Duration::days(1);
    params.not_after = now + ::time::Duration::days(5 * 365);
    let cert = params.self_signed(&key).map_err(|_| CryptoError)?;
    Ok((cert.der().to_vec(), pkcs8))
}

/// Re-export for status code mapping in the channel layer.
pub const SECURITY_CHECKS_FAILED: u32 = status::BAD_SECURITY_CHECKS_FAILED;

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fastua-pki-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn own_certificate_is_generated_and_reloaded() {
        let root = tmp("own");
        let a = Pki::open(&root, "urn:test:server", "localhost", false).unwrap();
        let info = inspect(&a.cert_der).unwrap();
        assert_eq!(info.application_uri.as_deref(), Some("urn:test:server"));
        assert_eq!(info.key_bits, 2048);
        let b = Pki::open(&root, "urn:test:server", "localhost", false).unwrap();
        assert_eq!(a.cert_der, b.cert_der);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn ecc_certificates_are_generated_trusted_and_reloaded() {
        use crate::ecc::Curve;
        let root = tmp("ecc");
        let a = Pki::open(&root, "urn:test:server", "localhost", false).unwrap();
        assert_eq!(a.ecc.len(), 3);
        for own in &a.ecc {
            let info = inspect(&own.cert_der).unwrap();
            assert_eq!(info.curve, Some(own.curve));
            assert_eq!(info.key_bits, 0);
            assert_eq!(info.application_uri.as_deref(), Some("urn:test:server"));
        }
        let b = Pki::open(&root, "urn:test:server", "localhost", false).unwrap();
        assert_eq!(a.ecc_own(Curve::NistP384).unwrap().cert_der, b.ecc_own(Curve::NistP384).unwrap().cert_der);
        // An ECC client certificate goes through the same trust flow.
        for curve in [Curve::NistP256, Curve::NistP384, Curve::Curve25519] {
            let (client, _) = generate_self_signed_ecc(curve, "urn:test:client", "client").unwrap();
            assert_eq!(a.validate_application(&client).unwrap_err(), BAD_CERTIFICATE_UNTRUSTED);
            std::fs::write(root.join("trusted/certs").join(format!("{curve:?}.der")), &client).unwrap();
            assert_eq!(a.validate_application(&client).unwrap().curve, Some(curve));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn self_signed_client_trust_flow() {
        let root = tmp("trust");
        let pki = Pki::open(&root, "urn:test:server", "localhost", false).unwrap();
        let (client, _) = generate_self_signed("urn:test:client", "client").unwrap();
        assert_eq!(pki.validate_application(&client).unwrap_err(), BAD_CERTIFICATE_UNTRUSTED);
        let rejected = root.join("rejected/certs").join(format!("{}.der", hex(&thumbprint(&client))));
        assert!(rejected.exists());
        // Administrator trusts it.
        std::fs::rename(&rejected, root.join("trusted/certs/client.der")).unwrap();
        let info = pki.validate_application(&client).unwrap();
        assert_eq!(info.application_uri.as_deref(), Some("urn:test:client"));
        // Tampered certificate.
        let mut bad = client.clone();
        let n = bad.len();
        bad[n - 5] ^= 1;
        assert!(pki.validate_application(&bad).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn rsa_key() -> rcgen::KeyPair {
        use aws_lc_rs::encoding::AsDer;
        let kp = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let der = kp.as_der().unwrap().as_ref().to_vec();
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&der.as_slice().into(), &rcgen::PKCS_RSA_SHA256).unwrap()
    }

    #[test]
    fn ca_issued_certificate_with_crl() {
        use rcgen::*;
        let root = tmp("ca");
        let pki = Pki::open(&root, "urn:test:server", "localhost", false).unwrap();

        // CA (ECDSA P-256) and a leaf (RSA 2048) it signs.
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.distinguished_name.push(DnType::CommonName, "Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, &ca_key);

        let leaf_key = rsa_key();
        let mut leaf_params = CertificateParams::new(vec!["client".to_string()]).unwrap();
        leaf_params.distinguished_name.push(DnType::CommonName, "client");
        leaf_params.subject_alt_names.push(SanType::URI("urn:test:client".try_into().unwrap()));
        leaf_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::DataEncipherment,
        ];
        leaf_params.serial_number = Some(SerialNumber::from_slice(&[0x42]));
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap().der().to_vec();

        // Issuer unknown.
        assert_eq!(pki.validate_application(&leaf).unwrap_err(), BAD_CERTIFICATE_CHAIN_INCOMPLETE);
        // CA trusted, but no CRL yet.
        std::fs::write(root.join("trusted/certs/ca.der"), ca_cert.der()).unwrap();
        assert_eq!(pki.validate_application(&leaf).unwrap_err(), BAD_CERTIFICATE_REVOCATION_UNKNOWN);

        let now = ::time::OffsetDateTime::now_utc();
        let crl = |revoked: Vec<RevokedCertParams>| {
            CertificateRevocationListParams {
                this_update: now - ::time::Duration::hours(1),
                next_update: now + ::time::Duration::days(30),
                crl_number: SerialNumber::from_slice(&[1]),
                issuing_distribution_point: None,
                revoked_certs: revoked,
                key_identifier_method: KeyIdMethod::Sha256,
            }
            .signed_by(&issuer)
            .unwrap()
            .der()
            .to_vec()
        };
        // Sleep so the directory mtime changes even on coarse clocks.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(root.join("trusted/crl/ca.crl"), crl(vec![])).unwrap();
        pki.validate_application(&leaf).unwrap();

        // Leaf revoked.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let revoked = RevokedCertParams {
            serial_number: SerialNumber::from_slice(&[0x42]),
            revocation_time: now - ::time::Duration::minutes(1),
            reason_code: None,
            invalidity_date: None,
        };
        std::fs::remove_file(root.join("trusted/crl/ca.crl")).unwrap();
        std::fs::write(root.join("trusted/crl/ca2.crl"), crl(vec![revoked])).unwrap();
        assert_eq!(pki.validate_application(&leaf).unwrap_err(), BAD_CERTIFICATE_REVOKED);

        // A chain sent by the client (leaf + CA) is accepted when the leaf is trusted.
        let _ = std::fs::remove_dir_all(&root);
        let pki = Pki::open(&root, "urn:test:server", "localhost", false).unwrap();
        std::fs::write(root.join("trusted/certs/leaf.der"), &leaf).unwrap();
        std::fs::write(root.join("trusted/crl/ca.crl"), crl(vec![])).unwrap();
        let mut chain = leaf.clone();
        chain.extend_from_slice(ca_cert.der());
        pki.validate_application(&chain).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn chain_splitting() {
        let (a, _) = generate_self_signed("urn:a", "a").unwrap();
        let (b, _) = generate_self_signed("urn:b", "b").unwrap();
        let mut both = a.clone();
        both.extend_from_slice(&b);
        let parts = split_chain(&both).unwrap();
        assert_eq!(parts, vec![a.as_slice(), b.as_slice()]);
        assert!(split_chain(&[0x30, 0x82, 0xFF]).is_err());
    }
}
