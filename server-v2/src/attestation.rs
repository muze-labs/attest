use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAGIC: [u8; 4] = *b"MTA\0";
pub const FORMAT_VERSION: u8 = 1;
pub const ASSURANCE_LEVEL_1: u8 = 1;
pub const HASH_ALG_SHA256: u8 = 1;
pub const BODY_LEN: usize = 63;
pub const SIGNATURE_LEN: usize = 64;
pub const ATTESTATION_LEN: usize = BODY_LEN + SIGNATURE_LEN;
pub const TEXT_PREFIX: &str = "mta1_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAttestation {
    pub format_version: u8,
    pub assurance_level: u8,
    pub hash_algorithm: u8,
    pub digest: [u8; 32],
    pub timestamp_ms: i64,
    pub key_id: [u8; 16],
    pub signature: [u8; 64],
}

#[derive(Debug)]
pub enum AttestationError {
    InvalidLength(usize),
    InvalidMagic,
    UnsupportedFormat(u8),
    InvalidText,
    InvalidBase64,
    InvalidSignature,
    WrongKey,
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(n) => write!(f, "invalid attestation length: {n}"),
            Self::InvalidMagic => write!(f, "invalid attestation magic"),
            Self::UnsupportedFormat(v) => write!(f, "unsupported attestation format version: {v}"),
            Self::InvalidText => write!(f, "invalid textual attestation"),
            Self::InvalidBase64 => write!(f, "invalid base64url payload"),
            Self::InvalidSignature => write!(f, "signature verification failed"),
            Self::WrongKey => write!(f, "attestation key id does not match supplied public key"),
        }
    }
}

impl std::error::Error for AttestationError {}

pub fn key_id(verifying_key: &VerifyingKey) -> [u8; 16] {
    let hash = Sha256::digest(verifying_key.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&hash[..16]);
    id
}

pub fn issue(signing_key: &SigningKey, digest: [u8; 32], timestamp_ms: i64) -> [u8; ATTESTATION_LEN] {
    let mut out = [0u8; ATTESTATION_LEN];
    out[0..4].copy_from_slice(&MAGIC);
    out[4] = FORMAT_VERSION;
    out[5] = ASSURANCE_LEVEL_1;
    out[6] = HASH_ALG_SHA256;
    out[7..39].copy_from_slice(&digest);
    out[39..47].copy_from_slice(&timestamp_ms.to_be_bytes());
    out[47..63].copy_from_slice(&key_id(&signing_key.verifying_key()));

    let sig = signing_key.sign(&out[..BODY_LEN]);
    out[BODY_LEN..].copy_from_slice(&sig.to_bytes());
    out
}

pub fn decode(bytes: &[u8]) -> Result<DecodedAttestation, AttestationError> {
    if bytes.len() != ATTESTATION_LEN {
        return Err(AttestationError::InvalidLength(bytes.len()));
    }
    if bytes[0..4] != MAGIC {
        return Err(AttestationError::InvalidMagic);
    }
    if bytes[4] != FORMAT_VERSION {
        return Err(AttestationError::UnsupportedFormat(bytes[4]));
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[7..39]);

    let mut ts = [0u8; 8];
    ts.copy_from_slice(&bytes[39..47]);

    let mut kid = [0u8; 16];
    kid.copy_from_slice(&bytes[47..63]);

    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[63..127]);

    Ok(DecodedAttestation {
        format_version: bytes[4],
        assurance_level: bytes[5],
        hash_algorithm: bytes[6],
        digest,
        timestamp_ms: i64::from_be_bytes(ts),
        key_id: kid,
        signature,
    })
}

pub fn verify(bytes: &[u8], verifying_key: &VerifyingKey) -> Result<DecodedAttestation, AttestationError> {
    let decoded = decode(bytes)?;
    if decoded.key_id != key_id(verifying_key) {
        return Err(AttestationError::WrongKey);
    }
    let sig = Signature::from_bytes(&decoded.signature);
    verifying_key
        .verify(&bytes[..BODY_LEN], &sig)
        .map_err(|_| AttestationError::InvalidSignature)?;
    Ok(decoded)
}

pub fn to_text(bytes: &[u8]) -> String {
    format!("{TEXT_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub fn from_text(input: &str) -> Result<Vec<u8>, AttestationError> {
    let trimmed = input.trim();
    let payload = trimmed
        .strip_prefix(TEXT_PREFIX)
        .ok_or(AttestationError::InvalidText)?;
    URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AttestationError::InvalidBase64)
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn parse_hex_32(input: &str) -> Result<[u8; 32], &'static str> {
    let s = input.trim();
    if s.len() != 64 {
        return Err("SHA-256 digest must be exactly 64 hex characters");
    }
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    for i in 0..32 {
        let hi = nibble(b[i * 2]).ok_or("invalid hex digest")?;
        let lo = nibble(b[i * 2 + 1]).ok_or("invalid hex digest")?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn roundtrip_and_verify() {
        let key = test_key();
        let digest = [42u8; 32];
        let bytes = issue(&key, digest, 1_800_000_000_123);
        let decoded = verify(&bytes, &key.verifying_key()).unwrap();
        assert_eq!(decoded.digest, digest);
        assert_eq!(decoded.assurance_level, 1);
        assert_eq!(decoded.timestamp_ms, 1_800_000_000_123);
        assert_eq!(bytes.len(), 127);
    }

    #[test]
    fn text_roundtrip() {
        let key = test_key();
        let bytes = issue(&key, [1u8; 32], 123);
        let text = to_text(&bytes);
        assert_eq!(from_text(&text).unwrap(), bytes);
    }

    #[test]
    fn changed_attestation_fails() {
        let key = test_key();
        let mut bytes = issue(&key, [1u8; 32], 123);
        bytes[10] ^= 0x01;
        assert!(verify(&bytes, &key.verifying_key()).is_err());
    }
}
