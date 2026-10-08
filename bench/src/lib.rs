//! Minimal hot-path model for the Muze temporal attestation service.
//!
//! This is intentionally *not* the final protocol. It models the work we expect
//! to be unavoidable for a v1 ingest request:
//!   1. receive a 32-byte commitment;
//!   2. generate a unique 128-bit attestation nonce;
//!   3. encode a compact receipt body;
//!   4. Ed25519-sign it;
//!   5. hash the signed receipt and create binary CIDv1 bytes.
//!
//! No I/O, persistence, HTTP, IPFS, batching, or external anchoring is included.
//! The point is to establish a CPU/memory upper bound for the synchronous path.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rand_chacha::{
    ChaCha12Rng,
    rand_core::{Rng, SeedableRng},
};
use sha2::{Digest, Sha256};

pub const COMMITMENT_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const KEY_ID_LEN: usize = 16;
pub const SIGNATURE_LEN: usize = 64;

/// Compact receipt body:
///
/// - magic: 4 bytes ("MTA1")
/// - version: 1 byte
/// - commitment multihash code: 2 bytes (big endian; SHA2-256 = 0x0012)
/// - commitment digest length: 1 byte
/// - commitment digest: 32 bytes
/// - attestation nonce: 16 bytes
/// - signing key id: 16 bytes
pub const UNSIGNED_RECEIPT_LEN: usize = 4 + 1 + 2 + 1 + 32 + 16 + 16;
pub const SIGNED_RECEIPT_LEN: usize = UNSIGNED_RECEIPT_LEN + SIGNATURE_LEN;

/// CIDv1 binary representation for a raw block hashed with SHA2-256:
/// version(1) + raw codec(0x55) + sha2-256 multihash code(0x12)
/// + digest length(0x20) + 32-byte digest.
pub const RECEIPT_CID_LEN: usize = 36;

const MAGIC: &[u8; 4] = b"MTA1";
const VERSION: u8 = 1;
const SHA2_256_CODE: u16 = 0x0012;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedReceipt {
    pub bytes: [u8; SIGNED_RECEIPT_LEN],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptCid {
    pub bytes: [u8; RECEIPT_CID_LEN],
}

/// Benchmark issuer state. In production the RNG would be seeded from the OS
/// (or from a securely seeded per-worker master generator), never from a fixed seed.
pub struct BenchIssuer {
    signing_key: SigningKey,
    key_id: [u8; KEY_ID_LEN],
    rng: ChaCha12Rng,
}

impl BenchIssuer {
    /// Deterministic constructor for repeatable benchmarks only.
    pub fn deterministic(worker_seed: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_hash = Sha256::digest(public_key);
        let mut key_id = [0u8; KEY_ID_LEN];
        key_id.copy_from_slice(&key_hash[..KEY_ID_LEN]);

        let mut rng_seed = [0u8; 32];
        rng_seed[0] = worker_seed;
        rng_seed[1..].fill(0xA5);
        let rng = ChaCha12Rng::from_seed(rng_seed);

        Self {
            signing_key,
            key_id,
            rng,
        }
    }

    #[inline]
    pub fn issue(&mut self, commitment: &[u8; COMMITMENT_LEN]) -> (SignedReceipt, ReceiptCid) {
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill_bytes(&mut nonce);

        let unsigned = encode_unsigned_receipt(commitment, &nonce, &self.key_id);
        let signature: Signature = self.signing_key.sign(&unsigned);
        let receipt = assemble_signed_receipt(&unsigned, &signature);
        let cid = receipt_cid(&receipt);
        (receipt, cid)
    }

    #[inline]
    pub fn sign_body(&self, body: &[u8; UNSIGNED_RECEIPT_LEN]) -> Signature {
        self.signing_key.sign(body)
    }

    #[inline]
    pub fn verify(&self, receipt: &SignedReceipt) -> bool {
        let mut sig_bytes = [0u8; SIGNATURE_LEN];
        sig_bytes.copy_from_slice(&receipt.bytes[UNSIGNED_RECEIPT_LEN..]);
        let signature = Signature::from_bytes(&sig_bytes);
        self.signing_key
            .verifying_key()
            .verify(&receipt.bytes[..UNSIGNED_RECEIPT_LEN], &signature)
            .is_ok()
    }

    #[inline]
    pub fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.key_id
    }
}

#[inline]
pub fn encode_unsigned_receipt(
    commitment: &[u8; COMMITMENT_LEN],
    nonce: &[u8; NONCE_LEN],
    key_id: &[u8; KEY_ID_LEN],
) -> [u8; UNSIGNED_RECEIPT_LEN] {
    let mut out = [0u8; UNSIGNED_RECEIPT_LEN];
    let mut p = 0;

    out[p..p + 4].copy_from_slice(MAGIC);
    p += 4;
    out[p] = VERSION;
    p += 1;
    out[p..p + 2].copy_from_slice(&SHA2_256_CODE.to_be_bytes());
    p += 2;
    out[p] = COMMITMENT_LEN as u8;
    p += 1;
    out[p..p + COMMITMENT_LEN].copy_from_slice(commitment);
    p += COMMITMENT_LEN;
    out[p..p + NONCE_LEN].copy_from_slice(nonce);
    p += NONCE_LEN;
    out[p..p + KEY_ID_LEN].copy_from_slice(key_id);

    out
}

#[inline]
pub fn assemble_signed_receipt(
    unsigned: &[u8; UNSIGNED_RECEIPT_LEN],
    signature: &Signature,
) -> SignedReceipt {
    let mut bytes = [0u8; SIGNED_RECEIPT_LEN];
    bytes[..UNSIGNED_RECEIPT_LEN].copy_from_slice(unsigned);
    bytes[UNSIGNED_RECEIPT_LEN..].copy_from_slice(&signature.to_bytes());
    SignedReceipt { bytes }
}

/// Compute binary CIDv1 bytes for the signed receipt as a raw IPLD block.
///
/// All fields fit in single-byte unsigned varints:
/// - CID version 1      = 0x01
/// - raw multicodec     = 0x55
/// - sha2-256 multihash = 0x12
/// - digest length      = 0x20
#[inline]
pub fn receipt_cid(receipt: &SignedReceipt) -> ReceiptCid {
    let digest = Sha256::digest(receipt.bytes);
    let mut bytes = [0u8; RECEIPT_CID_LEN];
    bytes[0] = 0x01;
    bytes[1] = 0x55;
    bytes[2] = 0x12;
    bytes[3] = 0x20;
    bytes[4..].copy_from_slice(&digest);
    ReceiptCid { bytes }
}

/// Produce a deterministic 32-byte commitment for benchmark input.
/// This models a digest already supplied by the client; hashing source data is
/// intentionally outside the service hot path.
#[inline]
pub fn benchmark_commitment(counter: u64) -> [u8; COMMITMENT_LEN] {
    let mut commitment = [0x5Au8; COMMITMENT_LEN];
    commitment[COMMITMENT_LEN - 8..].copy_from_slice(&counter.to_be_bytes());
    commitment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_verifies() {
        let mut issuer = BenchIssuer::deterministic(1);
        let commitment = benchmark_commitment(1);
        let (receipt, _cid) = issuer.issue(&commitment);
        assert!(issuer.verify(&receipt));
    }

    #[test]
    fn same_commitment_can_have_distinct_attestations() {
        let mut issuer = BenchIssuer::deterministic(1);
        let commitment = benchmark_commitment(1);
        let (_r1, c1) = issuer.issue(&commitment);
        let (_r2, c2) = issuer.issue(&commitment);
        assert_ne!(c1, c2);
    }

    #[test]
    fn cid_has_expected_v1_raw_sha256_prefix() {
        let mut issuer = BenchIssuer::deterministic(1);
        let (receipt, cid) = issuer.issue(&benchmark_commitment(7));
        assert_eq!(&cid.bytes[..4], &[0x01, 0x55, 0x12, 0x20]);
        assert_eq!(cid, receipt_cid(&receipt));
    }
}
