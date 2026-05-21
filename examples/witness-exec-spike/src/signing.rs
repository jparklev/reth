//! Ed25519 sign/verify helpers shared by `witness-publisher` (signs) and
//! `witness-validator` / `witness-stream` (verify).
//!
//! Same shape as `bucket-state-client::verify_ed25519`: the signature is the
//! raw 64-byte detached signature over the exact bytes uploaded to S3. The
//! companion object lives at `<key>.sig` and contains only the 64-byte signature.
//!
//! The signing key is a 32-byte ed25519 seed (raw, no encoding). Loaded with
//! [`load_signing_key`]. Same format as `/var/lib/reth/relay-indexer/writer.key`.
//!
//! The verifying key is a 32-byte ed25519 public key. Loaded with
//! [`load_verifying_key`]. Same format as `writer-keys/<id>.pub` in the bucket.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use eyre::{eyre, WrapErr};
use std::path::Path;

/// Detached signature length (ed25519).
pub(crate) const SIG_LEN: usize = 64;

/// Load a 32-byte ed25519 seed from disk, return a [`SigningKey`].
#[allow(dead_code)] // publisher binary only
pub(crate) fn load_signing_key(path: &Path) -> eyre::Result<SigningKey> {
    let bytes = std::fs::read(path).wrap_err_with(|| format!("read {}", path.display()))?;
    if bytes.len() != 32 {
        return Err(eyre!("signing key must be 32 raw bytes, got {}", bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

/// Load a 32-byte ed25519 public key from disk.
#[allow(dead_code)] // validator binaries only
pub(crate) fn load_verifying_key(path: &Path) -> eyre::Result<VerifyingKey> {
    let bytes = std::fs::read(path).wrap_err_with(|| format!("read {}", path.display()))?;
    verifying_key_from_bytes(&bytes)
}

/// Parse a 32-byte ed25519 public key.
pub(crate) fn verifying_key_from_bytes(bytes: &[u8]) -> eyre::Result<VerifyingKey> {
    if bytes.len() != 32 {
        return Err(eyre!("verifying key must be 32 raw bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    VerifyingKey::from_bytes(&arr).wrap_err("invalid ed25519 pubkey")
}

/// Sign `payload` with `key`, return the raw 64-byte signature.
#[allow(dead_code)] // publisher binary only
pub(crate) fn sign(key: &SigningKey, payload: &[u8]) -> [u8; SIG_LEN] {
    key.sign(payload).to_bytes()
}

/// Verify `sig` against `payload` using `key`. Returns Ok on success.
#[allow(dead_code)] // validator binaries only
pub(crate) fn verify(key: &VerifyingKey, payload: &[u8], sig: &[u8]) -> eyre::Result<()> {
    if sig.len() != SIG_LEN {
        return Err(eyre!("signature must be {SIG_LEN} bytes, got {}", sig.len()));
    }
    let mut arr = [0u8; SIG_LEN];
    arr.copy_from_slice(sig);
    let signature = ed25519_dalek::Signature::from_bytes(&arr);
    key.verify(payload, &signature).wrap_err("signature verify failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut seed = [0u8; 32];
        seed[0] = 7;
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let payload = b"hello world";
        let sig = sign(&sk, payload);
        verify(&vk, payload, &sig).unwrap();
        // Tamper: flip one bit.
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(verify(&vk, payload, &bad).is_err());
    }
}
