//! Ed25519 sign helpers — same format as the spike's `signing.rs`. 32-byte raw
//! seed on disk, 64-byte detached signature for each uploaded object.

use ed25519_dalek::{Signer, SigningKey};
use eyre::{eyre, WrapErr};
use std::path::Path;

pub(crate) const SIG_LEN: usize = 64;

pub(crate) fn load_signing_key(path: &Path) -> eyre::Result<SigningKey> {
    let bytes = std::fs::read(path).wrap_err_with(|| format!("read {}", path.display()))?;
    if bytes.len() != 32 {
        return Err(eyre!("signing key must be 32 raw bytes, got {}", bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

pub(crate) fn sign(key: &SigningKey, payload: &[u8]) -> [u8; SIG_LEN] {
    key.sign(payload).to_bytes()
}
