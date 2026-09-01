//! Non-mutating firmware signature verification.

use digest::Digest;
use embedded_storage::nor_flash::ReadNorFlash;
use embedded_storage_async::nor_flash::ReadNorFlash as AsyncReadNorFlash;

use crate::FirmwareUpdaterError;
#[cfg(feature = "ed25519-dalek")]
use crate::digest_adapters::ed25519_dalek::Sha512;
#[cfg(all(feature = "ed25519-salty", not(feature = "ed25519-dalek")))]
use crate::digest_adapters::salty::Sha512;

/// Verify an Ed25519 signature over the SHA-512 digest of a flash range.
#[cfg(feature = "_verify")]
pub fn verify_firmware<F: ReadNorFlash>(
    flash: &mut F,
    offset: u32,
    length: u32,
    scratch: &mut [u8],
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), FirmwareUpdaterError> {
    let digest = hash_firmware(flash, offset, length, scratch)?;
    verify_digest(public_key, signature, &digest)
}

/// Async variant of [`verify_firmware`].
#[cfg(feature = "_verify")]
pub async fn verify_firmware_async<F: AsyncReadNorFlash>(
    flash: &mut F,
    offset: u32,
    length: u32,
    scratch: &mut [u8],
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), FirmwareUpdaterError> {
    assert_valid_range(flash.capacity(), offset, length, scratch.len(), F::READ_SIZE);

    let mut digest = Sha512::new();
    let end = offset + length;
    let mut current = offset;
    while current < end {
        let remaining = (end - current) as usize;
        let read_len = remaining.min(scratch.len());
        let aligned_len = read_len.div_ceil(F::READ_SIZE) * F::READ_SIZE;
        flash.read(current, &mut scratch[..aligned_len]).await?;
        digest.update(&scratch[..read_len]);
        current += read_len as u32;
    }

    let digest = digest.finalize();
    verify_digest(public_key, signature, &digest)
}

#[cfg(feature = "_verify")]
fn hash_firmware<F: ReadNorFlash>(
    flash: &mut F,
    offset: u32,
    length: u32,
    scratch: &mut [u8],
) -> Result<[u8; 64], FirmwareUpdaterError> {
    assert_valid_range(flash.capacity(), offset, length, scratch.len(), F::READ_SIZE);

    let mut digest = Sha512::new();
    let end = offset + length;
    let mut current = offset;
    while current < end {
        let remaining = (end - current) as usize;
        let read_len = remaining.min(scratch.len());
        let aligned_len = read_len.div_ceil(F::READ_SIZE) * F::READ_SIZE;
        flash.read(current, &mut scratch[..aligned_len])?;
        digest.update(&scratch[..read_len]);
        current += read_len as u32;
    }

    Ok(digest.finalize().into())
}

#[cfg(feature = "_verify")]
fn assert_valid_range(capacity: usize, offset: u32, length: u32, scratch_len: usize, read_size: usize) {
    assert!(scratch_len >= read_size);
    assert_eq!(scratch_len % read_size, 0);
    assert_eq!(offset as usize % read_size, 0);
    let aligned_length = (length as usize).div_ceil(read_size) * read_size;
    assert!(offset as usize + aligned_length <= capacity);
}

#[cfg(feature = "ed25519-dalek")]
fn verify_digest(public_key: &[u8; 32], signature: &[u8; 64], digest: &[u8]) -> Result<(), FirmwareUpdaterError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let signature = Signature::from_bytes(signature);
    let public_key = VerifyingKey::from_bytes(public_key).map_err(FirmwareUpdaterError::Signature)?;
    public_key
        .verify(digest, &signature)
        .map_err(FirmwareUpdaterError::Signature)
}

#[cfg(all(feature = "ed25519-salty", not(feature = "ed25519-dalek")))]
fn verify_digest(public_key: &[u8; 32], signature: &[u8; 64], digest: &[u8]) -> Result<(), FirmwareUpdaterError> {
    use salty::{PublicKey, Signature};

    let signature =
        Signature::try_from(signature).map_err(|_| FirmwareUpdaterError::Signature(signature::Error::new()))?;
    let public_key =
        PublicKey::try_from(public_key).map_err(|_| FirmwareUpdaterError::Signature(signature::Error::new()))?;
    public_key
        .verify(digest, &signature)
        .map_err(|_| FirmwareUpdaterError::Signature(signature::Error::new()))
}
