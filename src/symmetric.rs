//! The symmetric path: a passphrase-derived AES-256-EAX key, with no
//! asymmetric keypair involved.
//!
//! Key derivation is PBKDF2-HMAC-SHA512 (16-byte salt, 1,000,000 iterations).
//! Output is `SYM-` ‖ salt(16) ‖ nonce(16) ‖ tag(16) ‖ ciphertext.

use aes::Aes256;
use eax::Eax;
use eax::aead::array::Array;
use eax::aead::{AeadInOut as _, KeyInit as _};
use pbkdf2::pbkdf2_hmac;
use rsa::rand_core::{OsRng, RngCore as _};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::{Result, codec};

type Aes256Eax = Eax<Aes256>;

const AES_KEY_BYTES: usize = 32;
pub const SALT_BYTES: usize = 16;
pub const NONCE_BYTES: usize = 16;
pub const TAG_BYTES: usize = 16;
const ITERATION_COUNT: u32 = 1_000_000;

/// Prefix that marks a payload as symmetrically encrypted.
pub const MARKER: &[u8] = b"SYM-";

/// Reports whether `payload` looks like a symmetrically-encrypted message,
/// used to auto-detect the algorithm on decrypt.
pub fn is_symmetric_payload(payload: &[u8]) -> bool {
    payload.starts_with(MARKER)
}

pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_BYTES];
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt);

    let mut ciphertext = codec::zlib_compress(plaintext);
    let cipher = Aes256Eax::new(&Array::from(*key));
    let tag = cipher.encrypt_inout_detached(
        &Array::from(nonce),
        b"",
        ciphertext.as_mut_slice().into(),
    )?;

    let mut payload = MARKER.to_vec();
    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&tag);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

pub fn decrypt(payload: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let payload = payload
        .strip_prefix(MARKER)
        .ok_or("not a symmetrically-encrypted message")?;

    let header = SALT_BYTES + NONCE_BYTES + TAG_BYTES;
    if payload.len() < header {
        return Err("the encrypted message is too short".into());
    }

    let (salt, rest) = payload.split_at(SALT_BYTES);
    let (nonce, rest) = rest.split_at(NONCE_BYTES);
    let (tag, ciphertext) = rest.split_at(TAG_BYTES);

    let key = derive_key(passphrase, salt);
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().expect("split_at guarantees the length");
    let tag: [u8; TAG_BYTES] = tag.try_into().expect("split_at guarantees the length");

    let mut plaintext = ciphertext.to_vec();
    let cipher = Aes256Eax::new(&Array::from(*key));
    cipher
        .decrypt_inout_detached(
            &Array::from(nonce),
            b"",
            plaintext.as_mut_slice().into(),
            &Array::from(tag),
        )
        .map_err(|_| "the encrypted message is not authentic (wrong passphrase or corrupt input)")?;

    codec::zlib_decompress(&plaintext)
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Zeroizing<[u8; AES_KEY_BYTES]> {
    let mut key = Zeroizing::new([0u8; AES_KEY_BYTES]);
    pbkdf2_hmac::<Sha512>(passphrase.as_bytes(), salt, ITERATION_COUNT, &mut *key);
    key
}
