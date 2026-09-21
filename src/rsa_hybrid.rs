//! The RSA path: RSA-OAEP wraps a session key, and the body is encrypted with
//! AES-256-EAX.
//!
//! OAEP uses SHA-1 (MGF1 is also SHA-1, with an empty label).
//! Output is `encrypted_session_key(k) ‖ nonce(16) ‖ tag(16) ‖ ciphertext`.

use std::path::Path;

use aes::Aes256;
use eax::Eax;
use eax::aead::array::Array;
use eax::aead::{AeadInOut as _, KeyInit as _};
use rsa::pkcs1::{DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _, EncodeRsaPrivateKey as _};
use rsa::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _, EncodePublicKey as _};
use rsa::rand_core::{OsRng, RngCore as _};
use rsa::traits::PublicKeyParts as _;
use rsa::{BigUint, Oaep, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::keys::{self, PrivateKeyDer, PublicKeyDer};
use crate::{Result, codec};

type Aes256Eax = Eax<Aes256>;

const AES_KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 16;
pub const TAG_BYTES: usize = 16;

/// RSA key generation constraints and public exponent.
const MIN_RSA_BITS: usize = 1024;
const PUBLIC_EXPONENT: u32 = 65537;

pub fn encrypt(plaintext: &[u8], key_path: &Path) -> Result<Vec<u8>> {
    let public_key = load_public_key(key_path)?;
    encrypt_with_key(plaintext, &public_key)
}

pub(crate) fn encrypt_from_der(plaintext: &[u8], der: PublicKeyDer) -> Result<Vec<u8>> {
    encrypt_with_key(plaintext, &rsa_public_from_der(der)?)
}

fn encrypt_with_key(plaintext: &[u8], public_key: &RsaPublicKey) -> Result<Vec<u8>> {
    let mut session_key = Zeroizing::new([0u8; AES_KEY_BYTES]);
    let mut nonce = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut *session_key);
    OsRng.fill_bytes(&mut nonce);

    let mut ciphertext = codec::zlib_compress(plaintext);
    let cipher = Aes256Eax::new(&Array::from(*session_key));
    let tag = cipher.encrypt_inout_detached(
        &Array::from(nonce),
        b"",
        ciphertext.as_mut_slice().into(),
    )?;

    let encrypted_session_key =
        public_key.encrypt(&mut OsRng, Oaep::new::<Sha1>(), session_key.as_slice())?;

    let mut payload = encrypted_session_key;
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&tag);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

pub fn decrypt(payload: &[u8], key_path: &Path, passphrase: Option<&str>) -> Result<Vec<u8>> {
    let private_key = load_private_key(key_path, passphrase)?;
    decrypt_with_key(payload, private_key)
}

pub(crate) fn decrypt_from_der(payload: &[u8], der: PrivateKeyDer) -> Result<Vec<u8>> {
    decrypt_with_key(payload, rsa_from_der(der)?)
}

fn decrypt_with_key(payload: &[u8], private_key: RsaPrivateKey) -> Result<Vec<u8>> {
    let key_bytes = private_key.size();

    let header = key_bytes + NONCE_BYTES + TAG_BYTES;
    if payload.len() < header {
        return Err("the encrypted message is too short for this RSA key".into());
    }

    let (encrypted_session_key, rest) = payload.split_at(key_bytes);
    let (nonce, rest) = rest.split_at(NONCE_BYTES);
    let (tag, ciphertext) = rest.split_at(TAG_BYTES);

    let session_key =
        Zeroizing::new(private_key.decrypt(Oaep::new::<Sha1>(), encrypted_session_key)?);
    if session_key.len() != AES_KEY_BYTES {
        return Err("the encrypted session key has an unexpected length".into());
    }

    let mut key = Zeroizing::new([0u8; AES_KEY_BYTES]);
    key.copy_from_slice(&session_key);
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
        .map_err(|_| "the encrypted message is not authentic (wrong key or corrupt input)")?;

    codec::zlib_decompress(&plaintext)
}

/// Returns the private and public key PEMs.
pub fn generate(bits: usize, passphrase: &str) -> Result<(Zeroizing<String>, String)> {
    if bits < MIN_RSA_BITS {
        return Err(format!("RSA modulus length must be >= {MIN_RSA_BITS}").into());
    }

    let private_key =
        RsaPrivateKey::new_with_exp(&mut OsRng, bits, &BigUint::from(PUBLIC_EXPONENT))?;
    let public_pem = keys::public_key_pem(
        RsaPublicKey::from(&private_key)
            .to_public_key_der()?
            .as_bytes(),
    );

    // PKCS#1 with no passphrase, or PBES2-encrypted PKCS#8 if one was given.
    let private_pem = if passphrase.is_empty() {
        keys::rsa_pkcs1_private_key_pem(private_key.to_pkcs1_der()?.as_bytes())
    } else {
        let pkcs8 = Zeroizing::new(
            rsa::pkcs8::EncodePrivateKey::to_pkcs8_der(&private_key)?
                .as_bytes()
                .to_vec(),
        );
        keys::private_key_pem(&pkcs8, passphrase)?
    };

    Ok((private_pem, public_pem))
}

fn load_public_key(key_path: &Path) -> Result<RsaPublicKey> {
    rsa_public_from_der(keys::load_public_key(key_path)?)
}

fn rsa_public_from_der(der: PublicKeyDer) -> Result<RsaPublicKey> {
    Ok(match der {
        PublicKeyDer::Spki(der) => {
            keys::check_algorithm(keys::spki_algorithm(&der)?, keys::RSA_OID)?;
            RsaPublicKey::from_public_key_der(&der)?
        }
        PublicKeyDer::Pkcs1Rsa(der) => RsaPublicKey::from_pkcs1_der(&der)?,
    })
}

fn load_private_key(key_path: &Path, passphrase: Option<&str>) -> Result<RsaPrivateKey> {
    rsa_from_der(keys::load_private_key(key_path, passphrase)?)
}

fn rsa_from_der(der: PrivateKeyDer) -> Result<RsaPrivateKey> {
    Ok(match der {
        PrivateKeyDer::Pkcs8(der) => {
            keys::check_algorithm(keys::pkcs8_algorithm(&der)?, keys::RSA_OID)?;
            RsaPrivateKey::from_pkcs8_der(&der)?
        }
        PrivateKeyDer::Pkcs1Rsa(der) => RsaPrivateKey::from_pkcs1_der(&der)?,
    })
}
