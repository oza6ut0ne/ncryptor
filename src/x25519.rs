//! The X25519 path, using HPKE (RFC 9180) base mode.
//!
//! Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM, `info = b"cryptor"`,
//! no AAD. Output is `enc(32) ‖ ciphertext ‖ tag(16)`.

use std::path::Path;

use hpke::aead::AesGcm256;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{
    Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _, single_shot_open,
    single_shot_seal,
};
use zeroize::Zeroizing;

use crate::keys::{self, PrivateKeyDer, PublicKeyDer, X25519_KEY_BYTES};
use crate::{Result, codec};

type Kem = X25519HkdfSha256;
type PublicKey = <Kem as hpke::Kem>::PublicKey;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;

const INFO: &[u8] = b"cryptor";

/// Length of the HPKE encapsulated key placed at the start of the ciphertext.
pub const ENC_BYTES: usize = X25519_KEY_BYTES;

pub fn encrypt(plaintext: &[u8], key_path: &Path) -> Result<Vec<u8>> {
    let public_key = match keys::load_public_key(key_path)? {
        PublicKeyDer::Spki(der) => keys::x25519_public_from_spki(&der)?,
        PublicKeyDer::Pkcs1Rsa(_) => {
            return Err("the key file holds an RSA public key; use --rsa".into());
        }
    };
    let public_key = PublicKey::from_bytes(&public_key)?;

    let compressed = codec::zlib_compress(plaintext);
    let (enc, ciphertext) = single_shot_seal::<AesGcm256, HkdfSha256, Kem>(
        &OpModeS::Base,
        &public_key,
        INFO,
        &compressed,
        b"",
    )?;

    let mut payload = enc.to_bytes().to_vec();
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

pub fn decrypt(payload: &[u8], key_path: &Path, passphrase: Option<&str>) -> Result<Vec<u8>> {
    if payload.len() < ENC_BYTES {
        return Err("the encrypted message is too short to hold an encapsulated key".into());
    }
    let (enc, ciphertext) = payload.split_at(ENC_BYTES);

    let secret = match keys::load_private_key(key_path, passphrase)? {
        PrivateKeyDer::Pkcs8(der) => keys::x25519_secret_from_pkcs8(&der)?,
        PrivateKeyDer::Pkcs1Rsa(_) => {
            return Err("the key file holds an RSA private key; use --rsa".into());
        }
    };
    let secret = PrivateKey::from_bytes(&*secret)?;
    let enc = EncappedKey::from_bytes(enc)?;

    let compressed = single_shot_open::<AesGcm256, HkdfSha256, Kem>(
        &OpModeR::Base,
        &secret,
        &enc,
        INFO,
        ciphertext,
        b"",
    )?;
    codec::zlib_decompress(&compressed)
}

/// Returns the private and public key PEMs.
pub fn generate(passphrase: &str) -> Result<(Zeroizing<String>, String)> {
    let (secret, public) = Kem::gen_keypair();

    let mut secret_bytes = Zeroizing::new([0u8; X25519_KEY_BYTES]);
    secret_bytes.copy_from_slice(&secret.to_bytes());
    let public_bytes: [u8; X25519_KEY_BYTES] = public.to_bytes().into();

    let pkcs8 = keys::x25519_secret_to_pkcs8(&secret_bytes)?;
    let spki = keys::x25519_public_to_spki(&public_bytes)?;

    Ok((
        keys::private_key_pem(&pkcs8, passphrase)?,
        keys::public_key_pem(&spki),
    ))
}
