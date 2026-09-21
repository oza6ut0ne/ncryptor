//! A file encryption CLI tool, built to be compatible in its command-line
//! options, encrypted output format, and key file format.

pub mod cli;
pub mod codec;
pub mod keys;
pub mod rsa_hybrid;
pub mod x25519;

use std::path::Path;

pub type Error = Box<dyn std::error::Error>;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    X25519,
    Rsa,
}

/// Encrypts plaintext. If `binary` is false, returns output compatible with
/// `base64.encodebytes`.
pub fn encrypt(
    plaintext: &[u8],
    algorithm: Algorithm,
    key_path: &Path,
    binary: bool,
) -> Result<Vec<u8>> {
    let payload = match algorithm {
        Algorithm::X25519 => x25519::encrypt(plaintext, key_path)?,
        Algorithm::Rsa => rsa_hybrid::encrypt(plaintext, key_path)?,
    };

    Ok(if binary {
        payload
    } else {
        codec::encode_b64_mime(&payload)
    })
}

/// Decrypts ciphertext. If `binary` is false, the input is treated as base64.
pub fn decrypt(
    encrypted: &[u8],
    algorithm: Algorithm,
    key_path: &Path,
    passphrase: Option<&str>,
    binary: bool,
) -> Result<Vec<u8>> {
    let payload = if binary {
        encrypted.to_vec()
    } else {
        codec::decode_b64_mime(encrypted)?
    };

    match algorithm {
        Algorithm::X25519 => x25519::decrypt(&payload, key_path, passphrase),
        Algorithm::Rsa => rsa_hybrid::decrypt(&payload, key_path, passphrase),
    }
}

/// Encrypts plaintext, detecting whether the key is RSA or X25519 from the
/// key file itself rather than requiring the caller to know in advance.
pub fn encrypt_auto(plaintext: &[u8], key_path: &Path, binary: bool) -> Result<Vec<u8>> {
    let der = keys::load_public_key(key_path)?;
    let payload = match keys::public_key_algorithm(&der)? {
        Algorithm::X25519 => x25519::encrypt_from_der(plaintext, der)?,
        Algorithm::Rsa => rsa_hybrid::encrypt_from_der(plaintext, der)?,
    };

    Ok(if binary {
        payload
    } else {
        codec::encode_b64_mime(&payload)
    })
}

/// Decrypts ciphertext, detecting whether the key is RSA or X25519 from the
/// key file itself rather than requiring the caller to know in advance. The
/// key is loaded exactly once, so a passphrase is prompted for at most once.
pub fn decrypt_auto(
    encrypted: &[u8],
    key_path: &Path,
    passphrase: Option<&str>,
    binary: bool,
) -> Result<Vec<u8>> {
    let payload = if binary {
        encrypted.to_vec()
    } else {
        codec::decode_b64_mime(encrypted)?
    };

    let der = keys::load_private_key(key_path, passphrase)?;
    match keys::private_key_algorithm(&der)? {
        Algorithm::X25519 => x25519::decrypt_from_der(&payload, der),
        Algorithm::Rsa => rsa_hybrid::decrypt_from_der(&payload, der),
    }
}

/// Writes out a key pair using an already-resolved passphrase (empty means
/// an unencrypted key). Does not prompt for overwrite confirmation.
pub fn generate_keypair(
    algorithm: Algorithm,
    path: &Path,
    rsa_bits: usize,
    passphrase: &str,
) -> Result<()> {
    let private_path = keys::resolve_path(path);
    let public_path = keys::with_pub_suffix(&private_path);
    write_keypair(algorithm, &private_path, &public_path, rsa_bits, passphrase)
}

/// Asks for overwrite confirmation if the keys already exist, prompts
/// interactively for a passphrase if needed, and writes out the key pair
/// (same order as `--generate-keys`).
pub fn generate_keypair_interactive(
    algorithm: Algorithm,
    path: &Path,
    rsa_bits: usize,
    passphrase: Option<&str>,
) -> Result<()> {
    let Some((private_path, public_path)) = keys::confirm_key_paths(path)? else {
        return Ok(());
    };
    let passphrase = keys::passphrase(passphrase)?;
    write_keypair(
        algorithm,
        &private_path,
        &public_path,
        rsa_bits,
        &passphrase,
    )
}

fn write_keypair(
    algorithm: Algorithm,
    private_path: &Path,
    public_path: &Path,
    rsa_bits: usize,
    passphrase: &str,
) -> Result<()> {
    let (private_pem, public_pem) = match algorithm {
        Algorithm::X25519 => x25519::generate(passphrase)?,
        Algorithm::Rsa => rsa_hybrid::generate(rsa_bits, passphrase)?,
    };

    keys::write_key_file(private_path, private_pem.as_bytes())?;
    keys::write_key_file(public_path, public_pem.as_bytes())?;
    Ok(())
}
