//! Standalone round-trip tests for `ncryptor`.
//! Checks that encryption, decryption, and key I/O are self-consistent.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use ncryptor::{Algorithm, codec, keys};
use tempfile::TempDir;

/// RSA key generation is expensive, so the passphrase-less key is shared
/// across all tests.
const RSA_BITS: usize = 2048;

fn sample_payloads() -> Vec<Vec<u8>> {
    vec![
        Vec::new(),
        b"A".to_vec(),
        b"hello cryptor\n".to_vec(),
        // Both compressible and incompressible data.
        vec![b'x'; 300_000],
        (0..100_000u32)
            .map(|i| i.wrapping_mul(2654435761) as u8)
            .collect(),
    ]
}

fn make_keypair(dir: &Path, name: &str, algorithm: Algorithm, passphrase: &str) -> PathBuf {
    let path = dir.join(name);
    ncryptor::generate_keypair(algorithm, &path, RSA_BITS, passphrase).unwrap();
    path
}

fn shared_rsa_key() -> &'static Path {
    static KEY: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    let (_dir, path) = KEY.get_or_init(|| {
        let dir = TempDir::new().unwrap();
        let path = make_keypair(dir.path(), "rsa", Algorithm::Rsa, "");
        (dir, path)
    });
    path
}

fn public_of(private: &Path) -> PathBuf {
    keys::with_pub_suffix(private)
}

fn roundtrip(algorithm: Algorithm, private: &Path, passphrase: Option<&str>) {
    let public = public_of(private);
    for binary in [false, true] {
        for payload in sample_payloads() {
            let encrypted = ncryptor::encrypt(&payload, algorithm, &public, binary).unwrap();
            let decrypted =
                ncryptor::decrypt(&encrypted, algorithm, private, passphrase, binary).unwrap();
            assert_eq!(decrypted, payload, "binary={binary} len={}", payload.len());
        }
    }
}

#[test]
fn x25519_roundtrip() {
    let dir = TempDir::new().unwrap();
    let key = make_keypair(dir.path(), "cryptor", Algorithm::X25519, "");
    roundtrip(Algorithm::X25519, &key, None);
}

#[test]
fn x25519_roundtrip_with_passphrase() {
    let dir = TempDir::new().unwrap();
    let key = make_keypair(dir.path(), "cryptor", Algorithm::X25519, "s3cret");
    roundtrip(Algorithm::X25519, &key, Some("s3cret"));
}

#[test]
fn rsa_roundtrip() {
    let key = shared_rsa_key();
    roundtrip(Algorithm::Rsa, key, None);
}

#[test]
fn rsa_roundtrip_with_passphrase() {
    let dir = TempDir::new().unwrap();
    let key = make_keypair(dir.path(), "cryptor", Algorithm::Rsa, "s3cret");
    roundtrip(Algorithm::Rsa, &key, Some("s3cret"));
}

#[test]
fn base64_output_matches_encodebytes_layout() {
    let dir = TempDir::new().unwrap();
    let key = make_keypair(dir.path(), "cryptor", Algorithm::X25519, "");

    let encrypted = ncryptor::encrypt(
        &vec![b'z'; 10_000],
        Algorithm::X25519,
        &public_of(&key),
        false,
    )
    .unwrap();
    let text = String::from_utf8(encrypted.clone()).unwrap();

    assert!(text.ends_with('\n'), "output must end with a newline");
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    assert!(
        lines.len() > 1,
        "a long payload should wrap onto several lines"
    );
    for line in &lines[..lines.len() - 1] {
        assert_eq!(line.len(), 76, "every full line is 76 characters wide");
    }
    assert!(lines.last().unwrap().len() <= 76);

    // Decryption still works with newlines and whitespace mixed in.
    let messy = text.replace('\n', "\r\n \t");
    let decrypted =
        ncryptor::decrypt(messy.as_bytes(), Algorithm::X25519, &key, None, false).unwrap();
    assert_eq!(decrypted, vec![b'z'; 10_000]);
}

#[test]
fn empty_input_encodes_to_empty_base64() {
    assert!(codec::encode_b64_mime(b"").is_empty());
}

#[test]
fn tampered_messages_are_rejected() {
    let dir = TempDir::new().unwrap();
    let key = make_keypair(dir.path(), "cryptor", Algorithm::X25519, "");
    let public = public_of(&key);
    let encrypted = ncryptor::encrypt(b"top secret", Algorithm::X25519, &public, true).unwrap();

    let mut flipped_tag = encrypted.clone();
    *flipped_tag.last_mut().unwrap() ^= 1;
    let mut flipped_enc = encrypted.clone();
    flipped_enc[0] ^= 1;
    let truncated = encrypted[..x25519_enc_bytes() - 1].to_vec();

    for (name, broken) in [
        ("flipped tag", flipped_tag),
        ("flipped encapsulated key", flipped_enc),
        ("truncated", truncated),
    ] {
        assert!(
            ncryptor::decrypt(&broken, Algorithm::X25519, &key, None, true).is_err(),
            "{name} should not decrypt"
        );
    }
}

fn x25519_enc_bytes() -> usize {
    ncryptor::x25519::ENC_BYTES
}

#[test]
fn wrong_passphrase_is_rejected() {
    let dir = TempDir::new().unwrap();
    let key = make_keypair(dir.path(), "cryptor", Algorithm::X25519, "s3cret");
    let encrypted = ncryptor::encrypt(b"hello", Algorithm::X25519, &public_of(&key), true).unwrap();

    assert!(ncryptor::decrypt(&encrypted, Algorithm::X25519, &key, Some("wrong"), true).is_err());
}

/// Tests that read `NCRYPTOR_PASSPHRASE` / `CRYPTOR_PASSPHRASE` /
/// `NCRYPTOR_RSA` / `CRYPTOR_RSA` mutate process-wide environment state, so
/// they are serialized with a mutex to avoid racing other tests.
fn env_var_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn passphrase_prefers_ncryptor_env_var_over_cryptor_env_var() {
    let _guard = env_var_lock().lock().unwrap();
    unsafe {
        std::env::set_var("NCRYPTOR_PASSPHRASE", "new-style");
        std::env::set_var("CRYPTOR_PASSPHRASE", "old-style");
    }
    let result = keys::passphrase(None);
    unsafe {
        std::env::remove_var("NCRYPTOR_PASSPHRASE");
        std::env::remove_var("CRYPTOR_PASSPHRASE");
    }
    assert_eq!(result.unwrap().as_str(), "new-style");
}

#[test]
fn passphrase_falls_back_to_cryptor_env_var() {
    let _guard = env_var_lock().lock().unwrap();
    unsafe {
        std::env::remove_var("NCRYPTOR_PASSPHRASE");
        std::env::set_var("CRYPTOR_PASSPHRASE", "old-style");
    }
    let result = keys::passphrase(None);
    unsafe {
        std::env::remove_var("CRYPTOR_PASSPHRASE");
    }
    assert_eq!(result.unwrap().as_str(), "old-style");
}

#[test]
fn passphrase_argument_takes_priority_over_both_env_vars() {
    let _guard = env_var_lock().lock().unwrap();
    unsafe {
        std::env::set_var("NCRYPTOR_PASSPHRASE", "new-style");
        std::env::set_var("CRYPTOR_PASSPHRASE", "old-style");
    }
    let result = keys::passphrase(Some("explicit"));
    unsafe {
        std::env::remove_var("NCRYPTOR_PASSPHRASE");
        std::env::remove_var("CRYPTOR_PASSPHRASE");
    }
    assert_eq!(result.unwrap().as_str(), "explicit");
}

#[test]
fn rsa_from_env_recognizes_truthy_values() {
    let _guard = env_var_lock().lock().unwrap();
    for value in ["1", "true", "TRUE", "yes", "on"] {
        unsafe {
            std::env::set_var("NCRYPTOR_RSA", value);
        }
        assert!(keys::rsa_from_env(), "{value:?} should be truthy");
    }
    for value in ["0", "false", "no", "off", ""] {
        unsafe {
            std::env::set_var("NCRYPTOR_RSA", value);
        }
        assert!(!keys::rsa_from_env(), "{value:?} should be falsy");
    }
    unsafe {
        std::env::remove_var("NCRYPTOR_RSA");
    }
    assert!(!keys::rsa_from_env(), "unset should be falsy");
}

#[test]
fn rsa_from_env_prefers_ncryptor_rsa_over_cryptor_rsa() {
    let _guard = env_var_lock().lock().unwrap();
    unsafe {
        std::env::set_var("NCRYPTOR_RSA", "0");
        std::env::set_var("CRYPTOR_RSA", "1");
    }
    let result = keys::rsa_from_env();
    unsafe {
        std::env::remove_var("NCRYPTOR_RSA");
        std::env::remove_var("CRYPTOR_RSA");
    }
    assert!(
        result,
        "CRYPTOR_RSA should still be checked when NCRYPTOR_RSA is falsy"
    );
}

#[test]
fn rsa_bits_below_the_minimum_are_rejected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tiny");
    assert!(ncryptor::generate_keypair(Algorithm::Rsa, &path, 512, "").is_err());
}

#[test]
fn a_missing_key_file_is_reported_with_its_path() {
    let dir = TempDir::new().unwrap();
    let missing = dir.path().join("nope.pub");
    let error = ncryptor::encrypt(b"hi", Algorithm::X25519, &missing, false).unwrap_err();
    assert!(
        error.to_string().contains("nope.pub"),
        "error should name the file: {error}"
    );
}

#[test]
fn using_an_rsa_key_without_the_rsa_flag_is_reported() {
    let key = shared_rsa_key();
    let error = ncryptor::encrypt(b"hi", Algorithm::X25519, &public_of(key), false).unwrap_err();
    assert!(
        error.to_string().contains("--rsa"),
        "unexpected error: {error}"
    );
}

#[test]
fn x25519_key_files_use_the_expected_encoding() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = TempDir::new().unwrap();
    let key = make_keypair(dir.path(), "cryptor", Algorithm::X25519, "");
    let public = public_of(&key);

    let private_pem = std::fs::read_to_string(&key).unwrap();
    assert!(private_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert!(private_pem.ends_with("-----END PRIVATE KEY-----"));

    let public_pem = std::fs::read_to_string(&public).unwrap();
    assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    assert!(public_pem.ends_with("-----END PUBLIC KEY-----"));

    // Fixed header (RFC 8410, OID 1.3.101.110).
    let private_der = pem_body(&private_pem);
    assert_eq!(private_der.len(), 48);
    assert_eq!(
        &private_der[..16],
        &[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22,
            0x04, 0x20
        ]
    );

    let public_der = pem_body(&public_pem);
    assert_eq!(public_der.len(), 44);
    assert_eq!(
        &public_der[..12],
        &[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
        ]
    );

    for path in [&key, &public] {
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "{} must not be group/world readable",
            path.display()
        );
    }
}

#[test]
fn passphrase_protected_keys_are_pkcs8_encrypted() {
    let dir = TempDir::new().unwrap();
    let key = make_keypair(dir.path(), "cryptor", Algorithm::X25519, "s3cret");
    let pem = std::fs::read_to_string(&key).unwrap();
    assert!(
        pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"),
        "{pem}"
    );
}

#[test]
fn rsa_private_keys_are_pkcs1_without_a_passphrase() {
    let pem = std::fs::read_to_string(shared_rsa_key()).unwrap();
    assert!(
        pem.starts_with("-----BEGIN RSA PRIVATE KEY-----\n"),
        "{pem}"
    );
}

#[test]
fn the_public_key_path_replaces_the_last_extension() {
    assert_eq!(
        keys::with_pub_suffix(Path::new("/tmp/cryptor")),
        Path::new("/tmp/cryptor.pub")
    );
    assert_eq!(
        keys::with_pub_suffix(Path::new("/tmp/cryptor.key")),
        Path::new("/tmp/cryptor.pub")
    );
    assert_eq!(
        keys::with_pub_suffix(Path::new("/tmp/a.tar.gz")),
        Path::new("/tmp/a.tar.pub")
    );
}

fn pem_body(pem: &str) -> Vec<u8> {
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap()
}
