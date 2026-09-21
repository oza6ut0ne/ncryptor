//! Key file I/O. Handles PEM/DER formats.

use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use pkcs8::der::asn1::{BitStringRef, OctetString, OctetStringRef};
use pkcs8::der::oid::ObjectIdentifier;
use pkcs8::der::{Decode as _, Encode as _};
use pkcs8::pkcs5::pbes2::{EncryptionScheme, Kdf, Parameters, Pbkdf2Params, Pbkdf2Prf};
use pkcs8::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use pkcs8::{EncryptedPrivateKeyInfoRef, PrivateKeyInfoRef};
use rsa::rand_core::{OsRng, RngCore as _};
use zeroize::Zeroizing;

use crate::Result;

/// The RFC 8410 X25519 algorithm identifier.
pub const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

/// The PKCS#1 `rsaEncryption` algorithm identifier.
pub const RSA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// Length in bytes of an X25519 private or public key.
pub const X25519_KEY_BYTES: usize = 32;

/// PBES2 parameters.
const PBKDF2_ITERATION_COUNT: u32 = 131_072;
const SALT_BYTES: usize = 8;
const IV_BYTES: usize = 16;

const KEY_PERMISSION: u32 = 0o600;
/// Prefer `NCRYPTOR_PASSPHRASE`, falling back to `CRYPTOR_PASSPHRASE`.
const PASSPHRASE_ENV_VARS: [&str; 2] = ["NCRYPTOR_PASSPHRASE", "CRYPTOR_PASSPHRASE"];

const PEM_PRIVATE_KEY: &str = "PRIVATE KEY";
const PEM_ENCRYPTED_PRIVATE_KEY: &str = "ENCRYPTED PRIVATE KEY";
const PEM_RSA_PRIVATE_KEY: &str = "RSA PRIVATE KEY";
const PEM_PUBLIC_KEY: &str = "PUBLIC KEY";
const PEM_RSA_PUBLIC_KEY: &str = "RSA PUBLIC KEY";

/// The DER representation of a loaded private key.
pub enum PrivateKeyDer {
    /// PKCS#8 `PrivateKeyInfo`
    Pkcs8(Zeroizing<Vec<u8>>),
    /// PKCS#1 `RSAPrivateKey`
    Pkcs1Rsa(Zeroizing<Vec<u8>>),
}

/// The DER representation of a loaded public key.
pub enum PublicKeyDer {
    /// X.509 `SubjectPublicKeyInfo`
    Spki(Vec<u8>),
    /// PKCS#1 `RSAPublicKey`
    Pkcs1Rsa(Vec<u8>),
}

// ---------------------------------------------------------------- Path resolution

pub fn default_private_key() -> PathBuf {
    resolve_path(Path::new("~/.ssh/cryptor"))
}

pub fn default_public_key() -> PathBuf {
    with_pub_suffix(&default_private_key())
}

/// Replaces the trailing extension with `.pub`, or appends it if there is none.
pub fn with_pub_suffix(path: &Path) -> PathBuf {
    let mut path = path.to_path_buf();
    path.set_extension("pub");
    path
}

/// Expands a path to an absolute, normalized form. Normalization is purely
/// lexical (symlinks are not resolved) so it also works for paths that don't
/// exist yet.
pub fn resolve_path(path: &Path) -> PathBuf {
    let expanded = expand_user(path);
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir().unwrap_or_default().join(expanded)
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn expand_user(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    let rest = if text == "~" {
        ""
    } else if let Some(rest) = text.strip_prefix("~/") {
        rest
    } else {
        return path.to_path_buf();
    };

    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(rest),
        None => path.to_path_buf(),
    }
}

// ------------------------------------------------------------ Passphrase

/// Resolves the passphrase in order: `-p` → `NCRYPTOR_PASSPHRASE` →
/// `CRYPTOR_PASSPHRASE` → interactive prompt. An empty string means "no
/// passphrase".
pub fn passphrase(argument: Option<&str>) -> Result<Zeroizing<String>> {
    if let Some(given) = argument.filter(|value| !value.is_empty()) {
        return Ok(Zeroizing::new(given.to_owned()));
    }
    for var in PASSPHRASE_ENV_VARS {
        if let Some(from_env) = std::env::var(var).ok().filter(|v| !v.is_empty()) {
            return Ok(Zeroizing::new(from_env));
        }
    }
    Ok(Zeroizing::new(prompt_passphrase()?))
}

/// Reads from the terminal first, falling back to stdin if no terminal is
/// available.
fn prompt_passphrase() -> Result<String> {
    match rpassword::prompt_password("Passphrase: ") {
        Ok(entered) => Ok(entered),
        Err(_) => {
            eprint!("Passphrase: ");
            std::io::stderr().flush()?;
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            Ok(line.trim_end_matches(['\n', '\r']).to_owned())
        }
    }
}

// -------------------------------------------------------------------- PEM

struct Pem {
    label: String,
    der: Vec<u8>,
}

fn parse_pem(data: &[u8]) -> Result<Pem> {
    let text = std::str::from_utf8(data).map_err(|_| "key file is not valid UTF-8")?;

    let mut label = None;
    let mut body = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(found) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
        {
            label = Some(found.to_owned());
            body.clear();
        } else if line.starts_with("-----END ") {
            break;
        } else if label.is_some() {
            body.push_str(line);
        }
    }

    let label = label.ok_or("no PEM block found in key file")?;
    Ok(Pem {
        label,
        der: STANDARD.decode(body)?,
    })
}

/// Builds a PEM block wrapped at 64 characters with no trailing newline.
fn encode_pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----"));
    out
}

// --------------------------------------------------------------- Loading

pub fn load_private_key(path: &Path, given_passphrase: Option<&str>) -> Result<PrivateKeyDer> {
    let path = resolve_path(path);
    let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let pem = parse_pem(&data)?;

    match pem.label.as_str() {
        PEM_PRIVATE_KEY => Ok(PrivateKeyDer::Pkcs8(Zeroizing::new(pem.der))),
        PEM_RSA_PRIVATE_KEY => Ok(PrivateKeyDer::Pkcs1Rsa(Zeroizing::new(pem.der))),
        PEM_ENCRYPTED_PRIVATE_KEY => {
            let passphrase = passphrase(given_passphrase)?;
            let encrypted = EncryptedPrivateKeyInfoRef::try_from(pem.der.as_slice())
                .map_err(|e| format!("{}: {e}", path.display()))?;
            let decrypted = encrypted
                .decrypt(passphrase.as_bytes())
                .map_err(|_| "could not decrypt the private key (wrong passphrase?)")?;
            Ok(PrivateKeyDer::Pkcs8(Zeroizing::new(
                decrypted.as_bytes().to_vec(),
            )))
        }
        other => Err(format!("unsupported PEM block '{other}' in {}", path.display()).into()),
    }
}

pub fn load_public_key(path: &Path) -> Result<PublicKeyDer> {
    let path = resolve_path(path);
    let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let pem = parse_pem(&data)?;

    match pem.label.as_str() {
        PEM_PUBLIC_KEY => Ok(PublicKeyDer::Spki(pem.der)),
        PEM_RSA_PUBLIC_KEY => Ok(PublicKeyDer::Pkcs1Rsa(pem.der)),
        other => Err(format!("unsupported PEM block '{other}' in {}", path.display()).into()),
    }
}

/// Extracts the 32-byte X25519 private key from a PKCS#8 `PrivateKeyInfo`.
pub fn x25519_secret_from_pkcs8(der: &[u8]) -> Result<Zeroizing<[u8; X25519_KEY_BYTES]>> {
    let info = PrivateKeyInfoRef::try_from(der)?;
    check_algorithm(info.algorithm.oid, X25519_OID)?;

    // RFC 8410's CurvePrivateKey is an OCTET STRING nested inside another.
    let curve_private_key = OctetString::from_der(info.private_key.as_bytes())?;
    let mut secret = Zeroizing::new([0u8; X25519_KEY_BYTES]);
    if curve_private_key.as_bytes().len() != X25519_KEY_BYTES {
        return Err("X25519 private key has an unexpected length".into());
    }
    secret.copy_from_slice(curve_private_key.as_bytes());
    Ok(secret)
}

/// Extracts the 32-byte X25519 public key from a `SubjectPublicKeyInfo`.
pub fn x25519_public_from_spki(der: &[u8]) -> Result<[u8; X25519_KEY_BYTES]> {
    let info = SubjectPublicKeyInfoRef::try_from(der)?;
    check_algorithm(info.algorithm.oid, X25519_OID)?;

    let bytes = info
        .subject_public_key
        .as_bytes()
        .ok_or("X25519 public key is not octet-aligned")?;
    bytes
        .try_into()
        .map_err(|_| "X25519 public key has an unexpected length".into())
}

pub fn spki_algorithm(der: &[u8]) -> Result<ObjectIdentifier> {
    Ok(SubjectPublicKeyInfoRef::try_from(der)?.algorithm.oid)
}

pub fn pkcs8_algorithm(der: &[u8]) -> Result<ObjectIdentifier> {
    Ok(PrivateKeyInfoRef::try_from(der)?.algorithm.oid)
}

/// Returns an error pointing at the other mode when a key's algorithm
/// doesn't match what was expected.
pub fn check_algorithm(found: ObjectIdentifier, expected: ObjectIdentifier) -> Result<()> {
    if found == expected {
        return Ok(());
    }
    Err(match (found, expected) {
        (RSA_OID, X25519_OID) => "the key file holds an RSA key; use --rsa".into(),
        (X25519_OID, RSA_OID) => "the key file holds an X25519 key; drop --rsa".into(),
        _ => format!("unexpected key algorithm {found}").into(),
    })
}

// --------------------------------------------------------------- Writing

/// Assembles an X25519 private key into PKCS#8 DER.
pub fn x25519_secret_to_pkcs8(secret: &[u8; X25519_KEY_BYTES]) -> Result<Zeroizing<Vec<u8>>> {
    let curve_private_key = Zeroizing::new(OctetStringRef::new(secret)?.to_der()?);
    let info = PrivateKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            oid: X25519_OID,
            parameters: None,
        },
        private_key: OctetStringRef::new(&curve_private_key)?,
        public_key: None,
    };
    Ok(Zeroizing::new(info.to_der()?))
}

/// Assembles an X25519 public key into `SubjectPublicKeyInfo` DER.
pub fn x25519_public_to_spki(public: &[u8; X25519_KEY_BYTES]) -> Result<Vec<u8>> {
    let info = SubjectPublicKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            oid: X25519_OID,
            parameters: None,
        },
        subject_public_key: BitStringRef::from_bytes(public)?,
    };
    Ok(info.to_der()?)
}

/// Encrypts a PKCS#8 `PrivateKeyInfo` with PBES2 parameters.
///
/// PBKDF2-HMAC-SHA512 (8-byte salt, 131072 iterations) + AES-256-CBC.
pub fn encrypt_pkcs8(der: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut salt = [0u8; SALT_BYTES];
    let mut iv = [0u8; IV_BYTES];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);

    let parameters = Parameters {
        kdf: Kdf::Pbkdf2(Pbkdf2Params {
            salt: salt.as_slice().try_into()?,
            iteration_count: PBKDF2_ITERATION_COUNT,
            key_length: None,
            prf: Pbkdf2Prf::HmacWithSha512,
        }),
        encryption: EncryptionScheme::Aes256Cbc { iv },
    };

    let info = PrivateKeyInfoRef::try_from(der)?;
    let encrypted = info.encrypt_with_params(parameters, passphrase.as_bytes())?;
    Ok(Zeroizing::new(encrypted.as_bytes().to_vec()))
}

/// Builds the PEM for a private key. Encrypts it with PBES2 if the
/// passphrase is non-empty.
pub fn private_key_pem(pkcs8_der: &[u8], passphrase: &str) -> Result<Zeroizing<String>> {
    if passphrase.is_empty() {
        return Ok(Zeroizing::new(encode_pem(PEM_PRIVATE_KEY, pkcs8_der)));
    }
    let encrypted = encrypt_pkcs8(pkcs8_der, passphrase)?;
    Ok(Zeroizing::new(encode_pem(
        PEM_ENCRYPTED_PRIVATE_KEY,
        &encrypted,
    )))
}

pub fn public_key_pem(spki_der: &[u8]) -> String {
    encode_pem(PEM_PUBLIC_KEY, spki_der)
}

/// PKCS#1 RSA private key PEM (the format used when there is no
/// passphrase).
pub fn rsa_pkcs1_private_key_pem(der: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(encode_pem(PEM_RSA_PRIVATE_KEY, der))
}

/// Asks for overwrite confirmation if the keys already exist. Returns
/// `None` if the user declines.
pub fn confirm_key_paths(path: &Path) -> Result<Option<(PathBuf, PathBuf)>> {
    let private_path = resolve_path(path);
    let public_path = with_pub_suffix(&private_path);

    if private_path.exists() || public_path.exists() {
        print!("The keys exist. Overwrite? (y/N)");
        std::io::stdout().flush()?;

        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            return Ok(None);
        }
    }

    Ok(Some((private_path, public_path)))
}

/// Writes the file with mode 0600, applied only on creation.
pub fn write_key_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(KEY_PERMISSION)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    file.write_all(contents)?;
    Ok(())
}
