use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser as _;
use ncryptor::cli::Cli;
use ncryptor::{Algorithm, Result, keys};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = Cli::parse();
    let rsa = args.rsa || keys::rsa_from_env();
    let symmetric = args.symmetric || keys::symmetric_from_env();
    let x25519 = args.x25519 || keys::x25519_from_env();
    let algorithm = if rsa { Algorithm::Rsa } else { Algorithm::X25519 };

    if args.generate_keys {
        let path = args
            .key
            .clone()
            .or_else(|| args.output().cloned())
            .unwrap_or_else(keys::default_private_key);
        return ncryptor::generate_keypair_interactive(
            algorithm,
            &path,
            args.rsa_bits,
            args.passphrase(),
        );
    }

    if !args.encrypt && !args.decrypt && !symmetric {
        return Err(
            "either --generate-keys or --encrypt or --decrypt or --symmetric must be set".into(),
        );
    }
    if args.encrypt && args.decrypt {
        return Err("--encrypt and --decrypt cannot be used together".into());
    }
    // `-c` alone (without `-e`/`-d`) implies encryption.
    let should_encrypt = args.encrypt || (symmetric && !args.decrypt);

    let input = read_input(args.input.as_deref())?;

    // Aside from `--symmetric`, neither `--rsa`/`--x25519`/the env vars are
    // consulted here: the algorithm is always detected from the key file
    // itself.
    let output = if should_encrypt {
        if symmetric {
            let passphrase = keys::passphrase(args.passphrase())?;
            ncryptor::encrypt_symmetric(&input, &passphrase, args.binary)?
        } else {
            let key_path = args.key.clone().unwrap_or_else(keys::default_public_key);
            ncryptor::encrypt_auto(&input, &key_path, args.binary)?
        }
    } else {
        // Only sniff the `SYM-` marker when the algorithm wasn't pinned
        // explicitly; `--x25519` (like `--rsa`) opts out of the guess.
        let use_symmetric = symmetric
            || (!rsa
                && !x25519
                && ncryptor::looks_symmetric(&input, args.binary).unwrap_or(false));
        if use_symmetric {
            let passphrase = keys::passphrase(args.passphrase())?;
            ncryptor::decrypt_symmetric(&input, &passphrase, args.binary)?
        } else {
            let key_path = args.key.clone().unwrap_or_else(keys::default_private_key);
            ncryptor::decrypt_auto(&input, &key_path, args.passphrase(), args.binary)?
        }
    };

    write_output(args.output(), &output)
}

fn read_input(path: Option<&Path>) -> Result<Vec<u8>> {
    match path {
        Some(path) => std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()).into()),
        None => {
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer)?;
            Ok(buffer)
        }
    }
}

fn write_output(path: Option<&PathBuf>, data: &[u8]) -> Result<()> {
    match path {
        Some(path) => {
            std::fs::write(path, data).map_err(|e| format!("{}: {e}", path.display()).into())
        }
        None => {
            let mut stdout = std::io::stdout();
            stdout.write_all(data)?;
            stdout.flush()?;
            Ok(())
        }
    }
}
