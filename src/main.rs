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
    let algorithm = if args.rsa || keys::rsa_from_env() {
        Algorithm::Rsa
    } else {
        Algorithm::X25519
    };

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

    if !args.encrypt && !args.decrypt {
        return Err("either --generate-keys or --encrypt or --decrypt must be set".into());
    }

    let input = read_input(args.input.as_deref())?;

    let key_path = match &args.key {
        Some(path) => path.clone(),
        None if args.encrypt => keys::default_public_key(),
        None => keys::default_private_key(),
    };

    // If both `-e` and `-d` are given, encryption takes priority.
    let output = if args.encrypt {
        ncryptor::encrypt(&input, algorithm, &key_path, args.binary)?
    } else {
        ncryptor::decrypt(&input, algorithm, &key_path, args.passphrase(), args.binary)?
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
