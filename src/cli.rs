use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "ncryptor", infer_long_args = true)]
pub struct Cli {
    #[arg(short, long)]
    pub encrypt: bool,

    #[arg(short, long)]
    pub decrypt: bool,

    #[arg(short, long)]
    pub passphrase: Option<String>,

    #[arg(short, long)]
    pub binary: bool,

    #[arg(short, long)]
    pub generate_keys: bool,

    #[arg(short, long)]
    pub rsa: bool,

    #[arg(long, default_value_t = 4096)]
    pub rsa_bits: usize,

    #[arg(short, long)]
    pub key: Option<PathBuf>,

    pub input: Option<PathBuf>,

    #[arg(short, long, num_args = 0..=1)]
    pub output: Option<Option<PathBuf>>,
}

impl Cli {
    /// Returns the value of `-o`. If `-o` was given with no value, this is `None`,
    /// same as if it were omitted entirely.
    pub fn output(&self) -> Option<&PathBuf> {
        self.output.as_ref().and_then(Option::as_ref)
    }

    /// An empty passphrase is treated the same as not having one.
    pub fn passphrase(&self) -> Option<&str> {
        self.passphrase.as_deref().filter(|p| !p.is_empty())
    }
}
