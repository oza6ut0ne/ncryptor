# Ncryptor

[![crates.io](https://img.shields.io/crates/v/ncryptor.svg)](https://crates.io/crates/ncryptor/)
[![crates.io](https://img.shields.io/crates/d/ncryptor)](https://crates.io/crates/ncryptor/)

Ncryptor is a command-line tool for encrypting and decrypting files (or piped
data) with public-key cryptography. It supports two schemes: X25519 with HPKE
(RFC 9180) by default, or RSA-OAEP combined with AES-256-EAX. Plaintext is
zlib-compressed before encryption, and output is base64 text by default, or
raw binary with `-b`. Key pairs are stored as standard, optionally
passphrase-protected PEM files, so they interoperate with other tools. RSA
keys can also be read from OpenSSH-formatted files (e.g. `ssh-keygen`
output), passphrase-protected or not. Written in pure Rust with no C
dependencies.

## Usage

```
Usage: ncryptor [OPTIONS] [INPUT]

Arguments:
  [INPUT]

Options:
  -e, --encrypt
  -d, --decrypt
  -p, --passphrase <PASSPHRASE>
  -b, --binary
  -g, --generate-keys
  -r, --rsa
      --rsa-bits <RSA_BITS>      [default: 4096]
  -k, --key <KEY>
  -o, --output [<OUTPUT>]
  -h, --help                     Print help
```

## License

Licensed under either of

* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
