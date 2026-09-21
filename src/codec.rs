use std::io::Write;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use flate2::Compression;
use flate2::write::{ZlibDecoder, ZlibEncoder};

use crate::Result;

/// Line-wrap width.
const MIME_LINE_LEN: usize = 76;

/// Default zlib compression level.
const ZLIB_LEVEL: u32 = 6;

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(ZLIB_LEVEL));
    encoder
        .write_all(data)
        .and_then(|()| encoder.finish())
        .expect("writing to a Vec never fails")
}

pub fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(Vec::new());
    decoder.write_all(data)?;
    Ok(decoder.finish()?)
}

/// Inserts an LF every 76 characters, including after the final line.
/// Returns empty output for empty input.
pub fn encode_b64_mime(data: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(data);
    let mut out = Vec::with_capacity(encoded.len() + encoded.len() / MIME_LINE_LEN + 1);
    for line in encoded.as_bytes().chunks(MIME_LINE_LEN) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out
}

/// Decodes after skipping whitespace and newlines.
pub fn decode_b64_mime(data: &[u8]) -> Result<Vec<u8>> {
    let compact: Vec<u8> = data
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    Ok(STANDARD.decode(compact)?)
}
