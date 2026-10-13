//! Base64 with padding, the standard alphabet: the PEM of the authority and the PKCS#12 file of a
//! device, carried in JSON.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                let sextet = (value >> (18 - 6 * index)) & 0x3f;
                text.push(char::from(ALPHABET[sextet as usize]));
            } else {
                text.push('=');
            }
        }
    }
    text
}

/// The bytes of `text`, ignoring white space; nothing when it is not base64.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let clean: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !clean.len().is_multiple_of(4) {
        return None;
    }
    let mut bytes = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let padding = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if padding > 2 {
            return None;
        }
        let mut value = 0_u32;
        for (index, byte) in chunk.iter().enumerate() {
            let sextet = if index >= 4 - padding {
                0
            } else {
                u32::try_from(ALPHABET.iter().position(|letter| letter == byte)?).ok()?
            };
            value = (value << 6) | sextet;
        }
        let decoded = [(value >> 16) as u8, (value >> 8) as u8, value as u8];
        bytes.extend_from_slice(&decoded[..3 - padding]);
    }
    Some(bytes)
}
