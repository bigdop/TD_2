use sha2::{Digest, Sha256};

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encode(data: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0];

    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::new();
    for &byte in data {
        if byte != 0 {
            break;
        }
        out.push('1');
    }

    let all_zero = data.iter().all(|&b| b == 0);
    if !all_zero {
        for &d in digits.iter().rev() {
            out.push(ALPHABET[d as usize] as char);
        }
    }

    out
}

pub fn encode_check(data: &[u8]) -> String {
    let checksum = Sha256::digest(Sha256::digest(data));
    let mut full = data.to_vec();
    full.extend_from_slice(&checksum[..4]);
    encode(&full)
}
