use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};

const WORDLIST: &str = include_str!("english.txt");

pub fn wordlist() -> Vec<&'static str> {
    WORDLIST.lines().map(|w| w.trim()).filter(|w| !w.is_empty()).collect()
}

pub fn generate_entropy(bits: usize) -> Vec<u8> {
    let mut entropy = vec![0u8; bits / 8];
    OsRng.fill_bytes(&mut entropy);
    entropy
}

pub fn to_bit_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:08b}", b)).collect()
}

pub fn entropy_with_checksum(entropy: &[u8]) -> String {
    let hash = Sha256::digest(entropy);
    let cs_len = entropy.len() * 8 / 32;
    let mut bits = to_bit_string(entropy);
    bits.push_str(&to_bit_string(&hash)[..cs_len]);
    bits
}

pub fn split_11(bits: &str) -> Vec<String> {
    bits.as_bytes()
        .chunks(11)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect()
}

pub fn entropy_to_mnemonic(entropy: &[u8]) -> Vec<String> {
    let words = wordlist();
    split_11(&entropy_with_checksum(entropy))
        .iter()
        .map(|chunk| {
            let idx = usize::from_str_radix(chunk, 2).unwrap();
            words[idx].to_string()
        })
        .collect()
}

pub fn mnemonic_to_entropy(mnemonic: &str) -> Result<Vec<u8>, String> {
    let words = wordlist();
    let input: Vec<&str> = mnemonic.split_whitespace().collect();

    if ![12, 15, 18, 21, 24].contains(&input.len()) {
        return Err(format!("{} mots, il en faut 12, 15, 18, 21 ou 24", input.len()));
    }

    let mut bits = String::new();
    for w in &input {
        let lower = w.to_lowercase();
        match words.iter().position(|x| *x == lower) {
            Some(i) => bits.push_str(&format!("{:011b}", i)),
            None => return Err(format!("mot inconnu : {}", w)),
        }
    }

    let cs_len = bits.len() / 33;
    let ent_len = bits.len() - cs_len;
    let entropy: Vec<u8> = bits[..ent_len]
        .as_bytes()
        .chunks(8)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 2).unwrap())
        .collect();

    let expected = &entropy_with_checksum(&entropy)[ent_len..];
    if expected != &bits[ent_len..] {
        return Err("checksum invalide".to_string());
    }

    Ok(entropy)
}

fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 64] {
    let mut block_salt = salt.to_vec();
    block_salt.extend_from_slice(&1u32.to_be_bytes());

    let mut mac = Hmac::<Sha512>::new_from_slice(password).unwrap();
    mac.update(&block_salt);
    let mut u: [u8; 64] = mac.finalize().into_bytes().into();
    let mut result = u;

    for _ in 1..rounds {
        let mut mac = Hmac::<Sha512>::new_from_slice(password).unwrap();
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        for (r, x) in result.iter_mut().zip(u.iter()) {
            *r ^= x;
        }
    }

    result
}

pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> [u8; 64] {
    let normalized = mnemonic.split_whitespace().collect::<Vec<_>>().join(" ");
    let salt = format!("mnemonic{}", passphrase);
    pbkdf2_hmac_sha512(normalized.as_bytes(), salt.as_bytes(), 2048)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_entropy() {
        let words = entropy_to_mnemonic(&[0u8; 16]).join(" ");
        assert_eq!(words, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        assert_eq!(mnemonic_to_entropy(&words).unwrap(), vec![0u8; 16]);
        let seed = mnemonic_to_seed(&words, "TREZOR");
        assert_eq!(hex::encode(seed), "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
    }

    #[test]
    fn bad_checksum() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert!(mnemonic_to_entropy(words).is_err());
    }

    #[test]
    fn roundtrip() {
        for bits in [128, 160, 192, 224, 256] {
            let e = generate_entropy(bits);
            let m = entropy_to_mnemonic(&e).join(" ");
            assert_eq!(mnemonic_to_entropy(&m).unwrap(), e);
        }
    }
}
