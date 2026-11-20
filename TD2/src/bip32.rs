use hmac::{Hmac, Mac};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{ProjectivePoint, Scalar, SecretKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

use crate::base58;

pub const HARDENED: u32 = 0x8000_0000;

#[derive(Clone)]
pub struct ExtendedKey {
    pub private_key: [u8; 32],
    pub chain_code: [u8; 32],
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub index: u32,
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(Sha256::digest(data)).into()
}

fn to_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr((*bytes).into()))
}

pub fn public_key_from_private(private_key: &[u8; 32]) -> [u8; 33] {
    let sk = SecretKey::from_slice(private_key).expect("cle privee invalide");
    let point = sk.public_key().to_encoded_point(true);
    point.as_bytes().try_into().unwrap()
}

impl ExtendedKey {
    pub fn master(seed: &[u8]) -> ExtendedKey {
        let i = hmac_sha512(b"Bitcoin seed", seed);
        let mut private_key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        private_key.copy_from_slice(&i[..32]);
        chain_code.copy_from_slice(&i[32..]);

        ExtendedKey {
            private_key,
            chain_code,
            depth: 0,
            parent_fingerprint: [0; 4],
            index: 0,
        }
    }

    pub fn public_key(&self) -> [u8; 33] {
        public_key_from_private(&self.private_key)
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        let h = hash160(&self.public_key());
        [h[0], h[1], h[2], h[3]]
    }

    pub fn child(&self, index: u32) -> Result<ExtendedKey, String> {
        let mut data = Vec::with_capacity(37);
        if index >= HARDENED {
            data.push(0);
            data.extend_from_slice(&self.private_key);
        } else {
            data.extend_from_slice(&self.public_key());
        }
        data.extend_from_slice(&index.to_be_bytes());

        let i = hmac_sha512(&self.chain_code, &data);
        let mut il = [0u8; 32];
        let mut ir = [0u8; 32];
        il.copy_from_slice(&i[..32]);
        ir.copy_from_slice(&i[32..]);

        let tweak = to_scalar(&il).ok_or("IL >= n, index invalide")?;
        let parent = to_scalar(&self.private_key).ok_or("cle parente invalide")?;
        let child = tweak + parent;
        if child == Scalar::ZERO {
            return Err("cle enfant nulle, index invalide".into());
        }

        Ok(ExtendedKey {
            private_key: child.to_repr().into(),
            chain_code: ir,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            index,
        })
    }

    pub fn derive_path(&self, path: &str) -> Result<ExtendedKey, String> {
        let mut parts = path.trim().split('/');
        match parts.next() {
            Some("m") | Some("M") => {}
            _ => return Err("le chemin doit commencer par m".into()),
        }

        let mut key = self.clone();
        for p in parts {
            if p.is_empty() {
                continue;
            }
            let hardened = p.ends_with('\'') || p.ends_with('h') || p.ends_with('H');
            let num = p.trim_end_matches(|c| c == '\'' || c == 'h' || c == 'H');
            let n: u32 = num.parse().map_err(|_| format!("index invalide : {}", p))?;
            if n >= HARDENED {
                return Err(format!("index trop grand : {}", n));
            }
            key = key.child(if hardened { n + HARDENED } else { n })?;
        }
        Ok(key)
    }

    fn serialize(&self, version: [u8; 4], key_data: &[u8; 33]) -> String {
        let mut data = Vec::with_capacity(78);
        data.extend_from_slice(&version);
        data.push(self.depth);
        data.extend_from_slice(&self.parent_fingerprint);
        data.extend_from_slice(&self.index.to_be_bytes());
        data.extend_from_slice(&self.chain_code);
        data.extend_from_slice(key_data);
        base58::encode_check(&data)
    }

    pub fn xprv(&self) -> String {
        let mut k = [0u8; 33];
        k[1..].copy_from_slice(&self.private_key);
        self.serialize([0x04, 0x88, 0xAD, 0xE4], &k)
    }

    pub fn xpub(&self) -> String {
        self.serialize([0x04, 0x88, 0xB2, 0x1E], &self.public_key())
    }

    pub fn address(&self) -> String {
        let mut data = vec![0x00];
        data.extend_from_slice(&hash160(&self.public_key()));
        base58::encode_check(&data)
    }

    pub fn wif(&self) -> String {
        let mut data = vec![0x80];
        data.extend_from_slice(&self.private_key);
        data.push(0x01);
        base58::encode_check(&data)
    }
}

pub fn public_child_from_xpub(parent_pub: &[u8; 33], chain_code: &[u8; 32], index: u32) -> Result<[u8; 33], String> {
    if index >= HARDENED {
        return Err("impossible de deriver un enfant hardened depuis une cle publique".into());
    }
    let mut data = parent_pub.to_vec();
    data.extend_from_slice(&index.to_be_bytes());
    let i = hmac_sha512(chain_code, &data);
    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);

    let tweak = to_scalar(&il).ok_or("IL >= n")?;
    let parent = k256::PublicKey::from_sec1_bytes(parent_pub).map_err(|_| "cle publique invalide")?;
    let point = ProjectivePoint::GENERATOR * tweak + parent.to_projective();
    let pk = k256::PublicKey::from_affine(point.to_affine()).map_err(|_| "point a l'infini")?;
    Ok(pk.to_encoded_point(true).as_bytes().try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip32_vector_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = ExtendedKey::master(&seed);
        assert_eq!(master.xprv(), "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
        assert_eq!(master.xpub(), "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");

        let k = master.derive_path("m/0'").unwrap();
        assert_eq!(k.xprv(), "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7");

        let k = master.derive_path("m/0'/1").unwrap();
        assert_eq!(k.xpub(), "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");
    }

    #[test]
    fn public_derivation_matches_private() {
        let master = ExtendedKey::master(&[7u8; 32]);
        for i in 0..5 {
            let from_pub = public_child_from_xpub(&master.public_key(), &master.chain_code, i).unwrap();
            assert_eq!(from_pub, master.child(i).unwrap().public_key());
        }
    }
}
