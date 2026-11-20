mod base58;
mod bip32;
mod bip39;

use bip32::{ExtendedKey, HARDENED};
use std::io::{self, Write};

struct Wallet {
    mnemonic: String,
    seed: [u8; 64],
    master: ExtendedKey,
}

fn ask(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut line = String::new();
    io::stdin().read_line(&mut line).unwrap();
    line.trim().to_string()
}

fn ask_number(prompt: &str) -> Option<u32> {
    match ask(prompt).parse::<u32>() {
        Ok(n) => Some(n),
        Err(_) => {
            println!("Nombre invalide.");
            None
        }
    }
}

fn ask_yes(prompt: &str) -> bool {
    matches!(ask(prompt).to_lowercase().as_str(), "o" | "oui" | "y" | "yes")
}

fn print_key(title: &str, path: &str, key: &ExtendedKey) {
    println!();
    println!("--- {} ({}) ---", title, path);
    println!("Profondeur      : {}", key.depth);
    println!("Index           : {}", format_index(key.index));
    println!("Cle privee      : {}", hex::encode(key.private_key));
    println!("Cle publique    : {}", hex::encode(key.public_key()));
    println!("Chain code      : {}", hex::encode(key.chain_code));
    println!("WIF             : {}", key.wif());
    println!("Adresse (P2PKH) : {}", key.address());
    println!("xprv            : {}", key.xprv());
    println!("xpub            : {}", key.xpub());
}

fn format_index(index: u32) -> String {
    if index >= HARDENED {
        format!("{}'", index - HARDENED)
    } else {
        index.to_string()
    }
}

fn build_wallet(mnemonic: String) -> Wallet {
    let passphrase = ask("Passphrase (laisser vide si aucune) : ");
    let seed = bip39::mnemonic_to_seed(&mnemonic, &passphrase);
    let master = ExtendedKey::master(&seed);
    Wallet { mnemonic, seed, master }
}

fn generate() -> Option<Wallet> {
    let choice = ask("Taille de l'entropie (128, 160, 192, 224, 256) [128] : ");
    let bits: usize = if choice.is_empty() { 128 } else { choice.parse().unwrap_or(0) };
    if ![128, 160, 192, 224, 256].contains(&bits) {
        println!("Taille invalide.");
        return None;
    }

    let entropy = bip39::generate_entropy(bits);
    let with_cs = bip39::entropy_with_checksum(&entropy);
    let chunks = bip39::split_11(&with_cs);
    let words = bip39::entropy_to_mnemonic(&entropy);
    let list = bip39::wordlist();

    println!();
    println!("Entropie (hex)    : {}", hex::encode(&entropy));
    println!("Entropie (binaire): {}", bip39::to_bit_string(&entropy));
    println!("Checksum          : {} ({} bits)", &with_cs[bits..], with_cs.len() - bits);
    println!();
    println!("Decoupage en lots de 11 bits :");
    for (i, chunk) in chunks.iter().enumerate() {
        let idx = usize::from_str_radix(chunk, 2).unwrap();
        println!("  {:>2}. {} -> {:>4} -> {}", i + 1, chunk, idx, list[idx]);
    }

    let mnemonic = words.join(" ");
    println!();
    println!("Mnemonic : {}", mnemonic);
    println!();

    let wallet = build_wallet(mnemonic);
    println!("Seed : {}", hex::encode(wallet.seed));
    Some(wallet)
}

fn import() -> Option<Wallet> {
    let input = ask("Entrez votre mnemonic : ");
    match bip39::mnemonic_to_entropy(&input) {
        Ok(entropy) => {
            println!("Mnemonic valide, entropie : {}", hex::encode(&entropy));
            let mnemonic = input.split_whitespace().map(|w| w.to_lowercase()).collect::<Vec<_>>().join(" ");
            let wallet = build_wallet(mnemonic);
            println!("Seed : {}", hex::encode(wallet.seed));
            Some(wallet)
        }
        Err(e) => {
            println!("Erreur : {}", e);
            None
        }
    }
}

fn derive_and_print(wallet: &Wallet, path: &str, title: &str) {
    match wallet.master.derive_path(path) {
        Ok(key) => print_key(title, path, &key),
        Err(e) => println!("Erreur : {}", e),
    }
}

fn index_str(n: u32, hardened: bool) -> String {
    if hardened {
        format!("{}'", n)
    } else {
        n.to_string()
    }
}

fn menu() {
    println!();
    println!("========== HD Wallet (BIP39 / BIP32) ==========");
    println!(" 1. Generer une nouvelle seed");
    println!(" 2. Importer une mnemonic");
    println!(" 3. Afficher la seed et la mnemonic");
    println!(" 4. Cle privee maitre + chain code");
    println!(" 5. Cle publique maitre");
    println!(" 6. Generer une cle enfant (m/0)");
    println!(" 7. Generer une cle enfant a l'index N");
    println!(" 8. Generer une cle enfant a l'index N au niveau M");
    println!(" 9. Deriver un chemin personnalise (ex: m/44'/0'/0'/0/0)");
    println!("10. Deriver une cle publique enfant depuis la xpub maitre");
    println!(" 0. Quitter");
}

fn main() {
    let mut wallet: Option<Wallet> = None;

    loop {
        menu();
        let choice = ask("> ");

        if choice == "0" || choice == "q" {
            break;
        }

        if choice == "1" {
            if let Some(w) = generate() {
                wallet = Some(w);
            }
            continue;
        }
        if choice == "2" {
            if let Some(w) = import() {
                wallet = Some(w);
            }
            continue;
        }

        let w = match &wallet {
            Some(w) => w,
            None => {
                println!("Aucun wallet charge, generez ou importez une seed d'abord.");
                continue;
            }
        };

        match choice.as_str() {
            "3" => {
                println!("Mnemonic : {}", w.mnemonic);
                println!("Seed     : {}", hex::encode(w.seed));
            }
            "4" => {
                println!("Cle privee maitre : {}", hex::encode(w.master.private_key));
                println!("Chain code maitre : {}", hex::encode(w.master.chain_code));
                println!("xprv              : {}", w.master.xprv());
            }
            "5" => {
                println!("Cle publique maitre : {}", hex::encode(w.master.public_key()));
                println!("xpub                : {}", w.master.xpub());
            }
            "6" => derive_and_print(w, "m/0", "Cle enfant"),
            "7" => {
                if let Some(n) = ask_number("Index N : ") {
                    let h = ask_yes("Hardened ? (o/n) : ");
                    let path = format!("m/{}", index_str(n, h));
                    derive_and_print(w, &path, "Cle enfant");
                }
            }
            "8" => {
                let n = match ask_number("Index N : ") {
                    Some(n) => n,
                    None => continue,
                };
                let m = match ask_number("Niveau M (>= 1) : ") {
                    Some(m) if m >= 1 => m,
                    _ => {
                        println!("Le niveau doit etre >= 1.");
                        continue;
                    }
                };
                let h = ask_yes("Hardened ? (o/n) : ");
                let mut path = String::from("m");
                for _ in 1..m {
                    path.push_str(&format!("/{}", index_str(0, h)));
                }
                path.push_str(&format!("/{}", index_str(n, h)));
                derive_and_print(w, &path, "Cle enfant");
            }
            "9" => {
                let path = ask("Chemin : ");
                derive_and_print(w, &path, "Cle derivee");
            }
            "10" => {
                if let Some(n) = ask_number("Index N (non hardened) : ") {
                    match bip32::public_child_from_xpub(&w.master.public_key(), &w.master.chain_code, n) {
                        Ok(pk) => {
                            println!("Cle publique m/{} (depuis xpub) : {}", n, hex::encode(pk));
                            if let Ok(k) = w.master.child(n) {
                                let same = k.public_key() == pk;
                                println!("Meme resultat que la derivation privee : {}", if same { "oui" } else { "non" });
                            }
                        }
                        Err(e) => println!("Erreur : {}", e),
                    }
                }
            }
            _ => println!("Choix invalide."),
        }
    }
}
