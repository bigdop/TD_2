# TD2 - HD Wallet (BIP39 / BIP32) en Rust

Programme en ligne de commande interactif qui génère une seed de wallet, la convertit en mnemonic selon BIP39, permet d'importer une mnemonic existante, puis dérive les clés selon BIP32.

## Lancer le programme

Il faut avoir Rust installé (https://rustup.rs).

```bash
git clone <url-du-repo>
cd TD2
cargo run --release
```

Pour lancer les tests (vecteurs officiels BIP39 et BIP32) :

```bash
cargo test
```

## Menu

```
 1. Generer une nouvelle seed
 2. Importer une mnemonic
 3. Afficher la seed et la mnemonic
 4. Cle privee maitre + chain code
 5. Cle publique maitre
 6. Generer une cle enfant (m/0)
 7. Generer une cle enfant a l'index N
 8. Generer une cle enfant a l'index N au niveau M
 9. Deriver un chemin personnalise (ex: m/44'/0'/0'/0/0)
10. Deriver une cle publique enfant depuis la xpub maitre
 0. Quitter
```

## Structure

```
src/
  main.rs     menu interactif
  bip39.rs    entropie, checksum, découpage 11 bits, mnemonic, import, PBKDF2 -> seed
  bip32.rs    clé maître, dérivation des enfants (normale et hardened), xprv/xpub
  base58.rs   encodage Base58 / Base58Check
  english.txt liste officielle des 2048 mots BIP39
```

## Librairies utilisées

Conformément aux contraintes, aucune librairie Bitcoin n'est utilisée. Seules des primitives crypto :

- `rand` (OsRng) : génération aléatoire sécurisée de l'entropie
- `sha2`, `hmac`, `ripemd` : fonctions de hash (SHA-256, SHA-512, HMAC, RIPEMD-160)
- `k256` : courbe secp256k1, uniquement pour passer d'une clé privée à une clé publique et pour l'addition modulo n
- `hex` : affichage

Tout le reste est codé à la main : checksum et découpage BIP39, PBKDF2-HMAC-SHA512, dérivation BIP32, Base58Check, sérialisation xprv/xpub, WIF et adresses P2PKH.

## Rapport

### BIP39

**Génération de la seed.** L'entropie est un entier aléatoire de 128 à 256 bits (multiple de 32) tiré avec `OsRng`, qui utilise le générateur du système d'exploitation. Un générateur classique (type `rand::thread_rng` mal seedé, ou un timestamp) ne serait pas acceptable pour un wallet.

**Checksum et découpage.** On calcule `SHA256(entropie)` et on garde les `ENT / 32` premiers bits comme checksum, qu'on colle à la fin de l'entropie. Pour 128 bits on obtient 128 + 4 = 132 bits, soit 12 lots de 11 bits. Le programme affiche l'entropie en hexa et en binaire, puis chaque lot.

**Mnemonic.** Chaque lot de 11 bits donne un nombre entre 0 et 2047 qui sert d'index dans la liste anglaise BIP39.

| Entropie | Checksum | Total | Mots |
|---------:|---------:|------:|-----:|
| 128 | 4 | 132 | 12 |
| 160 | 5 | 165 | 15 |
| 192 | 6 | 198 | 18 |
| 224 | 7 | 231 | 21 |
| 256 | 8 | 264 | 24 |

**Import.** On fait le chemin inverse : chaque mot redonne son index sur 11 bits, on sépare entropie et checksum, et on recalcule le checksum pour vérifier que la mnemonic est valide. Une faute de frappe ou un mot dans le mauvais ordre est donc détecté.

**Seed binaire.** La seed de 512 bits utilisée par BIP32 est obtenue avec `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase, 2048 itérations)`. J'ai réimplémenté PBKDF2 à partir de HMAC (un seul bloc suffit puisque la sortie fait 64 octets).

### BIP32

**Clé maître.** `I = HMAC-SHA512(key = "Bitcoin seed", data = seed)`. Les 32 premiers octets sont la clé privée maître, les 32 derniers le chain code.

**Clé publique maître.** C'est `k * G` sur secp256k1, affichée au format compressé (33 octets, préfixe 02 ou 03). Le programme affiche aussi la xpub (version `0488B21E` + profondeur + fingerprint parent + index + chain code + clé publique, en Base58Check).

**Dérivation d'un enfant.** Pour un index `i` :

- si `i < 2^31` (normal) : `I = HMAC-SHA512(chain_code, pubkey_parent || i)`
- si `i >= 2^31` (hardened) : `I = HMAC-SHA512(chain_code, 0x00 || privkey_parent || i)`

La clé privée enfant vaut `(IL + k_parent) mod n` et le chain code enfant vaut `IR`. Le fingerprint du parent correspond aux 4 premiers octets de `HASH160(pubkey_parent)`.

**Index N au niveau M.** L'option 8 construit le chemin `m/0/0/.../N` avec M niveaux (le dernier étant N), éventuellement en hardened. L'option 9 permet de toute façon d'entrer n'importe quel chemin, par exemple `m/44'/0'/0'/0/5` pour BIP44.

**Dérivation publique.** L'option 10 dérive une clé publique enfant uniquement à partir de la clé publique et du chain code (`IL * G + K_parent`), sans la clé privée. C'est ce qui permet de générer des adresses depuis une xpub. Le programme vérifie que le résultat est identique à la dérivation privée. Cela ne fonctionne pas pour les index hardened, puisqu'il faut la clé privée du parent.

### Vérification

Les résultats ont été comparés avec https://iancoleman.io/bip39/. Par exemple avec la mnemonic `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` sans passphrase :

- Seed : `5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4`
- BIP32 Root Key : `xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu`

On retrouve les mêmes valeurs sur le site. Pour comparer une clé enfant, il faut aller dans l'onglet "BIP32" du site, choisir "Custom derivation path" et mettre le même chemin.

`cargo test` vérifie aussi :

- le vecteur Trezor BIP39 (entropie nulle, passphrase `TREZOR`)
- le vecteur de test 1 de BIP32 (`m`, `m/0'`, `m/0'/1`)
- qu'une mnemonic avec un mauvais checksum est refusée
- que la dérivation publique donne le même résultat que la dérivation privée
