
use rand::{TryRngCore};
use rand::rngs::OsRng;
use bip39::{self, Mnemonic};
use ed25519_hd_key;
use ed25519_dalek::{SigningKey};
use bs58;
// mnemonic -> seed -> derivedseed -> keys


fn main(){

    let m = generate_mnemonic(Some(12));
    let path = "m/44'/501'/0'/0'";

    let (_priv_k, pub_k , mn) = generate_keys(Some(m), path);
    let phrase: String = mn.words().collect::<Vec<&str>>().join(" ");
    println!("{:?} \n{:?}",pub_k,phrase);
}

pub fn generate_keys(m: Option<Mnemonic>, path_hd: &str) -> (String,String,Mnemonic){
    let valid_path = ed25519_hd_key::is_valid_path(path_hd);
    if !valid_path{
        panic!("Not A Valid Path!");
    }
    let mn = m.unwrap_or(generate_mnemonic(None));
    let seed = mn.to_seed("");
    let secret_key = ed25519_hd_key::derive_from_path(&path_hd, &seed[..]).0;
    let private_key = SigningKey::from_bytes(&secret_key);
    let public_key = private_key.verifying_key();
    (bs58::encode(private_key.to_bytes()).into_string(),bs58::encode(public_key.to_bytes()).into_string(),mn)
}


pub fn generate_mnemonic(n_words: Option<u8>) -> Mnemonic{
    let k = match n_words{
        Some(12) => 16,
        Some(24) => 32,
        _ => 16
    };
    let mut os_rng = OsRng;
    let mut buffer = vec![0u8;k];
    os_rng.try_fill_bytes(&mut buffer).unwrap();
    let m = Mnemonic::from_entropy(&buffer[..]).unwrap();
    m
}

