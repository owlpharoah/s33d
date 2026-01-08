use rand::{TryRngCore};
use rand::rngs::OsRng;
use bip39::{self, Language, Mnemonic};
use ed25519_hd_key;
use ed25519_dalek::{SigningKey};
use bs58;
use zeroize::{self, Zeroize};
use std::{env, fs, error::Error};
use std::process::exit;
// mnemonic -> seed -> derivedseed -> keys

struct Secret{
    keypair: [u8;64],
    pub_key: String,
    priv_key: String,
    phrase: String
}

fn main(){
    // let arguments: Vec<String> = env::args().collect();
    // if arguments.len() < 2 {
    //     println!("Usage: cargo run -- <file>");
    //     exit(1)
    // }
    // println!("{:?}",arguments);
    let m = generate_mnemonic(Some(24));
    let path = "m/44'/501'/0'/0'";
    let (keypair,mut priv_k, mut pub_k , phrase) = generate_keys(Some(m), path);
    let acc1 = Secret{
        keypair,
        pub_key: pub_k,
        priv_key: priv_k,
        phrase
    };
    let _ = add_to_file("file_path",acc1);
    // let m = generate_mnemonic(Some(24));
    // let path = "m/44'/501'/0'/0'";

    // let (mut priv_k, mut pub_k , phrase) = generate_keys(Some(m), path);
    // println!("{:?} \n{:?}",pub_k,phrase);
    // pub_k.zeroize();
    // priv_k.zeroize();

}


//(keypair,pirv,pub,mnemonic)
pub fn generate_keys(m: Option<Mnemonic>, path_hd: &str) -> ([u8;64],String,String,String){
    let valid_path = ed25519_hd_key::is_valid_path(path_hd);
    if !valid_path{
        panic!("Not A Valid Path!");
    }
    let mn = m.unwrap_or(generate_mnemonic(None));
    let seed = mn.to_seed("");
    let secret_key = ed25519_hd_key::derive_from_path(&path_hd, &seed[..]).0;
    let private_key = SigningKey::from_bytes(&secret_key);
    let public_key = private_key.verifying_key();
    let mut sol_keypair = [0u8;64];
    sol_keypair[..32].copy_from_slice(private_key.as_bytes());
    sol_keypair[32..].copy_from_slice(public_key.as_bytes());
    (sol_keypair,bs58::encode(private_key.to_bytes()).into_string(),bs58::encode(public_key.to_bytes()).into_string(),mn.words().collect::<Vec<&str>>().join(" "))
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
    let m = Mnemonic::from_entropy_in(Language::English,&buffer[..]).unwrap();
    m
}


fn add_to_file(file_path: &str, s: Secret) -> Result<(), Box<dyn Error>>{
    let contents = format!(
"========================================
SOLANA WALLET BACKUP
========================================

Mnemonic (DO NOT SHARE)
-----------------------
{mnemonic}

Public Key (Base58)
-------------------
{public_key}

Private Key (Base58)
--------------------
{private_key}


Raw Keypair (Bytes)
-----------------
{keypair:?}

========================================
KEEP THIS FILE OFFLINE
========================================
",
    mnemonic = s.phrase,
    public_key = s.pub_key,
    private_key = s.priv_key,
    keypair= s.keypair,
);

    let K = fs::write(file_path, contents);
    match K {
        Ok(l) => l,
        Err(e) => {println!("{}",e);exit(1)}
    }
    Ok(())
}