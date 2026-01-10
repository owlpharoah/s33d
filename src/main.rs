use rand::{TryRngCore};
use rand::rngs::OsRng;
use bip39::{self, Language, Mnemonic};
use ed25519_hd_key;
use ed25519_dalek::{SigningKey};
use bs58;
use zeroize::{self, Zeroize};
use std::fs;
use std::{io::Write,env, fs::OpenOptions, error::Error};
use std::process::exit;
// mnemonic -> seed -> derivedseed -> keys

struct Secret{
    keypair: [u8;64],
    pub_key: Vec<u8>,
    priv_key: Vec<u8>,
    phrase: String
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.phrase.zeroize();
    }
}



fn main(){
    let arguments: Vec<String> = env::args().collect();
    if arguments.len() < 4 {
        println!("Usage: cargo run -- <words> <wallet_number> <file_path>");
        exit(1)
    }
    let wallets: Result<u8, _> = arguments[2].parse();
    let file_path: String = arguments[3].clone();
    let k = match wallets{
        Ok(x) => x,
        Err(y) => {
            println!("{}",y);
            exit(1);
        }
    };
    let m = generate_mnemonic(Some(arguments[1].parse().unwrap()));
    for i in 0..k{
        let path = format!("m/44'/501'/{}'/0'",i);
        let (keypair, priv_k,  pub_k , phrase) = generate_keys(Some(m.clone()), &path);
        let acc1 = Secret{
            keypair,
            pub_key: pub_k,
            priv_key: priv_k,
            phrase
        };
        let _ = add_to_file(&file_path,acc1,i);
        
        
    }
    // let m = generate_mnemonic(Some(24));
    // let path = "m/44'/501'/0'/0'";

    // let (mut priv_k, mut pub_k , phrase) = generate_keys(Some(m), path);
    // println!("{:?} \n{:?}",pub_k,phrase);
    // pub_k.zeroize();
    // priv_k.zeroize();

}


//(keypair,pirv,pub,mnemonic)
pub fn generate_keys(m: Option<Mnemonic>, path_hd: &str) -> ([u8;64],Vec<u8>,Vec<u8>,String){
    let valid_path = ed25519_hd_key::is_valid_path(path_hd);
    if !valid_path{
        panic!("Not A Valid Path!");
    }
    let mn = m.unwrap_or(generate_mnemonic(None));
    let mut seed = mn.to_seed("");
    let mut secret_key = ed25519_hd_key::derive_from_path(&path_hd, &seed[..]).0;
    seed.zeroize();
    let private_key = SigningKey::from_bytes(&secret_key);
    let public_key = private_key.verifying_key();
    secret_key.zeroize();
    let mut sol_keypair = [0u8;64];
    sol_keypair[..32].copy_from_slice(private_key.as_bytes());
    sol_keypair[32..].copy_from_slice(public_key.as_bytes());
    (sol_keypair,private_key.to_bytes().to_vec(),public_key.to_bytes().to_vec(),mn.words().collect::<Vec<&str>>().join(" "))
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
    buffer.zeroize();
    m
}


fn add_to_file(file_path: &str, s: Secret, i: u8) -> Result<(), Box<dyn Error>> {
    let mut pub_b58 = bs58::encode(&s.pub_key).into_string();
    let mut priv_b58 = bs58::encode(&s.priv_key).into_string();

    if i == 0 {
        let header = format!(
            r#"
            ================================================================================
            SOLANA HD WALLET EXPORT
            ================================================================================

            MASTER MNEMONIC (KEEP SECRET • DO NOT SHARE)
            -------------------------------------------
            {mnemonic}
            ================================================================================
            "#,mnemonic = s.phrase);

        fs::write(file_path, header)?;
    }

    let wallet_block = format!(
            r#"
            WALLET #{i}
            -------------------------------------------
            Public Key (Base58)
            ------------------
            {public_key}

            Private Key (Base58)
            -------------------
            {private_key}

            Raw Keypair (Ed25519 • 64 bytes)
            --------------------------------
            {keypair:?}"#,
        i = i+1,
        public_key = pub_b58,
        private_key = priv_b58,
        keypair = s.keypair,
    );

    let mut file = OpenOptions::new()
        .append(true)
        .open(file_path)?;

    writeln!(file, "{}", wallet_block)?;

    pub_b58.zeroize();
    priv_b58.zeroize();

    Ok(())
}