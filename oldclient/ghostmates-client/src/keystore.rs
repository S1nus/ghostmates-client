use std::fs::{File, create_dir_all, read, rename, read_to_string};
use std::path::{PathBuf, Path};
use std::io::Write;
use sha2::{Sha256, Digest, 
    digest::generic_array::GenericArray
};
use ripemd160::{Ripemd160};

use paillier::{
    *,
    EncryptionKey as PaillierPK,
    DecryptionKey as PaillierSK,
};

use sodiumoxide::crypto::box_::{
    SecretKey,
    PublicKey,
    gen_keypair,
};

use serde_json::from_str;
use serde::{Deserialize, Serialize};

use base58::{ToBase58, FromBase58};

#[derive(Debug)]
pub struct KeyStore {
    pub sodium: SodiumKeyPair,
    pub paillier: PaillierKeyPair
}

#[derive(Debug)]
pub struct SodiumKeyPair {
    pub sodium_sk: SecretKey,
    pub sodium_pk: PublicKey
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PaillierKeyPair {
    pub paillier_sk: PaillierSK,
    pub paillier_pk: PaillierPK
}

pub fn address_from_sodium_pk(pk: &PublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pk.as_ref());
    let result = hasher.finalize();
    let sha256hash : Vec<u8> = result.as_slice().to_owned();
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(sha256hash);
    let ripemd_result = ripemd_hasher.finalize();
    let ripemdhash: Vec<u8> = ripemd_result.as_slice().to_owned(); 
    let mut base58 = ripemdhash.to_base58();
    base58.push_str(".ghost");
    base58
}

fn make_sodium_keypair_file(path: &PathBuf) -> SodiumKeyPair {
    let (newpk, newsk) = gen_keypair();
    create_dir_all(path)
        .expect("directory doesn't exist, and couldn't create it");
    let mut file = File::create(path.join("sodium.sk"))
        .expect("could not create sodium.sk file at target location");
    file.write_all(newsk.as_ref())
        .expect("could not write new key to file");
    SodiumKeyPair {
        sodium_sk: newsk,
        sodium_pk: newpk
    }
}

fn make_paillier_keypair_file(path: &PathBuf) -> PaillierKeyPair {
    let (pk, sk) = Paillier::keypair().keys();
    let kp = PaillierKeyPair {
        paillier_sk: sk,
        paillier_pk: pk,
    };
    create_dir_all(path)
        .expect("failed to create directory. Weird, because it should have failed in the previous step.");
    let mut file = File::create(path.join("paillier.pair"))
        .expect("could not create Paillier file. Weird, because we should have already created the Sodium file.");
    file.write_all(
        serde_json::to_string(&kp)
        .expect("failed to serialize")
        .as_bytes()
    )
    .expect("failed to write Paillier file");
    kp
}

pub fn get_crypto_from_folder(path: &PathBuf) -> KeyStore {

    let sodium_keypair : SodiumKeyPair;

    sodium_keypair = if path.join("sodium.sk").exists() {
        let from_file = read(path.join("sodium.sk"))
            .expect("failed to read sodium.sk");
        if let Some(key) = SecretKey::from_slice(&from_file) {
            SodiumKeyPair {
                sodium_pk: key.public_key(),
                sodium_sk: key,
            }
        }
        else {
            println!("the file wasn't valid");
            // the file wasn't valid
            // rename / move the ones we found
            rename(path.join("sodium.sk"), path.join("sodium-old.sk"))
                .expect("unable to move an old, invalid sodium.sk file");
            // generate new ones
            make_sodium_keypair_file(path)
        }
    }
    else {
        println!("No private key found for sodium");
        make_sodium_keypair_file(path)
    };

    let paillier =
    if path.join("paillier.pair").exists() {
        let from_file = read_to_string(path.join("paillier.pair"))
            .expect("unable to read paillier.sk");
        let pair : PaillierKeyPair = serde_json::from_str(
            &from_file
        )
        .expect("unable to parse paillier.pair file");
        pair
    }
    else {
        // create paillier files
        make_paillier_keypair_file(path)
    };

    KeyStore {
        sodium: sodium_keypair,
        paillier: paillier
    }
}
