use rand::Rng;

use std::env;
use std::net::SocketAddrV4;
use std::sync::{Arc, Mutex};
use std::path::PathBuf;
use std::time::SystemTime;

use async_std::prelude::*;
use async_std::io::prelude::BufReadExt;

use async_std::{task,
    io::{BufRead, BufReader},
    net::{TcpListener, TcpStream},
    stream::{Stream, StreamExt},
};

use serde_json::de::Deserializer;

use paillier::*;

use std::mem::size_of;

use futures::stream::TryStreamExt;
use futures::SinkExt;
use futures_codec::{Bytes, BytesMut, LengthCodec, Framed, FramedWrite, Decoder, Encoder};
use std::io::{Error, ErrorKind};

mod net;
use net::connect_to_server;

mod keystore;
use keystore::{KeyStore, get_crypto_from_folder, address_from_sodium_pk};

use clap::{AppSettings, Clap};
use dirs::home_dir;

use sodiumoxide::crypto::box_::PublicKey as SodiumPublicKey;
use sodiumoxide::crypto::sign;

#[derive(Clap)]
#[clap(version="1.0", author = "S1nus")]
#[clap(setting = AppSettings::ColoredHelp)]
struct Opts {
    #[clap(long)]
    keys_dir: Option<String>
}

struct ServerIntro {
    ghostmates_address: String,
    public_key: SodiumPublicKey
}

fn main() {

    let opts: Opts = Opts::parse();

    let keys_dir : PathBuf = match &opts.keys_dir {
        Some(d) => PathBuf::from(d),
        None => {
            if let Some(mut p) = home_dir() {
                p.push(".config");
                p.push("ghostmates");
                p.push("keys");
                p
            }
            else {
                panic!("please specify a --keys-dir");
            }
        }
    };

    let keystore : KeyStore = get_crypto_from_folder(&keys_dir);  

    println!("Welcome to Ghostmates.");

    let address = address_from_sodium_pk(&keystore.sodium.sodium_pk); 
    println!("address: {}", address);

    println!("You are currently trusting a centralized server with your IP address.\nMixnet is coming soon!");

    let systemtime = SystemTime::now();
    println!("timestamp: {:?}", systemtime);
    let message_to_sign = b"hello ghostmates";
    let signed = sign::sign(message_to_sign, &keystore.sodium.sodium_sk);
    println!("signed {:?}", signed);

}
