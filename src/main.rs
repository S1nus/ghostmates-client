#![feature(iter_zip)]
use std::{
    sync::{Arc, Mutex},
    net::SocketAddr,
    borrow::Cow,
    io::{stdout,stdin,Write},
};

use futures::prelude::*;
use futures::{
    pin_mut,
    future,
    channel::mpsc::{unbounded},
};
use futures::stream::{SplitStream, SplitSink};

use async_std::{
    net::{TcpListener,
        TcpStream,
    },
    task,
};

use async_tungstenite::async_std::connect_async;
use async_tungstenite::WebSocketStream;
use async_tungstenite::tungstenite::Error as TungsteniteError;
use async_tungstenite::tungstenite::protocol::Message;

use colored::Colorize;

use sodiumoxide::crypto::box_::{PublicKey as SodiumPublicKey, SecretKey as SodiumSecretKey, Nonce as SodiumNonce};
use sodiumoxide::crypto::box_;

use base58::{ToBase58, FromBase58};
use sha2::{Sha256, Digest, 
    digest::generic_array::GenericArray
};
use ripemd160::{Ripemd160};
use bincode;
use serde::{Serialize, Deserialize};

use flurry::HashMap;

use ghostmates_common::{
    GhostmatesMessage, 
    ProtocolMessage, 
    PCheckMessage,
};

mod client;
use client::{address_from_sodium_pk, Client, new_client};

type WebSocketWrite = SplitSink<WebSocketStream<TcpStream>, Message>;
type WebSocketRead = SplitStream<WebSocketStream<TcpStream>>;

async fn connect_to_server() -> WebSocketStream<TcpStream> {

    let server_addr = "ws://127.0.0.1:4000".to_string();
    let (server_stream, _) = connect_async(server_addr)
        .await
        .expect("Failed to connect.");

    println!("Connected to ghxs!");

    server_stream

}

async fn server_loop(read: WebSocketRead, client: Client) {

    let _server_incoming = read
        .try_filter(|msg| {
            future::ready(!msg.is_close())
        })
        .try_for_each(|msg| {
            if let Message::Binary(d) = msg {
                let gm : GhostmatesMessage = bincode::deserialize(&d).unwrap();
                client.route(&gm);
            }
            stdout().flush().unwrap();
            future::ok(())
        }).await.expect("Server loop failed");

    println!("Server loop ended.");
}

async fn user_loop(client: Client) {
    loop {
        let mut input_string = String::new();
        stdout().flush().unwrap();
        print!("ghxc> ");
        stdout().flush().unwrap();
        stdin().read_line(&mut input_string).expect("Did not enter a correct string");
        if let Some('\n')=input_string.chars().next_back() {
            input_string.pop();
        }
        if let Some('\r')=input_string.chars().next_back() {
            input_string.pop();
        }
        let split_string : Vec<&str> = input_string.split(" ").collect();
        match split_string[0] {
            "pcheck" => {
                if split_string.len() == 3 {
                    let first_gaddress = split_string[1].to_string();
                    let second_gaddress = split_string[2].to_string();
                    client.pcheck(first_gaddress, second_gaddress);
                }
                else {
                    print!("{}\n", "Invalid".red());
                    continue
                }

            },
            "id" => {
                let address_to_lookup = split_string[1].to_string();
                client.lookup(address_to_lookup);
            },
            "toggle" => {
                client.toggle(split_string[1]);
            },
            _ => {

            }
        }
    }
}


enum ActiveProtocolRow {
    ACheck {
        courier_gaddress: String,
    },
    PCheckCourier {
        sender_gaddress: String,
        recipient_gaddress: String,
    },
    PCheckSender {
        courier_gaddress: String,
        recipient_gaddress: String,
    },
    PCheckRecipient {
        sender_gaddress: String,
        courier_gaddress: String,
    }
}

enum ProtocolRoundData {
    PCheckCourier {
        tValuesFromSender: Option<TValuesFromSender>,
        tValuesFromRecipient: Option<TValuesFromRecipient>,
    },
}

struct TValuesFromSender{}
struct TValuesFromRecipient{}

fn main() {
    println!("
╭━━━┳╮╱╱╱╱╱╱╱╭╮╱╱╱╱╱╱╭╮
┃╭━╮┃┃╱╱╱╱╱╱╭╯╰╮╱╱╱╱╭╯╰╮
┃┃╱╰┫╰━┳━━┳━┻╮╭╋╮╭┳━┻╮╭╋━━┳━━╮
┃┃╭━┫╭╮┃╭╮┃━━┫┃┃╰╯┃╭╮┃┃┃┃━┫━━┫
┃╰┻━┃┃┃┃╰╯┣━━┃╰┫┃┃┃╭╮┃╰┫┃━╋━━┃
╰━━━┻╯╰┻━━┻━━┻━┻┻┻┻╯╰┻━┻━━┻━━╯
    ");
    println!("{} You are currently trusting a centralized server for anonymity!", "Warning!".red().bold());

    let (ourpk, oursk) = box_::gen_keypair();
    let ghost_address = address_from_sodium_pk(&ourpk);
    println!("{} {}", "Your address: ".bold(), &ghost_address);

    let active_protocols = Arc::new(HashMap::<ActiveProtocolRow, ProtocolRoundData>::new());

    let id_message = GhostmatesMessage::Identify {
        ghostmates_address: ghost_address.clone(),
        pubkey: ourpk.clone(),
    };
    let id_message_as_bytes: Vec<u8> = bincode::serialize(&id_message)
        .expect("Could not serialize id_message");

    let server_connection = task::block_on(connect_to_server());
    let (server_write, server_read) = server_connection.split();
    let arc_server_write = Arc::new(Mutex::new(server_write));
    let client = new_client(ourpk.clone(), oursk.clone(), arc_server_write.clone());
    task::block_on(
        arc_server_write
            .lock()
            .unwrap()
            .send(
                Message::Binary(id_message_as_bytes)
            )
    );
    task::spawn(server_loop(server_read, client.clone()));
    task::block_on(user_loop(client.clone()));
}
