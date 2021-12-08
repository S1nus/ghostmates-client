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

async fn server_loop(read: WebSocketRead, s: Arc<Mutex<WebSocketWrite>>, peer_store: Arc<HashMap<String, SodiumPublicKey>>, sk: SodiumSecretKey) {

    let _server_incoming = read
        .try_filter(|msg| {
            future::ready(!msg.is_close())
        })
        .try_for_each(|msg| {
            if let Message::Binary(d) = msg {
                let gm : GhostmatesMessage = bincode::deserialize(&d).unwrap();
                match gm {
                    GhostmatesMessage::SuccesfulIdentify => {
                        print!("{}\nghxc> ", "Succesfully Authenticated".green());
                    },
                    GhostmatesMessage::FailedIdentify => {
                        print!("{}\nghxc> ", "Failed to authenticate!".red());
                    },
                    GhostmatesMessage::SuccesfulLookup {
                        ghostmates_address,
                        pubkey,
                    } => {
                        let address_from_pk = address_from_sodium_pk(&pubkey);
                        if address_from_pk.eq(&ghostmates_address) {
                            print!("{}\nghxc> ", "valid!!!".green());
                            if !peer_store.contains_key(&ghostmates_address, &peer_store.guard()) {
                                print!("\n{}\nghxc> ", "Added to peerstore.".yellow());
                                peer_store.insert(ghostmates_address, pubkey, &peer_store.guard());
                            }
                        }
                        else {
                            print!("{}\nghxc> ", "invalid!!! (This should never happen)".red());
                        }
                    },
                    GhostmatesMessage::FailedLookup {
                        ghostmates_address
                    } => {
                        print!("{}\nghxc> ", format!("invalid lookup for {}", ghostmates_address).red());
                    },
                    GhostmatesMessage::IncomingMessage {
                        from_address,
                        encrypted_message,
                        nonce,
                    } => {
                        print!("{}",
                            format!("{} {}\nghxc> ", "Received a message from".yellow(), from_address.blue())
                        );
                        if let Some(their_pk) = peer_store.get(&from_address, &peer_store.guard()) {
                            let decrypted = box_::open(&encrypted_message, &nonce, &their_pk, &sk)
                                .expect("Could not decrypt.");
                            let deserialized : ProtocolMessage = bincode::deserialize(&decrypted)
                                .expect("Couldn't deserialize.");
                            println!("deserialized: {:?}", deserialized);
                        }
                        else {
                            println!("{}", "We don't have their PK. bummer.".red());
                        }
                    },
                    _ => {
                        print!("{}\nghxc> ", "Got an unknown response".red());
                    }
                }
            }
            stdout().flush().unwrap();
            future::ok(())
        }).await.expect("Server loop failed");

    println!("Server loop ended.");
}

async fn user_loop(s: Arc<Mutex<WebSocketWrite>>, peer_store: Arc<HashMap<String, SodiumPublicKey>>, my_key: SodiumSecretKey) {
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
                    let first_gaddress = split_string[1];
                    let second_gaddress = split_string[2];
                    if ! (first_gaddress.len() > 31 && first_gaddress.len() < 35) {
                        print!("{}\n", "invalid first address".red());
                        continue
                    }
                    if ! (second_gaddress.len() > 31 && second_gaddress.len() < 35) {
                        print!("{}\n", "invalid second address".red());
                        continue
                    }
                    let intro = ProtocolMessage::PCheck(
                        PCheckMessage::RequestForPCheck {
                            recipient_ghost_address: second_gaddress.to_string()
                        }
                    );
                    let dm = direct_message(my_key.clone(), second_gaddress.to_string(), intro, peer_store.clone());
                    let serialized_dm = bincode::serialize(&dm)
                        .expect("Couldn't serialize dm");
                    task::block_on(
                        s
                            .lock()
                            .unwrap()
                            .send(
                                Message::Binary(serialized_dm)
                            )
                    );
                }
                else {
                    print!("{}\n", "Invalid".red());
                    continue
                }
            },
            "id" => {
                let lookup = GhostmatesMessage::Lookup {
                    dest_address: split_string[1].to_string()
                };
                let lookup_as_bytes: Vec<u8> = bincode::serialize(&lookup)
                    .expect("Could not serialize lookup message");
                task::block_on(
                    s
                        .lock()
                        .unwrap()
                        .send(
                            Message::Binary(lookup_as_bytes)
                        )
                );
            },
            _ => {

            }
        }
    }
}

pub fn address_from_sodium_pk(pk: &SodiumPublicKey) -> String {
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

#[derive(Serialize, Deserialize, Debug)]
enum GhostmatesMessage {
    Identify {
        ghostmates_address: String,
        pubkey: SodiumPublicKey,
    },
    SuccesfulIdentify,
    FailedIdentify,
    SuccesfulLookup {
        pubkey: SodiumPublicKey,
        ghostmates_address: String,
    },
    FailedLookup {
        ghostmates_address: String,
    },
    Lookup {
        dest_address: String,
    },
    DirectMessage {
        dest_address: String,
        encrypted_message: Vec<u8>,
        nonce: SodiumNonce
    },
    IncomingMessage {
        from_address: String,
        encrypted_message: Vec<u8>,
        nonce: SodiumNonce,
    },
}

#[derive(Serialize, Deserialize, Debug)]
enum PCheckMessage {
    RequestForPCheck {
        recipient_ghost_address: String
    }
}

#[derive(Serialize, Deserialize, Debug)]
enum ProtocolMessage {
    ACheck,
    PCheck(PCheckMessage),
}

fn direct_message(sk: SodiumSecretKey, ghost_address: String, protocol_message: ProtocolMessage, peer_store: Arc<HashMap<String, SodiumPublicKey>>) -> GhostmatesMessage {
    let pubkey = *peer_store.get(&ghost_address, &peer_store.guard()).unwrap();
    let nonce = box_::gen_nonce();
    let serialized_message = bincode::serialize(&protocol_message)
        .expect("Could not serialize protocol message");
    let cyphertext = box_::seal(&serialized_message, &nonce, &pubkey, &sk);
    GhostmatesMessage::DirectMessage{
        dest_address: ghost_address,
        encrypted_message: cyphertext,
        nonce: nonce,
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

    let peer_store = Arc::new(HashMap::<String, SodiumPublicKey>::new());
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
    task::block_on(
        arc_server_write
            .lock()
            .unwrap()
            .send(
                Message::Binary(id_message_as_bytes)
            )
    );
    task::spawn(server_loop(server_read, arc_server_write.clone(), peer_store.clone(), oursk.clone()));
    task::block_on(user_loop(arc_server_write.clone(), peer_store.clone(), oursk.clone()));
}
