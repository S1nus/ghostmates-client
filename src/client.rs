use futures::stream::{SplitStream, SplitSink};
use futures::SinkExt;

use sodiumoxide::crypto::box_::{PublicKey as SodiumPublicKey, SecretKey as SodiumSecretKey, Nonce as SodiumNonce};
use sodiumoxide::crypto::box_;

use flurry::HashMap;

use std::{
    sync::{Arc, Mutex},
    net::SocketAddr,
};

use async_std::task;
use async_std::net::{TcpStream};
use async_tungstenite::tungstenite::Message;
use async_tungstenite::WebSocketStream;

use ghostmates_common::{GhostmatesMessage,ProtocolMessage, PCheckMessage};
use colored::Colorize;
use base58::{ToBase58, FromBase58};
use sha2::{Sha256, Digest, 
    digest::generic_array::GenericArray
};
use ripemd160::{Ripemd160};
use bincode;

pub struct SenderPCheckProtoData {}
pub struct CourierPCheckProtoData {}
pub struct RecipientPCheckProtoData {}
pub struct ACheckProtoData {}

#[derive(Clone)]
pub struct Client {
    pk: SodiumPublicKey,
    sk: SodiumSecretKey,
    server_write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,

    peer_store: Arc<HashMap<String, SodiumPublicKey>>,
    sender_pcheck_table: Arc<HashMap<(String, String), SenderPCheckProtoData>>,
    courier_pcheck_table: Arc<HashMap<(String, String), CourierPCheckProtoData>>,
    recipient_pcheck_table: Arc<HashMap<(String, String), RecipientPCheckProtoData>>,

    outgoing_encrypts: Arc<HashMap<String, Arc<Mutex<Vec<ProtocolMessage>>>>>,
    incoming_decrypts: Arc<HashMap<String, Arc<Mutex<Vec<(SodiumNonce, Vec<u8>)>>>>>,

    accepting_achecks: bool,
    pcheck_courier: bool,
    pcheck_sender: bool,
    pcheck_recipient: bool,
}

pub fn new_client(pk: SodiumPublicKey, 
    sk: SodiumSecretKey, 
    server_write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
) -> Client {
    Client {
        pk: pk,
        sk: sk,
        server_write: server_write,

        sender_pcheck_table: Arc::new(HashMap::new()),
        courier_pcheck_table: Arc::new(HashMap::new()),
        recipient_pcheck_table: Arc::new(HashMap::new()),
        outgoing_encrypts: Arc::new(HashMap::new()),
        incoming_decrypts: Arc::new(HashMap::new()),
        peer_store: Arc::new(HashMap::new()),

        accepting_achecks: true,
        pcheck_courier: true,
        pcheck_sender: true,
        pcheck_recipient: true,
    }
}

impl Client {
    pub fn route(&self, gm: &GhostmatesMessage) {
        match gm {
            GhostmatesMessage::SuccesfulIdentify => {
                print!("{}\nghxc> ", "Succesfully Authenticated".green());
            },
            GhostmatesMessage::FailedIdentify => {
                print!("{}\nghxc> ", "Failed to authenticate!".red());
            },
            GhostmatesMessage::SuccesfulLookup {
                ghostmates_address,
                pubkey
            }=> {
                if self.validate_address(ghostmates_address.clone(), pubkey.clone()) {
                    if let Some(to_decrypt) = self.incoming_decrypts.get(
                        &ghostmates_address.clone(),
                        &self.incoming_decrypts.guard()
                    ) {
                        to_decrypt.lock().unwrap().iter().for_each(|(nonce, cyphertext)| {
                            self.decrypt_incoming(ghostmates_address.clone(), cyphertext.to_vec(), *nonce);
                        });
                    }
                    if let Some(to_encrypt) = self.outgoing_encrypts.get(
                        &ghostmates_address.clone(),
                        &self.outgoing_encrypts.guard()
                    ) {
                        to_encrypt.lock().unwrap().iter().for_each(|pm| {
                            if let Some(dm) = self.direct_message(self.sk.clone(), ghostmates_address.clone(), pm.clone(), self.peer_store.clone()) {
                                let serialized_dm = bincode::serialize(&dm)
                                    .expect("Couldn't serialize dm");
                                task::block_on(
                                    self.server_write
                                    .lock()
                                    .unwrap()
                                    .send(
                                        Message::Binary(serialized_dm)
                                    )
                                );
                            }
                            else {
                                print!("Major problem dude.\nghxc> ");
                            }
                        });
                    }
                }
                else {
                    println!("Not good!");
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
                self.decrypt_incoming(from_address.clone(), encrypted_message.clone(), nonce.clone());
            },
            _ => {
                print!("{}\nghxc> ", "Got an unknown response".red());
            }
        }
    }

    pub fn validate_address(&self, ghostmates_address: String, pubkey: SodiumPublicKey) -> bool {
        let address_from_pk = address_from_sodium_pk(&pubkey);
        if address_from_pk.eq(&ghostmates_address.clone()) {
            print!("{}\nghxc> ", "valid!!!".green());
            if !self.peer_store.contains_key(&ghostmates_address.clone(), &self.peer_store.guard()) {
                print!("\n{}\nghxc> ", "Added to peerstore.".yellow());
                self.peer_store.insert(ghostmates_address.clone(), pubkey.clone(), &self.peer_store.guard());
            }
            return true
        }
        else {
            print!("{}\nghxc> ", "invalid!!! (This should never happen)".red());
            return false
        }

    }

    pub fn decrypt_incoming(&self, from_address: String, encrypted_message: Vec<u8>, nonce: SodiumNonce) {
        print!("{}",
            format!("{} {}\nghxc> ", "Received a message from".yellow(), from_address.blue())
        );
        if let Some(their_pk) = self.peer_store.get(
            &from_address.clone(), 
            &self.peer_store.guard()
        ) {
            let decrypted = box_::open(&encrypted_message, &nonce, &their_pk, &self.sk)
                .expect("Could not decrypt.");
            let deserialized : ProtocolMessage = bincode::deserialize(&decrypted)
                .expect("Couldn't deserialize.");
            self.route_incoming(from_address.clone(), deserialized.clone());
        }
        else {
            print!("{} {}\nghxc> ", "We don't have their PK.".red(), "adding their message to the decrypt queue and looking up their PK...");
            if let Some(decrypt_vector) = self.incoming_decrypts.get(
                &from_address.clone(),
                &self.incoming_decrypts.guard()
            ) {
                decrypt_vector.lock().unwrap().push((nonce, encrypted_message));
            }
            else {
                self.incoming_decrypts.insert(
                    from_address.clone(), 
                    Arc::new(Mutex::new(vec![(
                        nonce,
                        encrypted_message
                    )])), 
                    &self.incoming_decrypts.guard()
                );
            }
            self.lookup(from_address);
        }

    }

    pub fn pcheck(&self, courier_address: String, recipient_address: String) {

        if ! (courier_address.len() > 31 && courier_address.len() < 35) {
            print!("{}\n", "invalid courier addres".red());
            return
        }
        if ! (recipient_address.len() > 31 && recipient_address.len() < 35) {
            print!("{}\n", "invalid recipient address".red());
            return
        }
        let intro = ProtocolMessage::PCheck(
            PCheckMessage::RequestForPCheck {
                recipient_ghost_address: recipient_address.clone(),
            }
        );
        if let Some(dm) = self.direct_message(self.sk.clone(), recipient_address.clone(), intro, self.peer_store.clone()) {
            let serialized_dm = bincode::serialize(&dm)
                .expect("Couldn't serialize dm");
            task::block_on(
                self.server_write
                .lock()
                .unwrap()
                .send(
                    Message::Binary(serialized_dm)
                )
            );
        }
    }

    pub fn lookup(&self, lookup_address: String) {

        let lookup = GhostmatesMessage::Lookup {
            dest_address: lookup_address
        };
        let lookup_as_bytes: Vec<u8> = bincode::serialize(&lookup)
            .expect("Could not serialize lookup message");
        task::block_on(
            self.server_write
            .lock()
            .unwrap()
            .send(
                Message::Binary(lookup_as_bytes)
            )
        );
    }

    pub fn toggle(&self, arg: &str) {
        println!("This doesn't do anything for now.");
        match arg {
            "neighbor" => {
            },
            "courier" => {

            },
            "recipient" => {

            },
            _ => {

            }
        }
    }

    pub fn direct_message(&self, sk: SodiumSecretKey, ghost_address: String, protocol_message: ProtocolMessage, peer_store: Arc<HashMap<String, SodiumPublicKey>>) -> Option<GhostmatesMessage> {
        //let pubkey = *peer_store.get(&ghost_address, &peer_store.guard()).unwrap();
        if let Some(pubkey) = peer_store.get(&ghost_address, &peer_store.guard()) {
            let nonce = box_::gen_nonce();
            let serialized_message = bincode::serialize(&protocol_message)
                .expect("Could not serialize protocol message");
            let cyphertext = box_::seal(&serialized_message, &nonce, &pubkey, &sk);
            Some(GhostmatesMessage::DirectMessage{
                dest_address: ghost_address,
                encrypted_message: cyphertext,
                nonce: nonce,
            })
        }
        else {
            if let Some(encrypt_vector) = self.outgoing_encrypts.get(
                &ghost_address.clone(),
                &self.incoming_decrypts.guard()
            ) {
                encrypt_vector.lock().unwrap().push(protocol_message);
            }
            else {
                self.outgoing_encrypts.insert(
                    ghost_address.clone(), 
                    Arc::new(Mutex::new(vec![
                        protocol_message
                    ])), 
                    &self.incoming_decrypts.guard()
                );
            }
            self.lookup(ghost_address);
            None
        }
    }

    pub fn route_incoming(&self, from_address: String, message: ProtocolMessage) {
        println!("{} {:?} from {}", "received".bold(), message, from_address.blue());
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

