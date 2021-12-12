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

use paillier::*;
use paillier::{
    EncryptionKey as PaillierEncryptionKey,
    DecryptionKey as PaillierDecryptionKey,
    encoding::EncodedCiphertext as PaillierEncodedCiphertext
};
use rand::{distributions::Uniform, Rng, rngs::ThreadRng};

pub struct SenderPCheckProtoData {
    sender_a_values: Vec<u64>,
    sender_b_values: Vec<u64>,
    recipient_paillier_key: Option<PaillierEncryptionKey>,
    recipient_to_sender_a_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    recipient_to_sender_b_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    recipient_to_sender_encrypted_a_b_pairs: Option<Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)>>,

    courier_paillier_key: Option<PaillierEncryptionKey>,
    courier_to_sender_a_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    courier_to_sender_b_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    courier_to_sender_encrypted_a_b_pairs: Option<Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)>>,
}

impl SenderPCheckProtoData {
    pub fn new_with_ab_values() -> SenderPCheckProtoData {

        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 7757);

        let a_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
        let b_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();

        SenderPCheckProtoData {
            sender_a_values: a_vals,
            sender_b_values: b_vals,
            recipient_paillier_key: None,
            recipient_to_sender_a_shares: None,
            recipient_to_sender_b_shares: None,
            recipient_to_sender_encrypted_a_b_pairs: None,

            courier_paillier_key: None,
            courier_to_sender_a_shares: None,
            courier_to_sender_b_shares: None,
            courier_to_sender_encrypted_a_b_pairs: None,
        }
    }
}

#[derive(Clone)]
pub struct CourierPCheckProtoData {
    a_values: Option<Vec<u64>>,
    b_values: Option<Vec<u64>>,
    encrypted_a_b_pairs: Option<Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)>>
}
#[derive(Clone)]
pub struct RecipientPCheckProtoData {
    a_values: Option<Vec<u64>>,
    b_values: Option<Vec<u64>>,
    encrypted_a_b_pairs: Option<Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)>>
}
pub struct ACheckProtoData {}

#[derive(Clone)]
pub struct Client {
    pk: SodiumPublicKey,
    sk: SodiumSecretKey,
    ghost_address: String,

    paillier_pubkey: PaillierEncryptionKey,
    paillier_privkey: PaillierDecryptionKey,

    server_write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,

    peer_store: Arc<HashMap<String, SodiumPublicKey>>,
    sender_pcheck_table: Arc<HashMap<(String, String), Arc<Mutex<SenderPCheckProtoData>>>>,
    courier_pcheck_table: Arc<HashMap<(String, String), Arc<Mutex<CourierPCheckProtoData>>>>,
    recipient_pcheck_table: Arc<HashMap<(String, String), Arc<Mutex<RecipientPCheckProtoData>>>>,

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
    let (ppk, psk) = Paillier::keypair().keys();
    Client {
        pk: pk,
        sk: sk,
        server_write: server_write,
        paillier_pubkey: ppk,
        paillier_privkey: psk,

        sender_pcheck_table: Arc::new(HashMap::new()),
        courier_pcheck_table: Arc::new(HashMap::new()),
        recipient_pcheck_table: Arc::new(HashMap::new()),
        outgoing_encrypts: Arc::new(HashMap::new()),
        incoming_decrypts: Arc::new(HashMap::new()),
        peer_store: Arc::new(HashMap::new()),

        ghost_address: address_from_sodium_pk(&pk),

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
        self.sender_pcheck_table.insert(
            (courier_address.clone(), recipient_address.clone()),
            Arc::new(Mutex::new(SenderPCheckProtoData::new_with_ab_values())),
            &self.sender_pcheck_table.guard()
        );
        let intro = ProtocolMessage::PCheck(
            PCheckMessage::RequestForPCheck {
                recipient_ghost_address: recipient_address.clone(),
                courier_ghost_address: courier_address.clone(),
            }
        );
        if let Some(recipient_dm) = self.direct_message(self.sk.clone(), recipient_address.clone(), intro.clone(), self.peer_store.clone()) {
            let serialized_dm = bincode::serialize(&recipient_dm)
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
        if let Some(courier_dm) = self.direct_message(self.sk.clone(), courier_address.clone(), intro.clone(), self.peer_store.clone()) {
            let serialized_dm = bincode::serialize(&courier_dm)
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
        println!("{} from {}", "received".bold(), from_address.blue());
        match message {
            ProtocolMessage::PCheck(pcm) => {
                match pcm {
                    PCheckMessage::RequestForPCheck {
                        recipient_ghost_address,
                        courier_ghost_address
                    } => {
                        if recipient_ghost_address == courier_ghost_address {
                            print!("they're the same. Invalid.\nghxc> ");
                            return
                        }
                        if recipient_ghost_address == self.ghost_address {
                            print!("I'm recipient.\nghxc> ");
                            println!("generating pcheck round1 data...");
                            let recipient_pcheck_data = Arc::new(Mutex::new(self.generate_recipient_pcheck_data()));
                            println!("finished generating.");
                            self.recipient_pcheck_table.insert(
                                (from_address.clone(), recipient_ghost_address.clone()),
                                recipient_pcheck_data.clone(),
                                &self.recipient_pcheck_table.guard()
                            );
                            if let Some(dm) = self.direct_message(
                                self.sk.clone(), 
                                from_address.clone(),
                                ProtocolMessage::PCheck(
                                    PCheckMessage::RecipientToSenderRound1 {
                                        courier_address: courier_ghost_address,
                                        paillier_key: self.paillier_pubkey.clone(),
                                        enc_ab_pairs: recipient_pcheck_data.lock().unwrap().encrypted_a_b_pairs.clone().unwrap(),
                                        a_shares: vec![],
                                        b_shares: vec![],
                                    }
                                ),
                                self.peer_store.clone(),
                            ) {
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
                            };
                        }
                        else if courier_ghost_address == self.ghost_address {
                            print!("I'm courier.\nghxc> ");
                            println!("generating pcheck round1 data...");
                            let courier_pcheck_data = Arc::new(Mutex::new(self.generate_courier_pcheck_data()));
                            println!("finished generating.");
                            self.courier_pcheck_table.insert(
                                (from_address.clone(), recipient_ghost_address.clone()),
                                courier_pcheck_data.clone(),
                                &self.courier_pcheck_table.guard()
                            );
                            if let Some(dm) = self.direct_message(
                                self.sk.clone(), 
                                from_address.clone(),
                                ProtocolMessage::PCheck(
                                    PCheckMessage::CourierToSenderRound1 {
                                        recipient_address: recipient_ghost_address,
                                        paillier_key: self.paillier_pubkey.clone(),
                                        enc_ab_pairs: courier_pcheck_data.lock().unwrap().encrypted_a_b_pairs.clone().unwrap(),
                                        a_shares: vec![],
                                        b_shares: vec![],
                                    }
                                ),
                                self.peer_store.clone(),
                            ) {
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
                            };

                        }
                    },
                    PCheckMessage::RecipientToSenderRound1 {
                        courier_address,
                        paillier_key,
                        enc_ab_pairs,
                        a_shares,
                        b_shares,
                    }=> {
                        println!("received a round1 from a recipient courier: {}", courier_address); 
                        if let Some(proto_data) = self.sender_pcheck_table
                            .get(
                                &(courier_address.clone(), from_address.clone()),
                                &self.sender_pcheck_table.guard()
                             )
                        { 
                            if let Ok(mut pd) = proto_data.lock() {
                                pd.recipient_paillier_key = Some(paillier_key);
                                pd.recipient_to_sender_a_shares = Some(a_shares);
                                pd.recipient_to_sender_b_shares = Some(b_shares);
                                pd.recipient_to_sender_encrypted_a_b_pairs = Some(enc_ab_pairs);
                            }

                        }
                        self.sender_process_round1(courier_address.clone(), from_address.clone());
                    },
                    PCheckMessage::CourierToSenderRound1 {
                        recipient_address,
                        paillier_key,
                        enc_ab_pairs,
                        a_shares,
                        b_shares,
                    } => {
                        println!("received a round1 from a courier"); 
                        println!("received a round1 from a courier recipient: {}", recipient_address); 
                        if let Some(proto_data) = self.sender_pcheck_table
                            .get(
                                &(from_address.clone(), recipient_address.clone()),
                                &self.sender_pcheck_table.guard()
                             )
                        { 
                            if let Ok(mut pd) = proto_data.lock() {
                                pd.courier_paillier_key = Some(paillier_key);
                                pd.courier_to_sender_a_shares = Some(a_shares);
                                pd.courier_to_sender_b_shares = Some(b_shares);
                                pd.courier_to_sender_encrypted_a_b_pairs = Some(enc_ab_pairs);
                            }

                        }
                        self.sender_process_round1(from_address.clone(), recipient_address.clone());
                    },
                    _ => {
                        print!("No implementation for this message type yet.\nghxc> ");
                    }
                }
            },
            _ => {
                print!("No implementation for this message type yet.\nghxc> ");
            }
        }
    }

    fn generate_courier_pcheck_data(&self) -> CourierPCheckProtoData {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 7757);

        let a_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
        let b_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
        let pairs: Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)> =  
            a_vals.iter().zip(b_vals.iter()).map(|(a, b)| 
        {
            (
                Paillier::encrypt(&self.paillier_privkey, *a),
                Paillier::encrypt(&self.paillier_privkey, *b)
            )
        }).collect();
        CourierPCheckProtoData {
            a_values: Some(a_vals),
            b_values: Some(b_vals),
            encrypted_a_b_pairs: Some(pairs),
        }
    }

    fn generate_recipient_pcheck_data(&self) -> RecipientPCheckProtoData {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 7757);

        let a_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
        let b_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
        let pairs: Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)> =  
            a_vals.iter().zip(b_vals.iter()).map(|(a, b)| 
        {
            (
                Paillier::encrypt(&self.paillier_privkey, *a),
                Paillier::encrypt(&self.paillier_privkey, *b)
            )
        }).collect();
        RecipientPCheckProtoData {
            a_values: Some(a_vals),
            b_values: Some(b_vals),
            encrypted_a_b_pairs: Some(pairs),
        }
    }

    fn sender_process_round1(&self, courier_address: String, recipient_address: String,) {
        if let Some(proto_data) = self.sender_pcheck_table
        .get(
            &(courier_address.clone(), recipient_address.clone()),
            &self.sender_pcheck_table.guard()
        ) {
            if let Ok(pd) = proto_data.lock() {
                if (
                    pd.recipient_paillier_key.is_some() &&
                    pd.recipient_to_sender_a_shares.is_some() &&
                    pd.recipient_to_sender_b_shares.is_some() &&
                    pd.recipient_to_sender_encrypted_a_b_pairs.is_some() &&

                    pd.courier_paillier_key.is_some() &&
                    pd.courier_to_sender_a_shares.is_some() &&
                    pd.courier_to_sender_b_shares.is_some() &&
                    pd.courier_to_sender_encrypted_a_b_pairs.is_some()
                ) {
                    print!("{}\nghxc> ", "WE ARE REDY FOR ROUND 2".green().bold());
                    self.sender_generate_RTs(&pd);
                }
                else {
                    print!("{}\nghxc> ", "We don't have it all yet".yellow());
                }
            }
            else {
                print!("{}\nghxc> ", "Major problem".red().bold());
            }
        }
        else {
            print!("{}\nghxc> ", "Major Problem!".red().bold());
        }
    }

    fn sender_generate_RTs(&self, pd: &SenderPCheckProtoData) {
        // duhhh
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

