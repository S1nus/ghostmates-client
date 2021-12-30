#![feature(iter_zip)]
use futures::stream::{SplitStream, SplitSink};
use futures::SinkExt;

use sodiumoxide::crypto::box_::{PublicKey as SodiumPublicKey, SecretKey as SodiumSecretKey, Nonce as SodiumNonce};
use sodiumoxide::crypto::box_;

use flurry::HashMap;

use std::{
    sync::{Arc, Mutex},
    net::SocketAddr,
    iter::zip,
    convert::TryFrom,
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

#[derive(Debug)]
pub struct SenderPCheckProtoData {
    r_values_from_courier: Option<Vec<u64>>,
    r_values_from_recipient: Option<Vec<u64>>,
    t_values_for_courier: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    t_values_for_recipient: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    sender_a_values: Vec<u64>,
    sender_b_values: Vec<u64>,
    sender_w_additive_shares: Option<Vec<u64>>,
    recipient_paillier_key: Option<PaillierEncryptionKey>,
    recipient_to_sender_a_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    recipient_to_sender_b_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    recipient_to_sender_encrypted_a_b_pairs: Option<Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)>>,

    courier_paillier_key: Option<PaillierEncryptionKey>,
    courier_to_sender_a_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    courier_to_sender_b_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    courier_to_sender_encrypted_a_b_pairs: Option<Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)>>,
    debug_recipient_a_vals: Option<Vec<u64>>,
    debug_recipient_b_vals: Option<Vec<u64>>,
    debug_recipient_w_vals: Option<Vec<u64>>,
    debug_courier_a_vals: Option<Vec<u64>>,
    debug_courier_b_vals: Option<Vec<u64>>,
    debug_courier_w_vals: Option<Vec<u64>>,
}

impl SenderPCheckProtoData {
    pub fn new_with_ab_values() -> SenderPCheckProtoData {

        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 7757);

        let a_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
        let b_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();

        SenderPCheckProtoData {
            r_values_from_courier: None,
            r_values_from_recipient: None,
            t_values_for_courier: None,
            t_values_for_recipient: None,

            sender_a_values: a_vals,
            sender_b_values: b_vals,
            sender_w_additive_shares: None,
            recipient_paillier_key: None,
            recipient_to_sender_a_shares: None,
            recipient_to_sender_b_shares: None,
            recipient_to_sender_encrypted_a_b_pairs: None,

            courier_paillier_key: None,
            courier_to_sender_a_shares: None,
            courier_to_sender_b_shares: None,
            courier_to_sender_encrypted_a_b_pairs: None,
            debug_recipient_a_vals: None,
            debug_recipient_b_vals: None,
            debug_recipient_w_vals: None,
            debug_courier_a_vals: None,
            debug_courier_b_vals: None,
            debug_courier_w_vals: None,
        }
    }
}

#[derive(Clone,Debug)]
pub struct CourierPCheckProtoData {
    a_values: Option<Vec<u64>>,
    b_values: Option<Vec<u64>>,
    encrypted_a_b_pairs: Option<Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)>>,
    t_values_from_sender: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    r_values_from_recipient: Option<Vec<u64>>,
    courier_w_additive_shares: Option<Vec<u64>>,
    sender_w_additive_shares: Option<Vec<u64>>,
    recipient_w_additive_shares: Option<Vec<u64>>,

    recipient_paillier_key: Option<PaillierEncryptionKey>,
    recipient_to_courier_a_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    recipient_to_courier_b_shares: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    recipient_to_courier_encrypted_a_b_pairs: Option<Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)>>,
    t_values_for_recipient: Option<Vec<PaillierEncodedCiphertext<u64>>>,

    debug_sender_a_vals: Option<Vec<u64>>,
    debug_sender_b_vals: Option<Vec<u64>>,
    debug_sender_w_vals: Option<Vec<u64>>,
    debug_recipient_a_vals: Option<Vec<u64>>,
    debug_recipient_b_vals: Option<Vec<u64>>,
    debug_recipient_w_vals: Option<Vec<u64>>,
}
#[derive(Clone, Debug)]
pub struct RecipientPCheckProtoData {

    a_values: Option<Vec<u64>>,
    b_values: Option<Vec<u64>>,
    encrypted_a_b_pairs: Option<Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)>>,
    t_values_from_sender: Option<Vec<PaillierEncodedCiphertext<u64>>>,
    t_values_from_courier: Option<Vec<PaillierEncodedCiphertext<u64>>>,

    debug_sender_a_vals: Option<Vec<u64>>,
    debug_sender_b_vals: Option<Vec<u64>>,
    debug_sender_w_vals: Option<Vec<u64>>,
    debug_courier_a_vals: Option<Vec<u64>>,
    debug_courier_b_vals: Option<Vec<u64>>,
    debug_courier_w_vals: Option<Vec<u64>>,
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
                            if !self.direct_message(ghostmates_address.clone(), pm.clone()) {
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
        if !self.direct_message(recipient_address.clone(), intro.clone()) {
            print!("{}", "weird that direct messaging would fail at this point.".yellow());
        }

        if !self.direct_message(courier_address.clone(), intro.clone()) {
            print!("{}", "weird that direct messaging would fail at this point.".yellow());
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

    // returns true if the message was sent, or false if it had to do a lookup
    pub fn direct_message(&self, ghost_address: String, protocol_message: ProtocolMessage) -> bool {
        //let pubkey = *peer_store.get(&ghost_address, &peer_store.guard()).unwrap();
        if let Some(pubkey) = self.peer_store.get(&ghost_address, &self.peer_store.guard()) {
            let nonce = box_::gen_nonce();
            let serialized_message = bincode::serialize(&protocol_message)
                .expect("Could not serialize protocol message");
            let cyphertext = box_::seal(&serialized_message, &nonce, &pubkey, &self.sk);
            let m = GhostmatesMessage::DirectMessage{
                dest_address: ghost_address,
                encrypted_message: cyphertext,
                nonce: nonce,
            };
            let serialized_dm = bincode::serialize(&m)
                .expect("Couldn't serialize dm");
            task::block_on(
                self.server_write
                .lock()
                .unwrap()
                .send(
                    Message::Binary(serialized_dm)
                )
            );
            true
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
            false
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

                            let mut pd = match self.recipient_pcheck_table
                            .get(
                                    &(from_address.clone(), courier_ghost_address.clone()),
                                    &self.recipient_pcheck_table.guard()
                             ) {
                                Some(proto_data) => {
                                    proto_data.clone()
                                },
                                None => {
                                    print!("{}\nghxc> ", "We don't have it, but I'll create it.".yellow());
                                    let recipient_pcheck_data = Arc::new(Mutex::new(self.generate_recipient_pcheck_data()));
                                    self.recipient_pcheck_table.insert(
                                        (from_address.clone(), courier_ghost_address.clone()),
                                        recipient_pcheck_data.clone(),
                                        &self.recipient_pcheck_table.guard()
                                    );
                                    println!("The loopup is {} , {}", &from_address, &courier_ghost_address);
                                    recipient_pcheck_data
                                }
                            };

                            println!("The loopup is {} , {}", &from_address, &courier_ghost_address);
                            if !self.direct_message(
                                from_address.clone(),
                                ProtocolMessage::PCheck(
                                    PCheckMessage::RecipientToSenderRound1 {
                                        courier_address: courier_ghost_address,
                                        paillier_key: self.paillier_pubkey.clone(),
                                        enc_ab_pairs: pd.lock().unwrap().encrypted_a_b_pairs.clone().unwrap(),
                                        a_shares: vec![],
                                        b_shares: vec![],
                                    }
                                ),
                            ) {
                                print!("{}\nghxc> ", "had to to a lookup but it should be fine.".yellow());
                            }
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
                            if !self.direct_message(
                                from_address.clone(),
                                ProtocolMessage::PCheck(
                                    PCheckMessage::CourierToSenderRound1 {
                                        recipient_address: recipient_ghost_address.clone(),
                                        paillier_key: self.paillier_pubkey.clone(),
                                        enc_ab_pairs: courier_pcheck_data.lock().unwrap().encrypted_a_b_pairs.clone().unwrap(),
                                        a_shares: vec![],
                                        b_shares: vec![],
                                    }
                                ),
                            ) {
                                print!("{}\nghxc> ", "had to do a lookup but should be fine".yellow());
                            }
                            
                            if !self.direct_message(
                                recipient_ghost_address.clone(),
                                ProtocolMessage::PCheck(
                                    PCheckMessage::CourierRequestRecipient {
                                        sender_ghost_address: from_address.clone(),
                                    }
                                ),
                            ) {
                                print!("{}\nghxc> ", "had to do a lookup for CourierRequestRecipient but should be fine".yellow());
                            }
                        }
                    },
                    PCheckMessage::CourierRequestRecipient {
                        sender_ghost_address
                    } => {
                        print!("{}{}\nghxc> ", "A courier wants me to receive a package from".yellow(), sender_ghost_address.blue());
                        println!("{:?}", self.recipient_pcheck_table
                        .get(
                                &(sender_ghost_address.clone(), from_address.clone()),
                                &self.recipient_pcheck_table.guard()
                         ));

                        let mut pd = match self.recipient_pcheck_table
                        .get(
                                &(sender_ghost_address.clone(), from_address.clone()),
                                &self.recipient_pcheck_table.guard()
                         ) {
                            Some(proto_data) => {
                                proto_data.clone()
                            },
                            None => {
                                print!("{}\nghxc> ", "We don't have it, but I'll create it.".yellow());
                                let recipient_pcheck_data = Arc::new(Mutex::new(self.generate_recipient_pcheck_data()));
                                self.recipient_pcheck_table.insert(
                                    (sender_ghost_address.clone(), from_address.clone()),
                                    recipient_pcheck_data.clone(),
                                    &self.recipient_pcheck_table.guard()
                                );
                                println!("The loopup is {} , {}", &sender_ghost_address, &from_address);
                                recipient_pcheck_data
                            }
                        };

                        if !self.direct_message(
                            from_address.clone(),
                            ProtocolMessage::PCheck(
                                PCheckMessage::RecipientToCourierRound1 {
                                    sender_address: sender_ghost_address,
                                    paillier_key: self.paillier_pubkey.clone(),
                                    enc_ab_pairs: pd.lock().unwrap().encrypted_a_b_pairs.clone().unwrap(),
                                    a_shares: vec![],
                                    b_shares: vec![],
                                }
                            ),
                        ) {
                            print!("{}\nghxc> ", "had to to a lookup but it should be fine.".yellow());
                        }

                    },
                    PCheckMessage::RecipientToSenderRound1 {
                        courier_address,
                        paillier_key,
                        enc_ab_pairs,
                        a_shares,
                        b_shares,
                    } => {
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
                    PCheckMessage::RecipientToCourierRound1 {
                        sender_address,
                        paillier_key,
                        enc_ab_pairs,
                        a_shares,
                        b_shares,
                    } => {
                        println!("received a round1 from a recipient. I'm courier. sender: {}", sender_address); 
                        if let Some(proto_data) = self.courier_pcheck_table
                            .get(
                                &(sender_address.clone(), from_address.clone()),
                                &self.courier_pcheck_table.guard()
                             )
                        {

                            if let Ok(mut pd) = proto_data.lock() {
                                pd.recipient_paillier_key = Some(paillier_key);
                                pd.recipient_to_courier_a_shares = Some(a_shares);
                                pd.recipient_to_courier_b_shares = Some(b_shares);
                                pd.recipient_to_courier_encrypted_a_b_pairs = Some(enc_ab_pairs);
                            }
                            else { panic!("Failed to lock proto data"); }
                            self.courier_generate_RTs(sender_address.clone(), from_address.clone(), proto_data.clone());
                            self.courier_process_round1(sender_address.clone(), from_address.clone());

                        }
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
                    PCheckMessage::SenderToCourierRound1 {
                        recipient_address,
                        sender_to_courier_t_values
                    } => {
                        print!("{}\nghxc> ", "Got some yummy T values from the sender xD".magenta());
                        if let Some(proto_data) = self.courier_pcheck_table
                            .get(
                                &(from_address.clone(), recipient_address.clone()),
                                &self.sender_pcheck_table.guard()
                             )
                        { 
                            if let Ok(mut pd) = proto_data.lock() {
                                pd.t_values_from_sender = Some(sender_to_courier_t_values);
                                // then, check for r values from recipient and generate Ws if we're
                                // ready
                            }
                            self.courier_process_round1(from_address.clone(), recipient_address.clone());
                        }
                    },
                    PCheckMessage::SenderToRecipientRound1 {
                        courier_address,
                        sender_to_recipient_t_values
                    } => {
                        print!("{}\nghxc> ", "Got some yummy T values from the sender xD".magenta());
                        if let Some(proto_data) = self.recipient_pcheck_table
                            .get(
                                &(from_address.clone(), courier_address.clone()),
                                &self.recipient_pcheck_table.guard()
                             )
                        { 
                            if let Ok(mut pd) = proto_data.lock() {
                                pd.t_values_from_sender = Some(sender_to_recipient_t_values);
                                // then, check for t values from recipient and generate Ws if we're
                                // ready
                            }
                            self.recipient_process_round1(from_address.clone(), courier_address.clone());

                        }
                    },
                    PCheckMessage::CourierToRecipientRound1 {
                        sender_address,
                        courier_to_recipient_t_values,
                    } => {
                        print!("{}\nghxc> ", "Received T vals from Courier");
                        if let Some(proto_data) = self.recipient_pcheck_table
                            .get(
                                &(sender_address.clone(), from_address.clone()),
                                &self.recipient_pcheck_table.guard()
                             )
                        { 
                            if let Ok(mut pd) = proto_data.lock() {
                                pd.t_values_from_courier = Some(courier_to_recipient_t_values);
                                // then, check for t values from recipient and generate Ws if we're
                                // ready
                            }
                            self.recipient_process_round1(sender_address.clone(), from_address.clone());
                        }
                    },
                    PCheckMessage::SenderABWReveal {
                        a_vals, b_vals, w_vals
                    } => {
                        println!("got a reveal message.");
                    },
                    PCheckMessage::CourierABWReveal {
                        a_vals, b_vals, w_vals
                    } => {
                        println!("got a reveal message.");
                    },
                    PCheckMessage::RecipientABWReveal {
                        a_vals, b_vals, w_vals
                    } => {
                        println!("got a reveal message.");
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
        let pairs: Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)> =  zip(&a_vals, &b_vals)
        .map(|(a, b)| {
            (Paillier::encrypt(&self.paillier_pubkey, *a), Paillier::encrypt(&self.paillier_pubkey, *b))
        }).collect(); 
        CourierPCheckProtoData {
            a_values: Some(a_vals),
            b_values: Some(b_vals),
            encrypted_a_b_pairs: Some(pairs),
            t_values_from_sender: None,
            r_values_from_recipient: None,
            courier_w_additive_shares: None,
            sender_w_additive_shares: None,
            recipient_w_additive_shares: None,
            recipient_paillier_key: None,
            recipient_to_courier_a_shares: None,
            recipient_to_courier_b_shares: None,
            recipient_to_courier_encrypted_a_b_pairs: None,
            t_values_for_recipient: None,
            debug_sender_a_vals: None,
            debug_sender_b_vals: None,
            debug_sender_w_vals: None,
            debug_recipient_a_vals: None,
            debug_recipient_b_vals: None,
            debug_recipient_w_vals: None,
        }
    }

    fn generate_recipient_pcheck_data(&self) -> RecipientPCheckProtoData {
        println!("THIS SHOULD RUN ONCE");
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 7757);

        let a_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
        let b_vals: Vec<u64> = (0..128).map(|_| rng.sample(&range)).collect();
        let pairs: Vec<(PaillierEncodedCiphertext<u64>, PaillierEncodedCiphertext<u64>)> = zip(&a_vals, &b_vals)
        .map(|(a, b)| {
            (Paillier::encrypt(&self.paillier_pubkey, *a), Paillier::encrypt(&self.paillier_pubkey, *b))
        }).collect();

        RecipientPCheckProtoData {
            a_values: Some(a_vals),
            b_values: Some(b_vals),
            encrypted_a_b_pairs: Some(pairs),
            t_values_from_sender: None,
            t_values_from_courier: None,
            debug_sender_a_vals: None,
            debug_sender_b_vals: None,
            debug_sender_w_vals: None,
            debug_courier_a_vals: None,
            debug_courier_b_vals: None,
            debug_courier_w_vals: None,
        }
    }

    fn sender_process_round1(&self, courier_address: String, recipient_address: String,) {
        let mut generate_ws = false;
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
                    generate_ws = true;
                    print!("{}\nghxc> ", "WE ARE REDY FOR ROUND 2".green().bold());
                }
                else {
                    print!("{}\nghxc> ", "We don't have it all yet".yellow());
                    return;
                }
            }
            else {
                print!("{}\nghxc> ", "Major problem".red().bold());
                return;
            }
            self.sender_generate_RTs(courier_address.clone(), recipient_address.clone(), proto_data.clone());
            if generate_ws {
                self.sender_generate_ws(proto_data.clone(), courier_address.clone(), recipient_address.clone());
            }
        }
        else {
            print!("{}\nghxc> ", "Major Problem!".red().bold());
        }
    }

    fn sender_generate_ws(&self, pdata: Arc<Mutex<SenderPCheckProtoData>>, courier_address: String, recipient_address: String,) {
        let mut pd = pdata.lock().unwrap();
        let r_courier = pd.r_values_from_courier.clone().unwrap();
        let r_recipient = pd.r_values_from_recipient.clone().unwrap();

        let ws : Vec<u64> = zip(r_recipient.clone(), zip(r_courier.clone(), zip(pd.sender_a_values.clone(), pd.sender_b_values.clone())))
            .map(|(rr, (rc, (a, b)))| {
                u64::try_from(7757*3+(
                    i64::try_from(((a*b)%7757)).unwrap() -
                    i64::try_from(rr).unwrap() -
                    i64::try_from(rc).unwrap()
                )%7757).unwrap()%7757
            }).collect();

        zip(pd.sender_a_values.clone(), zip(pd.sender_b_values.clone(), ws.clone()))
        .for_each(|(a, (b, w))| {
            println!("{},{},{}", a, b, w);
        });
        let reveal_message = PCheckMessage::SenderABWReveal {
            a_vals: pd.sender_a_values.clone(),
            b_vals: pd.sender_b_values.clone(),
            w_vals: ws.clone(),
        };
        if !self.direct_message(courier_address, ProtocolMessage::PCheck(reveal_message.clone())) {
            println!("had to lookup. weird.");
        }
        if !self.direct_message(recipient_address, ProtocolMessage::PCheck(reveal_message.clone())) {
            println!("had to lookup. weird.");
        }
    }

    fn courier_process_round1(&self, sender_address: String, recipient_address: String,) {
        println!("s: {} r: {}", sender_address, recipient_address);
        if let Some(proto_data) = self.courier_pcheck_table
        .get(
            &(sender_address.clone(), recipient_address.clone()),
            &self.courier_pcheck_table.guard()
        ) {
            let mut generate_ws = false;
            if let Ok(mut pd) = proto_data.lock() {
                if (
                    pd.t_values_from_sender.is_some() &&
                    pd.r_values_from_recipient.is_some()
                ) {
                    print!("{}\nghxc> ", "We have the t-vals from sender and R values from recipient.".green().bold());
                    generate_ws = true;
                }
                else {
                    print!("{}\nghxc> ", "We don't have it all yet".yellow());
                    return;
                }
            }
            else {
                print!("{}\nghxc> ", "Couldn't lock. Probably should panic here.".red().bold());
                return;
            }
            if generate_ws {
                self.courier_generate_ws(proto_data.clone(), sender_address.clone(), recipient_address.clone());
            }
        }
        else {
            print!("{}\nghxc> ", "Major Problem!".red().bold());
        }
    }

    fn courier_generate_ws(&self, pdata: Arc<Mutex<CourierPCheckProtoData>>, sender_address: String, recipient_address: String) {
        let mut pd = pdata.lock().unwrap();
        let ws : Vec<u64> = zip(pd.t_values_from_sender.clone().unwrap(), zip(pd.r_values_from_recipient.clone().unwrap(), zip(pd.a_values.clone().unwrap(), pd.b_values.clone().unwrap())))
            .map(|(t, (r, (a, b)))| {
                u64::try_from((
                    i64::try_from(((a*b)%7757)).unwrap() - i64::try_from(r).unwrap() + i64::try_from(Paillier::decrypt(&self.paillier_privkey, t)).unwrap()
                )%7757).unwrap()
            }).collect();
        zip(pd.a_values.clone().unwrap(), zip(pd.b_values.clone().unwrap(), ws.clone()))
            .for_each(|(a, (b, w))| {
                println!("{},{},{}", a, b, w);
            });
        let reveal_message = PCheckMessage::CourierABWReveal {
            a_vals: pd.a_values.clone().unwrap(),
            b_vals: pd.b_values.clone().unwrap(),
            w_vals: ws.clone(),
        };
        if !self.direct_message(recipient_address.clone(), ProtocolMessage::PCheck(reveal_message.clone())) {
            println!("weird.");
        }
        if !self.direct_message(sender_address.clone(), ProtocolMessage::PCheck(reveal_message.clone())) {
            println!("weird.");
        }
    }

    fn recipient_process_round1(&self, sender_address: String, courier_address: String) {
        let mut generate_ws = false;
        if let Some(proto_data) = self.recipient_pcheck_table
        .get(
            &(sender_address.clone(), courier_address.clone()),
            &self.recipient_pcheck_table.guard()
        ) {
            if let Ok(pd) = proto_data.lock() {
                if (
                    pd.t_values_from_sender.is_some() &&
                    pd.t_values_from_courier.is_some()
                ) {
                    generate_ws = true;
                    print!("{}\nghxc> ", "WE ARE REDY FOR ROUND 2".green().bold());
                }
                else {
                    print!("{}\nghxc> ", "We don't have it all yet".yellow());
                    return;
                }
            }
            else {
                print!("{}\nghxc> ", "Major problem".red().bold());
                return;
            }
            if generate_ws {
                self.recipient_generate_ws(proto_data.clone(), sender_address.clone(), courier_address.clone());
            }
        }
        else {
            print!("{}\nghxc> ", "Major Problem!".red().bold());
        }

    }

    fn recipient_generate_ws(&self, pdata: Arc<Mutex<RecipientPCheckProtoData>>, sender_address: String, courier_address: String) {
        let mut pd = pdata.lock().unwrap();

        let my_ab_products : Vec<u64> = zip(pd.a_values.clone().unwrap(), pd.b_values.clone().unwrap())
            .map(|(a, b)| {
                (a*b)%7757
            }).collect();

        let ws : Vec<u64> = zip(my_ab_products, zip(pd.t_values_from_sender.clone().unwrap(), pd.t_values_from_courier.clone().unwrap()))
            .map(|(ab, (ts, tc))| {
                (ab + Paillier::decrypt(&self.paillier_privkey, &ts) + Paillier::decrypt(&self.paillier_privkey, &tc))%7757
            }).collect();

        //ws.iter().for_each(|w| {println!("{}", w)});
        zip(pd.a_values.clone().unwrap(), zip(pd.b_values.clone().unwrap(), ws.clone()))
        .for_each(|(a, (b, w))| {
            println!("{},{},{}", a, b, w);
        });
        let reveal_message = PCheckMessage::RecipientABWReveal {
            a_vals: pd.a_values.clone().unwrap(),
            b_vals: pd.b_values.clone().unwrap(),
            w_vals: ws.clone(),
        };
        if !self.direct_message(sender_address.clone(), ProtocolMessage::PCheck(reveal_message.clone())) {
            println!("weird.");
        }
        if !self.direct_message(courier_address.clone(), ProtocolMessage::PCheck(reveal_message.clone())) {
            println!("weird.");
        }
    }

    fn sender_generate_RTs(&self, courier_address: String, recipient_address: String, pd: Arc<Mutex<SenderPCheckProtoData>>) {
        if let Ok(mut spd) = pd.lock() {
            println!("{}", "Starting homomorphic encryptions...".yellow());
            let courier_key = spd.courier_paillier_key.clone().unwrap();
            let recipient_key = spd.recipient_paillier_key.clone().unwrap();

            let mut rng = rand::thread_rng();
            let range = Uniform::new::<u64, u64>(0, 7757);

            spd.r_values_from_courier = Some((0..128).map(|_| rng.sample(&range)).collect());
            spd.r_values_from_recipient = Some((0..128).map(|_| rng.sample(&range)).collect());

            spd.t_values_for_courier = Some(zip(spd.sender_a_values.clone(), zip(spd.sender_b_values.clone(), zip(spd.r_values_from_courier.clone().unwrap(), spd.courier_to_sender_encrypted_a_b_pairs.clone().unwrap())))
                .map(|(a, (b, (r, (ea, eb))))| {
                    Paillier::add(&courier_key,
                        Paillier::add(&courier_key,
                            Paillier::mul(&courier_key, ea, b),
                            Paillier::mul(&courier_key, a, eb)
                        ),
                        r
                    )
                }).collect());

            spd.t_values_for_recipient = Some(zip(spd.sender_a_values.clone(), zip(spd.sender_b_values.clone(), zip(spd.r_values_from_recipient.clone().unwrap(), spd.recipient_to_sender_encrypted_a_b_pairs.clone().unwrap())))
                .map(|(a, (b, (r, (ea, eb))))| {
                    Paillier::add(&recipient_key,
                        Paillier::add(&recipient_key,
                            Paillier::mul(&recipient_key, ea, b),
                            Paillier::mul(&recipient_key, a, eb)
                        ),
                        r
                    )
                }).collect());

            let to_courier_r1 = PCheckMessage::SenderToCourierRound1 {
                    recipient_address: recipient_address.clone(),
                    sender_to_courier_t_values: spd.t_values_for_courier.as_ref().unwrap().to_vec(),
            };

            let to_recipient_r1 = PCheckMessage::SenderToRecipientRound1 {
                courier_address: courier_address.clone(),
                sender_to_recipient_t_values: spd.t_values_for_recipient.as_ref().unwrap().to_vec(),
            };

            if !self.direct_message(courier_address.clone(), ProtocolMessage::PCheck(to_courier_r1)) {
                print!("{}\nghxc> ", "not in lookup. weird.".yellow());
            }
            if !self.direct_message(recipient_address.clone(), ProtocolMessage::PCheck(to_recipient_r1)) {
                print!("{}\nghxc> ", "not in lookup. weird.".yellow());
            }

            println!("{}", "Done generating R and T values.".green().bold());
        }
        else {
            println!("NOT OK");
            print!("{}", "Major problem.".red().bold());
        }
    }

    fn courier_generate_RTs(&self, sender_address: String, recipient_address: String, pd: Arc<Mutex<CourierPCheckProtoData>>) {
        print!("{}\nghxc> ", "I'm the courier. Time to generate RTs for recipient.".yellow());
        if let Ok(mut pd) = pd.lock() {
            let ab_vals = pd.recipient_to_courier_encrypted_a_b_pairs.clone().unwrap();
            let key = pd.recipient_paillier_key.clone().unwrap();
            let courier_a_values = pd.a_values.clone().unwrap();
            let courier_b_values = pd.b_values.clone().unwrap();

            let mut rng = rand::thread_rng();
            let range = Uniform::new::<u64, u64>(0, 7757);

            pd.r_values_from_recipient = Some((0..128).map(|_| rng.sample(&range)).collect());

            pd.t_values_for_recipient = Some(zip(pd.a_values.clone().unwrap(), zip(pd.b_values.clone().unwrap(), zip(pd.r_values_from_recipient.clone().unwrap(), pd.recipient_to_courier_encrypted_a_b_pairs.clone().unwrap())))
                .map(|(a, (b, (r, (ea, eb))))| {
                    Paillier::add(&key,
                        Paillier::add(&key,
                            Paillier::mul(&key, ea, b),
                            Paillier::mul(&key, a, eb),
                        ),
                        r
                    )
                }).collect()
            );

            let to_recipient_t = PCheckMessage::CourierToRecipientRound1 {
                sender_address: sender_address,
                courier_to_recipient_t_values: pd.t_values_for_recipient.clone().unwrap(),
            };
            if !self.direct_message(recipient_address.clone(), ProtocolMessage::PCheck(to_recipient_t)) {
                print!("{}\nghxc> ", "weird that we had to do a lookup.".red());
            }
        }
        else {
            print!("{}\nghxc>", "Major problem.".red().bold());
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

