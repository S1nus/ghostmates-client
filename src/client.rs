use futures::stream::{SplitStream, SplitSink};
use sodiumoxide::crypto::box_::{PublicKey as SodiumPublicKey, SecretKey as SodiumSecretKey};
use flurry::HashMap;
use std::{
    sync::{Arc, Mutex},
    net::SocketAddr,
};
use async_std::net::{TcpStream};
use async_tungstenite::tungstenite::Message;
use async_tungstenite::WebSocketStream;

#[derive(Clone, Debug)]
pub struct Client {
    pk: SodiumPublicKey,
    sk: SodiumSecretKey,
    server_write: Arc<Mutex<SplitSink<WebSocketStream<TcpStream>, Message>>>,
    peer_store: Arc<HashMap<String, SodiumPublicKey>>
}

impl Client {
    pub fn validate_address(&GhostmatesMessage) {
    }
}
