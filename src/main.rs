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

async fn server_loop(read: WebSocketRead, s: Arc<Mutex<WebSocketWrite>>) /*-> Result<(), MyeetErr>*/ {

    let _server_incoming = read
        .try_filter(|msg| {
            future::ready(!msg.is_close())
        })
        .try_for_each(|msg| {
            print!("{}\nghxc> ", msg);
            stdout().flush().unwrap();
            future::ok(())
        }).await.expect("Server loop failed");

    println!("Server loop ended.");
}

async fn user_loop(s: Arc<Mutex<WebSocketWrite>>) {
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
        //println!("You typed: {}",s);
        s
            .lock()
            .unwrap()
            .send(
                Message::from(input_string.clone())
            ).await.expect("Failed to send");

    }
}

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
    let server_connection = task::block_on(connect_to_server());
    let (server_write, server_read) = server_connection.split();
    let arc_server_write = Arc::new(Mutex::new(server_write));
    task::spawn(server_loop(server_read, arc_server_write.clone()));
    task::block_on(user_loop(arc_server_write.clone()));
}
