use std::net::SocketAddrV4;
use async_std::prelude::*;
use async_std::io::prelude::BufReadExt;

use async_std::{task,
    io::{BufRead, BufReader, BufWriter},
    net::{TcpListener, TcpStream},
    stream::{Stream, StreamExt},
};

use ghostmates_common::{new_codec_writer, new_codec_reader, StringCodec};
use futures::stream::TryStreamExt;
use futures::SinkExt;
use futures_codec::{Bytes, BytesMut, LengthCodec, Framed, FramedRead, FramedWrite, Decoder, Encoder};
use std::io::{Error, ErrorKind};

async fn connect(addr: SocketAddrV4) -> TcpStream {
    TcpStream::connect(addr)
        .await
        .expect(&format!("failed to connect to player: {}", addr))
}

async fn run(addr: SocketAddrV4) {
    let stream = connect(addr)
    .await;

    let stream_reader = BufReader::new(&stream);
    let stream_writer = BufWriter::new(&stream);

    let mut writer = new_codec_writer(stream_writer);
    writer.send("Hello I am cinnamon".to_owned())
        .await
        .expect("failed to send my message");

    let mut reader = new_codec_reader(stream_reader);
    while let Some(message) = reader.try_next().await.expect("error with codec") {
        println!("{:?}", message);
    }

    //let reader = new_codec_reader(&stream);

}

pub fn connection_loop(reader: FramedRead<BufReader<&TcpStream>, StringCodec>) {

}

pub fn connect_to_server(addr: SocketAddrV4) {
    task::block_on(run(addr));
}
