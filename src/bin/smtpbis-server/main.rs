#![feature(async_await, async_closure)]
#![warn(rust_2018_idioms)]

use bytes::{Bytes, BytesMut};
use futures_util::try_stream::*;
use tokio::codec::FramedRead;
use tokio::net::TcpListener;
use tokio::prelude::*;

use rustyknife::behaviour::Intl;
use rustyknife::rfc5321::{command, Command};
use smtpbis::{SMTPLineCodec, SMTPLineError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8080".parse().unwrap();
    let mut listener = TcpListener::bind(&addr).unwrap();

    loop {
        let (socket, addr) = listener.accept().await?;

        tokio::spawn(async move {
            println!("{} connected !", addr);

            let (reader, mut writer) = socket.split();
            let mut reader = FramedRead::new(reader, SMTPLineCodec::default())
                .inspect(|line| println!("input: {:?}", line));

            if let Err(e) = writer
                .write_all(b"220 localhost ESMTP smtpbis 0.1.0\r\n")
                .await
            {
                println!("failed to write to socket; err = {:?}", e);
                return;
            }

            loop {
                let cmd = match read_command(&mut reader).await {
                    Err(e) => {
                        println!("command error: {:?}", e);
                        return;
                    }
                    Ok(cmd) => cmd,
                };

                println!("command: {:?}", cmd);
            }
        });
    }
}

#[derive(Debug)]
enum SMTPServerError {
    EOF,
    FramingError(SMTPLineError),
    SyntaxError(Bytes),
}

impl From<SMTPLineError> for SMTPServerError {
    fn from(source: SMTPLineError) -> Self {
        SMTPServerError::FramingError(source)
    }
}

async fn read_command<'a, S>(reader: &'a mut S) -> Result<Command, SMTPServerError>
where
    S: Stream<Item = Result<BytesMut, SMTPLineError>> + Unpin,
{
    let line = reader.next().await.ok_or(SMTPServerError::EOF)?.unwrap();

    match command::<Intl>(&line) {
        Err(_) => Err(SMTPServerError::SyntaxError(line.freeze())),
        Ok((rem, _)) if !rem.is_empty() => Err(SMTPServerError::SyntaxError(line.freeze())),
        Ok((_, cmd)) => Ok(cmd),
    }
}

async fn handle_data<S>(input: &mut S) -> Result<Vec<u8>, SMTPLineError>
where
    S: Stream<Item = Result<BytesMut, SMTPLineError>> + Unpin,
{
    let body_stream = read_body(input);
    let mut body: Vec<u8> = Vec::new();
    let mut nb_lines: usize = 0;
    body_stream
        .try_for_each(|line| {
            body.extend(line);
            nb_lines += 1;

            tokio::future::ready(Ok(()))
        })
        .await?;

    println!("got {} body lines", nb_lines);

    Ok(body)
}

#[must_use]
fn read_body<'a, S>(source: &'a mut S) -> impl Stream<Item = Result<BytesMut, SMTPLineError>> + 'a
where
    S: Stream<Item = Result<BytesMut, SMTPLineError>> + Unpin,
{
    source
        .take_while(|res| {
            tokio::future::ready(
                res.as_ref()
                    .map(|line| line.as_ref() != b".\r\n")
                    .unwrap_or(true),
            )
        })
        .map(|res| {
            res.map(|mut line| {
                if line.starts_with(b".") {
                    line.split_to(1);
                }
                line
            })
        })
}
