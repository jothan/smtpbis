#![warn(rust_2018_idioms)]

use std::fmt::Write;
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use futures_util::try_stream::*;
use tokio::codec::{Framed, FramedParts};
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use tokio_rustls::rustls::{
    internal::pemfile::{certs, pkcs8_private_keys},
    NoClientAuth, ServerConfig, ServerSession,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use rustyknife::behaviour::Intl;
use rustyknife::rfc5321::{command, Command};
use smtpbis::{LineCodec, LineError, Reply};

const CERT: &[u8] = include_bytes!("ssl-cert-snakeoil.pem");
const KEY: &[u8] = include_bytes!("ssl-cert-snakeoil.key");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:8080".parse().unwrap();
    let mut listener = TcpListener::bind(&addr).unwrap();

    let mut tls_config = ServerConfig::new(NoClientAuth::new());
    let certs = certs(&mut Cursor::new(CERT)).unwrap();
    let key = pkcs8_private_keys(&mut Cursor::new(KEY)).unwrap().remove(0);
    tls_config.set_single_cert(certs, key).unwrap();
    let tls_config = Arc::new(tls_config);

    loop {
        let tls_config = tls_config.clone();
        let (socket, addr) = listener.accept().await?;

        tokio::spawn(async move {
            smtp_server(socket, addr, tls_config).await.unwrap();
        });
    }
}

trait MaybeTLS {
    fn tls_session(&self) -> Option<&ServerSession> {
        None
    }
}

impl MaybeTLS for TcpStream {}
impl MaybeTLS for &TcpStream {}
impl MaybeTLS for &mut TcpStream {}

impl<T> MaybeTLS for TlsStream<T> {
    fn tls_session(&self) -> Option<&ServerSession> {
        Some(self.get_ref().1)
    }
}

impl<T> MaybeTLS for &mut TlsStream<T> {
    fn tls_session(&self) -> Option<&ServerSession> {
        Some(self.get_ref().1)
    }
}

async fn smtp_server<S>(
    mut socket: S,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + MaybeTLS,
{
    match smtp_server_loop(&mut socket, addr).await? {
        LoopExit::Done => println!("Server exited without error"),
        LoopExit::STARTTLS => {
            println!("Starting TLS");
            let acceptor = TlsAcceptor::from(tls_config);
            let mut tls_socket = acceptor.accept(socket).await?;
            match smtp_server_loop(&mut tls_socket, addr).await? {
                LoopExit::Done => println!("(TLS) Server exited without error"),
                LoopExit::STARTTLS => println!("(TLS) recursive TLS request :P"),
            }
            tls_socket.shutdown().await?;
        }
    }

    Ok(())
}

enum LoopExit {
    Done,
    STARTTLS,
}

async fn smtp_server_loop<S>(base_socket: &mut S, addr: SocketAddr) -> Result<LoopExit, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + MaybeTLS,
{
    let tls_session = base_socket.tls_session().is_some();
    let mut ehlo_keywords = vec!["PIPELINING", "ENHANCEDSTATUSCODES", "SMTPUTF8", "CHUNKING"];
    if !tls_session {
        ehlo_keywords.push("STARTTLS");
    }
    ehlo_keywords.sort_unstable();

    println!("{} connected, TLS:{:?} !", addr, tls_session);

    let mut socket = Framed::new(base_socket, LineCodec::default())
        .inspect(|line| println!("input: {:?}", line))
        .with::<_, _, _, LineError>(|reply| {
            print!("output: {}", reply);
            tokio::future::ok(reply)
        });

    if !tls_session {
        socket
            .send(Reply::new(220, None, "localhost ESMTP smtpbis 0.1.0"))
            .await?;
    }

    loop {
        let cmd = match read_command(&mut socket).await {
            Ok(cmd) => cmd,
            Err(ServerError::SyntaxError(badcmd)) => {
                if !tls_session && badcmd.eq_ignore_ascii_case(b"STARTTLS\r\n") {
                    println!("STARTTLS !");
                    socket.flush().await?;
                    let FramedParts { io, read_buf, .. } =
                        socket.into_inner().into_inner().into_parts();
                    // Absolutely do not allow pipelining past a
                    // STARTTLS command.
                    if !read_buf.is_empty() {
                        return Err(ServerError::Pipelining);
                    }

                    let tls_reply = Reply::new(220, None, "starting TLS").to_string();

                    io.write_all(tls_reply.as_bytes()).await?;
                    io.flush().await?;
                    return Ok(LoopExit::STARTTLS);
                }

                socket
                    .send(Reply::new(500, None, "Invalid command syntax"))
                    .await?;
                continue;
            }
            Err(e) => return Err(e),
        };
        println!("command: {:?}", cmd);

        match cmd {
            Command::EHLO(_) => {
                let mut reply_text = String::from("localhost\n");
                for kw in &ehlo_keywords {
                    writeln!(reply_text, "{}", kw).unwrap();
                }
                socket.send(Reply::new(250, None, reply_text)).await?;
            }
            Command::DATA => {
                socket.send(Reply::new(354, None, "send data")).await?;

                let body = handle_data(&mut socket).await?;
                socket
                    .send(Reply::new(
                        250,
                        None,
                        format!("{} bytes received, body ok", body.len()),
                    ))
                    .await?;
            }
            Command::QUIT => {
                socket.send(Reply::new(250, None, "bye")).await?;
                return Ok(LoopExit::Done);
            }
            _ => {
                socket.send(Reply::new(250, None, "ok")).await?;
            }
        }
    }
}

#[derive(Debug)]
enum ServerError {
    EOF,
    Framing(LineError),
    SyntaxError(BytesMut),
    IO(std::io::Error),
    Pipelining,
}

impl From<LineError> for ServerError {
    fn from(source: LineError) -> Self {
        match source {
            LineError::IO(e) => Self::IO(e),
            _ => Self::Framing(source),
        }
    }
}

impl From<std::io::Error> for ServerError {
    fn from(err: std::io::Error) -> Self {
        Self::IO(err)
    }
}

async fn read_command<S>(reader: &mut S) -> Result<Command, ServerError>
where
    S: Stream<Item = Result<BytesMut, LineError>> + Unpin,
{
    println!("Waiting for command...");
    let line = reader.next().await.ok_or(ServerError::EOF)??;

    match command::<Intl>(&line) {
        Err(_) => Err(ServerError::SyntaxError(line)),
        Ok((rem, _)) if !rem.is_empty() => Err(ServerError::SyntaxError(line)),
        Ok((_, cmd)) => Ok(cmd),
    }
}

async fn handle_data<S>(input: &mut S) -> Result<Vec<u8>, LineError>
where
    S: Stream<Item = Result<BytesMut, LineError>> + Unpin,
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
fn read_body<'a, S>(source: &'a mut S) -> impl Stream<Item = Result<BytesMut, LineError>> + 'a
where
    S: Stream<Item = Result<BytesMut, LineError>> + Unpin,
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
