use std::fmt::Write;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::try_stream::*;
use tokio::codec::{Framed, FramedParts};
use tokio::net::TcpStream;
use tokio::prelude::*;

use tokio_rustls::rustls::{ServerConfig, ServerSession};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::{command, Command, Command::Base, Command::*};
use crate::{LineCodec, LineError, Reply};

use rustyknife::behaviour::Intl;
use rustyknife::rfc5321::Command::*;

#[async_trait]
pub trait Handler {
    async fn tls_request(&mut self) -> Option<Arc<ServerConfig>>;
    async fn tls_started(&mut self, session: &ServerSession);
}

pub trait MaybeTLS {
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

pub async fn smtp_server<S, H>(mut socket: S, handler: H) -> Result<(), ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + MaybeTLS,
    H: Handler,
{
    match smtp_server_loop(&mut socket, handler).await? {
        LoopExit::Done => println!("Server exited without error"),
        LoopExit::STARTTLS(tls_config, handler) => {
            match starttls(socket, handler, tls_config).await? {
                LoopExit::Done => println!("TLS server exited without error"),
                LoopExit::STARTTLS(..) => println!("Nested TLS requested"),
            }
        }
    }

    Ok(())
}

enum LoopExit<H> {
    Done,
    STARTTLS(Arc<ServerConfig>, H),
}

#[derive(Debug, PartialEq)]
enum State {
    Initial,
    MAIL,
    RCPT,
}

async fn starttls<S, H>(
    mut socket: S,
    handler: H,
    tls_config: Arc<ServerConfig>,
) -> Result<LoopExit<H>, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + MaybeTLS,
    H: Handler,
{
    println!("Starting TLS");
    socket.flush().await?;
    let acceptor = TlsAcceptor::from(tls_config);
    let mut tls_socket = acceptor.accept(socket).await?;
    let res = smtp_server_loop(&mut tls_socket, handler).await?;
    tls_socket.shutdown().await?;
    Ok(res)
}

async fn smtp_server_loop<S, H>(
    base_socket: &mut S,
    mut handler: H,
) -> Result<LoopExit<H>, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + MaybeTLS,
    H: Handler,
{
    let mut state = State::Initial;
    let tls_session = base_socket.tls_session();
    if let Some(session) = &tls_session {
        handler.tls_started(session).await;
    }
    let tls_session = tls_session.is_some();

    let mut ehlo_keywords = vec!["PIPELINING", "ENHANCEDSTATUSCODES", "SMTPUTF8", "CHUNKING"];
    if !tls_session {
        ehlo_keywords.push("STARTTLS");
    }
    ehlo_keywords.sort_unstable();

    println!("connected, TLS:{:?} !", tls_session);

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
            Err(ServerError::SyntaxError(_)) => {
                socket
                    .send(Reply::new(500, None, "Invalid command syntax"))
                    .await?;
                continue;
            }
            Err(e) => return Err(e),
        };
        println!("command: {:?}", cmd);

        match cmd {
            Base(EHLO(_)) => {
                let mut reply_text = String::from("localhost\n");
                for kw in &ehlo_keywords {
                    writeln!(reply_text, "{}", kw).unwrap();
                }
                state = State::Initial;
                socket.send(Reply::new(250, None, reply_text)).await?;
            }
            Base(HELO(_)) => {
                state = State::Initial;
                socket.send(Reply::new(250, None, "ok")).await?;
            }
            Base(MAIL(_path, _)) => match state {
                State::Initial => {
                    state = State::MAIL;
                    socket.send(Reply::new(250, None, "ok")).await?;
                }
                _ => {
                    socket
                        .send(Reply::new(503, None, "bad sequence of commands"))
                        .await?;
                }
            },
            Base(RCPT(_path, _)) => match state {
                State::MAIL | State::RCPT => {
                    state = State::RCPT;
                    socket.send(Reply::new(250, None, "ok")).await?;
                }
                _ => {
                    socket
                        .send(Reply::new(503, None, "bad sequence of commands"))
                        .await?;
                }
            },
            Base(DATA) => match state {
                State::RCPT => {
                    socket.send(Reply::new(354, None, "send data")).await?;

                    let body = handle_data(&mut socket).await?;
                    socket
                        .send(Reply::new(
                            250,
                            None,
                            format!("{} bytes received, body ok", body.len()),
                        ))
                        .await?;

                    state = State::Initial;
                }
                State::Initial => {
                    socket
                        .send(Reply::new(503, None, "mail transaction not started"))
                        .await?;
                }
                State::MAIL => {
                    socket
                        .send(Reply::new(
                            503,
                            None,
                            "must have at least one valid recipient",
                        ))
                        .await?;
                }
            },
            Base(QUIT) => {
                socket.send(Reply::new(250, None, "bye")).await?;
                return Ok(LoopExit::Done);
            }
            Base(RSET) => {
                state = State::Initial;
                socket.send(Reply::new(250, None, "ok")).await?;
            }
            Ext(crate::Ext::STARTTLS) if !tls_session => {
                println!("STARTTLS !");

                if let Some(tls_config) = handler.tls_request().await {
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
                    return Ok(LoopExit::STARTTLS(tls_config, handler));
                } else {
                    socket
                        .send(Reply::new(502, None, "command not implemented"))
                        .await?;
                }
            }
            _ => {
                socket
                    .send(Reply::new(502, None, "command not implemented"))
                    .await?;
            }
        }
        println!("State: {:?}\n", state);
    }
}

#[derive(Debug)]
pub enum ServerError {
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
