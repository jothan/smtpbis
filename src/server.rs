use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;
use tokio::codec::{Framed, FramedParts};
use tokio::net::TcpStream;
use tokio::prelude::*;

use tokio_rustls::rustls::{ServerConfig, ServerSession};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::{command, Command, Command::Base, Command::*};
use crate::{LineCodec, LineError, Reply};

use rustyknife::behaviour::Intl;
use rustyknife::rfc5321::Command::*;
use rustyknife::rfc5321::{ForwardPath, Param, ReversePath};
use rustyknife::types::{Domain, DomainPart};

pub type HandlerResult = Result<Option<Reply>, Option<Reply>>;

#[async_trait]
pub trait Handler {
    async fn tls_request(&mut self) -> Option<Arc<ServerConfig>>;
    async fn tls_started(&mut self, session: &ServerSession);

    async fn ehlo(
        &mut self,
        domain: DomainPart,
        initial_keywords: EhloKeywords,
    ) -> Result<(String, EhloKeywords), Reply>;
    async fn helo(&mut self, domain: Domain) -> HandlerResult;
    async fn mail(&mut self, path: ReversePath, params: Vec<Param>) -> HandlerResult;
    async fn rcpt(&mut self, path: ForwardPath, params: Vec<Param>) -> HandlerResult;
    async fn data_start(&mut self) -> HandlerResult;
    async fn data<S>(&mut self, stream: &mut S) -> Result<Option<Reply>, ServerError>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Unpin + Send;
    async fn bdat<S>(
        &mut self,
        stream: &mut S,
        size: u64,
        last: bool,
    ) -> Result<Option<Reply>, ServerError>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Unpin + Send;
    async fn rset(&mut self);
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

pub async fn smtp_server<S, H>(mut socket: S, handler: H) -> Result<S, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + MaybeTLS + Send,
    H: Handler,
{
    match smtp_server_loop(&mut socket, handler, true).await? {
        LoopExit::Done => println!("Server exited without error"),
        LoopExit::STARTTLS(tls_config, handler) => {
            socket.flush().await?;
            let acceptor = TlsAcceptor::from(tls_config);
            let mut tls_socket = acceptor.accept(socket).await?;
            match smtp_server_loop(&mut tls_socket, handler, false).await? {
                LoopExit::Done => println!("TLS server exited without error"),
                LoopExit::STARTTLS(..) => println!("Nested TLS requested"),
            }
            tls_socket.shutdown().await?;
            let (s, _) = tls_socket.into_inner();
            socket = s;
        }
    }

    Ok(socket)
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
    BDAT,
    BDATFAIL,
}

async fn smtp_server_loop<S, H>(
    base_socket: &mut S,
    mut handler: H,
    banner: bool,
) -> Result<LoopExit<H>, ServerError>
where
    S: AsyncRead + AsyncWrite + Unpin + MaybeTLS + Send,
    H: Handler,
{
    let mut state = State::Initial;
    let tls_session = base_socket.tls_session();
    if let Some(session) = &tls_session {
        handler.tls_started(session).await;
    }
    let tls_session = tls_session.is_some();

    println!("connected, TLS:{:?} !", tls_session);

    let mut socket = Framed::new(base_socket, LineCodec::default())
        .inspect(|line| println!("input: {:?}", line))
        .with::<_, _, _, LineError>(|reply| {
            print!("output: {}", reply);
            tokio::future::ok(reply)
        });

    if banner {
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
            Base(EHLO(domain)) => {
                socket
                    .send(do_ehlo(&mut state, &mut handler, domain, tls_session).await?)
                    .await?;
            }
            Base(HELO(domain)) => {
                socket
                    .send(do_helo(&mut state, &mut handler, domain).await?)
                    .await?;
            }
            Base(MAIL(path, params)) => {
                socket
                    .send(do_mail(&mut state, &mut handler, path, params).await?)
                    .await?;
            }
            Base(RCPT(path, params)) => {
                socket
                    .send(do_rcpt(&mut state, &mut handler, path, params).await?)
                    .await?;
            }
            Base(DATA) => {
                let reply = do_data(&mut socket, &mut state, &mut handler).await?;
                socket.send(reply).await?;
            }
            Base(QUIT) => {
                socket.send(Reply::new(221, None, "bye")).await?;
                return Ok(LoopExit::Done);
            }
            Base(RSET) => {
                state = State::Initial;
                handler.rset().await;
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
            Ext(crate::Ext::BDAT(size, last)) => {
                let reply = do_bdat(
                    socket.get_mut().get_mut(),
                    &mut state,
                    &mut handler,
                    size,
                    last,
                )
                .await?;
                socket.send(reply).await?;
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

pub type EhloKeywords = BTreeMap<String, Option<String>>;

async fn do_ehlo<H: Handler>(
    state: &mut State,
    handler: &mut H,
    domain: DomainPart,
    is_tls: bool,
) -> Result<Reply, ServerError> {
    let mut initial_keywords = EhloKeywords::new();
    for kw in ["PIPELINING", "ENHANCEDSTATUSCODES", "SMTPUTF8", "CHUNKING"].as_ref() {
        initial_keywords.insert((*kw).into(), None);
    }
    if !is_tls {
        initial_keywords.insert("STARTTLS".into(), None);
    }

    match handler.ehlo(domain, initial_keywords).await {
        Err(reply) => Ok(reply),
        Ok((greeting, keywords)) => {
            assert!(!greeting.contains('\r') && !greeting.contains('\n'));
            let mut reply_text = format!("{}\n", greeting);

            for (kw, value) in keywords {
                match value {
                    Some(value) => writeln!(reply_text, "{} {}", kw, value).unwrap(),
                    None => writeln!(reply_text, "{}", kw).unwrap(),
                }
            }
            *state = State::Initial;
            Ok(Reply::new(250, None, reply_text))
        }
    }
}

async fn do_helo<H: Handler>(
    state: &mut State,
    handler: &mut H,
    domain: Domain,
) -> Result<Reply, ServerError> {
    Ok(match handler.helo(domain).await {
        Ok(reply) => {
            *state = State::Initial;
            reply.unwrap_or_else(|| Reply::new(250, None, "ok"))
        }
        Err(reply) => reply.unwrap_or_else(|| Reply::new(550, None, "refused")),
    })
}

async fn do_mail<H: Handler>(
    state: &mut State,
    handler: &mut H,
    path: ReversePath,
    params: Vec<Param>,
) -> Result<Reply, ServerError> {
    Ok(match state {
        State::Initial => match handler.mail(path, params).await {
            Ok(reply) => {
                *state = State::MAIL;
                reply.unwrap_or_else(|| Reply::new(250, None, "ok"))
            }
            Err(reply) => {
                reply.unwrap_or_else(|| Reply::new(550, None, "mail transaction refused"))
            }
        },
        _ => Reply::new(503, None, "bad sequence of commands"),
    })
}

async fn do_rcpt<H: Handler>(
    state: &mut State,
    handler: &mut H,
    path: ForwardPath,
    params: Vec<Param>,
) -> Result<Reply, ServerError> {
    Ok(match state {
        State::MAIL | State::RCPT => match handler.rcpt(path, params).await {
            Ok(reply) => {
                *state = State::RCPT;
                reply.unwrap_or_else(|| Reply::new(250, None, "ok"))
            }
            Err(reply) => reply.unwrap_or_else(|| Reply::new(550, None, "recipient not accepted")),
        },
        _ => Reply::new(503, None, "bad sequence of commands"),
    })
}

async fn do_data<H: Handler, S>(
    socket: &mut S,
    state: &mut State,
    handler: &mut H,
) -> Result<Reply, ServerError>
where
    S: Stream<Item = Result<BytesMut, LineError>> + Unpin + Send,
    S: Sink<Reply>,
    ServerError: From<<S as Sink<Reply>>::Error>,
{
    Ok(match state {
        State::RCPT => match handler.data_start().await {
            Ok(reply) => {
                socket
                    .send(reply.unwrap_or_else(|| Reply::new(354, None, "send data")))
                    .await?;

                let mut body_stream = read_body(socket).fuse();
                let reply = handler.data(&mut body_stream).await?;

                if !body_stream.is_done() {
                    drop(body_stream);
                    socket
                        .send(reply.unwrap_or_else(|| Reply::new(550, None, "data abort")))
                        .await?;

                    return Err(ServerError::DataAbort);
                }

                *state = State::Initial;
                reply.unwrap_or_else(|| Reply::new(250, None, "body ok"))
            }
            Err(reply) => reply.unwrap_or_else(|| Reply::new(550, None, "data not accepted")),
        },
        State::Initial => Reply::new(503, None, "mail transaction not started"),
        State::MAIL => Reply::new(503, None, "must have at least one valid recipient"),
        State::BDAT | State::BDATFAIL => Reply::new(503, None, "BDAT may not be mixed with DATA"),
    })
}

async fn do_bdat<H: Handler, S>(
    socket: &mut Framed<S, LineCodec>,
    state: &mut State,
    handler: &mut H,
    chunk_size: u64,
    last: bool,
) -> Result<Reply, ServerError>
where
    Framed<S, LineCodec>:
        Stream<Item = Result<BytesMut, LineError>> + Sink<Reply, Error = LineError> + Send + Unpin,
{
    Ok(match state {
        State::RCPT | State::BDAT => {
            let mut body_stream = read_body_bdat(socket, chunk_size).fuse();

            let reply = handler
                .bdat(&mut body_stream, chunk_size, last)
                .await
                .map_err(|e| {
                    *state = State::BDATFAIL;
                    e
                })?;

            if !body_stream.is_done() {
                drop(body_stream);
                socket
                    .send(reply.unwrap_or_else(|| Reply::new(550, None, "data abort")))
                    .await?;

                *state = State::BDATFAIL;
                return Err(ServerError::DataAbort);
            }

            *state = if last { State::Initial } else { State::BDAT };
            reply.unwrap_or_else(|| Reply::new(250, None, "data ok"))
        }
        State::MAIL => Reply::new(503, None, "must have at least one valid recipient"),
        _ => Reply::new(503, None, "mail transaction not started"),
    })
}

#[derive(Debug)]
pub enum ServerError {
    EOF,
    Framing(LineError),
    SyntaxError(BytesMut),
    IO(std::io::Error),
    Pipelining,
    DataAbort,
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

#[must_use]
fn read_body_bdat<'a, S>(
    socket: &'a mut Framed<S, LineCodec>,
    size: u64,
) -> impl Stream<Item = Result<BytesMut, LineError>> + 'a
where
    Framed<S, LineCodec>: Stream<Item = Result<BytesMut, LineError>> + Unpin,
{
    socket.codec_mut().chunking_mode(size);

    socket.take_while(|chunk| {
        let more = match chunk {
            Err(LineError::ChunkingDone) => false,
            _ => true,
        };

        tokio::future::ready(more)
    })
}
