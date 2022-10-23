#![warn(rust_2018_idioms)]

use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;

use futures_util::future::{select, Either};
use futures_util::future::{FutureExt, TryFutureExt};
use futures_util::pin_mut;
use futures_util::stream::Stream;
use futures_util::stream::TryStreamExt;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;
use tokio::sync::oneshot::Receiver;

use rustls_pemfile::{certs, rsa_private_keys};
use tokio_rustls::rustls::{Certificate, PrivateKey};
use tokio_rustls::rustls::{ServerConfig, ServerConnection};
use tokio_rustls::TlsAcceptor;

use rustyknife::rfc5321::{ForwardPath, Param, Path, ReversePath};
use rustyknife::types::{Domain, DomainPart};
use smtpbis::{
    smtp_server, Config, EhloKeywords, Handler, LineError, LoopExit, Reply, ServerError,
    ShutdownSignal,
};

const CERT: &[u8] = include_bytes!("../data/testcert.pem");
const KEY: &[u8] = include_bytes!("../data/testcert.key");

struct DummyHandler {
    tls_config: Arc<ServerConfig>,
    addr: SocketAddr,
    helo: Option<DomainPart>,
    mail: Option<ReversePath>,
    rcpt: Vec<ForwardPath>,
    body: Vec<u8>,
}

#[async_trait]
impl Handler for DummyHandler {
    type TlsConfig = Arc<ServerConfig>;
    type TlsSession = ServerConnection;

    async fn tls_request(&mut self) -> Option<Self::TlsConfig> {
        Some(self.tls_config.clone())
    }

    async fn tls_started(&mut self, session: &Self::TlsSession) {
        println!(
            "TLS started: {:?}/{:?}",
            session.protocol_version(),
            session.negotiated_cipher_suite()
        );
        self.reset_tx();
    }

    async fn ehlo(
        &mut self,
        domain: DomainPart,
        mut initial_keywords: EhloKeywords,
    ) -> Result<(String, EhloKeywords), Reply> {
        initial_keywords.insert("DSN".into(), None);
        initial_keywords.insert("8BITMIME".into(), None);
        initial_keywords.insert("SIZE".into(), Some("73400320".into()));
        initial_keywords.insert("AUTH".into(), Some("PLAIN".into()));

        let greet = format!("hello {} from {}", domain, self.addr);
        self.helo = Some(domain);
        self.reset_tx();

        Ok((greet, initial_keywords))
    }

    async fn helo(&mut self, domain: Domain) -> Option<Reply> {
        self.helo = Some(DomainPart::Domain(domain));
        self.reset_tx();

        None
    }

    async fn auth(&mut self, auth_msg: String) -> Option<Reply> {
        if let Ok(auth_msg) = base64::decode(auth_msg) {
            let auth_raw = String::from_utf8_lossy(&auth_msg);
            let auth_parts: Vec<&str> = auth_raw.split('\0').collect();
            println!("authorization_identity: {:?}", auth_parts[0]);
            println!("authentication_identity: {:?}", auth_parts[1]);
            println!("password: {:?}", auth_parts[2]);

            if true {
                Some(Reply::new(235, None, "Authentication successful"))
            } else {
                Some(Reply::new(535, None, "Authentication credentials invalid"))
            }
        } else {
            Some(Reply::new(501, None, "Base64-decode failed"))
        }
    }

    async fn mail(&mut self, path: ReversePath, _params: Vec<Param>) -> Option<Reply> {
        println!("Handler MAIL: {:?}", path);

        self.mail = Some(path);
        None
    }

    async fn rcpt(&mut self, path: ForwardPath, _params: Vec<Param>) -> Option<Reply> {
        println!("Handler RCPT: {:?}", path);
        if let ForwardPath::Path(Path(mbox, _)) = &path {
            if let DomainPart::Domain(domain) = mbox.domain_part() {
                if domain.starts_with('z') {
                    return Some(Reply::new(550, None, "I don't like zeds"));
                }
            }
        };
        self.rcpt.push(path);
        None
    }

    async fn data_start(&mut self) -> Option<Reply> {
        println!("Handler DATA start");
        None
    }

    async fn data<S>(&mut self, stream: &mut S) -> Result<Option<Reply>, ServerError>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Unpin + Send,
    {
        println!("Handler DATA read");
        let mut nb_lines: usize = 0;
        self.body.clear();

        while let Some(line) = stream.try_next().await? {
            self.body.extend(line);
            nb_lines += 1;
        }

        println!("got {} body lines", nb_lines);
        let reply_txt = format!("Received {} bytes in {} lines.", self.body.len(), nb_lines);
        self.reset_tx();

        Ok(Some(Reply::new(250, None, reply_txt)))
    }

    async fn bdat<S>(
        &mut self,
        stream: &mut S,
        _size: u64,
        last: bool,
    ) -> Result<Option<Reply>, ServerError>
    where
        S: Stream<Item = Result<BytesMut, LineError>> + Unpin + Send,
    {
        while let Some(chunk) = stream.try_next().await? {
            self.body.extend(chunk)
        }
        if last {
            self.reset_tx();
        }

        Ok(None)
    }

    async fn rset(&mut self) {
        self.reset_tx();
    }
}

impl DummyHandler {
    fn reset_tx(&mut self) {
        println!("Reset!");
        self.mail = None;
        self.rcpt.clear();
        self.body.clear();
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = Runtime::new()?;

    rt.block_on(async {
        let (listen_shutdown_tx, listen_shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(listen_loop(listen_shutdown_rx));

        tokio::signal::ctrl_c().await.unwrap();
        listen_shutdown_tx.send(()).unwrap();
        println!("Waiting for tasks to finish...");
        // FIXME: actually wait on tasks here.
    });

    Ok(())
}

async fn listen_loop(mut shutdown: Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();

    let certs = certs(&mut Cursor::new(CERT)).unwrap();
    let certificates: Vec<Certificate> = certs.into_iter().map(Certificate).collect();
    let key = rsa_private_keys(&mut Cursor::new(KEY)).unwrap().remove(0);

    let tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificates, PrivateKey(key))
        .expect("bad certificate/key");

    // tls_config.set_single_cert(certs, key).unwrap();
    let tls_config = Arc::new(tls_config);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_rx = shutdown_rx.map_err(|_| ()).shared();

    loop {
        let accept = listener.accept();
        pin_mut!(accept);

        match select(accept, &mut shutdown).await {
            Either::Left((listen_res, _)) => {
                let (socket, addr) = listen_res.unwrap();
                let mut shutdown_rx = shutdown_rx.clone();
                let tls_config = tls_config.clone();

                tokio::spawn(async move {
                    let smtp_res = serve_smtp(socket, addr, tls_config, &mut shutdown_rx).await;
                    println!("SMTP task done: {:?}", smtp_res);
                })
            }
            Either::Right(..) => {
                println!("socket listening loop stopping");
                shutdown_tx.send(()).unwrap();
                break;
            }
        };
    }
}

async fn serve_smtp(
    mut socket: TcpStream,
    addr: SocketAddr,
    tls_config: Arc<ServerConfig>,
    shutdown: &mut ShutdownSignal,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut handler = DummyHandler {
        addr,
        tls_config,
        helo: None,
        mail: None,
        rcpt: Vec::new(),
        body: Vec::new(),
    };

    let mut config = Config::default();
    match smtp_server(&mut socket, &mut handler, &config, shutdown, true).await {
        Ok(LoopExit::Done) => println!("Server done"),
        Ok(LoopExit::STARTTLS(tls_config)) => {
            let acceptor = TlsAcceptor::from(tls_config);
            let mut tls_socket = acceptor.accept(socket).await?;
            config.enable_starttls = false;
            handler.tls_started(tls_socket.get_ref().1).await;
            match smtp_server(&mut tls_socket, &mut handler, &config, shutdown, false).await {
                Ok(_) => println!("TLS Server done"),
                Err(e) => println!("TLS Top level error: {:?}", e),
            }
            tls_socket.shutdown().await?;
        }
        Err(e) => println!("Top level error: {:?}", e),
    }

    Ok(())
}
