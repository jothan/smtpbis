#![warn(rust_2018_idioms)]

use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpListener;

use tokio_rustls::rustls::{
    internal::pemfile::{certs, pkcs8_private_keys},
    NoClientAuth, ServerConfig, ServerSession, Session,
};

use smtpbis::{smtp_server, Handler};

const CERT: &[u8] = include_bytes!("ssl-cert-snakeoil.pem");
const KEY: &[u8] = include_bytes!("ssl-cert-snakeoil.key");

struct DummyHandler {
    tls_config: Arc<ServerConfig>,
    addr: SocketAddr,
}

#[async_trait]
impl Handler for DummyHandler {
    async fn tls_request(&mut self) -> Option<Arc<ServerConfig>> {
        Some(self.tls_config.clone())
    }

    async fn tls_started(&mut self, session: &ServerSession) {
        println!(
            "TLS started: {:?}/{:?}",
            session.get_protocol_version(),
            session.get_negotiated_ciphersuite()
        );
    }
}

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
        let (socket, addr) = listener.accept().await?;
        let handler = DummyHandler {
            addr,
            tls_config: tls_config.clone(),
        };

        tokio::spawn(async move {
            if let Err(e) = smtp_server(socket, handler).await {
                println!("Top level error: {:?}", e);
            }
        });
    }
}
