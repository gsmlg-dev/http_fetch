//! Independent unmodified quinn server fixture. The only knob is the public
//! `ServerConfig::migration(false)`, which makes quinn-proto advertise the
//! `disable_active_migration` transport parameter.
use std::{env, fs, sync::Arc, time::Duration};

use quinn::{crypto::rustls::QuicServerConfig, Endpoint, ServerConfig};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

const PEER: &str = "quinn-0.11.11/quinn-proto-0.11.17";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest(bytes: &[u8]) -> String {
    hex(ring::digest::digest(&ring::digest::SHA256, bytes).as_ref())
}

fn arg(name: &str) -> String {
    let args: Vec<String> = env::args().collect();
    let index = args.iter().position(|a| a == name).expect(name);
    args[index + 1].clone()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let certs = CertificateDer::pem_slice_iter(&fs::read(arg("--cert")).unwrap())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(&fs::read(arg("--key")).unwrap()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tls.alpn_protocols = vec![b"ex-quic-m2".to_vec()];
    let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    config.migration(false);
    let endpoint = Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    println!(
        "{{\"event\":\"listening\",\"address\":\"{}\",\"peer\":\"{PEER}\",\"migration\":false}}",
        endpoint.local_addr().unwrap()
    );
    let _ = tokio::time::timeout(Duration::from_secs(90), async {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                println!("{{\"event\":\"handshake\",\"peer\":\"{PEER}\"}}");
                while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                    let conn = conn.clone();
                    tokio::spawn(async move {
                        let id = send.id().index();
                        let mut received = Vec::new();
                        let mut buffer = [0u8; 4096];
                        loop {
                            match recv.read(&mut buffer).await {
                                Ok(Some(n)) => {
                                    received.extend_from_slice(&buffer[..n]);
                                    send.write_all(&buffer[..n]).await.unwrap();
                                    println!(
                                        "{{\"event\":\"receipt\",\"stream\":{id},\"bytes\":{},\"sha256\":\"{}\",\"remote\":\"{}\"}}",
                                        received.len(), digest(&received), conn.remote_address()
                                    );
                                }
                                Ok(None) => {
                                    println!(
                                        "{{\"event\":\"stream\",\"stream\":{id},\"bytes\":{},\"sha256\":\"{}\",\"fin\":true,\"remote\":\"{}\"}}",
                                        received.len(), digest(&received), conn.remote_address()
                                    );
                                    let _ = send.finish();
                                    let _ = send.stopped().await;
                                    return;
                                }
                                Err(error) => {
                                    println!("{{\"event\":\"stream\",\"stream\":{id},\"fin\":false,\"error\":\"{error}\"}}");
                                    return;
                                }
                            }
                        }
                    });
                }
            });
        }
    })
    .await;
}
