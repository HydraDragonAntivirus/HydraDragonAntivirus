use std::path::PathBuf;

use clap::{Args, Parser};
use http_mitm_proxy::{
    DefaultClient, MitmProxy, default_client::Upgraded, hyper::service::service_fn,
    moka::sync::Cache,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing_subscriber::EnvFilter;
use winnow::Parser as _;

#[derive(Parser)]
struct Opt {
    #[clap(flatten)]
    external_issuer: Option<ExternalIssuer>,
}

#[derive(Args, Debug)]
struct ExternalIssuer {
    #[arg(required = false)]
    cert: PathBuf,
    #[arg(required = false)]
    private_key: PathBuf,
}

fn make_root_issuer() -> rcgen::Issuer<'static, rcgen::KeyPair> {
    let mut params = rcgen::CertificateParams::default();

    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<HTTP-MITM-PROXY CA>".to_string()),
    );
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let signing_key = rcgen::KeyPair::generate().unwrap();

    let cert = params.self_signed(&signing_key).unwrap();

    println!();
    println!("Trust this cert if you want to use HTTPS");
    println!();
    println!("{}", cert.pem());
    println!();

    /*
        Save this cert to ca.crt and use it with curl like this:
        curl https://www.google.com -x http://127.0.0.1:3003 --cacert ca.crt
    */

    println!("Private key");
    println!("{}", signing_key.serialize_pem());

    rcgen::Issuer::new(params, signing_key)
}

#[tokio::main]
async fn main() {
    let opt = Opt::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_line_number(true)
        .init();

    let root_issuer = if let Some(external_issuer) = opt.external_issuer {
        // Use existing key
        let signing_key = rcgen::KeyPair::from_pem(
            &std::fs::read_to_string(&external_issuer.private_key).unwrap(),
        )
        .unwrap();

        rcgen::Issuer::from_ca_cert_pem(
            &std::fs::read_to_string(&external_issuer.cert).unwrap(),
            signing_key,
        )
        .unwrap()
    } else {
        make_root_issuer()
    };

    let proxy = MitmProxy::new(
        // This is the root cert that will be used to sign the fake certificates
        Some(root_issuer),
        Some(Cache::new(128)),
    );

    let client = DefaultClient::new().with_upgrades();
    let server = proxy
        .bind(
            ("127.0.0.1", 3003),
            service_fn(move |req| {
                let client = client.clone();
                async move {
                    let uri = req.uri().clone();

                    // You can modify request here
                    // or You can just return response anywhere

                    let (res, upgrade) = client.send_request(req).await?;

                    // println!("{} -> {}", uri, res.status());
                    if let Some(upgrade) = upgrade {
                        // If the response is an upgrade, e.g. Websocket, you can see traffic.
                        // Modifying upgraded traffic is not supported yet.

                        // You can try https://echo.websocket.org/.ws to test websocket.
                        println!("Upgrade connection");

                        tokio::spawn(async move {
                            let Upgraded { client, server } = upgrade.await.unwrap().unwrap();
                            let url = uri.to_string();

                            let (mut client_rx, mut client_tx) = tokio::io::split(client);
                            let (mut server_rx, mut server_tx) = tokio::io::split(server);

                            let url0 = url.clone();
                            let client_to_server = async move {
                                let mut buf = Vec::new();

                                loop {
                                    if client_rx.read_buf(&mut buf).await.unwrap() == 0 {
                                        break;
                                    }
                                    loop {
                                        let input = &mut buf.as_slice();
                                        if let Ok((frame, read)) =
                                            websocket::frame.with_taken().parse_next(input)
                                        {
                                            println!(
                                                "{} Client: {}",
                                                &url0,
                                                String::from_utf8_lossy(&frame.payload_data)
                                            );
                                            server_tx.write_all(read).await.unwrap();
                                            buf = input.to_vec();
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            };

                            let url0 = url.clone();
                            let server_to_client = async move {
                                let mut buf = Vec::new();

                                loop {
                                    if server_rx.read_buf(&mut buf).await.unwrap() == 0 {
                                        break;
                                    }
                                    loop {
                                        let input = &mut buf.as_slice();
                                        if let Ok((frame, read)) =
                                            websocket::frame.with_taken().parse_next(input)
                                        {
                                            println!(
                                                "{} Server: {}",
                                                &url0,
                                                String::from_utf8_lossy(&frame.payload_data)
                                            );
                                            client_tx.write_all(read).await.unwrap();
                                            buf = input.to_vec();
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            };

                            tokio::spawn(client_to_server);
                            tokio::spawn(server_to_client);
                        });
                    }

                    // You can modify response here

                    Ok::<_, http_mitm_proxy::default_client::Error>(res)
                }
            }),
        )
        .await
        .unwrap();

    println!("HTTP Proxy is listening on http://127.0.0.1:3003");

    server.await;
}

pub mod websocket {
    /*
    https://developer.mozilla.org/en-US/docs/Web/API/WebSockets_API/Writing_WebSocket_servers
    Frame format:

          0                   1                   2                   3
          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-------+-+-------------+-------------------------------+
         |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
         |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
         |N|V|V|V|       |S|             |   (if payload len==126/127)   |
         | |1|2|3|       |K|             |                               |
         +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
         |     Extended payload length continued, if payload len == 127  |
         + - - - - - - - - - - - - - - - +-------------------------------+
         |                               |Masking-key, if MASK set to 1  |
         +-------------------------------+-------------------------------+
         | Masking-key (continued)       |          Payload Data         |
         +-------------------------------- - - - - - - - - - - - - - - - +
         :                     Payload Data continued ...                :
         + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
         |                     Payload Data continued ...                |
         +---------------------------------------------------------------+

    */

    use winnow::{
        binary::{be_u16, be_u64, u8},
        prelude::*,
        token::take,
    };

    pub struct Frame {
        pub b0: u8,
        pub b1: u8,
        pub payload_len: usize,
        pub masking_key: Option<[u8; 4]>,
        pub payload_data: Vec<u8>,
    }

    pub fn frame(input: &mut &[u8]) -> ModalResult<Frame> {
        let b0 = u8(input)?;
        let b1 = u8(input)?;

        let payload_len = match b1 & 0b0111_1111 {
            126 => {
                let len = be_u16(input)?;
                len as usize
            }
            127 => {
                let len = be_u64(input)?;
                len as usize
            }
            len => len as usize,
        };

        let mask = b1 & 0b1000_0000 != 0;
        let masking_key = if mask {
            Some([u8(input)?, u8(input)?, u8(input)?, u8(input)?])
        } else {
            None
        };

        let mut payload_data = take(payload_len).parse_next(input)?.to_vec();

        if let Some(mask) = masking_key {
            for (i, byte) in payload_data.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }

        Ok(Frame {
            b0,
            b1,
            payload_len,
            masking_key,
            payload_data,
        })
    }
}
