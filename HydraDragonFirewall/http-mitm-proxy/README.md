# http-mitm-proxy

[![Crates.io](https://img.shields.io/crates/v/http-mitm-proxy.svg)](https://crates.io/crates/http-mitm-proxy)

A HTTP proxy server library intended to be a backend of application like Burp proxy.

- Sniff HTTP and HTTPS traffic by signing certificate on the fly.
- Server Sent Event
- WebSocket ("raw" traffic only. Parsers will not be implemented in this crate.)

## Usage

```rust, no_run
use std::path::PathBuf;

use clap::{Args, Parser};
use http_mitm_proxy::{
    DefaultClient, MitmProxy, RemoteAddr, hyper::service::service_fn, moka::sync::Cache,
};
use tracing_subscriber::EnvFilter;

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

    let client = DefaultClient::new();
    let server = proxy
        .bind(
            ("127.0.0.1", 3003),
            service_fn(move |req| {
                let client = client.clone();
                async move {
                    let uri = req.uri().clone();
                    let remote_addr = req.extensions().get::<RemoteAddr>().unwrap().0;
                    println!(
                        "Received request from {}: {} {}",
                        remote_addr,
                        req.method(),
                        uri
                    );

                    // You can modify request here
                    // or You can just return response anywhere

                    let (res, _upgrade) = client.send_request(req).await?;

                    println!("{} -> {}", uri, res.status());

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
```
