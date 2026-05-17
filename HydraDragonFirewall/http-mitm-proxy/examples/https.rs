use std::{path::PathBuf, sync::Arc};

use clap::{Args, Parser};
use http_mitm_proxy::{DefaultClient, MitmProxy, hyper::service::service_fn, moka::sync::Cache};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::pem::PemObject;
use tokio::net::TcpListener;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        self, ServerConfig,
        pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    },
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

fn make_root_issuer() -> (rcgen::Issuer<'static, rcgen::KeyPair>, Vec<u8>) {
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

    (rcgen::Issuer::new(params, signing_key), cert.der().to_vec())
}

#[tokio::main]
async fn main() {
    let opt = Opt::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_line_number(true)
        .init();

    let (root_issuer, cert_der) = if let Some(external_issuer) = opt.external_issuer {
        // Use existing key
        let signing_key = rcgen::KeyPair::from_pem(
            &std::fs::read_to_string(&external_issuer.private_key).unwrap(),
        )
        .unwrap();

        let cert_pem = std::fs::read_to_string(&external_issuer.cert).unwrap();
        let cert = rustls_pki_types::CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();

        (
            rcgen::Issuer::from_ca_cert_pem(
                &std::fs::read_to_string(&external_issuer.cert).unwrap(),
                signing_key,
            )
            .unwrap(),
            cert.to_vec(),
        )
    } else {
        make_root_issuer()
    };

    // Reusing the same root cert for proxy server
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                root_issuer.key().serialize_der(),
            )),
        )
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];

    let proxy = MitmProxy::new(
        // This is the root cert that will be used to sign the fake certificates
        Some(root_issuer),
        Some(Cache::new(128)),
    );
    let proxy = Arc::new(proxy);

    let client = DefaultClient::new();

    let listener = TcpListener::bind(("127.0.0.1", 3003)).await.unwrap();

    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let server = async move {
        loop {
            let (stream, _client_addr) = listener.accept().await.unwrap();
            let proxy = proxy.clone();
            let client = client.clone();
            let tls_acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                let client = client.clone();
                let service = MitmProxy::wrap_service(
                    proxy.clone(),
                    service_fn(move |req| {
                        let client = client.clone();
                        async move {
                            let uri = req.uri().clone();

                            // You can modify request here
                            // or You can just return response anywhere

                            let (res, _upgrade) = client.send_request(req).await?;

                            println!("{} -> {}", uri, res.status());

                            // You can modify response here

                            Ok::<_, http_mitm_proxy::default_client::Error>(res)
                        }
                    }),
                );

                let stream = tls_acceptor.accept(stream).await.unwrap();

                if stream.get_ref().1.alpn_protocol() == Some(b"h2") {
                    // HTTP/2
                    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                        .unwrap();
                } else {
                    // HTTP/1.1
                    hyper::server::conn::http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(TokioIo::new(stream), service)
                        .with_upgrades()
                        .await
                        .unwrap();
                }
            });
        }
    };

    println!("HTTPS Proxy is listening on https://127.0.0.1:3003");

    server.await;
}
