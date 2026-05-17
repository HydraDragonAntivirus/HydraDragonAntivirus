use std::{
    convert::Infallible,
    sync::{Arc, atomic::AtomicU16},
};

use axum::{
    Router,
    extract::Request,
    response::{Sse, sse::Event},
    routing::get,
};
use bytes::Bytes;
use futures::stream;
use http_mitm_proxy::{DefaultClient, MitmProxy, RemoteAddr};
use hyper::{
    Uri,
    body::{Body, Incoming},
    service::{HttpService, service_fn},
};
use moka::sync::Cache;

static PORT: AtomicU16 = AtomicU16::new(3666);

#[ctor::ctor]
#[cfg(test)]
fn init_subscriber() {
    tracing_subscriber::fmt::init();
}

fn get_port() -> u16 {
    PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn root_cert() -> rcgen::Issuer<'static, rcgen::KeyPair> {
    let mut params = rcgen::CertificateParams::default();

    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<http-mitm-proxy TEST CA>".to_string()),
    );
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let signing_key = rcgen::KeyPair::generate().unwrap();

    rcgen::Issuer::new(params, signing_key)
}

async fn bind_app(app: Router) -> (u16, impl std::future::Future<Output = ()>) {
    let port = get_port();
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    (port, async {
        axum::serve(listener, app).await.unwrap();
    })
}

fn client(proxy_port: u16) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .proxy(reqwest::Proxy::https(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .build()
        .unwrap()
}

fn client_tls(proxy_port: u16, cert: &rcgen::Certificate) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .proxy(reqwest::Proxy::https(format!("http://127.0.0.1:{proxy_port}")).unwrap())
        .add_root_certificate(reqwest::Certificate::from_der(cert.der()).unwrap())
        .build()
        .unwrap()
}

fn proxy_client() -> DefaultClient {
    DefaultClient::new()
}

async fn setup<B, E, E2, S>(app: Router, service: S) -> (u16, u16)
where
    B: Body<Data = Bytes, Error = E> + Send + Sync + 'static,
    E: std::error::Error + Send + Sync + 'static,
    E2: std::error::Error + Send + Sync + 'static,
    S: HttpService<Incoming, ResBody = B, Error = E2, Future: Send> + Send + Sync + Clone + 'static,
{
    let proxy = MitmProxy::new(Some(root_cert()), Some(Cache::new(128)));
    let proxy_port = get_port();
    let proxy = proxy
        .bind(("127.0.0.1", proxy_port), service)
        .await
        .unwrap();
    tokio::spawn(proxy);

    let (port, server) = bind_app(app).await;
    tokio::spawn(server);

    (proxy_port, port)
}

async fn setup_tls<B, E, E2, S>(
    app: Router,
    service: S,
    root_cert: Arc<rcgen::Issuer<'static, rcgen::KeyPair>>,
) -> (u16, u16)
where
    B: Body<Data = Bytes, Error = E> + Send + Sync + 'static,
    E: std::error::Error + Send + Sync + 'static,
    E2: std::error::Error + Send + Sync + 'static,
    S: HttpService<Incoming, ResBody = B, Error = E2, Future: Send> + Send + Sync + Clone + 'static,
{
    let proxy = MitmProxy::new(Some(root_cert), Some(Cache::new(128)));
    let proxy_port = get_port();
    let proxy = proxy
        .bind(("127.0.0.1", proxy_port), service)
        .await
        .unwrap();
    tokio::spawn(proxy);

    let (port, server) = bind_app(app).await;
    tokio::spawn(server);

    (proxy_port, port)
}

#[tokio::test]
async fn test_simple_http() {
    const BODY: &str = "Hello, World!";
    let app = Router::new().route("/", get(|| async move { BODY }));

    let proxy_client = proxy_client();
    let (proxy_port, port) = setup(
        app,
        service_fn(move |req| {
            let proxy_client = proxy_client.clone();
            async move {
                assert!(
                    req.extensions().get::<RemoteAddr>().is_some(),
                    "RemoteAddr missing"
                );
                proxy_client.send_request(req).await.map(|t| t.0)
            }
        }),
    )
    .await;

    let client = client(proxy_port);

    let res = client
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), BODY);
}

#[tokio::test]
async fn test_modify_http() {
    let app = Router::new().route(
        "/",
        get(|req: Request| async move {
            req.headers()
                .get("X-test")
                .map(|v| v.to_str().unwrap())
                .unwrap_or("none")
                .to_string()
        }),
    );

    let proxy_client = proxy_client();
    let (proxy_port, port) = setup(
        app,
        service_fn(move |mut req| {
            let proxy_client = proxy_client.clone();
            async move {
                assert!(
                    req.extensions().get::<RemoteAddr>().is_some(),
                    "RemoteAddr missing"
                );
                req.headers_mut()
                    .insert("X-test", "modified".parse().unwrap());
                proxy_client.send_request(req).await.map(|t| t.0)
            }
        }),
    )
    .await;

    let client = client(proxy_port);

    let res = client
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "modified");
}

#[tokio::test]
async fn test_sse_http() {
    let app = Router::new().route(
        "/sse",
        get(|| async {
            Sse::new(stream::iter(["1", "2", "3"].into_iter().map(|s| {
                Ok::<Event, Infallible>(Event::default().event("message").data(s))
            })))
        }),
    );

    let proxy_client = proxy_client();
    let (proxy_port, port) = setup(
        app,
        service_fn(move |req| {
            let proxy_client = proxy_client.clone();
            async move {
                assert!(
                    req.extensions().get::<RemoteAddr>().is_some(),
                    "RemoteAddr missing"
                );
                proxy_client.send_request(req).await.map(|t| t.0)
            }
        }),
    )
    .await;

    let client = client(proxy_port);
    let res = client
        .get(format!("http://127.0.0.1:{port}/sse"))
        .send()
        .await
        .unwrap();

    assert_eq!(
        res.bytes().await.unwrap(),
        b"event: message\ndata: 1\n\nevent: message\ndata: 2\n\nevent: message\ndata: 3\n\n"[..]
    );
}

#[tokio::test]
async fn test_simple_https() {
    const BODY: &str = "Hello, World!";
    let app = Router::new().route("/", get(|| async move { BODY }));

    let mut params = rcgen::CertificateParams::default();

    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("<http-mitm-proxy TEST CA>".to_string()),
    );
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let signing_key = rcgen::KeyPair::generate().unwrap();

    let cert = params.self_signed(&signing_key).unwrap();

    let issuer = rcgen::Issuer::new(params, signing_key);
    let issuer = Arc::new(issuer);

    let proxy_client = proxy_client();
    let (proxy_port, port) = setup_tls(
        app,
        service_fn(move |mut req| {
            let proxy_client = proxy_client.clone();
            async move {
                assert!(
                    req.extensions().get::<RemoteAddr>().is_some(),
                    "RemoteAddr missing"
                );
                let mut parts = req.uri().clone().into_parts();
                parts.scheme = Some(hyper::http::uri::Scheme::HTTP);

                *req.uri_mut() = Uri::from_parts(parts).unwrap();

                proxy_client.send_request(req).await.map(|t| t.0)
            }
        }),
        issuer.clone(),
    )
    .await;

    let client = client_tls(proxy_port, &cert);

    let res = client
        .get(format!("https://127.0.0.1:{port}/"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), BODY);
}
