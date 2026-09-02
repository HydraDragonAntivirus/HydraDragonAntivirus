#![doc = include_str!("../README.md")]

use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Body, Incoming},
    server,
    service::{HttpService, service_fn},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use moka::sync::Cache;
use std::{
    borrow::Borrow,
    collections::HashMap,
    error::Error as StdError,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tls::{CertifiedKeyDer, generate_cert};
use tokio::net::{TcpListener, TcpSocket, TcpStream, ToSocketAddrs, lookup_host};
use tokio_rustls::rustls;

pub use futures;
pub use hyper;
pub use moka;

#[cfg(feature = "native-tls-client")]
pub use tokio_native_tls;

#[cfg(any(feature = "native-tls-client", feature = "rustls-client"))]
pub mod default_client;
mod tls;

#[cfg(any(feature = "native-tls-client", feature = "rustls-client"))]
pub use default_client::DefaultClient;

const UPSTREAM_LOCAL_PORT_TTL: Duration = Duration::from_secs(3600);
static UPSTREAM_LOCAL_PORTS: OnceLock<Mutex<HashMap<u16, Instant>>> = OnceLock::new();

fn upstream_local_ports() -> &'static Mutex<HashMap<u16, Instant>> {
    UPSTREAM_LOCAL_PORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn prune_upstream_local_ports(ports: &mut HashMap<u16, Instant>, now: Instant) {
    ports.retain(|_, seen_at| now.duration_since(*seen_at) <= UPSTREAM_LOCAL_PORT_TTL);
}

pub fn register_upstream_local_port(port: u16) {
    if port == 0 {
        return;
    }

    let now = Instant::now();
    let mut ports = upstream_local_ports().lock().unwrap();
    prune_upstream_local_ports(&mut ports, now);
    ports.insert(port, now);
}

pub fn unregister_upstream_local_port(port: u16) {
    if port == 0 {
        return;
    }

    upstream_local_ports().lock().unwrap().remove(&port);
}

pub fn is_registered_upstream_local_port(port: u16) -> bool {
    if port == 0 {
        return false;
    }

    let now = Instant::now();
    let mut ports = upstream_local_ports().lock().unwrap();
    if ports.len() > 1000 {
        prune_upstream_local_ports(&mut ports, now);
    }
    if let Some(seen_at) = ports.get_mut(&port) {
        *seen_at = now;
        true
    } else {
        false
    }
}

pub async fn connect_registered_tcp(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let mut last_error = None;

    let addrs: Vec<SocketAddr> = lookup_host((host, port)).await?.collect();
    // Prioritize IPv4 addresses first to avoid multi-second IPv6 connection timeouts in VMs/IPv4 environments
    let (mut v4, v6): (Vec<_>, Vec<_>) = addrs.into_iter().partition(|a| a.is_ipv4());
    v4.extend(v6);

    for addr in v4 {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        };

        if let Err(err) = socket.bind(bind_addr) {
            last_error = Some(err);
            continue;
        }

        let registered_port = socket.local_addr().ok().map(|local_addr| {
            let port = local_addr.port();
            register_upstream_local_port(port);
            port
        });

        match socket.connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                if let Some(port) = registered_port {
                    unregister_upstream_local_port(port);
                }
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no address resolved for {host}:{port}"),
        )
    }))
}

#[derive(Clone, Copy, Debug)]
pub struct RemoteAddr(pub std::net::SocketAddr);

#[derive(Clone)]
/// The main struct to run proxy server
pub struct MitmProxy<I> {
    /// Root issuer to sign fake certificates. You may need to trust this issuer on client application to use HTTPS.
    ///
    /// If None, proxy will just tunnel HTTPS traffic and will not observe HTTPS traffic.
    pub root_issuer: Option<I>,
    /// Cache to store generated certificates. If None, cache will not be used.
    /// If root_issuer is None, cache will not be used.
    ///
    /// The key of cache is hostname.
    pub cert_cache: Option<Cache<String, CertifiedKeyDer>>,
    /// Configurable handshake timeout for SNI peeking.
    pub handshake_timeout: std::time::Duration,
}

impl<I> MitmProxy<I> {
    /// Create a new MitmProxy
    pub fn new(root_issuer: Option<I>, cache: Option<Cache<String, CertifiedKeyDer>>) -> Self {
        Self {
            root_issuer,
            cert_cache: cache,
            handshake_timeout: std::time::Duration::from_secs(5),
        }
    }

    /// Set a custom handshake timeout for SNI peeking
    pub fn with_handshake_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }
}

impl<I> MitmProxy<I>
where
    I: Borrow<rcgen::Issuer<'static, rcgen::KeyPair>> + Send + Sync + 'static,
{
    /// Bind to a socket address and return a future that runs the proxy server.
    /// URL for requests that passed to service are full URL including scheme.
    /// remote address of client is stored in request extensions as `RemoteAddr`.
    pub async fn bind<A: ToSocketAddrs, S>(
        self,
        addr: A,
        service: S,
    ) -> Result<impl Future<Output = ()>, std::io::Error>
    where
        S: HttpService<Incoming> + Clone + Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::ResBody: Send + Sync + 'static,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::Future: Send,
    {
        let listener = TcpListener::bind(addr).await?;

        let proxy = Arc::new(self);

        Ok(async move {
            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(err) => {
                        tracing::warn!("Failed to accept connection: {}", err);
                        continue;
                    }
                };

                let service = service.clone();

                let proxy = proxy.clone();
                tokio::spawn(Self::serve_standard_proxy_connection(
                    proxy,
                    service,
                    stream,
                    remote_addr,
                ));
            }
        })
    }

    /// Bind to a socket and accept both standard HTTP proxy connections and
    /// transparent TLS connections redirected to this listener.
    ///
    /// Standard proxy clients send HTTP/CONNECT first. Transparent TLS clients
    /// send a TLS ClientHello first; for those we peek SNI, generate a forged
    /// certificate for that host, terminate TLS, and forward decrypted HTTP to
    /// the wrapped service.
    pub async fn bind_transparent_or_proxy<A: ToSocketAddrs, S>(
        self,
        addr: A,
        service: S,
    ) -> Result<impl Future<Output = ()>, std::io::Error>
    where
        S: HttpService<Incoming> + Clone + Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::ResBody: Send + Sync + 'static,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::Future: Send,
    {
        let listener = TcpListener::bind(addr).await?;
        let proxy = Arc::new(self);

        Ok(async move {
            loop {
                let (stream, remote_addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(err) => {
                        tracing::warn!("Failed to accept connection: {}", err);
                        continue;
                    }
                };

                let service = service.clone();
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    match peek_tls_sni(&stream, proxy.handshake_timeout).await {
                        Some(host) => {
                            Self::serve_transparent_tls_connection(
                                proxy,
                                service,
                                stream,
                                remote_addr,
                                host,
                            )
                            .await;
                        }
                        None => {
                            Self::serve_standard_proxy_connection(
                                proxy,
                                service,
                                stream,
                                remote_addr,
                            )
                            .await;
                        }
                    }
                });
            }
        })
    }

    async fn serve_standard_proxy_connection<S>(
        proxy: Arc<Self>,
        service: S,
        stream: TcpStream,
        remote_addr: SocketAddr,
    ) where
        S: HttpService<Incoming> + Clone + Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::ResBody: Send + Sync + 'static,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::Future: Send,
    {
        if let Err(err) = server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(
                TokioIo::new(stream),
                service_fn(move |mut req| {
                    req.extensions_mut().insert(RemoteAddr(remote_addr));
                    Self::wrap_service(proxy.clone(), service.clone()).call(req)
                }),
            )
            .with_upgrades()
            .await
        {
            tracing::error!("Error in proxy: {}", err);
        }
    }

    async fn serve_transparent_tls_connection<S>(
        proxy: Arc<Self>,
        service: S,
        stream: TcpStream,
        remote_addr: SocketAddr,
        host: String,
    ) where
        S: HttpService<Incoming> + Clone + Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::ResBody: Send + Sync + 'static,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::Future: Send,
    {
        let authority = match format!("{}:443", host).parse::<hyper::http::uri::Authority>() {
            Ok(authority) => authority,
            Err(err) => {
                tracing::error!("Transparent TLS invalid SNI '{}': {}", host, err);
                return;
            }
        };

        let Some(server_config) = proxy.server_config(host.clone(), true) else {
            tracing::error!("Transparent TLS requires a root issuer for {}", host);
            return;
        };
        let server_config = match server_config {
            Ok(server_config) => Arc::new(server_config),
            Err(err) => {
                tracing::error!(
                    "Failed to create transparent TLS config for {}: {}",
                    host,
                    err
                );
                return;
            }
        };

        let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
        let client = match tls_acceptor.accept(stream).await {
            Ok(client) => client,
            Err(err) => {
                tracing::error!("Failed to accept transparent TLS for {}: {}", host, err);
                return;
            }
        };

        let f = move |mut req: Request<_>| {
            let authority = authority.clone();
            let mut service = service.clone();
            async move {
                req.extensions_mut().insert(RemoteAddr(remote_addr));
                inject_authority(&mut req, authority);
                service.call(req).await
            }
        };

        let res = if client.get_ref().1.alpn_protocol() == Some(b"h2") {
            server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(client), service_fn(f))
                .await
                .map(|_| ())
        } else {
            server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(TokioIo::new(client), service_fn(f))
                .with_upgrades()
                .await
                .map(|_| ())
        };

        if let Err(err) = res {
            tracing::debug!("Transparent TLS connection closed for {}: {}", host, err);
        }
    }

    /// Transform a service to a service that can be used in hyper server.
    /// URL for requests that passed to service are full URL including scheme.
    /// See `examples/https.rs` for usage.
    /// If you want to serve simple HTTP proxy server, you can use `bind` method instead.
    /// `bind` will call this method internally.
    pub fn wrap_service<S>(
        proxy: Arc<Self>,
        service: S,
    ) -> impl HttpService<
        Incoming,
        ResBody = BoxBody<<S::ResBody as Body>::Data, <S::ResBody as Body>::Error>,
        Future: Send,
    >
    where
        S: HttpService<Incoming> + Clone + Send + 'static,
        S::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::ResBody: Send + Sync + 'static,
        <S::ResBody as Body>::Data: Send,
        <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
        S::Future: Send,
    {
        service_fn(move |mut req| {
            let proxy = proxy.clone();
            let mut service = service.clone();

            async move {
                if req.method() == Method::CONNECT {
                    // https
                    let Some(connect_authority) = req.uri().authority().cloned() else {
                        tracing::error!(
                            "Bad CONNECT request: {}, Reason: Invalid Authority",
                            req.uri()
                        );
                        return Ok(no_body(StatusCode::BAD_REQUEST)
                            .map(|b| b.boxed().map_err(|never| match never {}).boxed()));
                    };

                    tokio::spawn(async move {
                        let remote_addr: Option<RemoteAddr> = req.extensions_mut().remove();
                        let client = match hyper::upgrade::on(req).await {
                            Ok(client) => client,
                            Err(err) => {
                                tracing::error!(
                                    "Failed to upgrade CONNECT request for {}: {}",
                                    connect_authority,
                                    err
                                );
                                return;
                            }
                        };
                        if let Some(server_config) =
                            proxy.server_config(connect_authority.host().to_string(), true)
                        {
                            let server_config = match server_config {
                                Ok(server_config) => server_config,
                                Err(err) => {
                                    tracing::error!(
                                        "Failed to create server config for {}, {}",
                                        connect_authority.host(),
                                        err
                                    );
                                    return;
                                }
                            };
                            let server_config = Arc::new(server_config);
                            let tls_acceptor = tokio_rustls::TlsAcceptor::from(server_config);
                            let client = match tls_acceptor.accept(TokioIo::new(client)).await {
                                Ok(client) => client,
                                Err(err) => {
                                    tracing::error!(
                                        "Failed to accept TLS connection for {}, {}",
                                        connect_authority.host(),
                                        err
                                    );
                                    return;
                                }
                            };
                            let f = move |mut req: Request<_>| {
                                let connect_authority = connect_authority.clone();
                                let mut service = service.clone();

                                async move {
                                    if let Some(remote_addr) = remote_addr {
                                        req.extensions_mut().insert(remote_addr);
                                    }
                                    inject_authority(&mut req, connect_authority.clone());
                                    service.call(req).await
                                }
                            };
                            let res = if client.get_ref().1.alpn_protocol() == Some(b"h2") {
                                server::conn::http2::Builder::new(TokioExecutor::new())
                                    .serve_connection(TokioIo::new(client), service_fn(f))
                                    .await
                            } else {
                                server::conn::http1::Builder::new()
                                    .preserve_header_case(true)
                                    .title_case_headers(true)
                                    .serve_connection(TokioIo::new(client), service_fn(f))
                                    .with_upgrades()
                                    .await
                            };

                            if let Err(err) = res {
                                tracing::debug!("Connection closed: {}", err);
                            }
                        } else {
                            let mut server = match connect_registered_tcp(
                                connect_authority.host(),
                                connect_authority.port_u16().unwrap_or(443),
                            )
                            .await
                            {
                                Ok(server) => server,
                                Err(err) => {
                                    tracing::error!(
                                        "Failed to connect to {}: {}",
                                        connect_authority,
                                        err
                                    );
                                    return;
                                }
                            };
                            let _ = tokio::io::copy_bidirectional(
                                &mut TokioIo::new(client),
                                &mut server,
                            )
                            .await;
                        }
                    });

                    Ok(Response::new(
                        http_body_util::Empty::new()
                            .map_err(|never: std::convert::Infallible| match never {})
                            .boxed(),
                    ))
                } else {
                    // http
                    service.call(req).await.map(|res| res.map(|b| b.boxed()))
                }
            }
        })
    }

    fn get_certified_key(&self, host: String) -> Option<CertifiedKeyDer> {
        self.root_issuer.as_ref().and_then(|root_issuer| {
            if let Some(cache) = self.cert_cache.as_ref() {
                // Try to get from cache, but handle generation errors gracefully
                cache
                    .try_get_with(host.clone(), move || {
                        generate_cert(host, root_issuer.borrow())
                    })
                    .map_err(|err| {
                        tracing::error!("Failed to generate certificate for host: {}", err);
                    })
                    .ok()
            } else {
                generate_cert(host, root_issuer.borrow())
                    .map_err(|err| {
                        tracing::error!("Failed to generate certificate for host: {}", err);
                    })
                    .ok()
            }
        })
    }

    fn server_config(
        &self,
        host: String,
        h2: bool,
    ) -> Option<Result<rustls::ServerConfig, rustls::Error>> {
        if let Some(cert) = self.get_certified_key(host) {
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::pki_types::CertificateDer::from(cert.cert_der)],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_der),
                    ),
                );

            Some(if h2 {
                config.map(|mut server_config| {
                    server_config.alpn_protocols = vec!["h2".into(), "http/1.1".into()];
                    server_config
                })
            } else {
                config
            })
        } else {
            None
        }
    }
}

async fn peek_tls_sni(stream: &TcpStream, timeout: std::time::Duration) -> Option<String> {
    let mut buf = [0u8; 4096];
    let fut = async {
        loop {
            let len = stream.peek(&mut buf).await.ok()?;
            if len < 5 {
                if len == 0 {
                    return None;
                }
                if stream.readable().await.is_err() {
                    return None;
                }
                continue;
            }

            if buf[0] != 0x16 {
                return None;
            }

            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            let expected_len = 5 + record_len;

            if expected_len > buf.len() {
                return None;
            }

            if len < expected_len {
                if stream.readable().await.is_err() {
                    return None;
                }
                continue;
            }

            return parse_tls_sni(&buf[..len]);
        }
    };

    tokio::time::timeout(timeout, fut).await.ok().flatten()
}

fn parse_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len || data.get(5).copied()? != 0x01 {
        return None;
    }

    let mut pos = 9;
    if pos + 2 + 32 > data.len() {
        return None;
    }
    pos += 2 + 32;

    let session_id_len = *data.get(pos)? as usize;
    pos += 1 + session_id_len;
    if pos + 2 > data.len() {
        return None;
    }

    let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= data.len() {
        return None;
    }

    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;
    if pos + 2 > data.len() {
        return None;
    }

    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let extensions_end = pos.checked_add(extensions_len)?.min(data.len());

    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > extensions_end {
            return None;
        }

        if ext_type == 0x0000 {
            return parse_sni_extension(&data[pos..pos + ext_len]);
        }
        pos += ext_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut pos: usize = 2;
    let end = pos.checked_add(list_len)?.min(data.len());

    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if pos + name_len > end {
            return None;
        }

        if name_type == 0 {
            let host = std::str::from_utf8(&data[pos..pos + name_len])
                .ok()?
                .trim()
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !host.is_empty() {
                return Some(host);
            }
        }
        pos += name_len;
    }

    None
}

fn no_body<D>(status: StatusCode) -> Response<Empty<D>> {
    let mut res = Response::new(Empty::new());
    *res.status_mut() = status;
    res
}

fn inject_authority<B>(request_middleman: &mut Request<B>, authority: hyper::http::uri::Authority) {
    let mut parts = request_middleman.uri().clone().into_parts();
    parts.scheme = Some(hyper::http::uri::Scheme::HTTPS);
    if parts.authority.is_none() {
        parts.authority = Some(authority.clone());
    }

    match hyper::http::uri::Uri::from_parts(parts) {
        Ok(uri) => *request_middleman.uri_mut() = uri,
        Err(err) => {
            tracing::error!(
                "Failed to inject authority '{}' into URI: {}",
                authority,
                err
            );
            // Keep the original URI if injection fails
        }
    }
}
