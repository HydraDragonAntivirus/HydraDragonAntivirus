#![cfg(any(feature = "native-tls-client", feature = "rustls-client"))]

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::{
    Request, Response, StatusCode, Uri, Version,
    body::{Body, Incoming},
    client, header,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    collections::HashMap,
    future::poll_fn,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

// Both TLS stacks may be enabled at once: rustls is tried first (immune to
// schannel provider/revocation failures), native-tls (schannel, Windows
// store, TLS < 1.2) is the fallback for hosts rustls cannot do.

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0} doesn't have an valid host")]
    InvalidHost(Box<Uri>),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    HyperError(#[from] hyper::Error),
    #[error("Failed to connect to {0}, {1}")]
    ConnectError(Box<Uri>, hyper::Error),

    #[cfg(feature = "native-tls-client")]
    #[error("Failed to connect with TLS to {0}, {1}")]
    NativeTlsConnectError(Box<Uri>, native_tls::Error),
    #[cfg(feature = "native-tls-client")]
    #[error(transparent)]
    NativeTlsError(#[from] tokio_native_tls::native_tls::Error),

    #[cfg(feature = "rustls-client")]
    #[error("Failed to connect with TLS to {0}, {1}")]
    RustlsTlsConnectError(Box<Uri>, std::io::Error),

    /// Both upstream stacks failed for one host. The message carries each
    /// stack's own error so one proxy-err line shows the full picture
    /// (proves which binary/fallback path actually ran in production).
    #[error("Failed to connect with TLS to {uri} (rustls: {rustls}; native-tls: {native})")]
    DualTlsConnectError {
        uri: Box<Uri>,
        rustls: String,
        native: String,
    },

    #[error("Failed to parse URI: {0}")]
    UriParsingError(#[from] hyper::http::uri::InvalidUri),

    #[error("Failed to parse URI parts: {0}")]
    UriPartsError(#[from] hyper::http::uri::InvalidUriParts),

    #[error("TLS connector initialization failed: {0}")]
    TlsConnectorError(String),
}

/// Upgraded connections
pub struct Upgraded {
    /// A socket to Client
    pub client: TokioIo<hyper::upgrade::Upgraded>,
    /// A socket to Server
    pub server: TokioIo<hyper::upgrade::Upgraded>,
}

type DynError = Box<dyn std::error::Error + Send + Sync>;
type PooledBody = BoxBody<Bytes, DynError>;
type Http1Sender = hyper::client::conn::http1::SendRequest<PooledBody>;
type Http2Sender = hyper::client::conn::http2::SendRequest<PooledBody>;
/// Post-handshake upstream TLS stream from either stack (`dyn AsyncRead +
/// AsyncWrite` is illegal as a trait object, so a concrete enum with
/// delegated impls carries both variants through one handshake path).
enum UpstreamTlsStream {
    #[cfg(feature = "native-tls-client")]
    Native(tokio_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "rustls-client")]
    Rustls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl tokio::io::AsyncRead for UpstreamTlsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "native-tls-client")]
            UpstreamTlsStream::Native(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "rustls-client")]
            UpstreamTlsStream::Rustls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for UpstreamTlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            #[cfg(feature = "native-tls-client")]
            UpstreamTlsStream::Native(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "rustls-client")]
            UpstreamTlsStream::Rustls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            #[cfg(feature = "native-tls-client")]
            UpstreamTlsStream::Native(s) => std::pin::Pin::new(s).poll_flush(cx),
            #[cfg(feature = "rustls-client")]
            UpstreamTlsStream::Rustls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            #[cfg(feature = "native-tls-client")]
            UpstreamTlsStream::Native(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "rustls-client")]
            UpstreamTlsStream::Rustls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum ConnectionProtocol {
    Http1,
    Http2,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct ConnectionKey {
    host: String,
    port: u16,
    is_tls: bool,
    protocol: ConnectionProtocol,
}

impl ConnectionKey {
    fn new(host: String, port: u16, is_tls: bool, protocol: ConnectionProtocol) -> Self {
        Self {
            host,
            port,
            is_tls,
            protocol,
        }
    }

    fn from_uri(uri: &Uri, protocol: ConnectionProtocol) -> Result<Self, Error> {
        let (host, port, is_tls) = host_port(uri)?;
        Ok(ConnectionKey::new(host, port, is_tls, protocol))
    }
}

#[derive(Clone, Default)]
struct ConnectionPool {
    http1: Arc<Mutex<HashMap<ConnectionKey, Vec<Http1Sender>>>>,
    http2: Arc<Mutex<HashMap<ConnectionKey, Http2Sender>>>,
}

impl ConnectionPool {
    async fn take_http1(&self, key: &ConnectionKey) -> Option<Http1Sender> {
        let mut guard = self.http1.lock().await;
        let entry = guard.get_mut(key)?;
        while let Some(mut conn) = entry.pop() {
            if sender_alive_http1(&mut conn).await {
                return Some(conn);
            }
        }
        if entry.is_empty() {
            guard.remove(key);
        }
        None
    }

    async fn put_http1(&self, key: ConnectionKey, sender: Http1Sender) {
        let mut guard = self.http1.lock().await;
        guard.entry(key).or_default().push(sender);
    }

    async fn get_http2(&self, key: &ConnectionKey) -> Option<Http2Sender> {
        let mut guard = self.http2.lock().await;
        let mut sender = guard.get(key).cloned()?;

        let alive = sender_alive_http2(&mut sender).await;

        if alive {
            Some(sender)
        } else {
            guard.remove(key);
            None
        }
    }

    async fn insert_http2_if_absent(&self, key: ConnectionKey, sender: Http2Sender) {
        let mut guard = self.http2.lock().await;
        guard.entry(key).or_insert(sender);
    }
}

async fn sender_alive_http1(sender: &mut Http1Sender) -> bool {
    poll_fn(|cx| sender.poll_ready(cx)).await.is_ok()
}

async fn sender_alive_http2(sender: &mut Http2Sender) -> bool {
    poll_fn(|cx| sender.poll_ready(cx)).await.is_ok()
}

#[derive(Clone)]
/// Default HTTP client for this crate
pub struct DefaultClient {
    #[cfg(feature = "native-tls-client")]
    native_tls_connector_no_alpn: tokio_native_tls::TlsConnector,
    #[cfg(feature = "native-tls-client")]
    native_tls_connector_alpn_h2: tokio_native_tls::TlsConnector,

    #[cfg(feature = "rustls-client")]
    rustls_tls_connector_no_alpn: tokio_rustls::TlsConnector,
    #[cfg(feature = "rustls-client")]
    rustls_tls_connector_alpn_h2: tokio_rustls::TlsConnector,

    /// If true, send_request will returns an Upgraded struct when the response is an upgrade
    /// If false, send_request never returns an Upgraded struct and just copy bidirectional when the response is an upgrade
    pub with_upgrades: bool,

    pool: ConnectionPool,
}
impl Default for DefaultClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultClient {
    pub fn new() -> Self {
        Self::try_new().unwrap_or_else(|err| {
            panic!("Failed to create DefaultClient: {err}");
        })
    }

    pub fn try_new() -> Result<Self, Error> {
        #[cfg(feature = "native-tls-client")]
        let (native_tls_connector_no_alpn, native_tls_connector_alpn_h2) = {
            let no_alpn = native_tls::TlsConnector::builder().build().map_err(|e| {
                Error::TlsConnectorError(format!("Failed to build no-ALPN connector: {e}"))
            })?;
            let alpn_h2 = native_tls::TlsConnector::builder()
                .request_alpns(&["h2", "http/1.1"])
                .build()
                .map_err(|e| {
                    Error::TlsConnectorError(format!("Failed to build ALPN-H2 connector: {e}"))
                })?;
            (
                tokio_native_tls::TlsConnector::from(no_alpn),
                tokio_native_tls::TlsConnector::from(alpn_h2),
            )
        };

        #[cfg(feature = "rustls-client")]
        let (rustls_tls_connector_no_alpn, rustls_tls_connector_alpn_h2) = {
            use std::sync::Arc;

            let mut root_cert_store = tokio_rustls::rustls::RootCertStore::empty();
            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let no_alpn = tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store.clone())
                .with_no_client_auth();
            let mut alpn_h2 = tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store.clone())
                .with_no_client_auth();
            alpn_h2.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            (
                tokio_rustls::TlsConnector::from(Arc::new(no_alpn)),
                tokio_rustls::TlsConnector::from(Arc::new(alpn_h2)),
            )
        };

        Ok(Self {
            #[cfg(feature = "native-tls-client")]
            native_tls_connector_no_alpn,
            #[cfg(feature = "native-tls-client")]
            native_tls_connector_alpn_h2,
            #[cfg(feature = "rustls-client")]
            rustls_tls_connector_no_alpn,
            #[cfg(feature = "rustls-client")]
            rustls_tls_connector_alpn_h2,
            with_upgrades: false,
            pool: ConnectionPool::default(),
        })
    }

    /// Enable HTTP upgrades
    /// If you don't enable HTTP upgrades, send_request will just copy bidirectional when the response is an upgrade
    pub fn with_upgrades(mut self) -> Self {
        self.with_upgrades = true;
        self
    }

    #[cfg(feature = "native-tls-client")]
    fn native_tls_connector(&self, http_version: Version) -> &tokio_native_tls::TlsConnector {
        match http_version {
            Version::HTTP_2 => &self.native_tls_connector_alpn_h2,
            _ => &self.native_tls_connector_no_alpn,
        }
    }

    #[cfg(feature = "rustls-client")]
    fn rustls_tls_connector(&self, http_version: Version) -> &tokio_rustls::TlsConnector {
        match http_version {
            Version::HTTP_2 => &self.rustls_tls_connector_alpn_h2,
            _ => &self.rustls_tls_connector_no_alpn,
        }
    }

    /// Send a request and return a response.
    /// If the response is an upgrade (= if status code is 101 Switching Protocols), it will return a response and an Upgrade struct.
    /// Request should have a full URL including scheme.
    pub async fn send_request<B>(
        &self,
        req: Request<B>,
    ) -> Result<
        (
            Response<Incoming>,
            Option<JoinHandle<Result<Upgraded, hyper::Error>>>,
        ),
        Error,
    >
    where
        B: Body<Data = Bytes> + Send + Sync + 'static,
        B::Data: Send + Buf,
        B::Error: Into<DynError>,
    {
        let target_uri = req.uri().clone();
        let mut send_request = if req.version() == Version::HTTP_2 {
            match ConnectionKey::from_uri(&target_uri, ConnectionProtocol::Http2) {
                Ok(pool_key) => {
                    if let Some(conn) = self.pool.get_http2(&pool_key).await {
                        SendRequest::Http2(conn)
                    } else {
                        self.connect(req.uri(), req.version(), Some(pool_key))
                            .await?
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "ConnectionKey::from_uri failed for HTTP/2 ({}): continuing without pool",
                        err
                    );
                    self.connect(req.uri(), req.version(), None).await?
                }
            }
        } else {
            match ConnectionKey::from_uri(&target_uri, ConnectionProtocol::Http1) {
                Ok(pool_key) => {
                    if let Some(conn) = self.pool.take_http1(&pool_key).await {
                        SendRequest::Http1(conn)
                    } else {
                        self.connect(req.uri(), req.version(), Some(pool_key))
                            .await?
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        "ConnectionKey::from_uri failed for HTTP/1 ({}): continuing without pool",
                        err
                    );
                    self.connect(req.uri(), req.version(), None).await?
                }
            }
        };

        let (req_parts, req_body) = req.into_parts();

        let boxed_req = Request::from_parts(req_parts.clone(), to_boxed_body(req_body));

        let res = send_request.send_request(boxed_req).await?;

        if res.status() == StatusCode::SWITCHING_PROTOCOLS {
            let (res_parts, res_body) = res.into_parts();

            let client_request = Request::from_parts(req_parts, Empty::<Bytes>::new());
            let server_response = Response::from_parts(res_parts.clone(), Empty::<Bytes>::new());

            let upgrade = if self.with_upgrades {
                Some(tokio::task::spawn(async move {
                    let client = hyper::upgrade::on(client_request).await?;
                    let server = hyper::upgrade::on(server_response).await?;

                    Ok(Upgraded {
                        client: TokioIo::new(client),
                        server: TokioIo::new(server),
                    })
                }))
            } else {
                tokio::task::spawn(async move {
                    let client = hyper::upgrade::on(client_request).await?;
                    let server = hyper::upgrade::on(server_response).await?;

                    let _ = tokio::io::copy_bidirectional(
                        &mut TokioIo::new(client),
                        &mut TokioIo::new(server),
                    )
                    .await;

                    Ok::<_, hyper::Error>(())
                });
                None
            };

            Ok((Response::from_parts(res_parts, res_body), upgrade))
        } else {
            match send_request {
                SendRequest::Http1(sender) => {
                    if let Ok(pool_key) =
                        ConnectionKey::from_uri(&target_uri, ConnectionProtocol::Http1)
                    {
                        self.pool.put_http1(pool_key, sender).await;
                    } else {
                        // If we couldn't build a pool key, skip pooling.
                    }
                }
                SendRequest::Http2(_) => {
                    // For HTTP/2 the pool retains a shared sender; no action needed.
                }
            }
            Ok((res, None))
        }
    }

    async fn connect(
        &self,
        uri: &Uri,
        http_version: Version,
        key: Option<ConnectionKey>,
    ) -> Result<SendRequest, Error> {
        let (host, port, is_tls) = host_port(uri)?;

        if is_tls {
            let (tls, is_h2) = self.connect_tls(uri, &host, port, http_version).await?;

            if is_h2 {
                let (sender, conn) = client::conn::http2::Builder::new(TokioExecutor::new())
                    .handshake(TokioIo::new(tls))
                    .await
                    .map_err(|err| Error::ConnectError(Box::new(uri.clone()), err))?;

                tokio::spawn(conn);

                if let Some(ref k) = key
                    && matches!(k.protocol, ConnectionProtocol::Http2)
                {
                    self.pool
                        .insert_http2_if_absent(k.clone(), sender.clone())
                        .await;
                }

                Ok(SendRequest::Http2(sender))
            } else {
                let (sender, conn) = client::conn::http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .handshake(TokioIo::new(tls))
                    .await
                    .map_err(|err| Error::ConnectError(Box::new(uri.clone()), err))?;

                tokio::spawn(conn.with_upgrades());

                Ok(SendRequest::Http1(sender))
            }
        } else {
            let tcp = crate::connect_registered_tcp(host.as_str(), port).await?;
            // This is actually needed to some servers
            let _ = tcp.set_nodelay(true);
            let (sender, conn) = client::conn::http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(TokioIo::new(tcp))
                .await
                .map_err(|err| Error::ConnectError(Box::new(uri.clone()), err))?;
            tokio::spawn(conn.with_upgrades());
            Ok(SendRequest::Http1(sender))
        }
    }

    /// Boxed post-handshake TLS stream: both stacks speak AsyncRead+AsyncWrite,
    /// so hyper can drive either through one handshake path.
    /// Upstream TLS stack order: rustls first (immune to schannel
    /// provider/revocation failures), native-tls (schannel: Windows store,
    /// legacy TLS < 1.2) as fallback for hosts rustls cannot do. Each attempt
    /// dials its own TCP connection — a failed handshake must never reuse
    /// the half-dead stream.
    async fn connect_tls(
        &self,
        uri: &Uri,
        host: &str,
        port: u16,
        http_version: Version,
    ) -> Result<(UpstreamTlsStream, bool), Error> {
        #[cfg(all(feature = "rustls-client", feature = "native-tls-client"))]
        {
            return self.connect_tls_dual(uri, host, port, http_version).await;
        }

        #[cfg(all(feature = "rustls-client", not(feature = "native-tls-client")))]
        {
            return self.try_rustls_tls(uri, host, port, http_version).await;
        }

        #[cfg(all(feature = "native-tls-client", not(feature = "rustls-client")))]
        {
            return self.try_native_tls(uri, host, port, http_version).await;
        }
    }

    /// Dual-stack connect: rustls first, native-tls fallback. A combined
    /// error names both failures so production logs stay decisive.
    #[cfg(all(feature = "rustls-client", feature = "native-tls-client"))]
    async fn connect_tls_dual(
        &self,
        uri: &Uri,
        host: &str,
        port: u16,
        http_version: Version,
    ) -> Result<(UpstreamTlsStream, bool), Error> {
        match self.try_rustls_tls(uri, host, port, http_version).await {
            Ok(ok) => Ok(ok),
            Err(rustls_err) => {
                tracing::warn!(
                    "rustls upstream TLS failed for {}:{}, falling back to native-tls: {}",
                    host,
                    port,
                    rustls_err
                );
                self.try_native_tls(uri, host, port, http_version)
                    .await
                    .map_err(|native_err| Error::DualTlsConnectError {
                        uri: Box::new(uri.clone()),
                        rustls: rustls_err.to_string(),
                        native: native_err.to_string(),
                    })
            }
        }
    }

    #[cfg(feature = "rustls-client")]
    async fn try_rustls_tls(
        &self,
        uri: &Uri,
        host: &str,
        port: u16,
        http_version: Version,
    ) -> Result<(UpstreamTlsStream, bool), Error> {
        let tcp = crate::connect_registered_tcp(host, port).await?;
        // This is actually needed to some servers
        let _ = tcp.set_nodelay(true);
        let tls = self
            .rustls_tls_connector(http_version)
            .connect(
                host.to_string()
                    .try_into()
                    .map_err(|_| Error::InvalidHost(Box::new(uri.clone())))?,
                tcp,
            )
            .await
            .map_err(|err| Error::RustlsTlsConnectError(Box::new(uri.clone()), err))?;
        let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        Ok((UpstreamTlsStream::Rustls(tls), is_h2))
    }

    #[cfg(feature = "native-tls-client")]
    async fn try_native_tls(
        &self,
        uri: &Uri,
        host: &str,
        port: u16,
        http_version: Version,
    ) -> Result<(UpstreamTlsStream, bool), Error> {
        let tcp = crate::connect_registered_tcp(host, port).await?;
        // This is actually needed to some servers
        let _ = tcp.set_nodelay(true);
        let tls = self
            .native_tls_connector(http_version)
            .connect(host, tcp)
            .await
            .map_err(|err| Error::NativeTlsConnectError(Box::new(uri.clone()), err))?;
        let is_h2 = matches!(
            tls.get_ref()
                .negotiated_alpn()
                .map(|a| a.map(|b| b == b"h2")),
            Ok(Some(true))
        );
        Ok((UpstreamTlsStream::Native(tls), is_h2))
    }
}

enum SendRequest {
    Http1(Http1Sender),
    Http2(Http2Sender),
}

impl SendRequest {
    async fn send_request(
        &mut self,
        mut req: Request<PooledBody>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        match self {
            SendRequest::Http1(sender) => {
                if req.version() == hyper::Version::HTTP_2
                    && let Some(authority) = req.uri().authority().cloned()
                {
                    match authority.as_str().parse::<header::HeaderValue>() {
                        Ok(host_value) => {
                            req.headers_mut().insert(header::HOST, host_value);
                        }
                        Err(err) => {
                            tracing::warn!(
                                "Failed to parse authority '{}' as HOST header: {}",
                                authority,
                                err
                            );
                        }
                    }
                }
                if let Err(err) = remove_authority(&mut req) {
                    tracing::error!("Failed to remove authority from URI: {}", err);
                    // Continue with the original request if URI modification fails
                }
                sender.send_request(req).await
            }
            SendRequest::Http2(sender) => {
                if req.version() != hyper::Version::HTTP_2 {
                    req.headers_mut().remove(header::HOST);
                }
                sender.send_request(req).await
            }
        }
    }
}

impl SendRequest {
    #[allow(dead_code)]
    // TODO: connection pooling
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), hyper::Error>> {
        match self {
            SendRequest::Http1(sender) => sender.poll_ready(cx),
            SendRequest::Http2(_sender) => Poll::Ready(Ok(())),
        }
    }
}

fn remove_authority<B>(req: &mut Request<B>) -> Result<(), hyper::http::uri::InvalidUriParts> {
    let mut parts = req.uri().clone().into_parts();
    parts.scheme = None;
    parts.authority = None;
    *req.uri_mut() = Uri::from_parts(parts)?;
    Ok(())
}

fn to_boxed_body<B>(body: B) -> PooledBody
where
    B: Body<Data = Bytes> + Send + Sync + 'static,
    B::Data: Send + Buf,
    B::Error: Into<DynError>,
{
    body.map_err(|err| err.into()).boxed()
}

fn host_port(uri: &Uri) -> Result<(String, u16, bool), Error> {
    let host = uri
        .host()
        .ok_or_else(|| Error::InvalidHost(Box::new(uri.clone())))?
        .to_string();
    let is_tls = uri.scheme() == Some(&hyper::http::uri::Scheme::HTTPS);
    let port = uri.port_u16().unwrap_or(if is_tls { 443 } else { 80 });
    Ok((host, port, is_tls))
}

impl DefaultClient {}
