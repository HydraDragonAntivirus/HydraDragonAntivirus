# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._sync.http_proxy


A connection pool that sends requests via an HTTP proxy.
a__qualname__
T nnnnl
nntFl
nnnnD aproxy_url
proxy_auth
proxy_headers
ssl_context
proxy_ssl_context
max_connections
max_keepalive_connections
keepalive_expiry
http1
http2
retries
local_address
uds
network_backend
socket_options
return
uURL | bytes | str
utuple[bytes | str, bytes | str] | None
uHeadersAsMapping | HeadersAsSequence | None
ussl.SSLContext | None
ussl.SSLContext | None
uint | None
uint | None
ufloat | None
bool
paint
ustr | None
ustr | None
uNetworkBackend | None
utyping.Iterable[SOCKET_OPTION] | None
aNone
uHTTPProxy.__init__
D aorigin
return
aOrigin
aConnectionInterface
create_connection
uHTTPProxy.create_connection
a__orig_bases__
T nnnnnD aproxy_origin
remote_origin
proxy_headers
keepalive_expiry
network_backend
socket_options
proxy_ssl_context
return
aOrigin
puHeadersAsMapping | HeadersAsSequence | None
ufloat | None
uNetworkBackend | None
utyping.Iterable[SOCKET_OPTION] | None
ussl.SSLContext | None
aNone
uForwardHTTPConnection.__init__
D arequest
return
aRequest
aResponse
uForwardHTTPConnection.handle_request
D aorigin
return
aOrigin
bool
can_handle_request
uForwardHTTPConnection.can_handle_request
D areturn
aNone
uForwardHTTPConnection.close
D areturn
str
uForwardHTTPConnection.info
D areturn
bool
uForwardHTTPConnection.is_available
uForwardHTTPConnection.has_expired
uForwardHTTPConnection.is_idle
uForwardHTTPConnection.is_closed
a__repr__
uForwardHTTPConnection.__repr__
T nnnntFnnD aproxy_origin
remote_origin
ssl_context
proxy_ssl_context
proxy_headers
keepalive_expiry
http1
http2
network_backend
socket_options
return
aOrigin
pussl.SSLContext | None
ussl.SSLContext | None
utyping.Sequence[tuple[bytes, bytes]] | None
ufloat | None
bool
puNetworkBackend | None
utyping.Iterable[SOCKET_OPTION] | None
aNone
uTunnelHTTPConnection.__init__
uTunnelHTTPConnection.handle_request
uTunnelHTTPConnection.can_handle_request
uTunnelHTTPConnection.close
uTunnelHTTPConnection.info
uTunnelHTTPConnection.is_available
uTunnelHTTPConnection.has_expired
uTunnelHTTPConnection.is_idle
uTunnelHTTPConnection.is_closed
uTunnelHTTPConnection.__repr__
uhttpcore\_sync\http_proxy.py
T a.0
key
value
u<module httpcore._sync.http_proxy>
T a__class__
T aself
proxy_origin
remote_origin
proxy_headers
keepalive_expiry
network_backend
socket_options
proxy_ssl_context
T aself
proxy_url
proxy_auth
proxy_headers
ssl_context
proxy_ssl_context
max_connections
max_keepalive_connections
keepalive_expiry
http1
http2
retries
local_address
uds
network_backend
socket_options
username
password
userpass
authorization
a__class__
T aself
proxy_origin
remote_origin
ssl_context
proxy_ssl_context
proxy_headers
keepalive_expiry
http1
http2
network_backend
socket_options
T aself
T aself
origin
T aself
request
headers
url
proxy_request
T aself
request
timeouts
timeout
target
connect_url
connect_headers
connect_request
connect_response
reason_bytes
reason_str
msg
stream
ssl_context
alpn_protocols
kwargs
trace
ssl_object
http2_negotiated
aHTTP2Connection
T adefault_headers
override_headers
has_override
a__spec__
.httpcore._sync.interfaces
V
enforce_bytes
D aname
method
enforce_url
D aname
url
enforce_headers
D aname
headers
include_request_headers
T aurl
content
aRequest
T amethod
url
headers
content
extensions
handle_request
read
close
method
url
headers
content
extensions
self
stream
uRequestInterface.stream

Return `True` if the connection is currently able to accept an
outgoing request.
An HTTP/1.1 connection will only be available if it is currently idle.
An HTTP/2 connection will be available so long as the stream ID space is
not yet exhausted, and the connection is not in an error state.
While the connection is being established we may not yet know if it is going
to result in an HTTP/1.1 or HTTP/2 connection. The connection should be
treated as being available, but might ultimately raise `NewConnectionRequired`
required exceptions if multiple requests are attempted over a connection
that ends up being established as HTTP/1.1.

Return `True` if the connection is in a state where it should be closed.
This either means that the connection is idle and it has passed the
expiry time on its keep-alive, or that server has sent an EOF.

Return `True` if the connection is currently idle.

Return `True` if the connection has been closed.
Used when a response is closed to determine if the connection may be
returned to the connection pool or not.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
contextlib
typing
a_models
T
aURL
aExtensions
aHeaderTypes
aOrigin
aRequest
aResponse
enforce_bytes
enforce_headers
enforce_url
include_request_headers
l aURL
aExtensions
aHeaderTypes
aOrigin
aResponse
