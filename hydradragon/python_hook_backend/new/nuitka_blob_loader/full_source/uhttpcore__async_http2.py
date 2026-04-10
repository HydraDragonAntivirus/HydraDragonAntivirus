# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._async.http2

a__qualname__
l a__orig_bases__
aAsyncHTTP2Connection
config
aH2Configuration
T FT avalidate_inbound_headers
T nD aorigin
stream
keepalive_expiry
aOrigin
aAsyncNetworkStream
ufloat | None
a__init__
uAsyncHTTP2Connection.__init__
D arequest
return
aRequest
aResponse
D arequest
return
aRequest
aNone
D arequest
stream_id
return
aRequest
int
aNone
D arequest
stream_id
data
return
aRequest
int
bytes
aNone
D arequest
stream_id
return
aRequest
int
utuple[int, list[tuple[bytes, bytes]]]
D arequest
stream_id
return
aRequest
int
utyping.AsyncIterator[bytes]
D arequest
stream_id
return
aRequest
int
uh2.events.ResponseReceived | h2.events.DataReceived | h2.events.StreamEnded
D arequest
stream_id
return
aRequest
uint | None
aNone
D aevent
return
uh2.events.Event
aNone
D astream_id
return
int
aNone
D areturn
aNone
D arequest
return
aRequest
ulist[h2.events.Event]
D arequest
stream_id
return
aRequest
int
pD aorigin
return
aOrigin
bool
uAsyncHTTP2Connection.can_handle_request
D areturn
bool
is_available
uAsyncHTTP2Connection.is_available
has_expired
uAsyncHTTP2Connection.has_expired
is_idle
uAsyncHTTP2Connection.is_idle
is_closed
uAsyncHTTP2Connection.is_closed
D areturn
str
info
uAsyncHTTP2Connection.info
a__repr__
uAsyncHTTP2Connection.__repr__
D areturn
aAsyncHTTP2Connection
D aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
aNone
D aconnection
request
stream_id
return
aAsyncHTTP2Connection
aRequest
int
aNone
uHTTP2ConnectionByteStream.__init__
D areturn
utyping.AsyncIterator[bytes]
uhttpcore\_async\http2.py
T a.0
wkwvu<module httpcore._async.http2>
T a__class__
T aself
T aself
exc_type
exc_value
traceback
T aself
kwargs
chunk
exc
T aself
origin
stream
keepalive_expiry
T aself
connection
request
stream_id
T aself
class_name
origin
T aself
request
events
timeouts
timeout
data
exc
T aself
request
stream_id
last_stream_id
events
event
trace
T aself
event
max_concurrent_streams
new_max_streams
T aself
request
stream_id
event
status_code
headers
wkwvT aself
request
stream_id
event
amount
T aself
request
stream_id
event
T aself
stream_id
now
T aself
request
T aself
request
stream_id
T aself
request
stream_id
data
T aself
request
stream_id
end_stream
authority
headers
T aself
request
stream_id
data
max_flow
chunk_size
chunk
T aself
request
stream_id
local_flow
max_frame_size
flow
T aself
request
timeouts
timeout
data_to_send
exc
T aself
kwargs
T aself
origin
T
self
request
kwargs
exc
local_settings_max_streams
w_astream_id
trace
status
headers
T arequest
T aself
now
a__spec__
.httpcore._async.http_proxy
}!
lower

Append default_headers and override_headers, de-duplicating if a key exists
in both cases.
u<genexpr>
umerge_headers.<locals>.<genexpr>
a__class__
a__init__
T assl_context
max_connections
max_keepalive_connections
keepalive_expiry
http1
http2
network_backend
retries
local_address
uds
socket_options
enforce_url
D aname
proxy_url
a_proxy_url
scheme
chttp
uThe `proxy_ssl_context` argument is not allowed for the http scheme
a_ssl_context
a_proxy_ssl_context
enforce_headers
D aname
proxy_headers
a_proxy_headers
enforce_bytes
D aname
proxy_auth
d:cBasic
base64
b64encode
cProxy-Authorization

A connection pool for making HTTP requests.
Parameters:
proxy_url: The URL to use when connecting to the proxy server.
For example `"http://127.0.0.1:8080/"`.
proxy_auth: Any proxy authentication as a two-tuple of
(username, password). May be either bytes or ascii-only str.
proxy_headers: Any HTTP headers to use for the proxy requests.
For example `{"Proxy-Authorization": "Basic <username>:<password>"}`.
ssl_context: An SSL context to use for verifying connections.
If not specified, the default `httpcore.default_ssl_context()`
will be used.
proxy_ssl_context: The same as `ssl_context`, but for a proxy server rather than a remote origin.
max_connections: The maximum number of concurrent HTTP connections that
the pool should allow. Any attempt to send a request on a pool that
would exceed this amount will block until a connection is available.
max_keepalive_connections: The maximum number of idle HTTP connections
that will be maintained in the pool.
keepalive_expiry: The duration in seconds that an idle HTTP connection
may be maintained for before being expired from the pool.
http1: A boolean indicating if HTTP/1.1 requests should be supported
by the connection pool. Defaults to True.
http2: A boolean indicating if HTTP/2 requests should be supported by
the connection pool. Defaults to False.
retries: The maximum number of retries when trying to establish
a connection.
local_address: Local address to connect from. Can also be used to
connect using a particular address family. Using
`local_address="0.0.0.0"` will connect using an `AF_INET` address
(IPv4), while using `local_address="::"` will connect using an
`AF_INET6` address (IPv6).
uds: Path to a Unix Domain Socket to use instead of TCP sockets.
network_backend: A backend instance to use for handling network I/O.
aAsyncForwardHTTPConnection
origin
a_keepalive_expiry
a_network_backend
T aproxy_origin
proxy_headers
remote_origin
keepalive_expiry
network_backend
proxy_ssl_context
aAsyncTunnelHTTPConnection
a_http1
a_http2
T	aproxy_origin
proxy_headers
remote_origin
ssl_context
proxy_ssl_context
keepalive_expiry
http1
http2
network_backend
aAsyncHTTPConnection
T aorigin
keepalive_expiry
network_backend
socket_options
ssl_context
a_connection
a_proxy_origin
a_remote_origin
merge_headers
self
request
headers
aURL
host
port
url
T ascheme
host
port
target
aRequest
method
stream
extensions
T amethod
url
headers
content
extensions
handle_async_request
uAsyncForwardHTTPConnection.handle_async_request
aclose
uAsyncForwardHTTPConnection.aclose
info
is_available
has_expired
is_idle
is_closed
w<a__name__

u [
u]>
aAsyncLock
a_connect_lock
a_connected
get
timeout
T aconnect
na__aenter__
a__aexit__
c%b:%d
cHost
T cAccept
c*/*
cCONNECT
T amethod
url
headers
extensions
status
l  l  T areason_phrase
c
decode
T aascii
ignore
T aerrors
u%d %s
aProxyError
network_stream
default_ssl_context
uhttp/1.1
h2
set_alpn_protocols
ssl_context
server_hostname
T aascii
aTrace
start_tls
logger
return_value
T nnnaget_extra_info
T assl_object
selected_alpn_protocol
http2
T aAsyncHTTP2Connection
aAsyncHTTP2Connection
T aorigin
stream
keepalive_expiry
aAsyncHTTP11Connection
uAsyncTunnelHTTPConnection.handle_async_request
uAsyncTunnelHTTPConnection.aclose
a__doc__
a__file__
has_location
a__cached__
annotations
logging
ssl
typing
u_backends.base
T aSOCKET_OPTION
aAsyncNetworkBackend
l aSOCKET_OPTION
aAsyncNetworkBackend
a_exceptions
T aProxyError
a_models
T aURL
aOrigin
aRequest
aResponse
enforce_bytes
enforce_headers
enforce_url
aOrigin
aResponse
a_ssl
T adefault_ssl_context
a_synchronization
T aAsyncLock
a_trace
T aTrace
connection
T aAsyncHTTPConnection
connection_pool
T aAsyncConnectionPool
aAsyncConnectionPool
http11
T aAsyncHTTP11Connection
interfaces
T aAsyncConnectionInterface
aAsyncConnectionInterface
aUnion
T Obytes
Ostr
aByteOrStr
aSequence
aTuple
aHeadersAsSequence
aMapping
aHeadersAsMapping
getLogger
T uhttpcore.proxy
T nnD adefault_headers
override_headers
return
utyping.Sequence[tuple[bytes, bytes]] | None
utyping.Sequence[tuple[bytes, bytes]] | None
ulist[tuple[bytes, bytes]]
a__prepare__
aAsyncHTTPProxy
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
