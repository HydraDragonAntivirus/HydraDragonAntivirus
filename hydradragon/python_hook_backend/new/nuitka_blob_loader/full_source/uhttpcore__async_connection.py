# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._async.connection

a__qualname__
T	nntFl
nnnnD aorigin
ssl_context
keepalive_expiry
http1
http2
retries
local_address
uds
network_backend
socket_options
return
aOrigin
ussl.SSLContext | None
ufloat | None
bool
paint
ustr | None
ustr | None
uAsyncNetworkBackend | None
utyping.Iterable[SOCKET_OPTION] | None
aNone
a__init__
uAsyncHTTPConnection.__init__
D arequest
return
aRequest
aResponse
D arequest
return
aRequest
aAsyncNetworkStream
D aorigin
return
aOrigin
bool
uAsyncHTTPConnection.can_handle_request
D areturn
aNone
D areturn
bool
uAsyncHTTPConnection.is_available
uAsyncHTTPConnection.has_expired
uAsyncHTTPConnection.is_idle
uAsyncHTTPConnection.is_closed
D areturn
str
uAsyncHTTPConnection.info
a__repr__
uAsyncHTTPConnection.__repr__
D areturn
aAsyncHTTPConnection
D aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
aNone
a__orig_bases__
uhttpcore\_async\connection.py
u<module httpcore._async.connection>
T a__class__
T aself
T aself
exc_type
exc_value
traceback
T aself
origin
ssl_context
keepalive_expiry
http1
http2
retries
local_address
uds
network_backend
socket_options
Taself
request
timeouts
sni_hostname
timeout
retries_left
delays
kwargs
trace
stream
ssl_context
alpn_protocols
delay
T aself
origin
T afactor
wnT aself
request
stream
ssl_object
http2_negotiated
aAsyncHTTP2Connection
exc
a__spec__
.httpcore._async.connection_pool
request
connection
aAsyncEvent
a_connection_acquired
set
self
wait
timeout
T atimeout
wait_for_connection
uAsyncPoolRequest.wait_for_connection
a_ssl_context
a_proxy
g            a_max_connections
a_max_keepalive_connections
min
a_keepalive_expiry
a_http1
a_http2
a_retries
a_local_address
a_uds
aAutoBackend
a_network_backend
a_socket_options
a_connections
a_requests
aAsyncThreadLock
a_optional_thread_lock

A connection pool for making HTTP requests.
Parameters:
ssl_context: An SSL context to use for verifying connections.
If not specified, the default `httpcore.default_ssl_context()`
will be used.
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
retries: The maximum number of retries when trying to establish a
connection.
local_address: Local address to connect from. Can also be used to connect
using a particular address family. Using `local_address="0.0.0.0"`
will connect using an `AF_INET` address (IPv4), while using
`local_address="::"` will connect using an `AF_INET6` address (IPv6).
uds: Path to a Unix Domain Socket to use instead of TCP sockets.
network_backend: A backend instance to use for handling network I/O.
socket_options: Socket options that have to be included
in the TCP socket when the connection was established.
url
scheme
T csocks5
csocks5h
socks_proxy
T aAsyncSocks5Connection
aAsyncSocks5Connection
origin
auth
T aproxy_origin
proxy_auth
remote_origin
ssl_context
keepalive_expiry
http1
http2
network_backend
chttp
http_proxy
T aAsyncForwardHTTPConnection
aAsyncForwardHTTPConnection
headers
ssl_context
T aproxy_origin
proxy_headers
proxy_ssl_context
remote_origin
keepalive_expiry
network_backend
T aAsyncTunnelHTTPConnection
aAsyncTunnelHTTPConnection
T	aproxy_origin
proxy_headers
proxy_ssl_context
remote_origin
ssl_context
keepalive_expiry
http1
http2
network_backend
aAsyncHTTPConnection
T
origin
ssl_context
keepalive_expiry
http1
http2
retries
local_address
uds
network_backend
socket_options

Return a list of the connections currently in the pool.
For example:
```python
>>> pool.connections
[
<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, ACTIVE, Request Count: 6]>,
<AsyncHTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 9]> ,
<AsyncHTTPConnection ['http://example.com:80', HTTP/1.1, IDLE, Request Count: 1]>,
]
```

Send an HTTP request, and return an HTTP response.
This is the core implementation that is called into by `.request()` or `.stream()`.
decode

aUnsupportedProtocol
T uRequest URL is missing an 'http://' or 'https://' protocol.
T ahttp
https
ws
wss
uRequest URL has an unsupported protocol '
u://'.
extensions
get
T apool
na__enter__
a__exit__
aAsyncPoolRequest
append
T nnna_assign_requests_to_connections
a_close_connections
closing
pool_request
handle_async_request
aConnectionNotAvailable
clear_connection
remove
response
stream
aAsyncIterable
aResponse
status
aPoolByteStream
T astream
pool_request
pool
T astatus
headers
content
extensions
uAsyncConnectionPool.handle_async_request
is_closed
has_expired
closing_connections
is_idle
is_queued
can_handle_request
is_available
assign_to_connection
create_connection

Manage the state of the connection pool, assigning incoming
requests to connections as available.
Called whenever a new request is added or removed from the pool.
Any closing connections are returned, allowing the I/O for closing
those connections to be handled seperately.
aAsyncShieldCancellation
aclose
uAsyncConnectionPool._close_connections
uAsyncConnectionPool.aclose
a__aenter__
uAsyncConnectionPool.__aenter__
a__aexit__
uAsyncConnectionPool.__aexit__
a__name__
count
T FT tuRequests:
num_active_requests
u active,
num_queued_requests
u queued
uConnections:
num_active_connections
num_idle_connections
u idle
w<u [
u |
u]>
a_stream
a_pool_request
a_pool
a_closed
a__aiter__
uPoolByteStream.__aiter__
uPoolByteStream.aclose
a__doc__
a__file__
has_location
a__cached__
annotations
ssl
sys
types
typing
u_backends.auto
T aAutoBackend
l u_backends.base
T aSOCKET_OPTION
aAsyncNetworkBackend
aSOCKET_OPTION
aAsyncNetworkBackend
a_exceptions
T aConnectionNotAvailable
aUnsupportedProtocol
a_models
T aOrigin
aProxy
aRequest
aResponse
aOrigin
aProxy
aRequest
a_synchronization
T aAsyncEvent
aAsyncShieldCancellation
aAsyncThreadLock
T aAsyncHTTPConnection
interfaces
T aAsyncConnectionInterface
aAsyncRequestInterface
aAsyncConnectionInterface
aAsyncRequestInterface
