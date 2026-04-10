# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._sync.connection

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
uNetworkBackend | None
utyping.Iterable[SOCKET_OPTION] | None
aNone
a__init__
uHTTPConnection.__init__
D arequest
return
aRequest
aResponse
uHTTPConnection.handle_request
D arequest
return
aRequest
aNetworkStream
uHTTPConnection._connect
D aorigin
return
aOrigin
bool
uHTTPConnection.can_handle_request
D areturn
aNone
uHTTPConnection.close
D areturn
bool
uHTTPConnection.is_available
uHTTPConnection.has_expired
uHTTPConnection.is_idle
uHTTPConnection.is_closed
D areturn
str
uHTTPConnection.info
a__repr__
uHTTPConnection.__repr__
D areturn
aHTTPConnection
uHTTPConnection.__enter__
D aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
aNone
uHTTPConnection.__exit__
a__orig_bases__
uhttpcore\_sync\connection.py
u<module httpcore._sync.connection>
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
aHTTP2Connection
exc
a__spec__
.httpcore._sync.connection_pool
K
request
connection
aEvent
a_connection_acquired
set
wait
T atimeout
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
aSyncBackend
a_network_backend
a_socket_options
a_connections
a_requests
aThreadLock
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
T aSocks5Connection
aSocks5Connection
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
T aForwardHTTPConnection
aForwardHTTPConnection
headers
ssl_context
T aproxy_origin
proxy_headers
proxy_ssl_context
remote_origin
keepalive_expiry
network_backend
T aTunnelHTTPConnection
aTunnelHTTPConnection
T	aproxy_origin
proxy_headers
proxy_ssl_context
remote_origin
ssl_context
keepalive_expiry
http1
http2
network_backend
aHTTPConnection
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
<HTTPConnection ['https://example.com:443', HTTP/1.1, ACTIVE, Request Count: 6]>,
<HTTPConnection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 9]> ,
<HTTPConnection ['http://example.com:80', HTTP/1.1, IDLE, Request Count: 1]>,
]
```
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
timeout
T apool
na__enter__
a__exit__
aPoolRequest
append
T nnnaself
a_assign_requests_to_connections
a_close_connections
closing
pool_request
wait_for_connection
handle_request
aConnectionNotAvailable
clear_connection
remove
response
stream
aIterable
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

Send an HTTP request, and return an HTTP response.
This is the core implementation that is called into by `.request()` or `.stream()`.
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
aShieldCancellation
close
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
a__iter__
uPoolByteStream.__iter__
a__doc__
a__file__
has_location
a__cached__
annotations
ssl
sys
types
typing
u_backends.sync
T aSyncBackend
l u_backends.base
T aSOCKET_OPTION
aNetworkBackend
aSOCKET_OPTION
aNetworkBackend
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
T aEvent
aShieldCancellation
aThreadLock
T aHTTPConnection
interfaces
T aConnectionInterface
aRequestInterface
aConnectionInterface
aRequestInterface
