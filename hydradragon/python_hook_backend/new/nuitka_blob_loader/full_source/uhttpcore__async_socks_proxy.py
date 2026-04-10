# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._async.socks_proxy


A connection pool that sends requests via an HTTP proxy.
a__qualname__
T	nnl
nntFl
nD aproxy_url
proxy_auth
ssl_context
max_connections
max_keepalive_connections
keepalive_expiry
http1
http2
retries
network_backend
return
uURL | bytes | str
utuple[bytes | str, bytes | str] | None
ussl.SSLContext | None
uint | None
uint | None
ufloat | None
bool
paint
uAsyncNetworkBackend | None
aNone
uAsyncSOCKSProxy.__init__
D aorigin
return
aOrigin
aAsyncConnectionInterface
create_connection
uAsyncSOCKSProxy.create_connection
a__orig_bases__
T nnntFnD	aproxy_origin
remote_origin
proxy_auth
ssl_context
keepalive_expiry
http1
http2
network_backend
return
aOrigin
putuple[bytes, bytes] | None
ussl.SSLContext | None
ufloat | None
bool
puAsyncNetworkBackend | None
aNone
uAsyncSocks5Connection.__init__
D arequest
return
aRequest
aResponse
D aorigin
return
aOrigin
bool
can_handle_request
uAsyncSocks5Connection.can_handle_request
D areturn
aNone
D areturn
bool
uAsyncSocks5Connection.is_available
uAsyncSocks5Connection.has_expired
uAsyncSocks5Connection.is_idle
uAsyncSocks5Connection.is_closed
D areturn
str
uAsyncSocks5Connection.info
a__repr__
uAsyncSocks5Connection.__repr__
uhttpcore\_async\socks_proxy.py
u<module httpcore._async.socks_proxy>
T a__class__
T aself
proxy_url
proxy_auth
ssl_context
max_connections
max_keepalive_connections
keepalive_expiry
http1
http2
retries
network_backend
username
password
username_bytes
password_bytes
a__class__
T	aself
proxy_origin
remote_origin
proxy_auth
ssl_context
keepalive_expiry
http1
http2
network_backend
T aself
T astream
host
port
auth
conn
auth_method
outgoing_bytes
incoming_bytes
response
requested
responded
username
password
reply_code
T aself
origin
T aself
request
timeouts
sni_hostname
timeout
kwargs
trace
stream
ssl_context
alpn_protocols
ssl_object
http2_negotiated
aAsyncHTTP2Connection
exc
a__spec__
.httpcore._backends.anyio
J
a_stream
aReadTimeout
anyio
aBrokenResourceError
aReadError
aClosedResourceError
aEndOfStream
map_exceptions
a__enter__
a__exit__
fail_after
timeout
self
receive
max_bytes
T amax_bytes
c
T nnnaread
uAnyIOStream.read
buffer
aWriteTimeout
aWriteError
send
T aitem
write
uAnyIOStream.write
aclose
uAnyIOStream.aclose
aConnectTimeout
aConnectError
ssl
aSSLError
streams
tls
aTLSStream
wrap
ssl_context
server_hostname
T assl_context
hostname
standard_compatible
server_side
aAnyIOStream
ssl_stream
start_tls
uAnyIOStream.start_tls
ssl_object
extra
aTLSAttribute
client_addr
abc
aSocketAttribute
local_address
server_addr
remote_address
socket
raw_socket
is_readable
is_socket_readable
socket_options
connect_tcp
host
port
T aremote_host
remote_port
local_host
stream
a_raw_socket
setsockopt
uAnyIOBackend.connect_tcp
connect_unix
path
connect_unix_socket
uAnyIOBackend.connect_unix_socket
sleep
seconds
uAnyIOBackend.sleep
a__doc__
a__file__
origin
has_location
a__cached__
annotations
typing
a_exceptions
T aConnectError
aConnectTimeout
aReadError
aReadTimeout
aWriteError
aWriteTimeout
map_exceptions
l a_utils
T ais_socket_readable
base
T aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
