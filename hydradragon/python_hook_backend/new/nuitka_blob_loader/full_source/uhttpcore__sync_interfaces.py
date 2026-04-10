# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._sync.interfaces

aRequestInterface
a__qualname__
D aheaders
content
extensions
nnnD amethod
url
headers
content
extensions
return
ubytes | str
uURL | bytes | str
aHeaderTypes
ubytes | typing.Iterator[bytes] | None
uExtensions | None
aResponse
request
uRequestInterface.request
contextmanager
D amethod
url
headers
content
extensions
return
ubytes | str
uURL | bytes | str
aHeaderTypes
ubytes | typing.Iterator[bytes] | None
uExtensions | None
utyping.Iterator[Response]
D arequest
return
aRequest
aResponse
uRequestInterface.handle_request
a__prepare__
aConnectionInterface
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
D areturn
aNone
uConnectionInterface.close
D areturn
str
info
uConnectionInterface.info
D aorigin
return
aOrigin
bool
can_handle_request
uConnectionInterface.can_handle_request
D areturn
bool
is_available
uConnectionInterface.is_available
has_expired
uConnectionInterface.has_expired
is_idle
uConnectionInterface.is_idle
is_closed
uConnectionInterface.is_closed
a__orig_bases__
uhttpcore\_sync\interfaces.py
u<module httpcore._sync.interfaces>
T a__class__
T aself
origin
T aself
T aself
request
T aself
method
url
headers
content
extensions
request
response

a__spec__
.httpcore._sync.socks_proxy
socksio
socks5
aSOCKS5Connection
aSOCKS5AuthMethod
aNO_AUTH_REQUIRED
aUSERNAME_PASSWORD
send
aSOCKS5AuthMethodsRequest
data_to_send
write
read
T l  T amax_bytes
receive_data
aSOCKS5AuthReply
method
aAUTH_METHODS
get
aUNKNOWN
aProxyError
uRequested

u from proxy server, but got
w.aSOCKS5UsernamePasswordRequest
aSOCKS5UsernamePasswordReply
success
T uInvalid username/password
aSOCKS5CommandRequest
from_address
aSOCKS5Command
aCONNECT
aSOCKS5Reply
reply_code
aSOCKS5ReplyCode
aSUCCEEDED
aREPLY_CODES
aUNKOWN
uProxy Server could not connect:
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
a_ssl_context
enforce_url
D aname
proxy_url
a_proxy_url
enforce_bytes
D aname
proxy_auth
a_proxy_auth

A connection pool for making HTTP requests.
Parameters:
proxy_url: The URL to use when connecting to the proxy server.
For example `"http://127.0.0.1:8080/"`.
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
retries: The maximum number of retries when trying to establish
a connection.
local_address: Local address to connect from. Can also be used to
connect using a particular address family. Using
`local_address="0.0.0.0"` will connect using an `AF_INET` address
(IPv4), while using `local_address="::"` will connect using an
`AF_INET6` address (IPv6).
uds: Path to a Unix Domain Socket to use instead of TCP sockets.
network_backend: A backend instance to use for handling network I/O.
aSocks5Connection
origin
a_keepalive_expiry
a_http1
a_http2
a_network_backend
T aproxy_origin
remote_origin
proxy_auth
ssl_context
keepalive_expiry
http1
http2
network_backend
a_proxy_origin
a_remote_origin
aSyncBackend
aLock
a_connect_lock
a_connection
a_connect_failed
extensions
timeout
T asni_hostname
nT aconnect
na__enter__
a__exit__
host
decode
T aascii
port
aTrace
connect_tcp
logger
return_value
T nnnastream
auth
setup_socks5_connection
a_init_socks5_connection
scheme
chttps
default_ssl_context
uhttp/1.1
h2
set_alpn_protocols
ssl_context
server_hostname
start_tls
get_extra_info
T assl_object
selected_alpn_protocol
http2
T aHTTP2Connection
aHTTP2Connection
T aorigin
stream
keepalive_expiry
aHTTP11Connection
is_available
aConnectionNotAvailable
handle_request
close
has_expired
is_idle
is_closed
uCONNECTION FAILED
aCONNECTING
info
w<a__name__
u [
u]>
a__doc__
a__file__
has_location
a__cached__
annotations
logging
ssl
u_backends.sync
T aSyncBackend
l u_backends.base
T aNetworkBackend
aNetworkStream
aNetworkBackend
aNetworkStream
a_exceptions
T aConnectionNotAvailable
aProxyError
a_models
T aURL
aOrigin
aRequest
aResponse
enforce_bytes
enforce_url
aURL
aOrigin
aRequest
aResponse
a_ssl
T adefault_ssl_context
a_synchronization
T aLock
a_trace
T aTrace
connection_pool
T aConnectionPool
aConnectionPool
http11
T aHTTP11Connection
interfaces
T aConnectionInterface
aConnectionInterface
getLogger
T uhttpcore.socks
D d
d d d uNO AUTHENTICATION REQUIRED
aGSSAPI
uUSERNAME/PASSWORD
uNO ACCEPTABLE METHODS
D	d
d d d d d d d d aSucceeded
uGeneral SOCKS server failure
uConnection not allowed by ruleset
uNetwork unreachable
uHost unreachable
uConnection refused
uTTL expired
uCommand not supported
uAddress type not supported
D aauth
nD astream
host
port
auth
return
aNetworkStream
bytes
int
utuple[bytes, bytes] | None
aNone
a__prepare__
aSOCKSProxy
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
