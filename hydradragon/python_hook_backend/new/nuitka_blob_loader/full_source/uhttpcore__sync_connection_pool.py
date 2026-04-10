# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._sync.connection_pool

a__qualname__
D arequest
return
aRequest
aNone
a__init__
uPoolRequest.__init__
D aconnection
return
uConnectionInterface | None
aNone
uPoolRequest.assign_to_connection
D areturn
aNone
uPoolRequest.clear_connection
T nD atimeout
return
ufloat | None
aConnectionInterface
uPoolRequest.wait_for_connection
D areturn
bool
uPoolRequest.is_queued
a__prepare__
aConnectionPool
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>

A connection pool for making HTTP requests.
T nnl
nntFl
nnnnDassl_context
proxy
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
ussl.SSLContext | None
uProxy | None
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
uConnectionPool.__init__
D aorigin
return
aOrigin
aConnectionInterface
uConnectionPool.create_connection
property
D areturn
ulist[ConnectionInterface]
connections
uConnectionPool.connections
D arequest
return
aRequest
aResponse
uConnectionPool.handle_request
uConnectionPool._assign_requests_to_connections
D aclosing
return
ulist[ConnectionInterface]
aNone
uConnectionPool._close_connections
uConnectionPool.close
D areturn
aConnectionPool
uConnectionPool.__enter__
D aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
aNone
uConnectionPool.__exit__
D areturn
str
a__repr__
uConnectionPool.__repr__
a__orig_bases__
D astream
pool_request
pool
return
utyping.Iterable[bytes]
aPoolRequest
aConnectionPool
aNone
uPoolByteStream.__init__
D areturn
utyping.Iterator[bytes]
uPoolByteStream.close
uhttpcore\_sync\connection_pool.py
u<module httpcore._sync.connection_pool>
T a__class__
T aself
T aself
exc_type
exc_value
traceback
Taself
ssl_context
proxy
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
T aself
stream
pool_request
pool
T aself
request
T aself
part
exc
T
self
class_name
request_is_queued
connection_is_idle
num_active_requests
num_queued_requests
num_active_connections
num_idle_connections
requests_info
connection_info
T aself
closing_connections
connection
queued_requests
pool_request
origin
available_connections
idle_connections
T aself
closing
connection
T aself
connection
T aself
closing_connections
T aself
closing
T aself
origin
aSocks5Connection
aForwardHTTPConnection
aTunnelHTTPConnection
T
self
request
scheme
timeouts
timeout
pool_request
closing
connection
response
exc
T aself
timeout
a__spec__
.httpcore._sync
9
4
uAttempted to use http2 support, but the `h2` package is not installed. Use 'pip install httpcore[http2]'.
uAttempted to use SOCKS support, but the `socksio` package is not installed. Use 'pip install httpcore[socks]'.
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_httpcore
u\not_existing
a_sync
T aNUITKA_PACKAGE_httpcore__sync
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
connection
T aHTTPConnection
aHTTPConnection
connection_pool
T aConnectionPool
aConnectionPool
http11
T aHTTP11Connection
aHTTP11Connection
http_proxy
T aHTTPProxy
aHTTPProxy
interfaces
T aConnectionInterface
aConnectionInterface
http2
T aHTTP2Connection
aHTTP2Connection
