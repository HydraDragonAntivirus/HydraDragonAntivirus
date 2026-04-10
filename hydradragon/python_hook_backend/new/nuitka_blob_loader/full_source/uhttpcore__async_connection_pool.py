# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._async.connection_pool

a__qualname__
D arequest
return
aRequest
aNone
a__init__
uAsyncPoolRequest.__init__
D aconnection
return
uAsyncConnectionInterface | None
aNone
uAsyncPoolRequest.assign_to_connection
D areturn
aNone
uAsyncPoolRequest.clear_connection
T nD atimeout
return
ufloat | None
aAsyncConnectionInterface
D areturn
bool
uAsyncPoolRequest.is_queued
a__prepare__
aAsyncConnectionPool
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
uAsyncNetworkBackend | None
utyping.Iterable[SOCKET_OPTION] | None
aNone
uAsyncConnectionPool.__init__
D aorigin
return
aOrigin
aAsyncConnectionInterface
uAsyncConnectionPool.create_connection
property
D areturn
ulist[AsyncConnectionInterface]
connections
uAsyncConnectionPool.connections
D arequest
return
aRequest
aResponse
uAsyncConnectionPool._assign_requests_to_connections
D aclosing
return
ulist[AsyncConnectionInterface]
aNone
D areturn
aAsyncConnectionPool
D aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
aNone
D areturn
str
a__repr__
uAsyncConnectionPool.__repr__
a__orig_bases__
D astream
pool_request
pool
return
utyping.AsyncIterable[bytes]
aAsyncPoolRequest
aAsyncConnectionPool
aNone
uPoolByteStream.__init__
D areturn
utyping.AsyncIterator[bytes]
uhttpcore\_async\connection_pool.py
u<module httpcore._async.connection_pool>
T a__class__
T aself
T aself
exc_type
exc_value
traceback
T aself
part
exc
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
request
T aself
stream
pool_request
pool
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
closing_connections
T aself
closing
T aself
connection
T aself
origin
aAsyncSocks5Connection
aAsyncForwardHTTPConnection
aAsyncTunnelHTTPConnection
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
.httpcore._async
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
a_async
T aNUITKA_PACKAGE_httpcore__async
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
connection
T aAsyncHTTPConnection
aAsyncHTTPConnection
connection_pool
T aAsyncConnectionPool
aAsyncConnectionPool
http11
T aAsyncHTTP11Connection
aAsyncHTTP11Connection
http_proxy
T aAsyncHTTPProxy
aAsyncHTTPProxy
interfaces
T aAsyncConnectionInterface
aAsyncConnectionInterface
http2
T aAsyncHTTP2Connection
aAsyncHTTP2Connection
