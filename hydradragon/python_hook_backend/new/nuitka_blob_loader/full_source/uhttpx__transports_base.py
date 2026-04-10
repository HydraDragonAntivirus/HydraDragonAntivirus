# Reconstructed from integrated Nuitka blob
# Module: uhttpx._transports.base

a__qualname__
D aself
return
wTpa__enter__
uBaseTransport.__enter__
T nnnD aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
aNone
a__exit__
uBaseTransport.__exit__
D arequest
return
aRequest
aResponse
handle_request
uBaseTransport.handle_request
D areturn
aNone
uBaseTransport.close
D aself
return
wApuhttpx\_transports\base.py
u<module httpx._transports.base>
T aself
T aself
exc_type
exc_value
traceback
T aself
request

a__spec__
.httpx._transports
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_httpx
u\not_existing
a_transports
T aNUITKA_PACKAGE_httpx__transports
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
asgi
T w*abase
default
mock
wsgi
L aASGITransport
aAsyncBaseTransport
aBaseTransport
aAsyncHTTPTransport
aHTTPTransport
aMockTransport
aWSGITransport
a__all__
uhttpx\_transports\__init__.py
u<module httpx._transports>

a__spec__
.httpx._transports.default
httpcore
aTimeoutException
aConnectTimeout
aReadTimeout
aWriteTimeout
aPoolTimeout
aNetworkError
aConnectError
aReadError
aWriteError
aProxyError
aUnsupportedProtocol
aProtocolError
aLocalProtocolError
aRemoteProtocolError
aHTTPCORE_EXC_MAP
a_load_httpcore_exceptions
items
mapped_exc
map_httpcore_exceptions
a_httpcore_stream
a__enter__
a__exit__
self
T nnna__iter__
uResponseStream.__iter__
close
aURL
aProxy
T aurl
create_ssl_context
T averify
cert
trust_env
aConnectionPool
max_connections
max_keepalive_connections
keepalive_expiry
T
ssl_context
max_connections
max_keepalive_connections
keepalive_expiry
http1
http2
uds
local_address
retries
socket_options
a_pool
url
scheme
T ahttp
https
aHTTPProxy
raw_scheme
raw_host
port
raw_path
T ascheme
host
port
target
raw_auth
headers
raw
ssl_context
T aproxy_url
proxy_auth
proxy_headers
ssl_context
proxy_ssl_context
max_connections
max_keepalive_connections
keepalive_expiry
http1
http2
socket_options
T asocks5
socks5h
socksio
uUsing SOCKS proxy, but the 'socksio' package is not installed. Make sure to install httpx using `pip install httpx[socks]`.
aSOCKSProxy
T aproxy_url
proxy_auth
ssl_context
max_connections
max_keepalive_connections
keepalive_expiry
http1
http2
uProxy protocol must be either 'http', 'https', 'socks5', or 'socks5h', but got

w.astream
aSyncByteStream
aRequest
method
extensions
T amethod
url
headers
content
extensions
handle_request
resp
aIterable
aResponse
status
aResponseStream
T astatus_code
headers
stream
extensions
a__aiter__
uAsyncResponseStream.__aiter__
aclose
uAsyncResponseStream.aclose
aAsyncConnectionPool
aAsyncHTTPProxy
T aproxy_url
proxy_auth
proxy_headers
proxy_ssl_context
ssl_context
max_connections
max_keepalive_connections
keepalive_expiry
http1
http2
socket_options
aAsyncSOCKSProxy
uProxy protocol must be either 'http', 'https', 'socks5', or 'socks5h', but got {proxy.url.scheme!r}.
a__aenter__
uAsyncHTTPTransport.__aenter__
a__aexit__
exc_type
exc_value
traceback
uAsyncHTTPTransport.__aexit__
request
aAsyncByteStream
handle_async_request
aAsyncIterable
aAsyncResponseStream
uAsyncHTTPTransport.handle_async_request
uAsyncHTTPTransport.aclose

Custom transports, with nicely configured defaults.
The following additional keyword arguments are currently supported by httpcore...
* uds: str
* local_address: str
* retries: int
Example usages...
# Disable HTTP/2 on a single specific domain.
mounts = {
"all://": httpx.HTTPTransport(http2=True),
"all://*example.org": httpx.HTTPTransport()
}
# Using advanced httpcore configuration, with connection retries.
transport = httpx.HTTPTransport(retries=1)
client = httpx.Client(transport=transport)
# Using advanced httpcore configuration, with unix domain sockets.
transport = httpx.HTTPTransport(uds="socket.uds")
client = httpx.Client(transport=transport)
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
contextlib
typing
aTracebackType
a_config
T aDEFAULT_LIMITS
aLimits
aProxy
create_ssl_context
l aDEFAULT_LIMITS
aLimits
a_exceptions
T aConnectError
aConnectTimeout
aLocalProtocolError
aNetworkError
aPoolTimeout
aProtocolError
aProxyError
aReadError
aReadTimeout
aRemoteProtocolError
aTimeoutException
aUnsupportedProtocol
aWriteError
aWriteTimeout
a_models
T aRequest
aResponse
a_types
T aAsyncByteStream
aCertTypes
aProxyTypes
aSyncByteStream
aCertTypes
aProxyTypes
a_urls
T aURL
base
T aAsyncBaseTransport
aBaseTransport
aAsyncBaseTransport
aBaseTransport
aTypeVar
T wTaHTTPTransport
T abound
wTT wAaAsyncHTTPTransport
wAaUnion
aTuple
T Oint
ppT Obytes
Obytearray
T Oint
pnOint
aSOCKET_OPTION
aAsyncHTTPTransport
aHTTPTransport
a__all__
udict[type[Exception], type[httpx.HTTPError]]
D areturn
udict[type[Exception], type[httpx.HTTPError]]
contextmanager
D areturn
utyping.Iterator[None]
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
