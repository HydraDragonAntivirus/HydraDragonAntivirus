# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._trace

aTrace
a__qualname__
T nnD aname
logger
request
kwargs
return
str
ulogging.Logger
uRequest | None
udict[str, typing.Any] | None
aNone
a__init__
uTrace.__init__
D aname
info
return
str
udict[str, typing.Any]
aNone
uTrace.trace
D areturn
aTrace
a__enter__
uTrace.__enter__
T nnnD aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
aNone
a__exit__
uTrace.__exit__
uhttpcore\_trace.py
u<module httpcore._trace>
T aself
info
T aself
exc_type
exc_value
traceback
info
T aself
name
logger
request
kwargs
T aself
name
info
prefix_and_name
coro
message
args
T aself
name
info
prefix_and_name
ret
message
args
a__spec__
.httpcore._utils
fileno
select

Return whether a socket, as identifed by its file descriptor, is readable.
"A socket is readable" means that the read buffer isn't empty, i.e. that calling
.recv() on it would immediately return some data.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
socket
sys
D asock
return
usocket.socket | None
bool
is_socket_readable
uhttpcore\_utils.py
u<module httpcore._utils>
T asock
sock_fd
rready
w_wpu
a__spec__
.httpcore
h
uAttempted to use 'httpcore.AnyIOBackend' but 'anyio' is not installed.
uAttempted to use 'httpcore.TrioBackend' but 'trio' is not installed.
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_httpcore
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
a_api
T arequest
stream
request
stream
a_async
T aAsyncConnectionInterface
aAsyncConnectionPool
aAsyncHTTP2Connection
aAsyncHTTP11Connection
aAsyncHTTPConnection
aAsyncHTTPProxy
aAsyncSOCKSProxy
aAsyncConnectionInterface
aAsyncConnectionPool
aAsyncHTTP2Connection
aAsyncHTTP11Connection
aAsyncHTTPConnection
aAsyncHTTPProxy
aAsyncSOCKSProxy
u_backends.base
T aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
aNetworkBackend
aNetworkStream
aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
aNetworkBackend
aNetworkStream
u_backends.mock
T aAsyncMockBackend
aAsyncMockStream
aMockBackend
aMockStream
aAsyncMockBackend
aAsyncMockStream
aMockBackend
aMockStream
u_backends.sync
T aSyncBackend
aSyncBackend
a_exceptions
T aConnectError
aConnectionNotAvailable
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
aConnectError
aConnectionNotAvailable
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
T aURL
aOrigin
aProxy
aRequest
aResponse
aURL
aOrigin
aProxy
aRequest
aResponse
a_ssl
T adefault_ssl_context
default_ssl_context
a_sync
T aConnectionInterface
aConnectionPool
aHTTP2Connection
aHTTP11Connection
aHTTPConnection
aHTTPProxy
aSOCKSProxy
aConnectionInterface
aConnectionPool
aHTTP2Connection
aHTTP11Connection
aHTTPConnection
aHTTPProxy
aSOCKSProxy
u_backends.anyio
T aAnyIOBackend
aAnyIOBackend
