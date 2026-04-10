# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._sync.socks_proxy


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
uNetworkBackend | None
aNone
uSOCKSProxy.__init__
D aorigin
return
aOrigin
aConnectionInterface
create_connection
uSOCKSProxy.create_connection
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
puNetworkBackend | None
aNone
uSocks5Connection.__init__
D arequest
return
aRequest
aResponse
uSocks5Connection.handle_request
D aorigin
return
aOrigin
bool
can_handle_request
uSocks5Connection.can_handle_request
D areturn
aNone
uSocks5Connection.close
D areturn
bool
uSocks5Connection.is_available
uSocks5Connection.has_expired
uSocks5Connection.is_idle
uSocks5Connection.is_closed
D areturn
str
uSocks5Connection.info
a__repr__
uSocks5Connection.__repr__
uhttpcore\_sync\socks_proxy.py
u<module httpcore._sync.socks_proxy>
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
aHTTP2Connection
exc
a__spec__
.httpcore._synchronization
sniffio
asyncio
current_async_library
environment
T aasyncio
trio
uRunning under an unsupported async environment.
anyio
uRunning with asyncio requires installation of 'httpcore[asyncio]'.
trio
uRunning with trio requires installation of 'httpcore[trio]'.

a_backend
aLock
a_trio_lock
a_anyio_lock

Detect if we're running under 'asyncio' or 'trio' and create
a lock with the correct implementation.
self
setup
acquire
a__aenter__
uAsyncLock.__aenter__
release
a__aexit__
uAsyncLock.__aexit__
aEvent
a_trio_event
a_anyio_event
set
aTooSlowError
aPoolTimeout
timeout
Z amap_exceptions
a__enter__
a__exit__
fail_after
wait
T nnnuAsyncEvent.wait
a_bound
aSemaphore
T ainitial_value
max_value
a_trio_semaphore
a_anyio_semaphore

Detect if we're running under 'asyncio' or 'trio' and create
a semaphore with the correct implementation.
uAsyncSemaphore.acquire
uAsyncSemaphore.release
aCancelScope
T tT ashield
a_trio_shield
a_anyio_shield

Detect if we're running under 'asyncio' or 'trio' and create
a shielded scope with the correct implementation.
threading
a_lock
a_event
T atimeout
T avalue
a_semaphore
a__doc__
a__file__
origin
has_location
a__cached__
annotations
types
a_exceptions
T aExceptionMapping
aPoolTimeout
map_exceptions
aExceptionMapping
T EImportError
ENotImplementedError
D areturn
str
