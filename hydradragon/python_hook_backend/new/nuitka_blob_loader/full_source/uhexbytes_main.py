# Reconstructed from integrated Nuitka blob
# Module: uhexbytes.main


Thin wrapper around the python built-in :class:`bytes` class.
It has these changes:
1. Accepts more initializing values: bool, bytearray, bytes, (non-negative) int,
str, and memoryview
2. The representation at console (__repr__) is 0x-prefixed
3. ``to_0x_hex`` returns a 0x-prefixed hex string
a__qualname__
cls
bytes
val
return
uHexBytes.__new__
key
aSupportsIndex
int
uHexBytes.__getitem__
slice
str
a__repr__
uHexBytes.__repr__
to_0x_hex
uHexBytes.to_0x_hex
a__orig_bases__
uhexbytes\main.py
u<module hexbytes.main>
T a__class__
T aself
key
T aself
key
result
a__class__
T acls
val
bytesval
a__class__
T aself
a__spec__
.httpcore._api
m
(
aConnectionPool
a__enter__
a__exit__
request
T amethod
url
headers
content
extensions
T nnnu
Sends an HTTP request, returning the response.
```
response = httpcore.request("GET", "https://www.example.com/")
```
Arguments:
method: The HTTP method for the request. Typically one of `"GET"`,
`"OPTIONS"`, `"HEAD"`, `"POST"`, `"PUT"`, `"PATCH"`, or `"DELETE"`.
url: The URL of the HTTP request. Either as an instance of `httpcore.URL`,
or as str/bytes.
headers: The HTTP request headers. Either as a dictionary of str/bytes,
or as a list of two-tuples of str/bytes.
content: The content of the request body. Either as bytes,
or as a bytes iterator.
extensions: A dictionary of optional extra information included on the request.
Possible keys include `"timeout"`.
Returns:
An instance of `httpcore.Response`.

Sends an HTTP request, returning the response within a content manager.
```
with httpcore.stream("GET", "https://www.example.com/") as response:
...
```
When using the `stream()` function, the body of the response will not be
utomatically read. If you want to access the response body you should
either use `content = response.read()`, or `for chunk in response.iter_content()`.
Arguments:
method: The HTTP method for the request. Typically one of `"GET"`,
`"OPTIONS"`, `"HEAD"`, `"POST"`, `"PUT"`, `"PATCH"`, or `"DELETE"`.
url: The URL of the HTTP request. Either as an instance of `httpcore.URL`,
or as str/bytes.
headers: The HTTP request headers. Either as a dictionary of str/bytes,
or as a list of two-tuples of str/bytes.
content: The content of the request body. Either as bytes,
or as a bytes iterator.
extensions: A dictionary of optional extra information included on the request.
Possible keys include `"timeout"`.
Returns:
An instance of `httpcore.Response`.
stream
method
url
headers
content
extensions
a__doc__
a__file__
origin
has_location
a__cached__
annotations
contextlib
typing
a_models
T aURL
aExtensions
aHeaderTypes
aResponse
aURL
aExtensions
aHeaderTypes
aResponse
u_sync.connection_pool
T aConnectionPool
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
uhttpcore\_api.py
u<module httpcore._api>
T amethod
url
headers
content
extensions
pool
T amethod
url
headers
content
extensions
pool
response

a__spec__
.httpcore._async.connection
R

Generate a geometric sequence that has a ratio of 2 and starts with 0.
For example:
- `factor = 2`: `0, 2, 4, 8, 16, 32, 64, ...`
- `factor = 3`: `0, 3, 6, 12, 24, 48, 96, ...`
itertools
count
factor
l aexponential_backoff
a_origin
a_ssl_context
a_keepalive_expiry
a_http1
a_http2
a_retries
a_local_address
a_uds
aAutoBackend
a_network_backend
a_connection
a_connect_failed
aAsyncLock
a_request_lock
a_socket_options
self
can_handle_request
request
url
origin
uAttempted to send request to

u on connection to
a__aenter__
a__aexit__
a_connect
get_extra_info
T assl_object
selected_alpn_protocol
h2
http2
T aAsyncHTTP2Connection
aAsyncHTTP2Connection
T aorigin
stream
keepalive_expiry
aAsyncHTTP11Connection
T nnnahandle_async_request
uAsyncHTTPConnection.handle_async_request
extensions
get
timeout
T asni_hostname
nT aconnect
naRETRIES_BACKOFF_FACTOR
T afactor
host
decode
T aascii
port
local_address
socket_options
aTrace
connect_tcp
logger
return_value
path
connect_unix_socket
scheme
T chttps
cwss
default_ssl_context
uhttp/1.1
set_alpn_protocols
ssl_context
server_hostname
start_tls
stream
aConnectError
aConnectTimeout
retries_left
retry
kwargs
sleep
uAsyncHTTPConnection._connect
close
aclose
uAsyncHTTPConnection.aclose
chttps
is_available
has_expired
is_idle
is_closed
uCONNECTION FAILED
aCONNECTING
info
w<a__name__
u [
u]>
uAsyncHTTPConnection.__aenter__
uAsyncHTTPConnection.__aexit__
a__doc__
a__file__
has_location
a__cached__
annotations
logging
ssl
types
typing
u_backends.auto
T aAutoBackend
u_backends.base
T aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
aSOCKET_OPTION
aAsyncNetworkBackend
aAsyncNetworkStream
a_exceptions
T aConnectError
aConnectTimeout
a_models
T aOrigin
aRequest
aResponse
aOrigin
aRequest
aResponse
a_ssl
T adefault_ssl_context
a_synchronization
T aAsyncLock
a_trace
T aTrace
http11
T aAsyncHTTP11Connection
interfaces
T aAsyncConnectionInterface
aAsyncConnectionInterface
f
?agetLogger
T uhttpcore.connection
D afactor
return
float
utyping.Iterator[float]
a__prepare__
aAsyncHTTPConnection
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
