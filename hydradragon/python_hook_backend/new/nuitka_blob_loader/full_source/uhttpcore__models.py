# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._models


A container for non-streaming content, and that supports both sync and async
stream iteration.
a__qualname__
D acontent
return
bytes
aNone
a__init__
uByteStream.__init__
D areturn
utyping.Iterator[bytes]
D areturn
utyping.AsyncIterator[bytes]
D areturn
str
a__repr__
uByteStream.__repr__
D ascheme
host
port
return
bytes
paint
aNone
uOrigin.__init__
D aother
return
utyping.Any
bool
a__eq__
uOrigin.__eq__
a__str__
uOrigin.__str__

Represents the URL against which an HTTP request may be made.
The URL may either be specified as a plain string, for convienence:
```python
url = httpcore.URL("https://www.example.com/")
```
Or be constructed with explicitily pre-parsed components:
```python
url = httpcore.URL(scheme=b'https', host=b'www.example.com', port=None, target=b'/')
```
Using this second more explicit style allows integrations that are using
`httpcore` to pass through URLs that have already been parsed in order to use
libraries such as `rfc-3986` rather than relying on the stdlib. It also ensures
that URL parsing is treated identically at both the networking level and at any
higher layers of abstraction.
The four components are important here, as they allow the URL to be precisely
specified in a pre-parsed format. They also allow certain types of request to
be created that could not otherwise be expressed.
For example, an HTTP request to `http://www.example.com/` forwarded via a proxy
t `http://localhost:8080`...
```python
# Constructs an HTTP request with a complete URL as the target:
# GET https://www.example.com/ HTTP/1.1
url = httpcore.URL(
scheme=b'http',
host=b'localhost',
port=8080,
target=b'https://www.example.com/'
)
request = httpcore.Request(
method="GET",
url=url
)
```
Another example is constructing an `OPTIONS *` request...
```python
# Constructs an 'OPTIONS *' HTTP request:
# OPTIONS * HTTP/1.1
url = httpcore.URL(scheme=b'https', host=b'www.example.com', target=b'*')
request = httpcore.Request(method="OPTIONS", url=url)
```
This kind of request is not possible to formulate with a URL string,
because the `/` delimiter is always used to demark the target from the
host/port portion of the URL.
For convenience, string-like arguments may be specified either as strings or
s bytes. However, once a request is being issue over-the-wire, the URL
components are always ultimately required to be a bytewise representation.
In order to avoid any ambiguity over character encodings, when strings are used
s arguments, they must be strictly limited to the ASCII range `chr(0)`-`chr(127)`.
If you require a bytewise representation that is outside this range you must
handle the character encoding directly, and pass a bytes instance.
T u
D ascheme
host
port
target
c
pnc
D aurl
scheme
host
port
target
return
ubytes | str
ubytes | str
ubytes | str
uint | None
ubytes | str
aNone
uURL.__init__
D areturn
aOrigin
uURL.origin
uURL.__eq__
D areturn
bytes
a__bytes__
uURL.__bytes__
uURL.__repr__

An HTTP request.
aRequest
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
ubytes | typing.Iterable[bytes] | typing.AsyncIterable[bytes] | None
uExtensions | None
aNone
uRequest.__init__
uRequest.__repr__

An HTTP response.
aResponse
D astatus
headers
content
extensions
return
int
aHeaderTypes
ubytes | typing.Iterable[bytes] | typing.AsyncIterable[bytes] | None
uExtensions | None
aNone
uResponse.__init__
content
uResponse.content
uResponse.__repr__
read
uResponse.read
D areturn
aNone
uResponse.close
aProxy
T nnnD aurl
auth
headers
ssl_context
uURL | bytes | str
utuple[bytes | str, bytes | str] | None
uHeadersAsMapping | HeadersAsSequence | None
ussl.SSLContext | None
uProxy.__init__
uhttpcore\_models.py
T a.0
wkwvu<module httpcore._models>
T a__class__
T aself
T aself
other
T aself
content
T aself
scheme
host
port
T	aself
url
auth
headers
ssl_context
username
password
userpass
authorization
T aself
method
url
headers
content
extensions
T aself
status
headers
content
extensions
T aself
url
scheme
host
port
target
parsed
T aself
chunk
T avalue
name
seen_type
T avalue
name
T aheaders
url
content
headers_set
default_port
header_value
content_length
T aself
default_port
a__spec__
.httpcore._ssl
ssl
create_default_context
load_verify_locations
certifi
where
a__doc__
a__file__
origin
has_location
a__cached__
return
aSSLContext
default_ssl_context
uhttpcore\_ssl.py
u<module httpcore._ssl>
T acontext

a__spec__
.httpcore._sync.connection

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
aSyncBackend
a_network_backend
a_connection
a_connect_failed
aLock
a_request_lock
a_socket_options
can_handle_request
url
origin
uAttempted to send request to

u on connection to
a__enter__
a__exit__
a_connect
get_extra_info
T assl_object
selected_alpn_protocol
h2
http2
T aHTTP2Connection
aHTTP2Connection
T aorigin
stream
keepalive_expiry
aHTTP11Connection
T nnnahandle_request
extensions
get
timeout
T asni_hostname
nT aconnect
naRETRIES_BACKOFF_FACTOR
T afactor
self
host
decode
T aascii
port
local_address
socket_options
aTrace
connect_tcp
logger
request
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
close
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
a__doc__
a__file__
has_location
a__cached__
annotations
logging
ssl
types
typing
u_backends.sync
T aSyncBackend
u_backends.base
T aSOCKET_OPTION
aNetworkBackend
aNetworkStream
aSOCKET_OPTION
aNetworkBackend
aNetworkStream
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
T aLock
a_trace
T aTrace
http11
T aHTTP11Connection
interfaces
T aConnectionInterface
aConnectionInterface
f
?agetLogger
T uhttpcore.connection
D afactor
return
float
utyping.Iterator[float]
a__prepare__
aHTTPConnection
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
