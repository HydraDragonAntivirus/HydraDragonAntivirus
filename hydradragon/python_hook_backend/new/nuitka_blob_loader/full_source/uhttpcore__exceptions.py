# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._exceptions

a__qualname__
a__orig_bases__
aProxyError
aUnsupportedProtocol
aProtocolError
aRemoteProtocolError
aLocalProtocolError
aTimeoutException
aPoolTimeout
aConnectTimeout
aReadTimeout
aWriteTimeout
aNetworkError
aConnectError
aReadError
aWriteError
uhttpcore\_exceptions.py
u<module httpcore._exceptions>
T amap
exc
from_exc
to_exc

a__spec__
.httpcore._models
9&
encode
T aascii

u strings may not include unicode characters.
a__name__
u must be bytes or str, but got
w.u
Any arguments that are ultimately represented as bytes can be specified
either as bytes or as strings.
However we enforce that any string arguments must only contain characters in
the plain ASCII range. chr(0)...chr(127). If you need to use characters
outside that range then be precise, and use a byte-wise argument.
T Obytes
Ostr
aURL
u must be a URL, bytes, or str, but got

Type check for URL parameters.
aMapping
items
enforce_bytes
D aname
uheader name
D aname
uheader value
aSequence
u must be a mapping or sequence of two-tuples, but got

Convienence function that ensure all items in request or response headers
re either bytes or strings in the plain ASCII range.
aByteStream
T c
chost
aDEFAULT_PORTS
get
scheme
port
host
c%b:%d
cHost
ccontent-length
ctransfer-encoding
headers
cContent-Length
T cTransfer-Encoding
cchunked
lower
u<genexpr>
uinclude_request_headers.<locals>.<genexpr>
a_content
self
a__iter__
uByteStream.__iter__
a__aiter__
uByteStream.__aiter__
w<u [
u bytes]>
aOrigin
decode
u://
w:aurllib
parse
urlparse
D aname
url
hostname
c
path
d/aquery
d?atarget
D aname
scheme
D aname
host
D aname
target

Parameters:
url: The complete URL as a string or bytes.
scheme: The URL scheme as a string or bytes.
Typically either `"http"` or `"https"`.
host: The URL host as a string or bytes. Such as `"www.example.com"`.
port: The port to connect to. Either an integer or `None`.
target: The target of the HTTP request. Such as `"/items?search=red"`.
D chttp
chttps
cws
cwss
csocks5
csocks5h
lPl  lPl  l  l  T ascheme
host
port
c%b://%b%b
c%b://%b:%d%b
u(scheme=
u, host=
u, port=
u, target=
w)D aname
method
method
enforce_url
url
enforce_headers
D aname
headers
enforce_stream
D aname
content
stream
extensions
T ascheme
host
port
target

Parameters:
method: The HTTP request method, either as a string or bytes.
For example: `GET`.
url: The request URL, either as a `URL` instance, or as a string or bytes.
For example: `"https://www.example.com".`
headers: The HTTP request headers.
content: The content of the request body.
extensions: A dictionary of optional extra information included on
the request. Possible keys include `"timeout"`, and `"trace"`.
u]>
status
a_stream_consumed

Parameters:
status: The HTTP status code of the response. For example `200`.
headers: The HTTP response headers.
content: The content of the response body.
extensions: A dictionary of optional extra information included on
the responseself.Possible keys include `"http_version"`,
`"reason_phrase"`, and `"network_stream"`.
aIterable
uAttempted to access 'response.content' on a streaming response. Call 'response.read()' first.
uAttempted to access 'response.content' on a streaming response. Call 'await response.aread()' first.
uAttempted to read an asynchronous response using 'response.read()'. You should use 'await response.aread()' instead.
iter_stream
uAttempted to stream an asynchronous response using 'for ... in response.iter_stream()'. You should use 'async for ... in response.aiter_stream()' instead.
uAttempted to call 'for ... in response.iter_stream()' more than once.
uResponse.iter_stream
uAttempted to close an asynchronous response using 'response.close()'. You should use 'await response.aclose()' instead.
close
aAsyncIterable
uAttempted to read an synchronous response using 'await response.aread()'. You should use 'response.read()' instead.
aiter_stream
aread
uResponse.aread
uAttempted to stream an synchronous response using 'async for ... in response.aiter_stream()'. You should use 'for ... in response.iter_stream()' instead.
uAttempted to call 'async for ... in response.aiter_stream()' more than once.
uResponse.aiter_stream
uAttempted to close a synchronous response using 'await response.aclose()'. You should use 'response.close()' instead.
aclose
uResponse.aclose
ssl_context
D aname
auth
d:cBasic
base64
b64encode
auth
cProxy-Authorization
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ssl
typing
uurllib.parse
aUnion
aByteOrStr
aTuple
aHeadersAsSequence
aHeadersAsMapping
aHeaderTypes
aMutableMapping
aAny
aExtensions
D avalue
name
return
ubytes | str
str
bytes
D avalue
name
return
uURL | bytes | str
str
aURL
T nD avalue
name
return
uHeadersAsMapping | HeadersAsSequence | None
str
ulist[tuple[bytes, bytes]]
D avalue
name
return
ubytes | typing.Iterable[bytes] | typing.AsyncIterable[bytes] | None
str
utyping.Iterable[bytes] | typing.AsyncIterable[bytes]
D cftp
chttp
chttps
cws
cwss
l lPl  lPl  D aheaders
url
content
return
ulist[tuple[bytes, bytes]]
u'URL'
uNone | bytes | typing.Iterable[bytes] | typing.AsyncIterable[bytes]
ulist[tuple[bytes, bytes]]
include_request_headers
