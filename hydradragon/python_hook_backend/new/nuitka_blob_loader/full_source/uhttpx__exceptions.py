# Reconstructed from integrated Nuitka blob
# Module: uhttpx._exceptions


Base class for `RequestError` and `HTTPStatusError`.
Useful for `try...except` blocks when issuing a request,
nd then calling `.raise_for_status()`.
For example:
```
try:
response = httpx.get("https://www.example.com")
response.raise_for_status()
except httpx.HTTPError as exc:
print(f"HTTP Exception for {exc.request.url} - {exc}")
```
a__qualname__
D amessage
return
str
aNone
uHTTPError.__init__
property
D areturn
aRequest
uHTTPError.request
setter
D arequest
return
aRequest
aNone
a__orig_bases__

Base class for all exceptions that may occur when issuing a `.request()`.
D arequest
nD amessage
request
return
str
uRequest | None
aNone
uRequestError.__init__
aTransportError

Base class for all exceptions that occur at the level of the Transport API.
aTimeoutException

The base class for timeout errors.
An operation has timed out.
aConnectTimeout

Timed out while connecting to the host.
aReadTimeout

Timed out while receiving data from the host.
aWriteTimeout

Timed out while sending data to the host.
aPoolTimeout

Timed out waiting to acquire a connection from the pool.
aNetworkError

The base class for network-related errors.
An error occurred while interacting with the network.
aReadError

Failed to receive data from the network.
aWriteError

Failed to send data through the network.
aConnectError

Failed to establish a connection.
aCloseError

Failed to close a connection.
aProxyError

An error occurred while establishing a proxy connection.
aUnsupportedProtocol

Attempted to make a request to an unsupported protocol.
For example issuing a request to `ftp://www.example.com`.
aProtocolError

The protocol was violated.
aLocalProtocolError

A protocol was violated by the client.
For example if the user instantiated a `Request` instance explicitly,
failed to include the mandatory `Host:` header, and then issued it directly
using `client.send()`.
aRemoteProtocolError

The protocol was violated by the server.
For example, returning malformed HTTP.
aDecodingError

Decoding of the response failed, due to a malformed encoding.
aTooManyRedirects

Too many redirects.
aHTTPStatusError

The response had an error HTTP status of 4xx or 5xx.
May be raised when calling `response.raise_for_status()`
D amessage
request
response
return
str
aRequest
aResponse
aNone
uHTTPStatusError.__init__
aInvalidURL

URL is improperly formed or cannot be parsed.
uInvalidURL.__init__
aCookieConflict

Attempted to lookup a cookie by name, but multiple cookies existed.
Can occur when calling `response.cookies.get(...)`.
uCookieConflict.__init__
T ERuntimeError
aStreamError

The base class for stream exceptions.
The developer made an error in accessing the request stream in
n invalid way.
uStreamError.__init__
aStreamConsumed

Attempted to read or stream content, but the content has already
been streamed.
D areturn
aNone
uStreamConsumed.__init__
aStreamClosed

Attempted to read or stream response content, but the request has been
closed.
uStreamClosed.__init__
aResponseNotRead

Attempted to access streaming response content, without having called `read()`.
uResponseNotRead.__init__
aRequestNotRead

Attempted to access streaming request content, without having called `read()`.
uRequestNotRead.__init__
contextmanager
T nD arequest
return
uRequest | None
utyping.Iterator[None]
uhttpx\_exceptions.py
u<module httpx._exceptions>
T a__class__
T aself
message
a__class__
T aself
message
request
response
a__class__
T aself
message
request
a__class__
T aself
T aself
request
T arequest
exc

a__spec__
.httpx._main
rich
console
aConsole
print
T u[bold]HTTPX :butterfly:
center
T ajustify
T uA next generation HTTP client.
center
T uUsage: [bold]httpx[/bold] [cyan]<URL> [OPTIONS][/cyan]
left
table
aTable
grid
T l tT apadding
pad_edge
add_column
T aParameter
taleft
bold
T ano_wrap
justify
style
T aDescription
add_row
T u-m, --method [cyan]METHOD
uRequest method, such as GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD.
[Default: GET, or POST if a request body is included]
T u-p, --params [cyan]<NAME VALUE> ...
uQuery parameters to include in the request URL.
T u-c, --content [cyan]TEXT
uByte content to include in the request body.
T u-d, --data [cyan]<NAME VALUE> ...
uForm data to include in the request body.
T u-f, --files [cyan]<NAME FILENAME> ...
uForm files to include in the request body.
T u-j, --json [cyan]TEXT
uJSON data to include in the request body.
T u-h, --headers [cyan]<NAME VALUE> ...
uInclude additional HTTP headers in the request.
T u--cookies [cyan]<NAME VALUE> ...
uCookies to include in the request.
T u--auth [cyan]<USER PASS>
uUsername and password to include in the request. Specify '-' for the password to use a password prompt. Note that using --verbose/-v will expose the Authorization header, including the password encoding in a trivially reversible format.
T u--proxy [cyan]URL
uSend the request via a proxy. Should be the URL giving the proxy address.
T u--timeout [cyan]FLOAT
uTimeout value to use for network operations, such as establishing the connection, reading some data, etc... [Default: 5.0]
T u--follow-redirects
uAutomatically follow redirects.
T u--no-verify
uDisable SSL verification.
T u--http2
uSend the request using HTTP/2, if the remote server supports it.
T u--download [cyan]FILE
uSave the response content as a file, rather than displaying it.
T u-v, --verbose
uVerbose output. Show request as well as response.
T u--help
uShow this message and exit.
headers
get
T uContent-Type
partition
T w;acast
pygments
lexers
get_lexer_for_mimetype
strip
name
util
aClassNotFound

uHTTP/2
uHTTP/1.1
lower
method
decode
T aascii
url
target
w u:
w
codes
get_reason_phrase
format_request_headers
T ahttp2
syntax
aSyntax
http
D atheme
word_wrap
ansi_dark
tT u
http
ansi_dark
tT atheme
word_wrap
format_response_headers
get_lexer_for_response
json
dumps
D aindent
l atext
w<acontent
u bytes of binary data>
items
T Olist
Otuple
lines
u*
w:T asubject
issuer
u*
uconnection.connect_tcp.started
host
u* Connecting to
uconnection.connect_tcp.complete
return_value
get_extra_info
T aserver_addr
u* Connected to
u on port
uconnection.start_tls.complete
T assl_object
version
cipher
getpeercert
selected_alpn_protocol
u* SSL established using
u /
u* Selected ALPN protocol:
T u* Server certificate:
format_certificate
uhttp11.send_request_headers.started
request
print_request_headers
D ahttp2
Fuhttp2.send_request_headers.started
D ahttp2
tuhttp11.receive_response_headers.complete
print_response_headers
uhttp2.receive_response_headers.complete
cHTTP/2
T uContent-Length
progress
aProgress
u[progress.description]{task.description}
u[progress.percentage]{task.percentage:>3.0f}%
aBarColumn
T nT abar_width
aDownloadColumn
aTransferSpeedColumn
a__enter__
a__exit__
uDownloading [bold]
markup
escape
add_task
T atotal
start
iter_bytes
download
write
update
download_task
response
num_bytes_downloaded
T acompleted
T nnnaloads
aJSONDecodeError
click
aBadParameter
T uNot valid JSON
T nnw-aprompt
T aPassword
tT ahide_input
resilient_parsing
print_help
exit
aPOST
aGET
aClient
T aproxy
timeout
http2
verify
stream
trace
partial
T averbose
T
params
content
data
files
json
headers
cookies
auth
follow_redirects
extensions
download_response
read
print_response
aRequestError
u[red]
a__name__
u[/red]:
is_success

An HTTP command line client.
Sends a request and displays the response.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
functools
sys
typing
upygments.lexers
upygments.util
urich.console
urich.markup
urich.progress
urich.syntax
urich.table
a_client
T aClient
a_exceptions
T aRequestError
a_models
T aResponse
aResponse
a_status_codes
T acodes
D areturn
aNone
D aresponse
return
aResponse
str
T FD arequest
http2
return
uhttpcore.Request
bool
str
D ahttp_version
status
reason_phrase
headers
return
bytes
int
ubytes | None
ulist[tuple[bytes, bytes]]
str
D arequest
http2
return
uhttpcore.Request
bool
aNone
D ahttp_version
status
reason_phrase
headers
return
bytes
int
ubytes | None
ulist[tuple[bytes, bytes]]
aNone
D aresponse
return
aResponse
aNone
aTuple
T Ostr
pa_PCTRTT
a_PCTRTTT
aDict
aUnion
a_PeerCertRetDictType
D acert
return
a_PeerCertRetDictType
str
D aname
info
verbose
return
str
utyping.Mapping[str, typing.Any]
bool
aNone
D aresponse
download
return
aResponse
utyping.BinaryIO
aNone
D actx
param
value
return
uclick.Context
uclick.Option | click.Parameter
utyping.Any
utyping.Any
validate_json
validate_auth
D actx
param
value
return
uclick.Context
uclick.Option | click.Parameter
utyping.Any
aNone
handle_help
command
T aadd_help_option
argument
T aurl
Ostr
T atype
option
T u--method
u-m
method
Ostr
uRequest method, such as GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD. [Default: GET, or POST if a request body is included]
T atype
help
T u--params
u-p
params
T Ostr
ptuQuery parameters to include in the request URL.
T atype
multiple
help
T u--content
u-c
content
Ostr
uByte content to include in the request body.
T u--data
u-d
data
T Ostr
ptuForm data to include in the request body.
aFile
T arb
T amode
uForm files to include in the request body.
T u--files
u-f
files
uJSON data to include in the request body.
T u--json
u-j
json
T atype
callback
help
T u--headers
u-h
headers
T Ostr
ptuInclude additional HTTP headers in the request.
T u--cookies
cookies
T Ostr
ptuCookies to include in the request.
uUsername and password to include in the request. Specify '-' for the password to use a password prompt. Note that using --verbose/-v will expose the Authorization header, including the password encoding in a trivially reversible format.
T u--auth
auth
T atype
default
callback
help
T u--proxy
proxy
Ostr
nuSend the request via a proxy. Should be the URL giving the proxy address.
T atype
default
help
T u--timeout
timeout
Ofloat
f
@uTimeout value to use for network operations, such as establishing the connection, reading some data, etc... [Default: 5.0]
T u--follow-redirects
follow_redirects
tFuAutomatically follow redirects.
T ais_flag
default
help
T u--no-verify
verify
tpuDisable SSL verification.
T u--http2
http2
Obool
tFuSend the request using HTTP/2, if the remote server supports it.
T atype
is_flag
default
help
T awb
uSave the response content as a file, rather than displaying it.
T u--download
T u--verbose
u-v
Obool
tFuVerbose. Show request as well as response.
uShow this message and exit.
T u--help
T ais_flag
is_eager
expose_value
callback
help
D aurl
method
params
content
data
files
json
headers
cookies
auth
proxy
timeout
follow_redirects
verify
http2
download
verbose
return
str
pulist[tuple[str, str]]
str
ulist[tuple[str, str]]
ulist[tuple[str, click.File]]
str
ulist[tuple[str, str]]
ulist[tuple[str, str]]
utuple[str, str] | None
str
float
bool
pputyping.BinaryIO | None
bool
aNone
main
uhttpx\_main.py
u<module httpx._main>
T aresponse
download
console
content_length
progress
description
download_task
chunk
T acert
lines
key
value
item
sub_item
T arequest
http2
version
headers
method
target
lines
T ahttp_version
status
reason_phrase
headers
version
reason
lines
T aresponse
content_type
mime_type
w_T actx
param
value
T aurl
method
params
content
data
files
json
headers
cookies
auth
proxy
timeout
follow_redirects
verify
http2
download
verbose
client
response
exc
console
T aconsole
table
T arequest
http2
console
http_text
syntax
T aresponse
console
lexer_name
data
text
syntax
T ahttp_version
status
reason_phrase
headers
console
http_text
syntax
T aname
info
verbose
console
host
stream
server_addr
ssl_object
version
cipher
server_cert
alpn
request
http_version
status
reason_phrase
headers
T actx
param
value
username
password
a__spec__
.httpx._models
G
J acodecs
lookup

Return `True` if `encoding` is a known codec.
encode
ascii

Coerce str/bytes into a strictly byte-wise HTTP header key.
uHeader value must be str or bytes, not


Coerce str/bytes into a strictly byte-wise HTTP header value.
email
message
aMessage
ucontent-type
get_content_charset
T nT afailobj
u '"
strip
re
split
u, *<
T w;l aurl
T u<> '"
T w;T w=areplace_chars
link
links

Returns a list of parsed link headers, for more info see:
https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Link
The generic syntax of those is:
Link: < uri-reference >; param1=value1; param2="value2"
So for instance:
Link; '<http:/.../front.jpeg>; type="image/jpeg",<http://.../back.jpeg>;'
would return
[
{"url": "http:/.../front.jpeg", "type": "image/jpeg"},
{"url": "http://.../back.jpeg"},
]
:param value: HTTP Link entity-header field
:return: list of parsed link headers
items
to_str
lower
aSENSITIVE_HEADERS
to_bytes_or_str
T u[secure]
T amatch_type_of
a_obfuscate_sensitive_headers
a_list
aHeaders
aMapping
a_normalize_header_key
encoding
a_normalize_header_value
self
append
a_encoding
T aascii
uutf-8
raw
decode
uiso-8859-1

Header encoding is mandated as ascii, but we allow fallbacks to utf-8
or iso-8859-1.

Returns a list of the raw header items, as byte pairs.
keys
values_dict
u,

Return `(key, value)` items of headers. Concatenate headers
into a single comma separated value when a key occurs multiple times.

Return a list of `(key, value)` pairs of headers. Allow multiple
occurrences of the same key without concatenating into a single
comma separated value.

Return a header value. If multiple occurrences of the header occur
then concatenate them together with commas.
split_values
T w,u
Return a list of all header values for a given key.
If `split_commas=True` is passed, then any comma separated header
values are split into multiple return strings.
pop
extend
T aencoding

Return a single header value.
If there are multiple headers with the same key, then we concatenate
them with commas. See: https://tools.ietf.org/html/rfc7230#section-3.2.2
uutf-8
:l nnu
Set the header `key` to `value`, removing any duplicate entries.
Retains insertion order.

Remove the header `key`.
sorted
a__name__
u, encoding=
multi_items
w(w)aupper
method
aURL
T aparams
headers
extensions
aCookies
set_cookie_header
get
T ucontent-type
encode_request
get_multipart_boundary_from_content_type
T acontent_type
T acontent
data
files
json
boundary
a_prepare
stream
aByteStream
read
utransfer-encoding
uContent-Length
setdefault
aHost
uTransfer-Encoding
host
cHost
netloc
T aPOST
aPUT
aPATCH
T cContent-Length
d0a_content
aRequestNotRead
aIterable
c

Read and return the request content.
aAsyncIterable
aread
uRequest.aread
w<u)>
T aextensions
stream
aUnattachedStream
status_code
a_request
next_request
history
is_closed
is_stream_consumed
default_encoding
encode_response
a_num_bytes_downloaded
ucontent-length
a_elapsed
u'.elapsed' may only be accessed after the response has been read or closed.

Returns the time taken for the complete request/response
cycle to complete.
uThe request instance has not been set on this response.

Returns the request instance associated to the current response.
http_version
uHTTP/1.1
T aascii
ignore
T aerrors
reason_phrase
codes
get_reason_phrase
request

Returns the URL for which the request was made.
aResponseNotRead
a_text
content
aTextDecoder
flush
charset_encoding
a_is_known_encoding

Return an encoding to use for decoding the byte content into text.
The priority for determining this is given by...
* `.encoding = <>` has been set explicitly.
* The encoding as specified by the charset parameter in the Content-Type header.
* The encoding as determined by `default_encoding`, which may either be
a string like "utf-8" indicating the encoding to use, or may be a callable
which enables charset autodetection.
uSetting encoding after `text` has been accessed is not allowed.

Set the encoding to use for decoding the byte content into text.
If the `text` attribute has been accessed, attempting to set the
encoding will throw a ValueError.
T uContent-Type
a_parse_content_type_charset

Return the encoding, as specified by the Content-Type header.
a_decoder
get_list
T ucontent-encoding
tT asplit_commas
aSUPPORTED_DECODERS
decoders
aMultiDecoder
T achildren
aIdentityDecoder

Returns a decoder instance which can be used to decode the raw byte
content, depending on the Content-Encoding used in the response.
is_informational

A property which is `True` for 1xx status codes, `False` otherwise.
is_success

A property which is `True` for 2xx status codes, `False` otherwise.
is_redirect

A property which is `True` for 3xx status codes, `False` otherwise.
Note that not all responses with a 3xx status code indicate a URL redirect.
Use `response.has_redirect_location` to determine responses with a properly
formed URL redirection.
is_client_error

A property which is `True` for 4xx status codes, `False` otherwise.
is_server_error

A property which is `True` for 5xx status codes, `False` otherwise.
is_error

A property which is `True` for 4xx and 5xx status codes, `False` otherwise.
aMOVED_PERMANENTLY
aFOUND
aSEE_OTHER
aTEMPORARY_REDIRECT
aPERMANENT_REDIRECT
aLocation

Returns True for 3xx responses with a properly formed URL redirection,
`False` otherwise.
uCannot call `raise_for_status` as the request instance has not been set on this response.
has_redirect_location
u{error_type} '{0.status_code} {0.reason_phrase}' for url '{0.url}'
Redirect location: '{0.headers[location]}'
For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/{0.status_code}
u{error_type} '{0.status_code} {0.reason_phrase}' for url '{0.url}'
For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/{0.status_code}
ldD l l l l uInformational response
uRedirect response
uClient error
uServer error
uInvalid status code
format
T aerror_type
aHTTPStatusError
T arequest
response

Raise the `HTTPStatusError` if one occurred.
jsonlib
loads
a_cookies
extract_cookies
T alink
a_parse_header_links
T arel
T aurl

Returns the parsed header links of the response, if any
u<Response [
w u]>
T aextensions
stream
is_closed
a_decoder
iter_bytes

Read and return the response content.

A byte-iterator over the decoded response content.
This allows us to handle gzip, deflate, brotli, and zstd encoded responses.
chunk_size
max
a_get_content_decoder
aByteChunker
T achunk_size
request_context
T arequest
a__enter__
a__exit__
iter_raw
decoder
chunker
T nnnuResponse.iter_bytes

A str-iterator over the decoded response content
that handles both gzip, deflate, etc but also detects the content's
string encoding.
aTextChunker
iter_text
uResponse.iter_text
aLineDecoder
iter_lines
uResponse.iter_lines

A byte-iterator over the raw response content.
aStreamConsumed
aStreamClosed
aSyncByteStream
uAttempted to call a sync iterator on an async stream.
close
uResponse.iter_raw
uAttempted to call an sync close on an async stream.

Close the response and release the connection.
Automatically called if the response body is read to completion.
aiter_bytes
uResponse.aread
aiter_raw
uResponse.aiter_bytes
aiter_text
uResponse.aiter_text
aiter_lines
uResponse.aiter_lines
aAsyncByteStream
uAttempted to call an async iterator on an sync stream.
aclose
uResponse.aiter_raw
uAttempted to call an async close on an sync stream.
uResponse.aclose
aCookieJar
jar
set
set_cookie
a_CookieCompatResponse
a_CookieCompatRequest

Loads any cookies based on the response `Set-Cookie` headers.
add_cookie_header

Sets an appropriate 'Cookie:' HTTP header on the `Request`.
version
name
value
port
port_specified
domain
domain_specified
domain_initial_dot
startswith
T w.apath
path_specified
secure
expires
discard
comment
comment_url
rest
D aHttpOnly
narfc2109
aCookie

Set a cookie value by name. May optionally include domain and path.
uMultiple cookies exist with name=
aCookieConflict

Get a cookie by name. May optionally include domain and path
in order to specify exactly which cookie to retrieve.
clear

Delete a cookie by name. May optionally include domain and path
in order to specify exactly which cookie to delete.

Delete all cookies. Optionally include a domain and path in
order to only delete a subset of all the cookies.
delete
u<genexpr>
uCookies.__iter__.<locals>.<genexpr>
u<Cookie
w=u for
u />
u<Cookies[
a__class__
a__init__
T aurl
headers
method
add_unredirected_header
response
info
a__doc__
a__file__
origin
has_location
a__cached__
annotations
datetime
uemail.message
json
typing
uurllib.request
urllib
ucollections.abc
T aMapping
uhttp.cookiejar
T aCookie
aCookieJar
T aByteStream
aUnattachedStream
encode_request
encode_response
a_decoders
T aSUPPORTED_DECODERS
aByteChunker
aContentDecoder
aIdentityDecoder
aLineDecoder
aMultiDecoder
aTextChunker
aTextDecoder
aContentDecoder
a_exceptions
T aCookieConflict
aHTTPStatusError
aRequestNotRead
aResponseNotRead
aStreamClosed
aStreamConsumed
request_context
a_multipart
T aget_multipart_boundary_from_content_type
a_status_codes
T acodes
a_types
T aAsyncByteStream
aCookieTypes
aHeaderTypes
aQueryParamTypes
aRequestContent
aRequestData
aRequestExtensions
aRequestFiles
aResponseContent
aResponseExtensions
aSyncByteStream
aCookieTypes
aHeaderTypes
aQueryParamTypes
aRequestContent
aRequestData
aRequestExtensions
aRequestFiles
aResponseContent
aResponseExtensions
a_urls
T aURL
a_utils
T ato_bytes_or_str
to_str
L aCookies
aHeaders
aRequest
aResponse
a__all__
S aauthorization
uproxy-authorization
D aencoding
return
str
bool
D akey
encoding
return
ustr | bytes
ustr | None
bytes
D avalue
encoding
return
ustr | bytes
ustr | None
bytes
D acontent_type
return
str
ustr | None
D avalue
return
str
ulist[dict[str, str]]
D aitems
return
utyping.Iterable[tuple[typing.AnyStr, typing.AnyStr]]
utyping.Iterator[tuple[typing.AnyStr, typing.AnyStr]]
aMutableMapping
T Ostr
pa__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
