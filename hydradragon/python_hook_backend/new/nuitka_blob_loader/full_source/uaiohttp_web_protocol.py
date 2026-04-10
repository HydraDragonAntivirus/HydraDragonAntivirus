# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.web_protocol

uPayload parsing error.
a__qualname__
a__orig_bases__
aPayloadAccessError
uPayload was accessed after response was sent.
wsT tppT aauto_attribs
frozen
slots
a__annotations__
a_MsgType
uHTTP protocol implementation.
RequestHandler handles incoming HTTP request. It reads request line,
request headers and request payload and calls handle_request() method.
By default it always returns with 404 response.
RequestHandler handles errors in incoming request, like bad
status line, bad headers or incomplete payload. If any error occurs,
connection gets closed.
keepalive_timeout -- number of seconds before closing
keep-alive connection
tcp_keepalive -- TCP keep-alive is on, default is on
debug -- enable debug mode
logger -- custom logger object
ccess_log_class -- custom class for access_logger
ccess_log -- custom logging object
ccess_log_format -- access log format string
loop -- Optional event loop
max_line_size -- Optional maximum header line size
max_field_size -- Optional maximum header field size
max_headers -- Optional maximum header size
timeout_ceil_threshold -- Optional value to specify
threshold to ceil() timeout
values
T a_request_count
a_keepalive
a_manager
a_request_handler
a_request_factory
a_tcp_keepalive
a_next_keepalive_close_time
a_keepalive_handle
a_keepalive_timeout
a_lingering_time
a_messages
a_message_tail
a_handler_waiter
a_waiter
a_task_handler
a_upgrade
a_payload_parser
a_request_parser
a_reading_paused
logger
debug
access_log
access_logger
a_close
a_force_close
a_current_request
a_timeout_ceil_threshold
a_request_in_progress
a__slots__
l  aaccess_log_class
access_log_format
aLOG_FORMAT
max_line_size
l ?amax_headers
l   amax_field_size
lingering_time
f
$@aread_bufsize
l   aauto_decompress
timeout_ceil_threshold
aServer
aAbstractEventLoop
float
bool
str
int
uRequestHandler.__init__
a__repr__
uRequestHandler.__repr__
property
uRequestHandler.keepalive_timeout
T f
.@aBaseTransport
uRequestHandler.connection_made
aBaseException
uRequestHandler.connection_lost
parser
set_parser
uRequestHandler.set_parser
D areturn
naeof_received
uRequestHandler.eof_received
data
bytes
data_received
uRequestHandler.data_received
val
uRequestHandler.keep_alive
uRequestHandler.close
uRequestHandler.force_close
response
uRequestHandler.log_access
args
kw
uRequestHandler.log_debug
uRequestHandler.log_exception
uRequestHandler._process_keepalive
T l  nnuRequestHandler.handle_error
uRequestHandler._make_error_handler
uaiohttp\web_protocol.py
u<module aiohttp.web_protocol>
T a__class__
T aself
manager
loop
keepalive_timeout
tcp_keepalive
logger
access_log_class
access_log
access_log_format
debug
max_line_size
max_headers
max_field_size
lingering_time
read_bufsize
auto_decompress
timeout_ceil_threshold
a__class__
T aself
T aself
request
start_time
request_handler
resp
exc
reset
T aself
err_info
handler
T aself
loop
now
close_time
T aself
exc
handler_cancellation
a__class__
T aself
transport
real_transport
loop
task
a__class__
T
self
data
messages
upgraded
tail
exc
msg
payload
waiter
eof
T aself
request
resp
start_time
prepare_meth
exc
T
self
request
status
exc
message
ct
title
msg
tb
resp
T arequest
self
err_info
T aerr_info
self
T aself
val
T aself
request
response
time
T aself
args
kw
T aself
parser
T aself
timeout
task
T aself
loop
handler
manager
keepalive_timeout
resp
message
payload
start
writer
request_handler
request
coro
task
reset
lingering_time
now
end_t
wtaexc
close_time
a__spec__
.aiohttp.web_request
q1
u<genexpr>
a_message
a_protocol
a_payload_writer
a_payload
headers
a_headers
method
a_method
version
a_version
a_cache
url
absolute
with_scheme
with_host
host
scheme
relative
a_rel_url
a_state
a_task
a_client_max_size
a_loop
transport
get_extra_info
T asslcontext
a_transport_sslcontext
T apeername
a_transport_peername
remote
a_read_bytes
uCannot clone request after reading its content
sentinel
aURL
path
aCIMultiDictProxy
aCIMultiDict
items
raw_headers
a_replace
client_max_size
state
copy
uClone itself with replacement some attributes.
Creates and returns a new instance of Request object. If no parameters
re given, an exact copy is returned. If a parameter is not passed, it
will reuse the one from the current request object.
encode
T uutf-8
uBaseRequest.clone.<locals>.<genexpr>
warnings
warn
uRequest.message is deprecated
aDeprecationWarning
D astacklevel
l urequest.loop property is deprecated
D astacklevel
l ahttps
uA bool indicating if the request is handled with SSL.
getall
hdrs
aFORWARDED
elems
aMappingProxyType
pos
a_FORWARDED_PAIR_RE
match
field_value
need_separator
find
w,agroups
w"a_QUOTED_PAIR_REPLACE_RE
sub
u\1
:l q naelem
lower
group
T l
w;u
uA tuple containing all parsed Forwarded header(s).
Makes an effort to parse Forwarded headers as specified by RFC 7239:
- It adds one (immutable) dictionary per Forwarded 'field-value', ie
per proxy. The element corresponds to the data in the Forwarded
field-value added by the first proxy encountered by the client. Each
subsequent item corresponds to those added by later proxies.
- It checks that every value has valid syntax in general as specified
in section 4: either a 'token' or a 'quoted-string'.
- It un-escapes found escape sequences.
- It does NOT validate 'by' and 'for' contents as specified in section
6.
- It does NOT validate 'host' contents (Host ABNF).
- It does NOT validate 'proto' contents for valid URI scheme names.
Returns a tuple containing one or more immutable dicts
http
uA string representing the scheme of the request.
Hostname is resolved in this order:
- overridden value by .clone(scheme=new_scheme) call.
- type of connection to peer: HTTPS if socket is SSL, HTTP otherwise.
'http' or 'https'.
uRead only property for getting HTTP method.
The value is upper-cased str like 'GET', 'POST', 'PUT' etc.
uRead only property for getting HTTP version of request.
Returns aiohttp.protocol.HttpVersion instance.
get
aHOST
socket
getfqdn
uHostname of the request.
Hostname is resolved in this order:
- overridden value by .clone(host=new_host) call.
- HOST HTTP header
- socket.getfqdn() value
For example, 'example.com' or 'localhost:8080'.
For historical reasons, the port number may be included.
T Olist
Otuple
uRemote IP of client initiated HTTP request.
The IP is resolved in this order:
- overridden value by .clone(remote=new_remote) call.
- peername of opened socket
build
T ascheme
authority
join
uThe full URL of the request.
uThe URL including *PATH INFO* without the host or scheme.
E.g., ``/app/blog``
uThe URL including PATH_INFO and the query string.
E.g, /app/blog?id=10
uThe URL including raw *PATH INFO* without the host or scheme.
Warning, the path is unquoted and may contains non valid URL characters
E.g., ``/my%2Fpath%7Cwith%21some%25strange%24characters``
query
uA multidict with all the variables in the query string.
query_string
uThe query string in the URL.
E.g., id=10
uA case-insensitive multidict proxy with all headers.
uA sequence of pairs for all headers.
parse_http_date
aIF_MODIFIED_SINCE
uThe value of If-Modified-Since HTTP header, or None.
This header is represented as a `datetime` object.
aIF_UNMODIFIED_SINCE
uThe value of If-Unmodified-Since HTTP header, or None.
This header is represented as a `datetime` object.
uExtract `ETag` objects from raw header.
etag_header
aETAG_ANY
aETag
T ais_weak
value
aLIST_QUOTED_ETAG_RE
finditer
T l l l a_etag_values
uBaseRequest._etag_values
a_if_match_or_none_impl
aIF_MATCH
uThe value of If-Match HTTP header, or None.
This header is represented as a `tuple` of `ETag` objects.
aIF_NONE_MATCH
uThe value of If-None-Match HTTP header, or None.
This header is represented as a `tuple` of `ETag` objects.
aIF_RANGE
uThe value of If-Range HTTP header, or None.
This header is represented as a `datetime` object.
should_close
uIs keepalive enabled by client?
aCOOKIE

aSimpleCookie
value
uReturn request cookies.
A read-only dictionary-like object.
aRANGE
T nnare
findall
u^bytes=(\d*)-(\d*)$
urange not in acceptable format
ustart cannot be after end
uNo start or end of range specified
end
uThe content of Range HTTP header.
Return a slice instance.
uReturn raw payload stream.
uDeprecated, use .can_read_body #2005
at_eof
uReturn True if request's HTTP BODY can be read, False otherwise.
aEmptyStreamReader
uReturn True if request has HTTP BODY, False otherwise.
uRelease request.
Eat unread part of HTTP BODY if present.
self
readany
release
uBaseRequest.release
uRead request body if present.
Returns bytes object with full request content.
B
body
extend
aHTTPRequestEntityTooLarge
T amax_size
actual_size
read
uBaseRequest.read
uReturn BODY as text using encoding from .charset.
charset
uutf-8
decode
text
uBaseRequest.text
uReturn BODY as JSON.
loads
json
uBaseRequest.json
uReturn async iterator to process BODY as multipart.
aMultipartReader
multipart
uBaseRequest.multipart
uReturn POST parameters.
a_post
aPOST_METHODS
aMultiDictProxy
aMultiDict
content_type
T u
uapplication/x-www-form-urlencoded
umultipart/form-data
umultipart/form-data
anext
field
aCONTENT_TYPE
aBodyPartReader
name
filename
run_in_executor
tempfile
aTemporaryFile
read_chunk
T l   T asize
chunk
tmp
write
size
max_size
close
seek
uapplication/octet-stream
aFileField
cast
aBufferedReader
out
add
T tT adecode
startswith
T utext/
get_charset
T adefault
uTo decode nested multipart you need to use custom reader
parse_qsl
rstrip
T akeep_blank_values
encoding
post
uBaseRequest.post
uExtra info from protocol transport
T aascii
backslashreplace
T aascii
u<{} {} {} >
a__name__
a_prepare_hook
uBaseRequest._prepare_hook
set_exception
file
aATTRS
uSetting custom {}.{} attribute is discouraged
a__class__
a__setattr__
clone
T amethod
rel_url
headers
scheme
host
remote
client_max_size
aRequest
a_match_info
uResult of route resolving.
current_app
uApplication instance.
apps
app
index
aChainMapProxy
a_apps
on_response_prepare
send
response
uRequest._prepare_hook
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
asyncio
datetime
io
string
types
uhttp.cookies
T aSimpleCookie
aTYPE_CHECKING
aAny
aDict
aFinal
aIterator
aMapping
aMutableMapping
aOptional
aPattern
aTuple
aUnion
uurllib.parse
T aparse_qsl
attr
multidict
T aCIMultiDict
aCIMultiDictProxy
aMultiDict
aMultiDictProxy
aMultiMapping
aMultiMapping
yarl
T aURL
T ahdrs
abc
T aAbstractStreamWriter
aAbstractStreamWriter
helpers
T a_SENTINEL
aDEBUG
aETAG_ANY
aLIST_QUOTED_ETAG_RE
aChainMapProxy
aETag
aHeadersMixin
parse_http_date
reify
sentinel
set_exception
a_SENTINEL
aDEBUG
aHeadersMixin
reify
http_parser
T aRawRequestMessage
aRawRequestMessage
http_writer
T aHttpVersion
aHttpVersion
T aBodyPartReader
aMultipartReader
streams
T aEmptyStreamReader
aStreamReader
aStreamReader
typedefs
T aDEFAULT_JSON_DECODER
aJSONDecoder
aLooseHeaders
aRawHeaders
aStrOrURL
aDEFAULT_JSON_DECODER
aJSONDecoder
aLooseHeaders
aRawHeaders
aStrOrURL
web_exceptions
T aHTTPRequestEntityTooLarge
web_response
T aStreamResponse
aStreamResponse
T aBaseRequest
aFileField
aRequest
a__all__
wsT tppT aauto_attribs
frozen
slots
