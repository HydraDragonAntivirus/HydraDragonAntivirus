# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.client_proto

uHelper class to adapt between Protocol and StreamReader.
a__qualname__
loop
aAbstractEventLoop
return
uResponseHandler.__init__
property
bool
upgraded
uResponseHandler.upgraded
uResponseHandler.should_close
D areturn
naforce_close
uResponseHandler.force_close
uResponseHandler.close
is_connected
uResponseHandler.is_connected
exc
aBaseException
uResponseHandler.connection_lost
eof_received
uResponseHandler.eof_received
uResponseHandler.pause_reading
uResponseHandler.resume_reading
exc_cause
uResponseHandler.set_exception
parser
set_parser
uResponseHandler.set_parser
D	atimer
skip_payload
read_until_eof
auto_decompress
read_timeout
read_bufsize
timeout_ceil_threshold
max_line_size
max_field_size
nFptnl   l l ?l ?atimer
skip_payload
read_until_eof
auto_decompress
read_timeout
float
read_bufsize
int
timeout_ceil_threshold
max_line_size
max_field_size
set_response_params
uResponseHandler.set_response_params
uResponseHandler._drop_timeout
uResponseHandler._reschedule_timeout
start_timeout
uResponseHandler.start_timeout
uResponseHandler.read_timeout
setter
uResponseHandler._on_read_timeout
data
bytes
uResponseHandler.data_received
a__orig_bases__
uaiohttp\client_proto.py
u<module aiohttp.client_proto>
T a__class__
T aself
loop
T aself
T aself
exc
T aself
timeout
T aself
transport
T
self
exc
original_connection_error
reraised_exc
connection_closed_cleanly
uncompleted
underlying_exc
client_payload_exc_msg
underlying_non_eof_exc
a__class__
T
self
data
payload
eof
tail
messages
upgraded
underlying_exc
exc
message
T aself
a__class__
T aself
read_timeout
T aself
exc
exc_cause
a__class__
T aself
parser
payload
data
T aself
timer
skip_payload
read_until_eof
auto_decompress
read_timeout
read_bufsize
timeout_ceil_threshold
max_line_size
max_field_size
data
a__spec__
.aiohttp.client_reqrep
x3
aHAS_BROTLI
ugzip, deflate, br
ugzip, deflate
a__new__
a_SENTINEL
uCreate a new RequestInfo instance.
For backwards compatibility, the real_url parameter is optional.
aHASHFUNC_BY_DIGESTLEN
get
ufingerprint has invalid length
md5
sha1
umd5 and sha1 are insecure and not supported. Use sha256.
a_hashfunc
a_fingerprint
get_extra_info
T asslcontext
T assl_object
getpeercert
T tT abinary_form
digest
T apeername
unot enough values to unpack (expected at least 2, got %d)
aServerFingerprintMismatch
warnings
warn
uverify_ssl is deprecated, use ssl=False instead
aDeprecationWarning
D astacklevel
l uverify_ssl, ssl_context, fingerprint and ssl parameters are mutually exclusive
ussl_context is deprecated, use ssl=context instead
ufingerprint is deprecated, use ssl=Fingerprint(fingerprint) instead
aFingerprint
aSSL_ALLOWED_TYPES
ussl should be SSLContext, bool, Fingerprint or None, got {!r} instead.
uapplication/json
json_re
match
asyncio
get_event_loop
a_CONTAINS_CONTROL_CHAR_RE
search
uMethod cannot contain non-token characters

u (found at least
group
w)aURL
a_session
extend_query
original_url
raw_fragment
with_fragment
T naurl
upper
method
chunked
compress
loop
length
aClientResponse
response_class
aTimerNoop
a_timer
a_ssl
server_hostname
get_debug
traceback
extract_stack
a_getframe
T l a_source_traceback
update_version
update_host
update_headers
update_auto_headers
update_cookies
update_content_encoding
update_auth
update_proxy
update_body_from_data
aGET_METHODS
update_transfer_encoding
update_expect_continue
a_traces
a_ClientRequest__writer
a_skip_auto_headers
aCIMultiDict
remove_done_callback
a_ClientRequest__reset_writer
add_done_callback
scheme
a_SSL_SCHEMES
proxy_headers
items
aConnectionKey
raw_host
port
proxy
proxy_auth
aCIMultiDictProxy
headers
aRequestInfo
aInvalidURL
raw_user
raw_password
helpers
aBasicAuth
user
password
auth
uUpdate destination host, port and connection type (ssl).
split
T w.l astrip
http
aHttpVersion
uCan not parse http version number:
version
uConvert request version to two elements tuple.
parser HTTP version '1.1' => (1, 1)
host_port_subcomponent
hdrs
aHOST
aMultiDictProxy
aMultiDict
aHOST_ALL
self
add
uUpdate request headers.
sorted
copy
extend
aDEFAULT_HEADERS
used_headers
aUSER_AGENT
aSERVER_SOFTWARE
u<genexpr>
uClientRequest.update_auto_headers.<locals>.<genexpr>
aSimpleCookie
aCOOKIE
load
aMapping
aMorsel
key
set
value
coded_value
wcaoutput
T u
w;T aheader
sep
uUpdate request cookies header.
aCONTENT_ENCODING
ucompress can not be set if Content-Encoding header is set
deflate
uSet request content encoding.
aTRANSFER_ENCODING
lower
uchunked can not be set if "Transfer-Encoding: chunked" header is set
aCONTENT_LENGTH
uchunked can not be set if Content-Length header is set
body
uAnalyze transfer-encoding header.
host
netrc_from_env
contextlib
suppress
T ELookupError
a__enter__
a__exit__
basicauth_from_netrc
T nnnuBasicAuth() tuple is required instead
encode
aAUTHORIZATION
uSet basic auth.
aFormData
payload
aPAYLOAD_REGISTRY
D adisposition
naLookupError
size
u100-continue
aEXPECT
create_future
a_continue
uproxy_auth must be None or BasicAuth() tuple
uSupport coroutines that yields bytes objects.
writer
drain
conn
protocol
aPayload
write
T Obytes
Obytearray
errno
aTimeoutError
aClientOSError
uCan not write request body for
set_exception
aCancelledError
close
aClientConnectionError
uFailed to send bytes into the underlying connection
write_eof
start_timeout
write_bytes
uClientRequest.write_bytes
aMETH_CONNECT
host_subcomponent
w:ais_ssl
raw_path_qs
aStreamWriter
partial
a_on_chunk_request_sent
a_on_headers_request_sent
T aon_chunk_sent
on_headers_sent
enable_compression
enable_chunking
aPOST_METHODS
aCONTENT_TYPE
uapplication/octet-stream
aCONNECTION
a_connector
force_close
aHttpVersion11
aHttpVersion10
ukeep-alive
w u HTTP/
major
w.aminor
write_headers
writing_paused
create_task
done
a_writer
set_eof
task
request_info
T awriter
continue100
timer
request_info
traces
loop
session
response
send
uClientRequest.send
uClientRequest.close
is_closed
cancel
send_request_chunk_sent
chunk
uClientRequest._on_chunk_request_sent
send_request_headers
uClientRequest._on_headers_request_sent
a_real_url
a_url
a_request_info
a_cache
a_loop
a_resolve_charset
a_ClientResponse__writer
uThe writer task for streaming data.
_writer is only provided for backwards compatibility
for subclasses that may need to access it.
a_ClientResponse__reset_writer
uSet the writer task for streaming data.
a_cookies
uDeprecated, use .url #1654
D astacklevel
l a_headers
a_raw_headers
aCONTENT_DISPOSITION
multipart
parse_content_disposition
aMappingProxyType
content_disposition_filename
aContentDisposition
a_closed
a_connection
release
a_cleanup_writer
source
uUnclosed response
aResourceWarning
client_response
message
uUnclosed response
source_traceback
call_exception_handler
aStringIO
reason
T aascii
backslashreplace
decode
T aascii
aNone
print
u<ClientResponse({}) [{} {}]>
status
T afile
getvalue
a_history
uA sequence of of responses, if redirects occurred.
u,
getall
link
re
u,(?=\s*<)
u\s*<(.*)>(.*)
groups
T w;:l nnu^\s*(\S*)\s*=\s*(['\"]?)(.*?)(\2)\s*$
wMarel
join
links
uStart response processing.
connection
a_protocol
read
aHttpProcessingError
aClientResponseError
history
code
T astatus
message
headers
ldl  leaset_result
on_eof
a_response_eof
raw_headers
content
aSET_COOKIE
cookies
aCookieError
client_logger
warning
uCan not load response cookies: %s
start
uClientResponse.start
upgraded
a_release_connection
a_released
a_notify_content
noop
l  uReturns ``True`` if ``status`` is less than ``400``, ``False`` if not.
This is **not** a check for ``200 OK`` but a check that the response
status is under 400.
ok
a_in_context
u<lambda>
uClientResponse._release_connection.<locals>.<lambda>
a_wait_released
uClientResponse._wait_released
exception
a_CONNECTION_CLOSED_EXCEPTION
wait_for_close
uClientResponse.wait_for_close
uRead response payload.
a_body
send_response_chunk_received
T uConnection closed
uClientResponse.read
parse_mimetype
parameters
T acharset
T ELookupError
EValueError
codecs
lookup
name
type
application
subtype
json
rdap
uutf-8
uCannot compute fallback encoding of a not yet read body
uRead response payload and decode.
encoding
get_encoding
errors
T aerrors
text
uClientResponse.text
uRead and decodes JSON response.
content_type
a_is_expected_content_type
aContentTypeError
uAttempt to decode JSON with unexpected mimetype: %s
loads
uClientResponse.json
a__aenter__
uClientResponse.__aenter__
a__aexit__
uClientResponse.__aexit__
a__doc__
a__file__
origin
has_location
a__cached__
functools
io
sys
hashlib
T amd5
sha1
sha256
sha256
uhttp.cookies
T aCookieError
aMorsel
aSimpleCookie
aTracebackType
aTYPE_CHECKING
aAny
aCallable
aDict
aIterable
aList
aNamedTuple
aOptional
aTuple
aType
aUnion
attr
multidict
T aCIMultiDict
aCIMultiDictProxy
aMultiDict
aMultiDictProxy
yarl
T aURL
T ahdrs
helpers
http
multipart
payload
abc
T aAbstractStreamWriter
aAbstractStreamWriter
client_exceptions
T aClientConnectionError
aClientOSError
aClientResponseError
aContentTypeError
aInvalidURL
aServerFingerprintMismatch
compression_utils
T aHAS_BROTLI
formdata
T aFormData
T a_SENTINEL
aBaseTimerContext
aBasicAuth
aHeadersMixin
aTimerNoop
basicauth_from_netrc
netrc_from_env
noop
reify
set_exception
set_result
aBaseTimerContext
aHeadersMixin
reify
T aSERVER_SOFTWARE
aHttpVersion
aHttpVersion10
aHttpVersion11
aStreamWriter
log
T aclient_logger
streams
T aStreamReader
aStreamReader
typedefs
T aDEFAULT_JSON_DECODER
aJSONDecoder
aLooseCookies
aLooseHeaders
aQuery
aRawHeaders
aDEFAULT_JSON_DECODER
aJSONDecoder
aLooseCookies
aLooseHeaders
aQuery
aRawHeaders
ssl
T aSSLContext
aSSLContext
T aClientRequest
aClientResponse
aRequestInfo
aFingerprint
a__all__
compile
T u[^-!#$%&'*+.^_`|~0-9a-zA-Z]
T u^application/(?:[\w.+-]+?\+)?json
D areturn
Ostr
a_gen_default_accept_encoding
wsT tppT aauto_attribs
frozen
slots
