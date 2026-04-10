# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.web_request

a__qualname__
digits
ascii_letters
u!#$%&'*+.^_`|~-
a_TCHAR
w[u]+
a_TOKEN
u[{}]
T_l	l l!l#l$l%l&l'l(l)l*l+l,l-l.l/l0l1l2l3l4l5l6l7l8l9l:l;l<l=l>l?l@lAlBlClDlElFlGlHlIlJlKlLlMlNlOlPlQlRlSlTlUlVlWlXlYlZl[l\l]l^l_l`lalblcldlelflglhliljlklllmlnlolplqlrlsltlulvlwlxlylzl{l|l}l~a_QDTEXT
u\\[\t !-~]
a_QUOTED_PAIR
u"(?:{quoted_pair}|{qdtext})*"
T aqdtext
quoted_pair
a_QUOTED_STRING
u({token})=({token}|{quoted_string})(:\d{{1,4}})?
T atoken
quoted_string
a_FORWARDED_PAIR
compile
T u\\([\t !-~])
a__prepare__
aBaseRequest
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
aMETH_PATCH
aMETH_POST
aMETH_PUT
aMETH_TRACE
aMETH_DELETE
frozenset
L a_message
a_protocol
a_payload_writer
a_payload
a_headers
a_method
a_version
a_rel_url
a_post
a_read_bytes
a_state
a_cache
a_task
a_client_max_size
a_loop
a_transport_sslcontext
a_transport_peername
P a_loop
a_version
a_transport_sslcontext
a_payload
a_method
a_post
a_state
a_rel_url
a_cache
a_headers
a_client_max_size
a_task
a_payload_writer
a_read_bytes
a_protocol
a_transport_peername
a_message
str
bytes
D aclient_max_size
state
scheme
host
remote
l  @nnnnamessage
payload
protocol
aRequestHandler
payload_writer
task
uasyncio.Task[None]
loop
aAbstractEventLoop
int
return
a__init__
uBaseRequest.__init__
rel_url
uBaseRequest.clone
property
D areturn
uasyncio.Task[None]
uBaseRequest.task
D areturn
aRequestHandler
uBaseRequest.protocol
aTransport
uBaseRequest.transport
writer
uBaseRequest.writer
uBaseRequest.client_max_size
uBaseRequest.message
uBaseRequest.rel_url
uBaseRequest.loop
key
uBaseRequest.__getitem__
a__setitem__
uBaseRequest.__setitem__
a__delitem__
uBaseRequest.__delitem__
a__len__
uBaseRequest.__len__
a__iter__
uBaseRequest.__iter__
bool
secure
uBaseRequest.secure
forwarded
uBaseRequest.forwarded
uBaseRequest.scheme
uBaseRequest.method
uBaseRequest.version
uBaseRequest.host
uBaseRequest.remote
uBaseRequest.url
uBaseRequest.path
path_qs
uBaseRequest.path_qs
raw_path
uBaseRequest.raw_path
D areturn
uMultiMapping[str]
uBaseRequest.query
uBaseRequest.query_string
uBaseRequest.headers
uBaseRequest.raw_headers
if_modified_since
uBaseRequest.if_modified_since
if_unmodified_since
uBaseRequest.if_unmodified_since
staticmethod
classmethod
header_value
uBaseRequest._if_match_or_none_impl
if_match
uBaseRequest.if_match
if_none_match
uBaseRequest.if_none_match
if_range
uBaseRequest.if_range
keep_alive
uBaseRequest.keep_alive
cookies
uBaseRequest.cookies
slice
http_range
uBaseRequest.http_range
content
uBaseRequest.content
has_body
uBaseRequest.has_body
can_read_body
uBaseRequest.can_read_body
body_exists
uBaseRequest.body_exists
D areturn
nD areturn
uMultiDictProxy[Union[str, bytes, FileField]]
T nadefault
uBaseRequest.get_extra_info
a__repr__
uBaseRequest.__repr__
other
object
a__eq__
uBaseRequest.__eq__
a__bool__
uBaseRequest.__bool__
exc
aBaseException
a_cancel
uBaseRequest._cancel
a_finish
uBaseRequest._finish
a__orig_bases__
P a_match_info
aUrlMappingMatchInfo
val
uRequest.__setattr__
uRequest.clone
D areturn
aUrlMappingMatchInfo
match_info
uRequest.match_info
D areturn
aApplication
uRequest.app
config_dict
uRequest.config_dict
uaiohttp\web_request.py
T a.0
wcT a.0
wkwvu<module aiohttp.web_request>
T a__class__
T aself
T aself
key
T aself
other
T aself
message
payload
protocol
payload_writer
task
loop
client_max_size
state
scheme
host
remote
url
transport
T aself
ascii_encodable_path
T aself
name
val
a__class__
T aself
key
value
T aself
exc
T aetag_header
match
is_weak
value
garbage
T aself
file_name
file_field_object
T acls
header_value
T aself
response
T aself
response
match_info
app
on_response_prepare
T aself
match_info
T aself
method
rel_url
headers
scheme
host
remote
client_max_size
dct
new_url
message
kwargs
T aself
method
rel_url
headers
scheme
host
remote
client_max_size
ret
new_ret
a__class__
T aself
match_info
lst
app
idx
sublist
T aself
raw
parsed
T aself
elem
elems
field_value
length
pos
need_separator
match
name
value
port
T aself
name
default
protocol
transport
T aself
host
T aself
rng
start
end
pattern
T aself
loads
body
T aself
out
content_type
multipart
max_size
field
size
field_ct
tmp
chunk
ff
value
charset
data
T aself
body
chunk
body_size
T aself
bytes_body
encoding
a__spec__
.aiohttp.web_response
W"
a_state
a_headers
aCIMultiDict
a_set_status
uInitialize a new stream response object.
_real_headers is an internal parameter used to pass a pre-populated
headers object. It is used by the `Response` class to avoid copying
the headers when creating a new response object. It is not intended
to be used by external code.
a_eof_sent
a_payload_writer
a_req
task
a_status
a_chunked
a_compression
a_reason
prepared
T uCannot change the response status code after the headers have been sent
aREASON_PHRASES
get

w
uReason cannot contain \n
a_keep_alive
a_body_length
warnings
warn
uoutput_length is deprecated
aDeprecationWarning
buffer_size
hdrs
aCONTENT_LENGTH
uYou can't enable chunked encoding when a content length is set
uChunk size is deprecated #1615
uEnables automatic chunked transfer encoding.
aContentCoding
deflate
identity
uUsing boolean for force is deprecated #3318
T uforce should one of None, bool or ContentEncoding
a_compression_force
a_compression_strategy
uEnables response compression encoding.
a_cookies
aSimpleCookie
expires
T aexpires
uThu, 01 Jan 1970 00:00:00 GMT
wcadomain
umax-age
path
secure
httponly
version
samesite
uSet or update response cookie.
Sets new cookie or updates existent with new value.
Also updates only those params which are not None.
pop
set_cookie
T amax_age
expires
domain
path
secure
httponly
samesite
uDelete cookie.
Creates new empty expired cookie.
a__class__
content_length
uYou can't set content length when chunked encoding is enable
content_type
a_content_type
a_generate_content_type_header
charset
uapplication/octet-stream
uSetting charset for application/octet-stream doesn't make sense, setup content_type first
a_content_dict
T acharset
nalower
parse_http_date
aLAST_MODIFIED
uThe value of Last-Modified HTTP header, or None.
This header is represented as a `datetime` object.
T Oint
Ofloat
time
strftime
u%a, %d %b %Y %H:%M:%S GMT
gmtime
math
ceil
datetime
utctimetuple
aETAG
aETAG_ANY
aETag
T avalue
aQUOTED_ETAG_RE
fullmatch
group
T l l T ais_weak
value
value
validate_etag_value
w"ais_weak
uW/"
uUnsupported etag type:
u. etag must be str, ETag or None
u;
items
w=u<genexpr>
uStreamResponse._generate_content_type_header.<locals>.<genexpr>
coding
self
aCONTENT_ENCODING
enable_compression
popall
a_do_start_compression
uStreamResponse._do_start_compression
request
headers
aACCEPT_ENCODING
aCONTENT_CODINGS
a_start_compression
uStreamResponse._start_compression
must_be_empty_body
method
status
a_must_be_empty_body
a_start
prepare
uStreamResponse.prepare
a_prepare_headers
a_prepare_hook
a_write_headers
uStreamResponse._start
keep_alive
values
output
T u
T aheader
:l nnaadd
aSET_COOKIE
aHttpVersion11
uUsing chunked encoding is forbidden for HTTP/{0.major}.{0.minor}
enable_chunking
chunked
aTRANSFER_ENCODING
a_length_check
length
should_remove_content_length
writer
setdefault
aCONTENT_TYPE
aDATE
rfc822_formatted_time
aSERVER
aSERVER_SOFTWARE
aCONNECTION
aHttpVersion10
ukeep-alive
close
uStreamResponse._prepare_headers
uHTTP/
w.w awrite_headers
uStreamResponse._write_headers
data
T Obytes
Obytearray
Omemoryview
udata argument must be byte-ish (%r)
uCannot call write() after write_eof()
uCannot call write() before prepare()
write
uStreamResponse.write
T uEOF has already been sent
T uResponse has not been started
udrain method is deprecated, use await resp.write()
D astacklevel
l adrain
uStreamResponse.drain
write_eof
output_size
uStreamResponse.write_eof
eof
unot prepared
w<a__name__
reason
w>ubody and text are not allowed together
ucharset must not be in content_type argument
upassing both Content-Type header and content_type or charset params is forbidden
utext argument must be str (%r)
utext/plain
uutf-8
u; charset=
encode
a__init__
real_headers
T astatus
reason
a_real_headers
text
body
a_zlib_executor_size
a_zlib_executor
a_body
T Obytes
Obytearray
payload
aPAYLOAD_REGISTRY
aLookupError
uUnsupported body type %r
a_compressed_body
decode
aPayload
uContent length is set automatically
udata arg is not supported, got
cast
uResponse.write_eof
size
w0l  aMETH_HEAD_ALL
uResponse._start
aZLibCompressor
T aencoding
max_sync_chunk_size
executor
aLARGE_BODY_SIZE
uSynchronous compression of large response bodies (
u bytes) might block the async event loop. Consider providing a custom value to zlib_executor_size/zlib_executor response properties or disabling compression on it.
compress
flush
uResponse._do_start_compression
sentinel
uonly one of data, text, or body should be specified
aResponse
T atext
body
status
reason
headers
content_type
a__doc__
a__file__
origin
has_location
a__cached__
asyncio
ucollections.abc
collections
enum
json
zlib
uconcurrent.futures
T aExecutor
aExecutor
http
T aHTTPStatus
aHTTPStatus
uhttp.cookies
T aSimpleCookie
aTYPE_CHECKING
aAny
aDict
aIterator
aMutableMapping
aOptional
aUnion
multidict
T aCIMultiDict
istr
istr
T ahdrs
payload
abc
T aAbstractStreamWriter
aAbstractStreamWriter
compression_utils
T aZLibCompressor
helpers
T
aETAG_ANY
aQUOTED_ETAG_RE
aETag
aHeadersMixin
must_be_empty_body
parse_http_date
rfc822_formatted_time
sentinel
should_remove_content_length
validate_etag_value
aHeadersMixin
T aSERVER_SOFTWARE
aHttpVersion10
aHttpVersion11
T aPayload
typedefs
T aJSONEncoder
aLooseHeaders
aJSONEncoder
aLooseHeaders
phrase
l  @T aContentCoding
aStreamResponse
aResponse
json_response
a__all__
aBaseClass
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
