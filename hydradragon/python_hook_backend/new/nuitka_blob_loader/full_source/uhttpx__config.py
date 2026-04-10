# Reconstructed from integrated Nuitka blob
# Module: uhttpx._config

a__qualname__
T tntD averify
cert
trust_env
return
ussl.SSLContext | str | bool
uCertTypes | None
bool
ussl.SSLContext
create_ssl_context

Timeout configuration.
**Usage**:
Timeout(None)               # No timeouts.
Timeout(5.0)                # 5s timeout on all operations.
Timeout(None, connect=5.0)  # 5s timeout on connect, no other timeouts.
Timeout(5.0, connect=10.0)  # 10s timeout on connect. 5s timeout elsewhere.
Timeout(5.0, pool=None)     # No timeout on acquiring connection from pool.
# 5s timeout elsewhere.
D atimeout
connect
read
write
pool
return
uTimeoutTypes | UnsetType
uNone | float | UnsetType
uNone | float | UnsetType
uNone | float | UnsetType
uNone | float | UnsetType
aNone
a__init__
uTimeout.__init__
D areturn
udict[str, float | None]
as_dict
uTimeout.as_dict
D aother
return
utyping.Any
bool
a__eq__
uTimeout.__eq__
D areturn
str
a__repr__
uTimeout.__repr__

Configuration for limits to various client behaviors.
**Parameters:**
* **max_connections** - The maximum number of concurrent connections that may be
established.
* **max_keepalive_connections** - Allow the connection pool to maintain
keep-alive connections below this point. Should be less than or equal
to `max_connections`.
* **keepalive_expiry** - Time limit on idle keep-alive connections in seconds.
aLimits
D amax_connections
max_keepalive_connections
keepalive_expiry
nnf
@D amax_connections
max_keepalive_connections
keepalive_expiry
return
uint | None
uint | None
ufloat | None
aNone
uLimits.__init__
uLimits.__eq__
uLimits.__repr__
aProxy
D assl_context
auth
headers
nnnD aurl
ssl_context
auth
headers
return
uURL | str
ussl.SSLContext | None
utuple[str, str] | None
uHeaderTypes | None
aNone
uProxy.__init__
D areturn
utuple[bytes, bytes] | None
raw_auth
uProxy.raw_auth
uProxy.__repr__
T f
@T atimeout
aDEFAULT_TIMEOUT_CONFIG
T ldl T amax_connections
max_keepalive_connections
aDEFAULT_LIMITS
l aDEFAULT_MAX_REDIRECTS
uhttpx\_config.py
u<module httpx._config>
T a__class__
T aself
other
T aself
max_connections
max_keepalive_connections
keepalive_expiry
T aself
url
ssl_context
auth
headers
T aself
timeout
connect
read
write
pool
T aself
class_name
T aself
auth
url_str
auth_str
headers_str
T aself
T averify
cert
trust_env
ssl
warnings
certifi
ctx
message
a__spec__
.httpx._content
a_stream
self
a__iter__
uByteStream.__iter__
a__aiter__
uByteStream.__aiter__
a_is_stream_consumed
inspect
isgenerator
a_is_generator
aStreamConsumed
read
aCHUNK_SIZE
chunk
uIteratorByteStream.__iter__
isasyncgen
aread
uAsyncIteratorByteStream.__aiter__
aStreamClosed
uUnattachedStream.__aiter__
T Obytes
Ostr
encode
T uutf-8
uContent-Length
aByteStream
aIterable
peek_filelike_length
D uTransfer-Encoding
chunked
aIteratorByteStream
aAsyncIterable
aAsyncIteratorByteStream
uUnexpected type for 'content',

items
T Olist
Otuple
plain_data
primitive_value_to_str
urlencode
D adoseq
tuContent-Type
uapplication/x-www-form-urlencoded
aMultipartStream
T adata
files
boundary
get_headers
utext/plain; charset=utf-8
utext/html; charset=utf-8
json_dumps
D aensure_ascii
separators
allow_nan
FT w,w:Fuapplication/json
aMapping
warnings
warn
uUse 'content=<...>' to upload raw bytes/text content.
aDeprecationWarning
D astacklevel
l aencode_content
encode_multipart_data
encode_urlencoded_data
encode_json
T c

Handles encoding the given `content`, `data`, `files`, and `json`,
returning a two-tuple of (<headers>, <stream>).
encode_text
encode_html

Handles encoding the given `content`, returning a two-tuple of
(<headers>, <stream>).
a__doc__
a__file__
origin
has_location
a__cached__
annotations
json
T adumps
dumps
aAny
aAsyncIterator
aIterator
uurllib.parse
T aurlencode
a_exceptions
T aStreamClosed
aStreamConsumed
a_multipart
T aMultipartStream
a_types
T aAsyncByteStream
aRequestContent
aRequestData
aRequestFiles
aResponseContent
aSyncByteStream
aAsyncByteStream
aRequestContent
aRequestData
aRequestFiles
aResponseContent
aSyncByteStream
a_utils
T apeek_filelike_length
primitive_value_to_str
a__all__
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
