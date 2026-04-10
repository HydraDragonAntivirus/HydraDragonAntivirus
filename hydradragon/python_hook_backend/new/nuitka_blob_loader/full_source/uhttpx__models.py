# Reconstructed from integrated Nuitka blob
# Module: uhttpx._models


HTTP headers, as a case-insensitive multi-dict.
a__qualname__
T nnD aheaders
encoding
return
uHeaderTypes | None
ustr | None
aNone
uHeaders.__init__
property
D areturn
str
uHeaders.encoding
setter
D avalue
return
str
aNone
D areturn
ulist[tuple[bytes, bytes]]
uHeaders.raw
D areturn
utyping.KeysView[str]
uHeaders.keys
D areturn
utyping.ValuesView[str]
values
uHeaders.values
D areturn
utyping.ItemsView[str, str]
uHeaders.items
D areturn
ulist[tuple[str, str]]
uHeaders.multi_items
D akey
default
return
str
utyping.Any
utyping.Any
uHeaders.get
T FD akey
split_commas
return
str
bool
ulist[str]
uHeaders.get_list
D aheaders
return
uHeaderTypes | None
aNone
update
uHeaders.update
D areturn
aHeaders
copy
uHeaders.copy
D akey
return
str
puHeaders.__getitem__
D akey
value
return
str
paNone
a__setitem__
uHeaders.__setitem__
D akey
return
str
aNone
a__delitem__
uHeaders.__delitem__
D akey
return
utyping.Any
bool
a__contains__
uHeaders.__contains__
D areturn
utyping.Iterator[typing.Any]
a__iter__
uHeaders.__iter__
D areturn
int
a__len__
uHeaders.__len__
D aother
return
utyping.Any
bool
a__eq__
uHeaders.__eq__
a__repr__
uHeaders.__repr__
a__orig_bases__
aRequest
D	aparams
headers
cookies
content
data
files
json
stream
extensions
nnnnnnnnnD amethod
url
params
headers
cookies
content
data
files
json
stream
extensions
return
str
uURL | str
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uRequestContent | None
uRequestData | None
uRequestFiles | None
utyping.Any | None
uSyncByteStream | AsyncByteStream | None
uRequestExtensions | None
aNone
uRequest.__init__
D adefault_headers
return
udict[str, str]
aNone
uRequest._prepare
D areturn
bytes
uRequest.content
uRequest.read
uRequest.__repr__
D areturn
udict[str, typing.Any]
a__getstate__
uRequest.__getstate__
D astate
return
udict[str, typing.Any]
aNone
a__setstate__
uRequest.__setstate__
aResponse
D
headers
content
text
html
json
stream
request
extensions
history
default_encoding
nnnnnnnnnuutf-8
D astatus_code
headers
content
text
html
json
stream
request
extensions
history
default_encoding
return
int
uHeaderTypes | None
uResponseContent | None
ustr | None
ustr | None
utyping.Any
uSyncByteStream | AsyncByteStream | None
uRequest | None
uResponseExtensions | None
ulist[Response] | None
ustr | typing.Callable[[bytes], str]
aNone
uResponse.__init__
uResponse._prepare
D areturn
udatetime.timedelta
elapsed
uResponse.elapsed
D aelapsed
return
udatetime.timedelta
aNone
D areturn
aRequest
uResponse.request
D avalue
return
aRequest
aNone
uResponse.http_version
uResponse.reason_phrase
D areturn
aURL
uResponse.url
uResponse.content
text
uResponse.text
D areturn
ustr | None
uResponse.encoding
uResponse.charset_encoding
D areturn
aContentDecoder
uResponse._get_content_decoder
D areturn
bool
uResponse.is_informational
uResponse.is_success
uResponse.is_redirect
uResponse.is_client_error
uResponse.is_server_error
uResponse.is_error
uResponse.has_redirect_location
D areturn
aResponse
raise_for_status
uResponse.raise_for_status
D akwargs
return
utyping.Any
utyping.Any
uResponse.json
D areturn
aCookies
cookies
uResponse.cookies
D areturn
udict[str | None, dict[str, str]]
uResponse.links
num_bytes_downloaded
uResponse.num_bytes_downloaded
uResponse.__repr__
uResponse.__getstate__
uResponse.__setstate__
uResponse.read
D achunk_size
return
uint | None
utyping.Iterator[bytes]
D achunk_size
return
uint | None
utyping.Iterator[str]
D areturn
utyping.Iterator[str]
D areturn
aNone
uResponse.close
D achunk_size
return
uint | None
utyping.AsyncIterator[bytes]
D achunk_size
return
uint | None
utyping.AsyncIterator[str]
D areturn
utyping.AsyncIterator[str]

HTTP Cookies, as a mutable mapping.
D acookies
return
uCookieTypes | None
aNone
uCookies.__init__
D aresponse
return
aResponse
aNone
uCookies.extract_cookies
D arequest
return
aRequest
aNone
uCookies.set_cookie_header
T u
w/D aname
value
domain
path
return
str
pppaNone
uCookies.set
D aname
default
domain
path
return
str
ustr | None
ustr | None
ustr | None
ustr | None
uCookies.get
D aname
domain
path
return
str
ustr | None
ustr | None
aNone
uCookies.delete
D adomain
path
return
ustr | None
ustr | None
aNone
uCookies.clear
uCookies.update
D aname
value
return
str
paNone
uCookies.__setitem__
D aname
return
str
puCookies.__getitem__
D aname
return
str
aNone
uCookies.__delitem__
uCookies.__len__
uCookies.__iter__
a__bool__
uCookies.__bool__
uCookies.__repr__

Wraps a `Request` instance up in a compatibility interface suitable
for use with `CookieJar` operations.
uCookies._CookieCompatRequest
uCookies._CookieCompatRequest.__init__
uCookies._CookieCompatRequest.add_unredirected_header
uCookies._CookieCompatResponse
uCookies._CookieCompatResponse.__init__
D areturn
uemail.message.Message
uCookies._CookieCompatResponse.info
uhttpx\_models.py
T a.0
cookie
u<module httpx._models>
T a__class__
T aself
w_T aself
key
header_key
T aself
name
T aself
key
del_key
pop_indexes
idx
T aself
other
other_headers
self_list
other_list
T aself
name
value
T aself
key
normalized_key
items
T aself
T aself
request
a__class__
T aself
response
T aself
cookies
key
value
cookie
T aself
headers
encoding
wkwvabytes_key
bytes_value
Taself
method
url
params
headers
cookies
content
data
files
json
stream
extensions
content_type
T aself
status_code
headers
content
text
html
json
stream
request
extensions
history
default_encoding
T aself
cookies_repr
T aself
class_name
encoding_str
as_list
as_dict
no_duplicate_keys
T aself
class_name
url
T aself
key
value
set_key
set_value
lookup_key
found_indexes
idx
T aself
state
name
value
T aself
decoders
values
value
decoder_cls
T akey
encoding
T avalue
encoding
T aitems
wkwvT acontent_type
msg
T	avalue
links
replace_chars
val
url
params
link
param
key
T aself
default_headers
auto_headers
key
value
has_host
has_content_length
T aself
default_headers
key
value
T aself
key
value
a__class__
T aself
chunk_size
wiadecoder
chunker
raw_bytes
decoded
chunk
T aself
decoder
text
line
T aself
chunk_size
chunker
raw_stream_bytes
chunk
T aself
chunk_size
decoder
chunker
byte_content
text_content
chunk
T aself
content_type
T aself
domain
path
args
T aself
name
domain
path
remove
cookie
T aself
elapsed
T aself
encoding
key
value
T aself
value
T aself
encoding
T aself
response
urllib_response
urllib_request
T aself
name
default
domain
path
value
cookie
message
T aself
key
default
T aself
key
split_commas
get_header_key
values
split_values
value
T aself
http_version
T aself
info
key
value
T aself
values_dict
w_akey
value
str_key
str_value
T aself
kwargs
T aself
header
T aself
request
message
status_class
error_types
error_type
T aself
reason_phrase
T aself
name
value
domain
path
kwargs
cookie
T aself
request
urllib_request
T aself
content
decoder
T aself
cookies
cookie
T aself
headers
key
a__spec__
.httpx._multipart
F
D amatch
return
utyping.Match[str]
str
replacer
u_format_form_param.<locals>.replacer
a_HTML5_FORM_ENCODING_RE
sub

u="
w"u
Encode a name/value pair within a multipart form.
a_HTML5_FORM_ENCODING_REPLACEMENTS
group
T l
mimetypes
guess_type
uapplication/octet-stream

Guesses the mimetype based on a filename. Defaults to `application/octet-stream`.
Returns `None` if `filename` is `None` or empty.
startswith
T cmultipart/form-data
d;asplit
T d;astrip
lower
T cboundary=
:l	nnT d"uInvalid type for name. Expected str, got
u:
T Ostr
Obytes
Oint
Ofloat
uInvalid type for value. Expected primitive type, got
name
primitive_value_to_str
value
a_headers
a_format_form_param
c
cContent-Disposition: form-data;
c
a_data
to_bytes
render_headers
render_data
self
render
uDataField.render
aPath
upload
a_guess_content_type
uContent-Type
aStringIO
uMultipart file uploads require 'io.BytesIO', not 'io.StringIO'.
aTextIOBase
uMultipart file uploads must be opened in binary mode, not text mode.
filename
file
headers
ucontent-type
u<genexpr>
uFileField.__init__.<locals>.<genexpr>
T Ostr
Obytes
peek_filelike_length
c;
items

encode
parts
seek
aUnsupportedOperation
read
aCHUNK_SIZE
chunk
uFileField.render_data
uFileField.render
urandom
T l ahex
T aascii
boundary
umultipart/form-data; boundary=%s
decode
content_type
a_iter_fields
fields
data
T Otuple
Olist
aDataField
T aname
value
files
aMapping
aFileField
uMultipartStream._iter_fields
c--%s
c
c--%s--
iter_chunks
uMultipartStream.iter_chunks
get_length
length
l u
Return the length of the multipart encoded content, or `None` if
ny of the files have a length that cannot be determined upfront.
get_content_length
uTransfer-Encoding
chunked
uContent-Length
a__iter__
uMultipartStream.__iter__
a__aiter__
uMultipartStream.__aiter__
a__doc__
a__file__
origin
has_location
a__cached__
annotations
io
os
re
typing
pathlib
T aPath
a_types
T aAsyncByteStream
aFileContent
aFileTypes
aRequestData
aRequestFiles
aSyncByteStream
aAsyncByteStream
aFileContent
aFileTypes
aRequestData
aRequestFiles
aSyncByteStream
a_utils
T apeek_filelike_length
primitive_value_to_str
to_bytes
D w"w\u%22
u\\
;l
l l l u%{:02X}
compile
w|akeys
escape
D aname
value
return
str
pabytes
D afilename
return
ustr | None
ustr | None
D acontent_type
return
ubytes | None
ubytes | None
get_multipart_boundary_from_content_type
