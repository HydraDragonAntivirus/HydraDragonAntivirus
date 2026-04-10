# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.http_writer

a__qualname__
a__annotations__
int
major
minor
a__orig_bases__
T l l
aHttpVersion10
T l paHttpVersion11
a_T_OnChunkSent
uCIMultiDict[str]
a_T_OnHeadersSent
aStreamWriter
bool
T nnaprotocol
aAbstractEventLoop
on_chunk_sent
on_headers_sent
return
a__init__
uStreamWriter.__init__
property
aTransport
uStreamWriter.transport
uStreamWriter.protocol
D areturn
naenable_chunking
uStreamWriter.enable_chunking
deflate
aZ_DEFAULT_STRATEGY
encoding
str
strategy
enable_compression
uStreamWriter.enable_compression
bytes
bytearray
memoryview
uStreamWriter._write
chunks
uStreamWriter._writelines
D adrain
aLIMIT
tl   aset_eof
uStreamWriter.set_eof
T c
D astring
return
Ostr
pD astatus_line
headers
return
Ostr
uCIMultiDict[str]
Obytes
a_py_serialize_headers
uaiohttp._http_writer
a_http_writer
a_c_serialize_headers
uaiohttp\http_writer.py
T a.0
wkwvu<module aiohttp.http_writer>
T a__class__
T aself
protocol
loop
on_chunk_sent
on_headers_sent
T astatus_line
headers
headers_gen
line
T astring
T aself
chunk
size
transport
T aself
chunks
size
chunk
transport
T aself
protocol
T aself
T aself
encoding
strategy
T aself
chunk
drain
aLIMIT
chunk_len
T aself
chunk
chunks
chunks_len
compressed_chunk
flush_chunk
chunk_len_pre
T aself
status_line
headers
buf
a__spec__
.aiohttp.log
A
a__doc__
a__file__
origin
has_location
a__cached__
logging
getLogger
T uaiohttp.access
access_logger
T uaiohttp.client
client_logger
T uaiohttp.internal
internal_logger
T uaiohttp.server
server_logger
T uaiohttp.web
web_logger
T uaiohttp.websocket
ws_logger
uaiohttp\log.py
u<module aiohttp.log>

a__spec__
.aiohttp.multipart
r/
* D astring
return
Ostr
Obool
is_token
uparse_content_disposition.<locals>.is_token
is_quoted
uparse_content_disposition.<locals>.is_quoted
is_rfc5987
uparse_content_disposition.<locals>.is_rfc5987
is_extended_param
uparse_content_disposition.<locals>.is_extended_param
is_continuous_param
uparse_content_disposition.<locals>.is_continuous_param
chars

re
escape
aCHAR
D atext
chars
return
Ostr
ppaunescape
uparse_content_disposition.<locals>.unescape
T nD
split
T w;unot enough values to unpack (expected at least 1, got %d)
warnings
warn
aBadContentDispositionHeader
parts
w=T w=l alower
strip
lstrip
params
aBadContentDispositionParam
:l q nT w'l uutf-8
unquote
strict
T u\/
w;apop
T l
value
aTOKEN
w"acount
T w'l aendswith
T w*afind
isdigit
sub
u\\([
u])
u\1
u%s*
sorted
items
T w*l :nq natail
w'astartswith
name_suf
u<genexpr>
ucontent_disposition_filename.<locals>.<genexpr>
resp
stream
self
anext
a__anext__
uMultipartResponseWrapper.__anext__
content
at_eof
uReturns True when all response data had been read.
uEmits next multipart reader object.
release
uMultipartResponseWrapper.next
uRelease the connection gracefully.
All remaining content is read to the void.
uMultipartResponseWrapper.release
headers
a_boundary
a_boundary_len
a_content
a_default_charset
a_at_eof
uform-data
a_is_form_data
get
aCONTENT_LENGTH
a_length
a_read_bytes
deque
a_unread
a_prev_chunk
a_content_eof
a_cache
uBodyPartReader.__anext__
read
uBodyPartReader.next
uReads body part data.
decode: Decodes data following by encoding
method from Content-Encoding header. If it missed
data remains untouched
c
B
data
extend
read_chunk
chunk_size
decode
uBodyPartReader.read
uReads body part content chunk of the specified size.
size: chunk size
a_read_chunk_from_length
size
a_read_chunk_from_stream
aCONTENT_TRANSFER_ENCODING
base64
l aremainder
over_chunk
stripped_chunk
chunk
readline
c
T ureader did not read all the data or it is malformed
uBodyPartReader.read_chunk
T uContent-Length required for chunked read
min
uBodyPartReader._read_chunk_from_length
T uChunk size must be greater or equal than boundary length + 2
l T uReading after EOF
unread_data
max
catch_warnings
a__enter__
a__exit__
filterwarnings
aDeprecationWarning
T aignore
T acategory
window
T nnnuBodyPartReader._read_chunk_from_stream
uReads body part by line by line.
popleft
rstrip
T c
c--
append
:nq naline
uBodyPartReader.readline
uLike read(), but reads all the data to the void.
uBodyPartReader.release
uLike read(), but assumes that body part contains text data.
T tT adecode
encoding
get_charset
T uutf-8
T adefault
text
uBodyPartReader.text
uLike read(), but assumes that body parts contains JSON data.
cast
aDict
aAny
json
loads
uBodyPartReader.json
uLike read(), but assumes that body parts contain form urlencoded data.
udata cannot be decoded with %s encoding
parse_qsl
T akeep_blank_values
encoding
form
uBodyPartReader.form
uReturns True if the boundary was reached or False otherwise.
a_decode_content_transfer
aCONTENT_ENCODING
a_decode_content
uDecodes data.
Decoding is done according the specified Content-Encoding
or Content-Transfer-Encoding headers value.
identity
P adeflate
gzip
aZLibDecompressor
T aencoding
suppress_deflate_header
decompress_sync
uunknown content encoding:
b64decode
uquoted-printable
binascii
a2b_qp
T abinary
u8bit
u7bit
uunknown content transfer encoding:
aCONTENT_TYPE
parse_mimetype
parameters
charset
uReturns charset parameter from Content-Type header or default.
parse_content_disposition
aCONTENT_DISPOSITION
content_disposition_filename
name
uReturns name specified in Content-Disposition header.
If the header is missing or malformed, returns None.
filename
uReturns filename specified in Content-Disposition header.
Returns None if the header is missing or malformed.
a__class__
a__init__
set_content_disposition
T aattachment
tuUnable to decode.
a_value
T l   T asize
writer
write
field
uBodyPartReaderPayload.write
a_mimetype
type
multipart
T umultipart/* content type expected
boundary
uboundary missed for Content-Type: %s
u--
a_get_boundary
encode
a_last_part
a_at_bof
uMultipartReader.__anext__
response_wrapper_cls
uConstructs reader instance from HTTP response.
:param response: :class:`~aiohttp.client.ClientResponse` instance
uReturns True if the final boundary was reached, false otherwise.
uEmits the next multipart body part.
a_maybe_release_last_part
a_read_until_first_boundary
a_read_boundary
fetch_next_part
subtype
aBodyPartReader
T aname
a_charset_
T l uInvalid default charset
part
uMultipartReader.next
uReads all the body parts to the void till the final boundary.
uMultipartReader.release
uReturns the next body part reader.
a_read_headers
a_get_part_reader
uMultipartReader.fetch_next_part
multipart_reader_cls
part_reader_cls
T asubtype
default_charset
uDispatches the response by the `Content-Type` header.
Returns a suitable reader instance.
:param dict headers: Response headers
uboundary %r is too long (70 chars max)
a_readline
uMultipartReader._readline
uCould not find starting boundary %r
uMultipartReader._read_until_first_boundary
:nl nuInvalid boundary
u, expected
uMultipartReader._read_boundary
lines
aHeadersParser
parse_headers
uMultipartReader._read_headers
uEnsures that the last read body part is read completely.
uMultipartReader._maybe_release_last_part
uuid
uuid4
hex
T aascii
uboundary should contain ASCII only chars
umultipart/
u; boundary=
a_boundary_value
T nT acontent_type
a_parts
match
a_valid_tchar_regex
search
a_invalid_qdtext_char_regex
uboundary value contains invalid characters
replace
T d\c\\
T d"c\"
uWrap boundary parameter value in quotes, if necessary.
Reads self.boundary and returns a unicode string.
aCIMultiDict
aPayload
update
append_payload
get_payload
T aheaders
aLookupError
uCannot create payload from %r
keys
usection-
T uform-data
T adeflate
gzip
identity
T u
base64
uquoted-printable
binary
binary
payload
uAdds a new body part to multipart writer.
aJsonPayload
uHelper to append JSON part.
aSequence
aMapping
urlencode
D adoseq
taStringPayload
uapplication/x-www-form-urlencoded
T aheaders
content_type
uHelper to append form urlencoded part.
total
a_binary_headers
uSize of the payload.

errors
uMultipartWriter.decode.<locals>.<genexpr>
uWrite body.
uname=
aMultipartPayloadWriter
enable_compression
enable_encoding
write_eof
close_boundary
c--
uMultipartWriter.write
a_writer
a_encoding
a_compress
a_encoding_buffer
aZLibCompressor
T aencoding
suppress_deflate_header
strategy
flush
b64encode
uMultipartPayloadWriter.write_eof
compress
b2a_qp
uMultipartPayloadWriter.write
a__doc__
a__file__
origin
has_location
a__cached__
sys
zlib
collections
T adeque
aTracebackType
aTYPE_CHECKING
aDeque
aIterator
aList
aOptional
aTuple
aType
aUnion
uurllib.parse
T aparse_qsl
unquote
urlencode
multidict
T aCIMultiDict
aCIMultiDictProxy
aCIMultiDictProxy
compression_utils
T aZLibCompressor
aZLibDecompressor
hdrs
T aCONTENT_DISPOSITION
aCONTENT_ENCODING
aCONTENT_LENGTH
aCONTENT_TRANSFER_ENCODING
aCONTENT_TYPE
helpers
T aCHAR
aTOKEN
parse_mimetype
reify
reify
http
T aHeadersParser
T aJsonPayload
aLookupError
aOrder
aPayload
aStringPayload
get_payload
payload_type
aOrder
payload_type
streams
T aStreamReader
aStreamReader
aTypeVar
T aSelf
aBodyPartReader
T abound
aSelf
T aMultipartReader
aMultipartWriter
aBodyPartReader
aBadContentDispositionHeader
aBadContentDispositionParam
parse_content_disposition
content_disposition_filename
a__all__
aRuntimeWarning
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
