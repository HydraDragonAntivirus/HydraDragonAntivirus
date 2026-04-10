# Reconstructed from integrated Nuitka blob
# Module: uhttpx._content

a__qualname__
D astream
return
bytes
aNone
a__init__
uByteStream.__init__
D areturn
uIterator[bytes]
D areturn
uAsyncIterator[bytes]
a__orig_bases__
l   D astream
return
uIterable[bytes]
aNone
uIteratorByteStream.__init__
D astream
return
uAsyncIterable[bytes]
aNone
uAsyncIteratorByteStream.__init__
aUnattachedStream

If a request or response is serialized using pickle, then it is no longer
ttached to a stream for I/O purposes. Any stream operations should result
in `httpx.StreamClosed`.
uUnattachedStream.__iter__
D acontent
return
ustr | bytes | Iterable[bytes] | AsyncIterable[bytes]
utuple[dict[str, str], SyncByteStream | AsyncByteStream]
D adata
return
aRequestData
utuple[dict[str, str], ByteStream]
D adata
files
boundary
return
aRequestData
aRequestFiles
ubytes | None
utuple[dict[str, str], MultipartStream]
D atext
return
str
utuple[dict[str, str], ByteStream]
D ahtml
return
str
utuple[dict[str, str], ByteStream]
D ajson
return
aAny
utuple[dict[str, str], ByteStream]
T nnnnnD acontent
data
files
json
boundary
return
uRequestContent | None
uRequestData | None
uRequestFiles | None
uAny | None
ubytes | None
utuple[dict[str, str], SyncByteStream | AsyncByteStream]
encode_request
T nnnnD acontent
text
html
json
return
uResponseContent | None
ustr | None
ustr | None
uAny | None
utuple[dict[str, str], SyncByteStream | AsyncByteStream]
encode_response
uhttpx\_content.py
u<module httpx._content>
T a__class__
T aself
chunk
part
T aself
T aself
stream
T acontent
body
content_length
headers
content_length_or_none
T ahtml
body
content_length
content_type
headers
T ajson
body
content_length
content_type
headers
T adata
files
boundary
multipart
headers
T acontent
data
files
json
boundary
message
T acontent
text
html
json
T atext
body
content_length
content_type
headers
T adata
plain_data
key
value
body
content_length
content_type
headers
a__spec__
.httpx._decoders
.
first_attempt
zlib
decompressobj
decompressor
decompress
error
aMAX_WBITS
decode
aDecodingError
flush
l abrotli
uUsing 'BrotliDecoder', but neither of the 'brotlicffi' or 'brotli' packages have been installed. Make sure to install httpx using `pip install httpx[brotli]`.
aDecompressor
seen_data
a_decompress
process
c
finish
zstandard
uUsing 'ZStandardDecoder', ...Make sure to install httpx using `pip install httpx[zstd]`.
aZstdDecompressor
aBytesIO
write
self
eof
unused_data
output
aZstdError
getvalue
T uZstandard data is incomplete
children

'children' should be a sequence of decoders in the order in which
each was applied.
data
a_buffer
a_chunk_size
tell
seek
T l
truncate
:nq naStringIO
codecs
getincrementaldecoder
T areplace
T aerrors
decoder
T c
tabuffer
trailing_cr
waendswith
T watext

splitlines
append

:l nnalines
pop

Handlers for Content-Encoding.
See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
a__doc__
a__file__
origin
has_location
a__cached__
annotations
io
typing
a_exceptions
T aDecodingError
brotlicffi
