# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.multipart

a__qualname__
a__orig_bases__
header
return
T Ostr
pT afilename
uWrapper around the MultipartReader.
It takes care about
underlying connection and close it when it needs in.
aMultipartResponseWrapper
D aresp
stream
return
aClientResponse
aMultipartReader
nuMultipartResponseWrapper.__init__
D areturn
aMultipartResponseWrapper
a__aiter__
uMultipartResponseWrapper.__aiter__
T aMultipartReader
aBodyPartReader
D areturn
Obool
uMultipartResponseWrapper.at_eof
D areturn
nuMultipart reader for single body part.
l @D asubtype
default_charset
mixed
nuCIMultiDictProxy[str]
default_charset
uBodyPartReader.__init__
uBodyPartReader.__aiter__
D areturn
Obytes
D adecode
FD adecode
return
Obool
Obytes
D asize
return
Oint
Obytes
D aencoding
nuBodyPartReader.at_eof
D adata
return
Obytes
puBodyPartReader.decode
uBodyPartReader._decode_content
uBodyPartReader._decode_content_transfer
D adefault
return
Ostr
puBodyPartReader.get_charset
uBodyPartReader.name
uBodyPartReader.filename
aBodyPartReaderPayload
try_first
T aorder
a__annotations__
args
kwargs
uBodyPartReaderPayload.__init__
T uutf-8
strict
str
uBodyPartReaderPayload.decode
uMultipart body reader.
aMultipartReader
uMultipartReader.__init__
uMultipartReader.__aiter__
response
aClientResponse
from_response
uMultipartReader.from_response
uMultipartReader.at_eof
uMultipartReader._get_part_reader
D areturn
Ostr
uMultipartReader._get_boundary
D areturn
uCIMultiDictProxy[str]
a_Part
aMultipartWriter
uMultipart body writer.
T amixed
nuMultipartWriter.__init__
D areturn
aMultipartWriter
uMultipartWriter.__enter__
exc_type
aBaseException
exc_val
exc_tb
uMultipartWriter.__exit__
a__iter__
uMultipartWriter.__iter__
int
a__len__
uMultipartWriter.__len__
bool
a__bool__
uMultipartWriter.__bool__
compile
T c\A[!#$%&'*+\-.^_`|~\w]+\Z
T c[\x00-\x08\x0A-\x1F\x7F]
property
uMultipartWriter._boundary_value
uMultipartWriter.boundary
obj
uMultipartWriter.append
uMultipartWriter.append_payload
append_json
uMultipartWriter.append_json
append_form
uMultipartWriter.append_form
uMultipartWriter.size
uMultipartWriter.decode
uMultipartPayloadWriter.__init__
D aencoding
return
Ostr
nuMultipartPayloadWriter.enable_encoding
deflate
aZ_DEFAULT_STRATEGY
D aencoding
strategy
return
Ostr
Oint
nuMultipartPayloadWriter.enable_compression
D achunk
return
Obytes
nuaiohttp\multipart.py
T a.0
part
a_e
a_te
self
encoding
errors
T a.0
key
value
name_suf
u<module aiohttp.multipart>
T a__class__
T aself
T aself
part
T aself
exc_type
exc_val
exc_tb
T aself
boundary
headers
content
subtype
default_charset
length
T aself
value
args
kwargs
params
a__class__
T aself
writer
T aself
headers
content
T aself
resp
stream
T aself
subtype
boundary
ctype
a__class__
T aself
value
quoted_value_content
T aself
data
encoding
T aself
boundary
T aself
headers
ctype
mimetype
T aself
chunk
epilogue
next_line
T aself
size
chunk_size
chunk
T aself
size
first_chunk
chunk
window
sub
idx
result
T aself
lines
chunk
parser
headers
raw_headers
T aself
chunk
T aself
obj
headers
payload
T aself
obj
headers
data
T aself
obj
headers
T aself
payload
encoding
te_encoding
name
size
T aparams
name
name_suf
parts
fnparams
num
key
value
w_atail
encoding
T aself
data
T aself
encoding
errors
T aself
encoding
strategy
T aself
encoding
T aself
headers
T aself
w_aparams
T aself
encoding
data
real_encoding
decoded_data
T acls
response
obj
T aself
default
ctype
mimetype
T astring
pos
substring
T astring
T astring
is_token
T ais_token
T aself
encoding
data
T aself
item
T aself
part
w_aparams
charset
T aheader
params
is_token
is_quoted
is_rfc5987
is_extended_param
is_continuous_param
unescape
disptype
parts
item
key
value
encoding
w_afailed
a_value
T aself
decode
data
T	aself
size
chunk
encoding
stripped_chunk
remainder
over_chunk_size
over_chunk
clrf
T aself
line
sline
boundary
last_boundary
next_line
T aself
total
part
encoding
te_encoding
T atext
chars
T aself
writer
field
chunk
T aself
chunk
buf
div
mod
enc_chunk
b64chunk
T aself
writer
close_boundary
part
encoding
te_encoding
wwa__spec__
.aiohttp.payload
aPAYLOAD_REGISTRY
get
register
T aorder
type
order
register_payload
a_first
a_normal
a_last
a_normal_lookup
aPayload
aLookupError
aOrder
try_first
append
normal
aIterable
factory
self
try_last
uUnsupported order

a_encoding
a_filename
aCIMultiDict
a_headers
a_value
sentinel
hdrs
aCONTENT_TYPE
mimetypes
guess_type
a_default_content_type
update
a_size
uSize of the payload.
uFilename of the payload.
uCustom item headers
headers
items
u:

uutf-8
c
uPayload encoding
uContent type
content_disposition_header
quote_fields
a_charset
aCONTENT_DISPOSITION
uSets ``Content-Disposition`` header.
uWrite payload.
writer is an AbstractStreamWriter instance:
write
uPayload.write
content_type
uapplication/octet-stream
a__class__
a__init__
nbytes
T Obytes
Obytearray
uvalue argument must be byte-ish, not
aTOO_LARGE_BYTES_BODY
source
warnings
warn
uSending a large body directly with raw bytes might lock the event loop. You should probably pass an io.BytesIO object instead
aResourceWarning
decode
writer
uBytesPayload.write
utext/plain; charset=utf-8
parse_mimetype
parameters
T acharset
uutf-8
utext/plain; charset=%s
encode
encoding
read
filename
guess_filename
set_content_disposition
T afilename
asyncio
get_event_loop
run_in_executor
l   achunk
loop
close
uIOBasePayload.write
readlines
errors
u<genexpr>
uIOBasePayload.decode.<locals>.<genexpr>
fstat
fileno
st_size
tell
T aencoding
uTextIOPayload.write
seek
aSEEK_END
T EOSError
EAttributeError
aAsyncIterable
uvalue argument must support collections.abc.AsyncIterable interface, got {!r}
a__aiter__
a_iter
a__anext__
uAsyncIterablePayload.write
uUnable to decode.
iter_any
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
enum
io
json
os
sys
abc
T aABC
abstractmethod
aABC
abstractmethod
itertools
T achain
chain
aIO
aTYPE_CHECKING
aAny
aDict
aFinal
aOptional
aTextIO
aTuple
aType
aUnion
multidict
T aCIMultiDict
T ahdrs
T aAbstractStreamWriter
aAbstractStreamWriter
helpers
T a_SENTINEL
content_disposition_header
guess_filename
parse_mimetype
sentinel
a_SENTINEL
streams
T aStreamReader
aStreamReader
typedefs
T aJSONEncoder
a_CIMultiDict
aJSONEncoder
a_CIMultiDict
TaPAYLOAD_REGISTRY
get_payload
payload_type
aPayload
aBytesPayload
aStringPayload
aIOBasePayload
aBytesIOPayload
aBufferedReaderPayload
aTextIOPayload
aStringIOPayload
aJsonPayload
aAsyncIterablePayload
a__all__
l  @T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
