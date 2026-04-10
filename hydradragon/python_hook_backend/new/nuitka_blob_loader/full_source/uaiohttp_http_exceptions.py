# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.http_exceptions

uHTTP error.
Shortcut for raising HTTP errors with custom code, message and headers.
code: HTTP Error code.
message: (optional) Error message.
headers: (optional) Headers to be sent in response, a list of pairs
a__qualname__
D acode
message
headers
nu
naint
str
return
uHttpProcessingError.__init__
a__str__
uHttpProcessingError.__str__
a__repr__
uHttpProcessingError.__repr__
a__orig_bases__
aBadHttpMessage
l  uBad Request
D aheaders
nuBadHttpMessage.__init__
aHttpBadRequest
aPayloadEncodingError
uBase class for payload errors
aContentEncodingError
uContent encoding error.
aTransferEncodingError
utransfer encoding error.
aContentLengthError
uNot enough data for satisfy content length header.
aLineTooLong
T aUnknown
aUnknown
limit
actual_size
uLineTooLong.__init__
aInvalidHeader
bytes
uInvalidHeader.__init__
aBadStatusLine
T u
naerror
uBadStatusLine.__init__
aBadHttpMethod
uInvalid HTTP method in status line.
uBadHttpMethod.__init__
aInvalidURLError
uaiohttp\http_exceptions.py
u<module aiohttp.http_exceptions>
T a__class__
T aself
message
headers
a__class__
T aself
line
error
a__class__
T aself
code
message
headers
T aself
hdr
hdr_s
a__class__
T aself
line
limit
actual_size
a__class__
T aself
T aself
msg
a__spec__
.aiohttp.http_parser
max_line_size
max_headers
max_field_size
a_lax
aCIMultiDict
line
split
T d:l aInvalidHeader
S l l	alstrip
T c
self
aLineTooLong
urequest header name {}
decode
T autf8
backslashreplace
T uutf-8
surrogateescape
aTOKENRE
fullmatch
lines_idx
T l l	acontinuation
header_length
urequest header field {}
bvalue_lst
c
bvalue
strip
w
ww
headers
add
raw_headers
aCIMultiDictProxy
get
hdrs
aUPGRADE

lower
P awebsocket
tcp
uCheck if the upgrade header is supported.
protocol
loop
timer
code
method
payload_exception
response_with_body
read_until_eof
a_lines
a_tail
a_upgraded
a_payload
a_payload_parser
a_auto_decompress
a_limit
aHeadersParser
lax
a_headers_parser
feed_eof
append

T c
suppress
T EException
a__enter__
a__exit__
parse_message
T nnnastart_pos
data_len
data
find
aSEP
should_close
aBadHttpMessage
T uData after `Connection: close`
d
rstrip
T daclear
return
aOptional
get_content_length
uHttpParser.feed_data.<locals>.get_content_length
upgrade
a_is_supported_upgrade
aEMPTY_BODY_STATUS_CODES
aEMPTY_BODY_METHODS
chunked
aStreamReader
T atimer
loop
limit
aHttpPayloadParser
compression
T alength
chunked
method
compression
code
response_with_body
auto_decompress
lax
done
aRawRequestMessage
T amethod
compression
auto_decompress
lax
aEMPTY_PAYLOAD
messages
payload
feed_data
set_exception
msg
aCONTENT_LENGTH
aDIGITS
parse_headers
aCONTENT_LOCATION
aCONTENT_RANGE
aCONTENT_TYPE
aETAG
aHOST
aMAX_FORWARDS
aSERVER
aTRANSFER_ENCODING
aUSER_AGENT
uDuplicate '
u' header found.
aCONNECTION
close
ukeep-alive
aCONTENT_ENCODING
T agzip
deflate
br
a_is_chunked_te
T uTransfer-Encoding can't be present with Content-Length
uParses RFC 5322 headers from a stream.
Line continuations are supported. Returns list of header name
nd value pairs. Header name is in upper case.
getall
u<genexpr>
uHttpParser.parse_headers.<locals>.<genexpr>
uSet connection upgraded (to websocket) mode.
:param bool val: new state.
T w l T amaxsplit
aBadHttpMethod
uStatus line is too long
aVERSRE
aBadStatusLine
aHttpVersion
group
T l T l aCONNECT
aURL
build
T aauthority
encoded
startswith
T w/apartition
T w#T w?T apath
query_string
fragment
encoded
w*aOPTIONS
D aencoded
tascheme
aInvalidURLError
encode
T asurrogateescape
T aerrors
T alatin1
aHttpVersion10
url
rsplit
T w,l T u
T uRequest has invalid `Transfer-Encoding`
aDEBUG
c
a__class__
ldl  P l  l  aRawResponseMessage
a_length
aParseState
aPARSE_UNTIL_EOF
a_type
aChunkState
aPARSE_CHUNKED_SIZE
a_chunk
a_chunk_size
a_chunk_tail
aDeflateBuffer
aPARSE_NONE
aPARSE_CHUNKED
aPARSE_LENGTH
real_payload
aContentLengthError
T uNot enough data for satisfy content length header.
aTransferEncodingError
T uNot enough data for satisfy transfer length header.
T tc
chunk
aCHUNK_EXT
uUnexpected LF in chunk-extension:
re
aHEXDIGITS
T aascii
surrogateescape
l aPARSE_MAYBE_TRAILERS
:l nnaPARSE_CHUNKED_CHUNK
begin_http_chunk_receiving
T Fc
aPARSE_CHUNKED_CHUNK_EOF
end_http_chunk_receiving
:nl naPARSE_TRAILERS
out
size
encoding
a_started_decoding
br
aHAS_BROTLI
aContentEncodingError
T uCan not decode content-encoding: brotli (br). Please install `Brotli`
aBrotliDecompressor
decompressor
aZLibDecompressor
T aencoding
deflate
l l T aencoding
suppress_deflate_header
decompress_sync
uCan not decode content-encoding: %s
flush
eof
T adeflate
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
abc
asyncio
string
contextlib
T asuppress
enum
T aIntEnum
aIntEnum
aAny
aClassVar
aFinal
aGeneric
aList
aLiteral
aNamedTuple
aPattern
aSet
aTuple
aType
aTypeVar
aUnion
multidict
T aCIMultiDict
aCIMultiDictProxy
istr
istr
yarl
T aURL
T ahdrs
base_protocol
T aBaseProtocol
aBaseProtocol
compression_utils
T aHAS_BROTLI
aBrotliDecompressor
aZLibDecompressor
helpers
T a_EXC_SENTINEL
aDEBUG
aEMPTY_BODY_METHODS
aEMPTY_BODY_STATUS_CODES
aNO_EXTENSIONS
aBaseTimerContext
set_exception
a_EXC_SENTINEL
aNO_EXTENSIONS
aBaseTimerContext
http_exceptions
T	aBadHttpMessage
aBadHttpMethod
aBadStatusLine
aContentEncodingError
aContentLengthError
aInvalidHeader
aInvalidURLError
aLineTooLong
aTransferEncodingError
http_writer
T aHttpVersion
aHttpVersion10
streams
T aEMPTY_PAYLOAD
aStreamReader
typedefs
T aRawHeaders
aRawHeaders
T aHeadersParser
aHttpParser
aHttpRequestParser
aHttpResponseParser
aRawRequestMessage
aRawResponseMessage
a__all__
T c
d
a_SEP
printable
aASCIISET
escape
T u!#$%&'*+-.^_`|~
a_TCHAR_SPECIALS
compile
u[0-9A-Za-z
u]+
uHTTP/(\d)\.(\d)
aASCII
u\d+
T c[0-9a-fA-F]+
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
