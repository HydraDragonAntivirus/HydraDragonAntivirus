# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.http_parser

a__qualname__
str
path
version
uCIMultiDictProxy[str]
bool
a__orig_bases__
int
reason
a_MsgT
l l l T l ?l   l ?FD amax_line_size
max_headers
max_field_size
lax
return
Oint
ppObool
na__init__
uHeadersParser.__init__
lines
uHeadersParser.parse_headers
aABC
aHttpParser
Tnnl   l ?l   l ?nnnntFtaAbstractEventLoop
limit
aBaseException
auto_decompress
uHttpParser.__init__
abstractmethod
bytes
uHttpParser.parse_message
te
uHttpParser._is_chunked_te
uHttpParser.feed_eof
aMETH_CONNECT
aSEC_WEBSOCKET_KEY1
aEMPTY
uHttpParser.feed_data
uHttpParser.parse_headers
val
set_upgraded
uHttpParser.set_upgraded
aHttpRequestParser
uRead request status line.
Exception .http_exceptions.BadStatusLine
could be raised in case of any errors in status line.
Returns RawRequestMessage.
uHttpRequestParser.parse_message
uHttpRequestParser._is_chunked_te
aHttpResponseParser
uRead response status line and headers.
BadStatusLine could be raised in case of any errors in status line.
Returns RawResponseMessage.
T naargs
kwargs
uHttpResponseParser.feed_data
uHttpResponseParser.parse_message
uHttpResponseParser._is_chunked_te
T nFnnntpFalength
uHttpPayloadParser.__init__
D areturn
nuHttpPayloadParser.feed_eof
T c
d;T Obool
Obytes
uHttpPayloadParser.feed_data
uDeflateStream decompress stream and feed data into specified stream.
uDeflateBuffer.__init__
D aexc
exc_cause
return
EBaseException
pnuDeflateBuffer.set_exception
D achunk
size
return
Obytes
Oint
nuDeflateBuffer.feed_data
uDeflateBuffer.feed_eof
uDeflateBuffer.begin_http_chunk_receiving
uDeflateBuffer.end_http_chunk_receiving
aHttpRequestParserPy
aHttpResponseParserPy
aRawRequestMessagePy
aRawResponseMessagePy
a_http_parser
T aHttpRequestParser
aHttpResponseParser
aRawRequestMessage
aRawResponseMessage
aHttpRequestParserC
aHttpResponseParserC
aRawRequestMessageC
aRawResponseMessageC
uaiohttp\http_parser.py
T a.0
whaheaders
u<module aiohttp.http_parser>
T a__class__
T aself
out
encoding
T aself
max_line_size
max_headers
max_field_size
lax
T aself
protocol
loop
limit
max_line_size
max_headers
max_field_size
timer
code
method
payload_exception
response_with_body
read_until_eof
auto_decompress
T aself
payload
length
chunked
compression
code
method
response_with_body
auto_decompress
lax
real_payload
T aself
te
T aheaders
T aself
T aself
chunk
size
T aself
data
aSEP
aEMPTY
aCONTENT_LENGTH
aMETH_CONNECT
aSEC_WEBSOCKET_KEY1
msg
messages
data_len
start_pos
loop
should_close
pos
line
get_content_length
length
method
code
empty_body
payload
payload_parser
eof
underlying_exc
reraised_exc
Taself
chunk
aSEP
aCHUNK_EXT
required
chunk_len
pos
wiasize_b
ext
exc
size
head
T aself
data
aSEP
args
kwargs
a__class__
T aself
chunk
T alength_hdr
msg
aCONTENT_LENGTH
T aCONTENT_LENGTH
msg
T aself
lines
headers
raw_headers
lines_idx
line
line_count
bname
bvalue
name
header_length
continuation
bvalue_lst
value
T aself
lines
headers
raw_headers
close_conn
encoding
upgrade
chunked
singletons
bad_hdr
conn
wvaenc
te
T aself
lines
T aself
lines
line
method
path
version
match
version_o
url
path_part
a_hash_separator
url_fragment
a_question_mark_separator
qs_part
headers
raw_headers
close
compression
upgrade
chunked
T aself
lines
line
version
status
reason
match
version_o
status_i
headers
raw_headers
close
compression
upgrade
chunked
T aself
exc
exc_cause
T aself
val
a__spec__
.aiohttp.http_websocket
W
%
uWebSocket protocol versions 13 and 8.
a__doc__
a__file__
origin
has_location
a__cached__
u_websocket.helpers
T aWS_KEY
ws_ext_gen
ws_ext_parse
aWS_KEY
ws_ext_gen
ws_ext_parse
u_websocket.models
T aWS_CLOSED_MESSAGE
aWS_CLOSING_MESSAGE
aWebSocketError
aWSCloseCode
aWSHandshakeError
aWSMessage
aWSMsgType
aWS_CLOSED_MESSAGE
aWS_CLOSING_MESSAGE
aWebSocketError
aWSCloseCode
aWSHandshakeError
aWSMessage
aWSMsgType
u_websocket.reader
T aWebSocketReader
aWebSocketReader
u_websocket.writer
T aWebSocketWriter
aWebSocketWriter
aCLOSE
aCLOSING
aPING
aPONG
a_INTERNAL_RECEIVE_TYPES
TaWS_CLOSED_MESSAGE
aWS_CLOSING_MESSAGE
aWS_KEY
aWebSocketReader
aWebSocketWriter
aWSMessage
aWebSocketError
aWSMsgType
aWSCloseCode
ws_ext_gen
ws_ext_parse
aWSHandshakeError
aWSMessage
a__all__
uaiohttp\http_websocket.py
u<module aiohttp.http_websocket>

a__spec__
.aiohttp.http_writer
a_protocol
loop
a_on_chunk_sent
a_on_headers_sent
transport
chunked
aZLibCompressor
T aencoding
strategy
a_compress
buffer_size
output_size
is_closing
aClientConnectionResetError
T uCannot write to closing transport
write
size
aSKIP_WRITELINES
aMIN_PAYLOAD_FOR_WRITELINES
c
writelines
uWrites chunk of data to a stream.
write_eof() indicates end of stream.
writer can't be used after write_eof() method being called.
write() return drain future.
self
chunk
nbytes
cast
T wcacompress
length
a_writelines
wxu

ascii
c
a_write
aLIMIT
drain
uStreamWriter.write
uWrite request/response status and headers.
headers
a_serialize_headers
status_line
write_headers
uStreamWriter.write_headers
a_eof
uIndicate that the message is complete.
compressed_chunk
flush
T c
0
c
0
T c0
write_eof
uStreamWriter.write_eof
uFlush the write buffer.
The intended use is to write
wait w.write(data)
wait w.drain()
a_paused
a_drain_helper
uStreamWriter.drain
ww
uNewline or carriage return detected in headers. Potential header injection attack.
items

encode
T uutf-8
a_safe_header
u:
u<genexpr>
u_py_serialize_headers.<locals>.<genexpr>
uHttp related parsers and protocol.
a__doc__
a__file__
origin
has_location
a__cached__
asyncio
sys
zlib
aAny
aAwaitable
aCallable
aIterable
aList
aNamedTuple
aOptional
aUnion
multidict
T aCIMultiDict
aCIMultiDict
abc
T aAbstractStreamWriter
aAbstractStreamWriter
base_protocol
T aBaseProtocol
aBaseProtocol
client_exceptions
T aClientConnectionResetError
compression_utils
T aZLibCompressor
helpers
T aNO_EXTENSIONS
aNO_EXTENSIONS
T aStreamWriter
aHttpVersion
aHttpVersion10
aHttpVersion11
a__all__
l  aIS_PY313_BEFORE_313_2
aIS_PY_BEFORE_312_9
a__prepare__
aHttpVersion
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
