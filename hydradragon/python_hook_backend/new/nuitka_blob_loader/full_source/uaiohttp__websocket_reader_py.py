# Reconstructed from integrated Nuitka blob
# Module: uaiohttp._websocket.reader_py

uWebSocketDataQueue resumes and pauses an underlying stream.
It is a destination for WebSocket data.
aWebSocketDataQueue
a__qualname__
protocol
limit
loop
aAbstractEventLoop
return
a__init__
uWebSocketDataQueue.__init__
D areturn
Obool
is_eof
uWebSocketDataQueue.is_eof
exception
uWebSocketDataQueue.exception
exc
aBaseException
exc_cause
uWebSocketDataQueue.set_exception
D areturn
nuWebSocketDataQueue._release_waiter
uWebSocketDataQueue.feed_eof
D adata
size
return
aWSMessage
int_
nuWebSocketDataQueue.feed_data
uWebSocketDataQueue._read_from_buffer
aWebSocketReader
max_msg_size
compress
uWebSocketReader.__init__
uWebSocketReader.feed_eof
data
T Obytes
Obytearray
Omemoryview
T Obool
Obytes
uWebSocketReader.feed_data
D adata
return
Obytes
nuWebSocketReader._feed_data
buf
T Obytes
Obytearray
uWebSocketReader.parse_frame
uaiohttp\_websocket\reader_py.py
u<module aiohttp._websocket.reader_py>
T a__class__
T aself
protocol
limit
loop
T aself
queue
max_msg_size
compress
T aself
data
msg
assembled_payload
frame
fin
opcode
payload
compressed
is_continuation
has_partial
payload_merged
left
text
exc
close_code
close_message
T aself
data
size
T aself
waiter
T aself
T aself
data
exc
T aself
buf
frames
start_pos
buf_length
first_byte
second_byte
fin
rsv1
rsv2
rsv3
opcode
has_mask
length
length_flag
data
chunk_len
end_pos
T aself
exc
exc_cause
waiter
a__spec__
.aiohttp._websocket.writer
r
protocol
transport
use_mask
partial
getrandbits
l aget_random_bits
compress
notakeover
a_closing
a_limit
a_output_size
a_compressobj
uInitialize a WebSocket writer.
uSend a frame over the websocket with message as its payload.
self
opcode
aWSMsgType
aCLOSE
aClientConnectionResetError
T uCannot write to closing transport
l l@a_make_compress_obj
message
flush
zlib
aZ_FULL_FLUSH
aZ_SYNC_FLUSH
removesuffix
aWS_DEFLATE_TRAILING
l  aPACK_LEN1
l aPACK_LEN2
l~l aPACK_LEN3
l l
is_closing
aPACK_RANDBITS
websocket_mask
write
aMASK_LEN
msg_length
aMSG_SIZE
a_paused
a_drain_helper
send_frame
uWebSocketWriter.send_frame
aZLibCompressor
aZ_BEST_SPEED
aWEBSOCKET_MAX_SYNC_CHUNK_SIZE
T alevel
wbits
max_sync_chunk_size
uClose the websocket, sending the specified code and message.
encode
T uutf-8
aPACK_CLOSE_CODE
code
T aopcode
close
uWebSocketWriter.close
uWebSocket protocol versions 13 and 8.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
asyncio
random
aAny
aFinal
aOptional
aUnion
base_protocol
T aBaseProtocol
aBaseProtocol
client_exceptions
T aClientConnectionResetError
compression_utils
T aZLibCompressor
helpers
T aMASK_LEN
aMSG_SIZE
aPACK_CLOSE_CODE
aPACK_LEN1
aPACK_LEN2
aPACK_LEN3
aPACK_RANDBITS
websocket_mask
models
T aWS_DEFLATE_TRAILING
aWSMsgType
l   aDEFAULT_LIMIT
