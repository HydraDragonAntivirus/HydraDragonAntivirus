# Reconstructed from integrated Nuitka blob
# Module: uaiohttp._websocket.models

a__qualname__
l  aOK
l  aGOING_AWAY
l  aPROTOCOL_ERROR
l  aUNSUPPORTED_DATA
l  aABNORMAL_CLOSURE
l  aINVALID_TEXT
l  aPOLICY_VIOLATION
l  aMESSAGE_TOO_BIG
l  aMANDATORY_EXTENSION
l  aINTERNAL_ERROR
l  aSERVICE_RESTART
l  aTRY_AGAIN_LATER
l  aBAD_GATEWAY
a__orig_bases__
aWSMsgType
aCONTINUATION
aTEXT
l aBINARY
l	aPING
l
aPONG
l aCLOSE
l  aCLOSING
l  aCLOSED
l  aERROR
text
binary
ping
pong
close
closing
closed
error
aWSMessage
type
str
extra
loads
return
uWSMessage.json
a__new__
aWS_CLOSED_MESSAGE
aWS_CLOSING_MESSAGE
T EException
aWebSocketError
uWebSocket protocol parser error.
int
message
uWebSocketError.__init__
a__str__
uWebSocketError.__str__
aWSHandshakeError
uWebSocket protocol handshake error.
uaiohttp\_websocket\models.py
u<module aiohttp._websocket.models>
T a__class__
T aself
code
message
a__class__
T aself
T aself
loads

a__spec__
.aiohttp._websocket.reader
uReader for WebSocket protocol versions 13 and 8.
a__doc__
a__file__
origin
has_location
a__cached__
aTYPE_CHECKING
helpers
T aNO_EXTENSIONS
l aNO_EXTENSIONS
reader_py
T aWebSocketDataQueue
aWebSocketReader
aWebSocketDataQueue
aWebSocketDataQueuePython
aWebSocketReader
aWebSocketReaderPython
reader_c
aWebSocketDataQueueCython
aWebSocketReaderCython
uaiohttp\_websocket\reader.py
u<module aiohttp._websocket.reader>

a__spec__
.aiohttp._websocket.reader_py
a_size
a_protocol
l a_limit
a_loop
a_eof
a_waiter
a_exception
deque
a_buffer
popleft
a_get_buffer
append
a_put_buffer
set_exception
done
set_result
T na_release_waiter
a_reading_paused
pause_reading
self
create_future
asyncio
aCancelledError
aTimeoutError
a_read_from_buffer
read
uWebSocketDataQueue.read
resume_reading
aEofStream
queue
a_max_msg_size
a_exc
B
a_partial
aREAD_HEADER
a_state
a_opcode
a_frame_fin
a_frame_opcode
c
a_frame_payload
a_frame_payload_len
a_tail
a_has_mask
a_frame_mask
a_payload_length
a_payload_length_flag
a_compressed
a_decompressobj
a_compress
feed_eof
a_feed_data
aEMPTY_FRAME_ERROR
aEMPTY_FRAME
parse_frame
l aOP_CODE_CONTINUATION
aOP_CODE_TEXT
aOP_CODE_BINARY
aWebSocketError
aWSCloseCode
aMESSAGE_TOO_BIG
uMessage size {} exceeds limit {}
aPROTOCOL_ERROR
uContinuation frame for non started message
uThe opcode in non-fin frame is expected to be zero, got {!r}
clear
aZLibDecompressor
T tT asuppress_deflate_header
decompress_sync
aWS_DEFLATE_TRAILING
unconsumed_tail
uDecompressed message size {} exceeds limit {}
decode
T uutf-8
aINVALID_TEXT
uInvalid UTF-8 text message
feed_data
aTUPLE_NEW
aWSMessage
aWS_MSG_TYPE_TEXT

aWS_MSG_TYPE_BINARY
aOP_CODE_CLOSE
aUNPACK_CLOSE_CODE
:nl nl  aALLOWED_CLOSE_CODES
uInvalid close code:
:l nnaWSMsgType
aCLOSE
uInvalid close frame:
w aOP_CODE_PING
aPING
aOP_CODE_PONG
aPONG
uUnexpected opcode=
buf_length
start_pos
l l l l l uReceived frame with non-zero reserved bits
uReceived fragmented control frame
l l}uControl frame payload cannot be larger than 125 bytes
aREAD_PAYLOAD_LENGTH
l~l aUNPACK_LEN3
aREAD_PAYLOAD_MASK
aREAD_PAYLOAD
websocket_mask
frames
uReturn the next frame from the socket.
uReader for WebSocket protocol versions 13 and 8.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
builtins
collections
T adeque
aDeque
aFinal
aList
aOptional
aSet
aTuple
aUnion
base_protocol
T aBaseProtocol
aBaseProtocol
compression_utils
T aZLibDecompressor
helpers
T a_EXC_SENTINEL
set_exception
a_EXC_SENTINEL
streams
T aEofStream
T aUNPACK_CLOSE_CODE
aUNPACK_LEN3
websocket_mask
models
T aWS_DEFLATE_TRAILING
aWebSocketError
aWSCloseCode
aWSMessage
aWSMsgType
aBINARY
aTEXT
aCONTINUATION
value
T tc
T Fc
a__new__
int_
