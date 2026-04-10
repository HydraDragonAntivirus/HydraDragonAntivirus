# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.client_ws

aClientWSTimeout
a__qualname__
ib
T atype
default
T nf
$@T aws_receive
ws_close
aDEFAULT_WS_CLIENT_TIMEOUT
aClientWebSocketResponse
D aheartbeat
compress
client_notakeover
nl
Fareader
writer
protocol
response
autoclose
autoping
loop
aAbstractEventLoop
heartbeat
client_notakeover
return
a__init__
uClientWebSocketResponse.__init__
D areturn
nuClientWebSocketResponse._cancel_heartbeat
uClientWebSocketResponse._cancel_pong_response_cb
uClientWebSocketResponse._reset_heartbeat
uClientWebSocketResponse._send_heartbeat
D atask
return
uasyncio.Task[None]
nuClientWebSocketResponse._ping_task_done
uClientWebSocketResponse._pong_not_received
D aexc
return
EBaseException
nuClientWebSocketResponse._handle_ping_pong_exception
uClientWebSocketResponse._set_closed
uClientWebSocketResponse._set_closing
D areturn
Obool
closed
uClientWebSocketResponse.closed
close_code
uClientWebSocketResponse.close_code
uClientWebSocketResponse.protocol
D areturn
Oint
uClientWebSocketResponse.compress
uClientWebSocketResponse.client_notakeover
T naname
default
uClientWebSocketResponse.get_extra_info
uClientWebSocketResponse.exception
T c
D amessage
return
Obytes
nD acode
message
return
Oint
Obytes
Obool
D atimeout
nD areturn
aClientWebSocketResponse
a__aiter__
uClientWebSocketResponse.__aiter__
exc_type
exc_val
exc_tb
uaiohttp\client_ws.py
u<module aiohttp.client_ws>
T a__class__
T aself
T aself
exc_type
exc_val
exc_tb
T aself
msg
T aself
reader
writer
protocol
response
timeout
autoclose
autoping
loop
heartbeat
compress
client_notakeover
T aself
exc
T aself
task
exc
T aself
loop
conn
timeout_ceil_threshold
now
when
T aself
loop
now
conn
timeout_ceil_threshold
when
coro
ping_task
T aself
code
message
exc
msg
T aself
name
default
conn
transport
T aself
message
T aself
timeout
receive_timeout
msg
exc
T aself
timeout
msg
T aself
loads
timeout
data
T aself
data
compress
T aself
message
opcode
compress
T aself
data
compress
dumps
a__spec__
.aiohttp.compression_utils
c
{
gzip
l azlib
aMAX_WBITS
a_mode
a_executor
a_max_sync_chunk_size
a__class__
a__init__
encoding_to_mode
T amode
executor
max_sync_chunk_size
compressobj
T awbits
strategy
a_compressor
T awbits
strategy
level
asyncio
aLock
self
a_compress_lock
compress
uCompress the data and returned the compressed bytes.
Note that flush() must be called after the last call to compress()
If the data size is large than the max_sync_chunk_size, the compression
will be done in the executor. Otherwise, the compression will be done
in the event loop.
a__aenter__
a__aexit__
data
get_running_loop
run_in_executor
compress_sync
T nnnuZLibCompressor.compress
flush
decompressobj
T awbits
a_decompressor
decompress
uDecompress the data and return the decompressed bytes.
If the data size is large than the max_sync_chunk_size, the decompression
will be done in the executor. Otherwise, the decompression will be done
in the event loop.
max_length
decompress_sync
uZLibDecompressor.decompress
eof
unconsumed_tail
unused_data
aHAS_BROTLI
uThe brotli decompression is not available. Please install `Brotli` module
brotli
aDecompressor
a_obj
cast
process
c
a__doc__
a__file__
origin
has_location
a__cached__
uconcurrent.futures
T aExecutor
aExecutor
aOptional
brotlicffi
l  aMAX_SYNC_CHUNK_SIZE
T nFaencoding
suppress_deflate_header
return
