# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.resolver

uThreaded resolver.
Uses an Executor for synchronous getaddrinfo() calls.
concurrent.futures.ThreadPoolExecutor is used by default.
a__qualname__
T naloop
aAbstractEventLoop
return
a__init__
uThreadedResolver.__init__
str
int
aAddressFamily
D areturn
na__orig_bases__
aAsyncResolver
uUse the `aiodns` package to make asynchronous DNS lookups
kwargs
uAsyncResolver.__init__
a_DefaultType
aDefaultResolver
uaiohttp\resolver.py
u<module aiohttp.resolver>
T a__class__
T aself
loop
args
kwargs
T aself
loop
T
self
host
port
family
qtype
resp
exc
msg
hosts
rr
T aself
T aself
host
port
family
hosts
address
resp
exc
msg
node
result
resolved_host
T aself
host
port
family
hosts
infos
w_aproto
address
resolved_host
a_port

a__spec__
.aiohttp.streams
; aread_func
self
aEofStream
c
a__anext__
uAsyncStreamIterator.__anext__
a_stream
readchunk
T c
FuChunkTupleAsyncStreamIterator.__anext__
aAsyncStreamIterator
readline
u<lambda>
uAsyncStreamReaderMixin.iter_chunked.<locals>.<lambda>
uReturns an asynchronous iterator that yields chunks of size n.
read
wnareadany
uYield all available data as soon as it is received.
aChunkTupleAsyncStreamIterator
uYield chunks of data as they are received by the server.
The yielded objects are tuples
of (bytes, bool) as returned by the StreamReader.readchunk method.
a_protocol
a_low_water
l a_high_water
asyncio
get_event_loop
a_loop
a_size
a_cursor
a_http_chunk_splits
collections
deque
a_buffer
a_buffer_offset
a_eof
a_waiter
a_eof_waiter
a_exception
aTimerNoop
a_timer
a_eof_callbacks
a_eof_counter
total_bytes
a__name__
u%d bytes
eof
l   ulow=%d high=%d
uw=%r
ue=%r
u<%s>
w aclear
set_exception
internal_logger
exception
T uException in eof callback
append
set_result
a_reading_paused
resume_reading
uReturn True if  'feed_eof' was called.
uReturn True if the buffer is empty and 'feed_eof' was called.
create_future
wait_eof
uStreamReader.wait_eof
warnings
warn
uunread_data() is deprecated and will be removed in future releases (#3260)
aDeprecationWarning
D astacklevel
l aappendleft
urollback reading some data from stream, inserting it to buffer head.
T ufeed_data after feed_eof
pause_reading
uCalled begin_http_chunk_receiving when some data was already fed
uCalled end_chunk_receiving without calling begin_chunk_receiving first
connected
uConnection closed.
u%s() called while another coroutine is already waiting for incoming data
func_name
a__enter__
a__exit__
T nnna_wait
uStreamReader._wait
readuntil
uStreamReader.readline
separator
uSeparator should be at least one-byte string
not_enough
find
a_read_nowait_chunk
seplen
chunk
chunk_size
uChunk too big
T areaduntil
uStreamReader.readuntil
l awarning
T uMultiple access to StreamReader in eof state, might be infinite loop.
tT astack_info
blocks
T aread
a_read_nowait
uStreamReader.read
T areadany
T q uStreamReader.readany
uReturns a tuple of (data, end_of_http_chunk).
When chunked transfer
encoding is used, end_of_http_chunk is a boolean indicating if the end
of the data corresponds to the end of a HTTP chunk , otherwise it is
lways False.
pop
T l
T c
tT uSkipping HTTP chunk end due to data consumption beyond chunk boundary
T areadchunk
uStreamReader.readchunk
aIncompleteReadError
readexactly
uStreamReader.readexactly
done
uCalled while some coroutine is waiting for incoming data.
popleft
chunk_splits
assert_timeout
chunks
uRead not more than n bytes, or whole buffer if n == -1
a_read_eof_chunk
uEmptyStreamReader.wait_eof
uEmptyStreamReader.readline
uEmptyStreamReader.read
uEmptyStreamReader.readany
uEmptyStreamReader.readchunk
uEmptyStreamReader.readexactly
aCancelledError
aTimeoutError
uDataQueue.read
a__class__
a__init__
T aloop
a_limit
feed_data
uFlowControlDataQueue.read
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
aAwaitable
aCallable
aDeque
aFinal
aGeneric
aList
aOptional
aTuple
aTypeVar
base_protocol
T aBaseProtocol
aBaseProtocol
helpers
T a_EXC_SENTINEL
aBaseTimerContext
aTimerNoop
set_exception
set_result
a_EXC_SENTINEL
aBaseTimerContext
log
T ainternal_logger
T aEMPTY_PAYLOAD
aEofStream
aStreamReader
aDataQueue
a__all__
T a_T
a_T
T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
