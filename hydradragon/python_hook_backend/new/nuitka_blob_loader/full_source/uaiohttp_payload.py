# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.payload

a__qualname__
a__orig_bases__
aEnum
data
args
kwargs
return
get_payload
payload_type
upayload_type.__init__
a__call__
upayload_type.__call__
aPayloadType
a_PayloadRegistryItem
uPayload registry.
note: we need zope.interface for more efficient adapter search
aPayloadRegistry
T a_first
a_normal
a_last
a_normal_lookup
a__slots__
D areturn
nuPayloadRegistry.__init__
a_CHAIN
uType[chain[_PayloadRegistryItem]]
uPayloadRegistry.get
uPayloadRegistry.register
str
int
value
uPayload.__init__
property
size
uPayload.size
uPayload.filename
uPayload.headers
bytes
a_binary_headers
uPayload._binary_headers
uPayload.encoding
uPayload.content_type
T tuutf-8
disptype
bool
params
uPayload.set_content_disposition
T uutf-8
strict
uReturn string representation of the value.
This is named decode() to allow compatibility with bytes objects.
uPayload.decode
aBytesPayload
bytearray
memoryview
uBytesPayload.__init__
uBytesPayload.decode
aStringPayload
D aencoding
content_type
nnuStringPayload.__init__
aStringIOPayload
uStringIOPayload.__init__
aIOBasePayload
aIOBase
T aattachment
disposition
uIOBasePayload.__init__
uIOBasePayload.decode
aTextIOPayload
aTextIOBase
uTextIOPayload.__init__
uTextIOPayload.size
uTextIOPayload.decode
aBytesIOPayload
aBytesIO
uBytesIOPayload.size
uBytesIOPayload.decode
aBufferedReaderPayload
aBufferedIOBase
uBufferedReaderPayload.size
uBufferedReaderPayload.decode
aJsonPayload
uapplication/json
dumps
uJsonPayload.__init__
ucollections.abc
T aAsyncIterable
aAsyncIterator
aAsyncIterator
a_AsyncIterator
a_AsyncIterable
aAsyncIterablePayload
uAsyncIterablePayload.__init__
uAsyncIterablePayload.decode
aStreamReaderPayload
uStreamReaderPayload.__init__
T Obytes
Obytearray
Omemoryview
aStringIO
aBufferedReader
aBufferedRandom
uaiohttp\payload.py
T a.0
wraencoding
errors
u<module aiohttp.payload>
T a__class__
T aself
factory
T aself
value
args
kwargs
a__class__
T aself
value
disposition
args
kwargs
a__class__
T aself
value
encoding
content_type
dumps
args
kwargs
a__class__
T aself
value
headers
content_type
filename
encoding
kwargs
guesser
T aself
T	aself
value
encoding
content_type
args
kwargs
real_encoding
mimetype
a__class__
T aself
value
encoding
content_type
args
kwargs
mimetype
a__class__
T aself
type
order
T aself
encoding
errors
T aself
data
a_CHAIN
args
kwargs
factory
type_
lookup_factory
T adata
args
kwargs
T aself
factory
type
order
wtT afactory
type
order
T aself
disptype
quote_fields
a_charset
params
T aself
position
end
T aself
writer
chunk
T aself
writer
T aself
writer
loop
chunk
T aself
writer
loop
chunk
data
a__spec__
.aiohttp.payload_streamer
M
coroutine
coro
args
kwargs
self
writer
a__call__
u_stream_wrapper.__call__
warnings
warn
u@streamer is deprecated, use async generators instead
aDeprecationWarning
D astacklevel
l a_stream_wrapper
a_value
write
uStreamWrapperPayload.write
uUnable to decode.
a__class__
a__init__
uStreamPayload.write

Payload implementation for coroutines as data provider.
As a simple case, you can upload data from file::
@aiohttp.streamer
sync def file_sender(writer, file_name=None):
with open(file_name, 'rb') as f:
chunk = f.read(2**16)
while chunk:
wait writer.write(chunk)
chunk = f.read(2**16)
Then you can use `file_sender` like this:
sync with session.post('http://httpbin.org/post',
data=file_sender(file_name='huge_file')) as resp:
print(await resp.text())
..note:: Coroutine must accept `writer` as first argument
a__doc__
a__file__
origin
has_location
a__cached__
types
aAny
aAwaitable
aCallable
aDict
aTuple
abc
T aAbstractStreamWriter
aAbstractStreamWriter
payload
T aPayload
payload_type
aPayload
payload_type
T astreamer
a__all__
