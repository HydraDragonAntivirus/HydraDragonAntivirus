# Reconstructed from integrated Nuitka blob
# Module: uhttpx._decoders

aContentDecoder
a__qualname__
D adata
return
bytes
puContentDecoder.decode
D areturn
bytes
uContentDecoder.flush
a__prepare__
aIdentityDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Handle unencoded data.
uIdentityDecoder.decode
uIdentityDecoder.flush
a__orig_bases__
aDeflateDecoder

Handle 'deflate' decoding.
See: https://stackoverflow.com/questions/1838699
D areturn
aNone
a__init__
uDeflateDecoder.__init__
uDeflateDecoder.decode
uDeflateDecoder.flush
aGZipDecoder

Handle 'gzip' decoding.
See: https://stackoverflow.com/questions/1838699
uGZipDecoder.__init__
uGZipDecoder.decode
uGZipDecoder.flush
aBrotliDecoder

Handle 'brotli' decoding.
Requires `pip install brotlipy`. See: https://brotlipy.readthedocs.io/
or   `pip install brotli`. See https://github.com/google/brotli
Supports both 'brotlipy' and 'Brotli' packages since they share an import
name. The top branches are for 'brotlipy' and bottom branches for 'Brotli'
uBrotliDecoder.__init__
uBrotliDecoder.decode
uBrotliDecoder.flush
aZStandardDecoder

Handle 'zstd' RFC 8878 decoding.
Requires `pip install zstandard`.
Can be installed as a dependency of httpx using `pip install httpx[zstd]`.
uZStandardDecoder.__init__
uZStandardDecoder.decode
uZStandardDecoder.flush
aMultiDecoder

Handle the case where multiple encodings have been applied.
D achildren
return
utyping.Sequence[ContentDecoder]
aNone
uMultiDecoder.__init__
uMultiDecoder.decode
uMultiDecoder.flush

Handles returning byte content in fixed-size chunks.
aByteChunker
T nD achunk_size
return
uint | None
aNone
uByteChunker.__init__
D acontent
return
bytes
ulist[bytes]
uByteChunker.decode
D areturn
ulist[bytes]
uByteChunker.flush

Handles returning text content in fixed-size chunks.
aTextChunker
uTextChunker.__init__
D acontent
return
str
ulist[str]
uTextChunker.decode
D areturn
ulist[str]
uTextChunker.flush

Handles incrementally decoding bytes into text
aTextDecoder
T uutf-8
D aencoding
return
str
aNone
uTextDecoder.__init__
D adata
return
bytes
str
uTextDecoder.decode
D areturn
str
uTextDecoder.flush

Handles incrementally reading lines from text.
Has the same behaviour as the stdllib splitlines,
but handling the input iteratively.
aLineDecoder
uLineDecoder.__init__
D atext
return
str
ulist[str]
uLineDecoder.decode
uLineDecoder.flush
identity
gzip
deflate
br
zstd
aSUPPORTED_DECODERS
T azstd
uhttpx\_decoders.py
u<module httpx._decoders>
T a__class__
T aself
T aself
chunk_size
T aself
children
T aself
encoding
T aself
data
exc
T aself
content
value
chunks
T aself
data
T aself
data
was_first_attempt
exc
T aself
text
aNEWLINE_CHARS
trailing_newline
lines
T aself
data
child
T aself
data
output
unused_data
exc
T aself
exc
T aself
value
T aself
lines
T aself
ret
a__spec__
.httpx._exceptions
|
a__class__
a__init__
a_request
uThe .request property has not been set.
request
response
T uAttempted to read or stream some content, but the content has already been streamed. For requests, this could be due to passing a generator as request content, and then receiving a redirect response or a secondary request as part of an authentication flow.For responses, this could be due to attempting to stream the response content more than once.
T uAttempted to read or stream content, but the stream has been closed.
T uAttempted to access streaming response content, without having called `read()`.
T uAttempted to access streaming request content, without having called `read()`.

A context manager that can be used to attach the given request context
to any `RequestError` exceptions that are raised within the block.
aRequestError
request_context

Our exception hierarchy:
* HTTPError
x RequestError
+ TransportError
- TimeoutException
ConnectTimeout
ReadTimeout
WriteTimeout
PoolTimeout
- NetworkError
ConnectError
ReadError
WriteError
CloseError
- ProtocolError
LocalProtocolError
RemoteProtocolError
- ProxyError
- UnsupportedProtocol
+ DecodingError
+ TooManyRedirects
x HTTPStatusError
* InvalidURL
* CookieConflict
* StreamError
x StreamConsumed
x StreamClosed
x ResponseNotRead
x RequestNotRead
a__doc__
a__file__
origin
has_location
a__cached__
annotations
contextlib
typing
L aCloseError
aConnectError
aConnectTimeout
aCookieConflict
aDecodingError
aHTTPError
aHTTPStatusError
aInvalidURL
aLocalProtocolError
aNetworkError
aPoolTimeout
aProtocolError
aProxyError
aReadError
aReadTimeout
aRemoteProtocolError
aRequestError
aRequestNotRead
aResponseNotRead
aStreamClosed
aStreamConsumed
aStreamError
aTimeoutException
aTooManyRedirects
aTransportError
aUnsupportedProtocol
aWriteError
aWriteTimeout
a__all__
T EException
a__prepare__
aHTTPError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
