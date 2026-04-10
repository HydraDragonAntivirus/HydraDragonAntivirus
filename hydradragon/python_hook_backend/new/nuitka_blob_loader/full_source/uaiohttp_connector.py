# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.connector

a__qualname__
T a_awaitable
a_awaited
a__slots__
awaitable
return
u_DeprecationWaiter.__init__
u_DeprecationWaiter.__await__
D areturn
na__del__
u_DeprecationWaiter.__del__
aBaseConnector
aConnectionKey
protocol
loop
aAbstractEventLoop
uConnection.__init__
D areturn
Ostr
a__repr__
uConnection.__repr__
a_warnings
uConnection.__del__
uForce subclasses to not be falsy, to make checks simpler.
a__bool__
uConnection.__bool__
uConnection.loop
uConnection.transport
uConnection.protocol
callback
T L
naadd_callback
uConnection.add_callback
uConnection._notify_release
uConnection.close
release
uConnection.release
D areturn
Obool
closed
uConnection.closed
uplaceholder for BaseConnector.connect function
uClose the placeholder transport.
u_TransportPlaceholder.close
uBase connector class.
keepalive_timeout - (optional) Keep-alive timeout.
force_close - Set to True to force close and do reconnect
fter each request (and between redirects).
limit - The total number of simultaneous connections.
limit_per_host - Number of simultaneous connections to one host.
enable_cleanup_closed - Enables clean-up closed ssl transports.
Disabled by default.
timeout_ceil_threshold - Trigger ceiling of timeout values when
it's above timeout_ceil_threshold.
loop - Optional event loop.
f
@aallowed_protocol_schema_set
keepalive_timeout
force_close
limit
ldalimit_per_host
enable_cleanup_closed
timeout_ceil_threshold
l T Oobject
nOfloat
uBaseConnector.__init__
uBaseConnector.__del__
D areturn
aBaseConnector
uBaseConnector.__enter__
exc
uBaseConnector.__exit__
exc_type
exc_value
exc_traceback
uBaseConnector.force_close
D areturn
Oint
uBaseConnector.limit
uBaseConnector.limit_per_host
uBaseConnector._cleanup
uBaseConnector._cleanup_closed
uBaseConnector.close
uBaseConnector._close
uBaseConnector.closed
D akey
return
aConnectionKey
Oint
uBaseConnector._available_connections
aTrace
aClientTimeout
uBaseConnector._release_waiter
uBaseConnector._release_acquired
D ashould_close
FuBaseConnector._release
ttl
u_DNSCacheTable.__init__
D ahost
return
Oobject
Obool
a__contains__
u_DNSCacheTable.__contains__
T Ostr
Oint
addrs
u_DNSCacheTable.add
u_DNSCacheTable.remove
u_DNSCacheTable.clear
u_DNSCacheTable.next_addrs
u_DNSCacheTable.expired
verified
a_make_ssl_context
T ta__prepare__
aTCPConnector
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uTCP connector.
verify_ssl - Set to True to check ssl certifications.
fingerprint - Pass the binary sha256
digest of the expected certificate in DER format to verify
that the certificate the server presents matches. See also
https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
resolver - Enable DNS lookups and use this
resolver
use_dns_cache - Use memory cache for DNS lookups.
ttl_dns_cache - Max seconds having cached a DNS entry, None forever.
family - socket address family
local_addr - local tuple of (host, port) to bind socket to
keepalive_timeout - (optional) Keep-alive timeout.
force_close - Set to True to force close and do reconnect
fter each request (and between redirects).
limit - The total number of simultaneous connections.
limit_per_host - Number of simultaneous connections to one host.
enable_cleanup_closed - Enables clean-up closed ssl transports.
Disabled by default.
happy_eyeballs_delay - This is the    Connection Attempt Delay
s defined in RFC 8305. To disable
the happy eyeballs algorithm, set to None.
interleave -    First Address Family Count    as defined in RFC 8305
loop - Optional event loop.
frozenset
S atcp
P atcp
verify_ssl
use_dns_cache
ttl_dns_cache
l
aAddressFamily
aAF_UNSPEC
ssl_context
local_addr
happy_eyeballs_delay
f
?ainterleave
bool
bytes
int
str
float
object
uTCPConnector.__init__
uTCPConnector.close
property
uTCPConnector.family
uTCPConnector.use_dns_cache
T nnaclear_dns_cache
uTCPConnector.clear_dns_cache
uasyncio.Future[None]
uTCPConnector._get_ssl_context
uTCPConnector._get_fingerprint
aAddrInfoType
aException
D areq
return
aClientRequest
nuTCPConnector._fail_on_no_start_tls
uTCPConnector._check_loop_for_start_tls
uTCPConnector._loop_supports_start_tls
uTCPConnector._warn_about_tls_in_tls
aBaseTransport
hosts
uTCPConnector._convert_hosts_to_addr_infos
a__orig_bases__
aUnixConnector
uUnix socket connector.
path - Unix socket path.
keepalive_timeout - (optional) Keep-alive timeout.
force_close - Set to True to force close and do reconnect
fter each request (and between redirects).
limit - The total number of simultaneous connections.
limit_per_host - Number of simultaneous connections to one host.
loop - Optional event loop.
S aunix
P aunix
uUnixConnector.__init__
uUnixConnector.path
aNamedPipeConnector
uNamed pipe connector.
Only supported by the proactor event loop.
See also: https://docs.python.org/3/library/asyncio-eventloop.html
path - Windows named pipe path.
keepalive_timeout - (optional) Keep-alive timeout.
force_close - Set to True to force close and do reconnect
fter each request (and between redirects).
limit - The total number of simultaneous connections.
limit_per_host - Number of simultaneous connections to one host.
loop - Optional event loop.
S anpipe
P anpipe
uNamedPipeConnector.__init__
uNamedPipeConnector.path
uaiohttp\connector.py
u<module aiohttp.connector>
T a__class__
T aself
T aself
exc_type
exc_value
exc_traceback
T aself
host
T aself
a_warnings
conns
kwargs
context
T aself
a_warnings
kwargs
context
T aself
exc
T aself
keepalive_timeout
force_close
limit
limit_per_host
enable_cleanup_closed
loop
timeout_ceil_threshold
T aself
connector
key
protocol
loop
T aself
path
force_close
keepalive_timeout
limit
limit_per_host
loop
a__class__
T aself
verify_ssl
fingerprint
use_dns_cache
ttl_dns_cache
family
ssl_context
ssl
local_addr
resolver
keepalive_timeout
force_close
limit
limit_per_host
enable_cleanup_closed
loop
timeout_ceil_threshold
happy_eyeballs_delay
interleave
a__class__
T aself
ttl
T aself
awaitable
T aself
key
total_remain
host_remain
acquired
T aself
attr_exc
T aself
alive
now
timeout
connections
deadline
key
conns
proto
use_time
transport
T aself
transport
T aself
data
proto
t0
transport
keyed_waiters
keyed_waiter
T aself
hosts
addr_infos
hinfo
host
is_ipv6
family
addr
T aself
req
traces
timeout
T aself
req
traces
timeout
w_aproto
exc
T aself
req
traces
timeout
w_aproto
T aself
req
traces
timeout
client_error
last_exc
sock
sslcontext
fingerprint
host
port
hosts
exc
addr_infos
server_hostname
transp
proto
bad_peer
T aself
req
traces
timeout
headers
runtime_has_start_tls
url
proxy_req
transport
proto
auth
key
conn
proxy_resp
protocol
resp
message
rawsock
sslcontext
T aself
req
proxy_url
T	aself
key
traces
conns
t1
proto
t0
trace
transport
T aself
req
ret
T aself
req
sslcontext
T averified
sslcontext
T aself
callbacks
cb
T aself
key
protocol
should_close
transport
T aself
key
proto
conns
T aself
queues
key
waiters
waiter
w_T aself
host
port
traces
futures
future
trace
res
key
result
coro
loop
resolved_host_task
drop_exception
T
self
key
host
port
futures
traces
trace
addrs
fut
weT aself
underlying_transport
req
timeout
client_error
tls_proto
sslcontext
tls_transport
fingerprint
exc
type_err
msg
T aself
key
traces
fut
attempts
keyed_waiters
trace
T aself
underlying_transport
req
asyncio_supports_tls_in_tls
T
self
addr_infos
req
timeout
client_error
args
kwargs
sock
connection
exc
T aself
req
timeout
client_error
args
kwargs
exc
T aself
key
addrs
T aself
callback
T aself
host
port
T aself
fut
wta__class__
T
self
req
traces
timeout
key
conn
placeholder
trace
proto
acquired_per_host
T afut
T aself
key
T aself
key
loop
length
addrs
a__spec__
.aiohttp
C
a__all__
T a__doc__
T aGunicornUVLoopWebWorker
aGunicornWebWorker
worker
aGunicornUVLoopWebWorker
aGunicornWebWorker
umodule aiohttp has no attribute

a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_aiohttp
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
a__annotations__
u3.11.13
a__version__
aTYPE_CHECKING
aTuple
T ahdrs
hdrs
client
T*aBaseConnector
aClientConnectionError
aClientConnectionResetError
aClientConnectorCertificateError
aClientConnectorDNSError
aClientConnectorError
aClientConnectorSSLError
aClientError
aClientHttpProxyError
aClientOSError
aClientPayloadError
aClientProxyConnectionError
aClientRequest
aClientResponse
aClientResponseError
aClientSession
aClientSSLError
aClientTimeout
aClientWebSocketResponse
aClientWSTimeout
aConnectionTimeoutError
aContentTypeError
aFingerprint
aInvalidURL
aInvalidUrlClientError
aInvalidUrlRedirectClientError
aNamedPipeConnector
aNonHttpUrlClientError
aNonHttpUrlRedirectClientError
aRedirectClientError
aRequestInfo
aServerConnectionError
aServerDisconnectedError
aServerFingerprintMismatch
aServerTimeoutError
aSocketTimeoutError
aTCPConnector
aTooManyRedirects
aUnixConnector
aWSMessageTypeError
aWSServerHandshakeError
request
aBaseConnector
aClientConnectionError
aClientConnectionResetError
aClientConnectorCertificateError
aClientConnectorDNSError
aClientConnectorError
aClientConnectorSSLError
aClientError
aClientHttpProxyError
aClientOSError
aClientPayloadError
aClientProxyConnectionError
aClientRequest
aClientResponse
aClientResponseError
aClientSession
aClientSSLError
aClientTimeout
aClientWebSocketResponse
aClientWSTimeout
aConnectionTimeoutError
aContentTypeError
aFingerprint
aInvalidURL
aInvalidUrlClientError
aInvalidUrlRedirectClientError
aNamedPipeConnector
aNonHttpUrlClientError
aNonHttpUrlRedirectClientError
aRedirectClientError
aRequestInfo
aServerConnectionError
aServerDisconnectedError
aServerFingerprintMismatch
aServerTimeoutError
aSocketTimeoutError
aTCPConnector
aTooManyRedirects
aUnixConnector
aWSMessageTypeError
aWSServerHandshakeError
request
cookiejar
T aCookieJar
aDummyCookieJar
aCookieJar
aDummyCookieJar
formdata
T aFormData
aFormData
helpers
T aBasicAuth
aChainMapProxy
aETag
aBasicAuth
aChainMapProxy
aETag
http
T aHttpVersion
aHttpVersion10
aHttpVersion11
aWebSocketError
aWSCloseCode
aWSMessage
aWSMsgType
aHttpVersion
aHttpVersion10
aHttpVersion11
aWebSocketError
aWSCloseCode
aWSMessage
aWSMsgType
multipart
T aBadContentDispositionHeader
aBadContentDispositionParam
aBodyPartReader
aMultipartReader
aMultipartWriter
content_disposition_filename
parse_content_disposition
aBadContentDispositionHeader
aBadContentDispositionParam
aBodyPartReader
aMultipartReader
aMultipartWriter
content_disposition_filename
parse_content_disposition
payload
TaPAYLOAD_REGISTRY
aAsyncIterablePayload
aBufferedReaderPayload
aBytesIOPayload
aBytesPayload
aIOBasePayload
aJsonPayload
aPayload
aStringIOPayload
aStringPayload
aTextIOPayload
get_payload
payload_type
aPAYLOAD_REGISTRY
aAsyncIterablePayload
aBufferedReaderPayload
aBytesIOPayload
aBytesPayload
aIOBasePayload
aJsonPayload
aPayload
aStringIOPayload
aStringPayload
aTextIOPayload
get_payload
payload_type
payload_streamer
T astreamer
streamer
resolver
T aAsyncResolver
aDefaultResolver
aThreadedResolver
aAsyncResolver
aDefaultResolver
aThreadedResolver
streams
T aEMPTY_PAYLOAD
aDataQueue
aEofStream
aFlowControlDataQueue
aStreamReader
aEMPTY_PAYLOAD
aDataQueue
aEofStream
aFlowControlDataQueue
aStreamReader
tracing
T aTraceConfig
aTraceConnectionCreateEndParams
aTraceConnectionCreateStartParams
aTraceConnectionQueuedEndParams
aTraceConnectionQueuedStartParams
aTraceConnectionReuseconnParams
aTraceDnsCacheHitParams
aTraceDnsCacheMissParams
aTraceDnsResolveHostEndParams
aTraceDnsResolveHostStartParams
aTraceRequestChunkSentParams
aTraceRequestEndParams
aTraceRequestExceptionParams
aTraceRequestHeadersSentParams
aTraceRequestRedirectParams
aTraceRequestStartParams
aTraceResponseChunkReceivedParams
aTraceConfig
aTraceConnectionCreateEndParams
aTraceConnectionCreateStartParams
aTraceConnectionQueuedEndParams
aTraceConnectionQueuedStartParams
aTraceConnectionReuseconnParams
aTraceDnsCacheHitParams
aTraceDnsCacheMissParams
aTraceDnsResolveHostEndParams
aTraceDnsResolveHostStartParams
aTraceRequestChunkSentParams
aTraceRequestEndParams
aTraceRequestExceptionParams
aTraceRequestHeadersSentParams
aTraceRequestRedirectParams
aTraceRequestStartParams
aTraceResponseChunkReceivedParams
Thahdrs
aBaseConnector
aClientConnectionError
aClientConnectionResetError
aClientConnectorCertificateError
aClientConnectorDNSError
aClientConnectorError
aClientConnectorSSLError
aClientError
aClientHttpProxyError
aClientOSError
aClientPayloadError
aClientProxyConnectionError
aClientResponse
aClientRequest
aClientResponseError
aClientSSLError
aClientSession
aClientTimeout
aClientWebSocketResponse
aClientWSTimeout
aConnectionTimeoutError
aContentTypeError
aFingerprint
aFlowControlDataQueue
aInvalidURL
aInvalidUrlClientError
aInvalidUrlRedirectClientError
aNonHttpUrlClientError
aNonHttpUrlRedirectClientError
aRedirectClientError
aRequestInfo
aServerConnectionError
aServerDisconnectedError
aServerFingerprintMismatch
aServerTimeoutError
aSocketTimeoutError
aTCPConnector
aTooManyRedirects
aUnixConnector
aNamedPipeConnector
aWSServerHandshakeError
request
aCookieJar
aDummyCookieJar
aFormData
aBasicAuth
aChainMapProxy
aETag
aHttpVersion
aHttpVersion10
aHttpVersion11
aWSMsgType
aWSCloseCode
aWSMessage
aWebSocketError
aBadContentDispositionHeader
aBadContentDispositionParam
aBodyPartReader
aMultipartReader
aMultipartWriter
content_disposition_filename
parse_content_disposition
aAsyncIterablePayload
aBufferedReaderPayload
aBytesIOPayload
aBytesPayload
aIOBasePayload
aJsonPayload
aPAYLOAD_REGISTRY
aPayload
aStringIOPayload
aStringPayload
aTextIOPayload
get_payload
payload_type
streamer
aAsyncResolver
aDefaultResolver
aThreadedResolver
aDataQueue
aEMPTY_PAYLOAD
aEofStream
aStreamReader
aTraceConfig
aTraceConnectionCreateEndParams
aTraceConnectionCreateStartParams
aTraceConnectionQueuedEndParams
aTraceConnectionQueuedStartParams
aTraceConnectionReuseconnParams
aTraceDnsCacheHitParams
aTraceDnsCacheMissParams
aTraceDnsResolveHostEndParams
aTraceDnsResolveHostStartParams
aTraceRequestChunkSentParams
aTraceRequestEndParams
aTraceRequestExceptionParams
aTraceRequestHeadersSentParams
aTraceRequestRedirectParams
aTraceRequestStartParams
aTraceResponseChunkReceivedParams
aGunicornUVLoopWebWorker
aGunicornWebWorker
aWSMessageTypeError
T Ostr
Q
return
a__dir__
D aname
return
Ostr
Oobject
a__getattr__
uaiohttp\__init__.py
u<module aiohttp>
T aname
guv
gw
a__spec__
.aiohttp.cookiejar
) a__class__
a__init__
T aloop
defaultdict
aSimpleCookie
a_cookies
T Odict
a_morsel_cache
a_host_only_cookies
a_unsafe
a_quote_cookie
aURL
origin
a_treat_as_secure_origin
a_expire_heap
a_expirations
pathlib
aPath
open
T awb
T amode
a__enter__
a__exit__
pickle
dump
aHIGHEST_PROTOCOL
T nnnT arb
load
clear
time
items
self
predicate
a_delete_cookies
u<lambda>
uCookieJar.clear_domain.<locals>.<lambda>
a_is_domain_match
domain
a_do_expiration
values
a__iter__
uCookieJar.__iter__
uReturn number of cookies.
This function does not iterate self to avoid unnecessary expiration
checks.
u<genexpr>
uCookieJar.__len__.<locals>.<genexpr>
a_MIN_SCHEDULED_COOKIE_EXPIRATION
l aget
heapq
heapify
heappop
to_del
uRemove expired cookies.
discard
pop
heappush
raw_host
is_ip_address
aMapping
aMorsel
w.u
hostname
add
:l nnapath
w/aresponse_url
startswith
T w/arfind
rstrip
umax-age
min
aMAX_TIME
a_expire_cookie
expires
a_parse_date
uUpdate cookies.
aBaseCookie
warnings
warn
ufilter_cookies expects yarl.URL instances only,and will stop working in 4.x, got
aDeprecationWarning
D astacklevel
l ascheme
T ahttps
wss
contextlib
suppress
T EValueError
T u
pavalue
filtered
key
itertools
accumulate
split
T w.a_FORMAT_DOMAIN_REVERSED
a_FORMAT_PATH
product
secure
cast
uMorsel[str]
set
coded_value
uReturns this jar's cookies filtered by their attributes.
endswith
uImplements domain matching adhering to RFC 6265.
aDATE_TOKENS_RE
finditer
group
T atoken
found_time
cls
aDATE_HMS_TIME_RE
match
groups
found_day
aDATE_DAY_OF_MONTH_RE
found_month
aDATE_MONTH_RE
lastindex
found_year
aDATE_YEAR_RE
year
lFlcl  lEl  aday
l l  ahour
l aminute
l;asecond
calendar
timegm
month
uImplements date string parsing adhering to RFC 6265.
uCookieJar._parse_date.<locals>.<genexpr>
uDummyCookieJar.__iter__
a__doc__
a__file__
has_location
a__cached__
asyncio
datetime
os
re
collections
T adefaultdict
uhttp.cookies
T aBaseCookie
aMorsel
aSimpleCookie
aDefaultDict
aDict
aIterable
aIterator
aList
aOptional
aSet
aTuple
aUnion
yarl
T aURL
abc
T aAbstractCookieJar
aClearCookiePredicate
aAbstractCookieJar
aClearCookiePredicate
helpers
T ais_ip_address
typedefs
T aLooseCookies
aPathLike
aStrOrURL
aLooseCookies
aPathLike
aStrOrURL
T aCookieJar
aDummyCookieJar
a__all__
T Ostr
uMorsel[str]
aCookieItem
u{}/{}
format
u{1}.{0}
lda__prepare__
aCookieJar
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
