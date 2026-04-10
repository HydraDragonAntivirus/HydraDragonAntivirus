# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.compression_utils

aZlibBaseHandler
a__qualname__
mode
executor
max_sync_chunk_size
uZlibBaseHandler.__init__
a__prepare__
aZLibCompressor
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
aZ_DEFAULT_STRATEGY
str
bool
level
int
wbits
strategy
uZLibCompressor.__init__
bytes
uZLibCompressor.compress_sync
aZ_FINISH
uZLibCompressor.flush
a__orig_bases__
aZLibDecompressor
uZLibDecompressor.__init__
T l
uZLibDecompressor.decompress_sync
length
uZLibDecompressor.flush
property
uZLibDecompressor.eof
uZLibDecompressor.unconsumed_tail
uZLibDecompressor.unused_data
aBrotliDecompressor
D areturn
nuBrotliDecompressor.__init__
D adata
return
Obytes
puBrotliDecompressor.decompress_sync
D areturn
Obytes
uBrotliDecompressor.flush
uaiohttp\compression_utils.py
u<module aiohttp.compression_utils>
T a__class__
T aself
T	aself
encoding
suppress_deflate_header
level
wbits
strategy
executor
max_sync_chunk_size
a__class__
T aself
encoding
suppress_deflate_header
executor
max_sync_chunk_size
a__class__
T aself
mode
executor
max_sync_chunk_size
T aself
data
T aself
data
max_length
T aencoding
suppress_deflate_header
T aself
mode
T aself
length

a__spec__
.aiohttp.connector
L
a_awaitable
a_awaited
a__await__
warnings
warn
uConnector.close() is a coroutine, please use await connector.close()
aDeprecationWarning
a_key
a_connector
a_loop
a_protocol
a_callbacks
get_debug
traceback
extract_stack
a_getframe
T l a_source_traceback
uConnection<

w>asource
uUnclosed connection
aResourceWarning
is_closed
a_release
D ashould_close
taclient_connection
message
uUnclosed connection
source_traceback
call_exception_handler
uconnector.loop property is deprecated
D astacklevel
l atransport
append
:nnnasuppress
T EException
a__enter__
a__exit__
T nnna_notify_release
is_connected
sentinel
ukeepalive_timeout cannot be set if force_close is True
f
.@aasyncio
get_running_loop
a_timeout_ceil_threshold
a_closed
defaultdict
deque
a_conns
a_limit
a_limit_per_host
a_acquired
T Oset
a_acquired_per_host
cast
a_keepalive_timeout
a_force_close
aOrderedDict
a_waiters
partial
aResponseHandler
T aloop
a_factory
a_cleanup_handle
a_cleanup_closed_handle
aNEEDS_CLEANUP_CLOSED
uenable_cleanup_closed ignored because https://github.com/python/cpython/pull/118960 is fixed in Python version
a_cleanup_closed_disabled
a_cleanup_closed_transports
a_cleanup_closed
values
a_close
uUnclosed connector
connector
connections
uUnclosed connector
u"with Connector():" is deprecated, use "async with Connector():" instead
self
a__aenter__
uBaseConnector.__aenter__
close
a__aexit__
uBaseConnector.__aexit__
uUltimately close connection on releasing if True.
uThe total number for simultaneous connections.
If limit is 0 the connector has no limit.
The default limit size is 100.
uThe limit for simultaneous connections to the same endpoint.
Endpoints are the same if they are have equal
(host, port, is_ssl) triple.
cancel
monotonic
items
deadline
alive
key
is_ssl
helpers
weakref_handle
a_cleanup
T atimeout_ceil_threshold
uCleanup unused transports.
abort
a_cleanup_closed_period
uDouble confirmation for transport close.
Some broken ssl servers may leave socket open without proper close.
a_DeprecationWaiter
noop
uClose all opened transports.
clear
uIs connector closed.
A readonly property.
get

Return number of available connections.
The limit, limit_per_host and the connection key are taken into account.
If it returns less than 1 means that there are no connections
vailable.
uGet from pool or create new connection.
req
connection_key
a_get
traces
ceil_timeout
timeout
connect
ceil_threshold
a_available_connections
a_wait_for_available_connection
a_TransportPlaceholder
add
send_connection_create_start
a_create_connection
send_connection_create_end
a_release_acquired
aClientConnectionError
T uConnector is closed.
remove
placeholder
proto
aConnection
uBaseConnector.connect
uWait for an available connection slot.
create_future
attempts
move_to_end
D alast
Fasend_connection_queued_start
send_connection_queued_end
pop
uBaseConnector._wait_for_available_connection
uGet next reusable connection for the key or None.
The connection will be marked as acquired.
conns
popleft
t1
send_connection_reuseconn
uBaseConnector._get
random
shuffle
waiters
popitem
T FT alast
done
set_result
T nu
Iterates over all waiters until one to be released is found.
The one to be released is not finished and
belongs to a host that has available connections.
discard
a_release_waiter
uRelease acquired connection.
should_close
uBaseConnector._create_connection
a_addrs_rr
a_timestamps
a_ttl
cycle
islice
ssl
create_default_context
aSSLContext
aPROTOCOL_TLS_CLIENT
options
aOP_NO_SSLv2
aOP_NO_SSLv3
check_hostname
aCERT_NONE
verify_mode
aOP_NO_COMPRESSION
set_default_verify_paths
sslcontext
set_alpn_protocols
T T uhttp/1.1
uCreate SSL context.
This method is not async-friendly and should be called from a thread
because it will load certificates from disk and do other blocking I/O.
a__class__
a__init__
T akeepalive_timeout
force_close
limit
limit_per_host
enable_cleanup_closed
loop
timeout_ceil_threshold
a_merge_ssl_params
a_ssl
aDefaultResolver
a_resolver
a_use_dns_cache
a_DNSCacheTable
T attl
a_cached_hosts
a_throttle_dns_futures
a_family
aiohappyeyeballs
addr_to_addr_infos
a_local_addr_infos
a_happy_eyeballs_delay
a_interleave
a_resolve_host_tasks
chain
from_iterable
uClose all ongoing DNS calls.
uSocket family like AF_INET.
uTrue if local DNS caching is enabled.
ueither both host and port or none of them are allowed
uRemove specified host/port or clear all dns local cache.
uResolve host and return list of addresses.
is_ip_address
host
hostname
port
family
flags
send_dns_resolvehost_start
resolve
T afamily
send_dns_resolvehost_end
expired
next_addrs
send_dns_cache_hit
a_resolve_host_with_throttle
create_task
add_done_callback
shield
aCancelledError
D afut
return
uasyncio.Future[List[ResolveResult]]
nadrop_exception
uTCPConnector._resolve_host.<locals>.drop_exception
a_resolve_host
uTCPConnector._resolve_host
result
uResolve host and set result for all waiters.
This method must be run in a task and shielded from cancellation
to avoid cancelling the underlying lookup.
send_dns_cache_miss
futures
set_exception
weuTCPConnector._resolve_host_with_throttle
uCreate connection.
Has same keyword arguments as BaseEventLoop.create_connection.
proxy
a_create_proxy_connection
a_create_direct_connection
uTCPConnector._create_connection
uSSL is not supported.
a_SSL_CONTEXT_UNVERIFIED
a_SSL_CONTEXT_VERIFIED
uLogic to get the correct SSL context
0. if req.ssl is false, return None
1. if ssl_context is specified in req, use it
2. if _ssl_context is specified in self, use it
3. otherwise:
1. if verify_ssl is not specified in req, use self.ssl_context
(will generate a default context according to self.verify_ssl)
2. if verify_ssl is True in req, generate a default SSL context
3. if verify_ssl is False in req, generate a SSL context that
won't verify
aFingerprint
sock_connect
T aceil_threshold
start_connection
addr_infos
T aaddr_infos
local_addr_infos
happy_eyeballs_delay
interleave
loop
create_connection
args
kwargs
sock
cert_errors
aClientConnectorCertificateError
ssl_errors
aClientConnectorSSLError
errno
aTimeoutError
client_error
a_wrap_create_connection
uTCPConnector._wrap_create_connection
a_wrap_existing_connection
uTCPConnector._wrap_existing_connection
scheme
https
a_check_loop_for_start_tls
uRaise a :py:exc:`RuntimeError` on missing ``start_tls()``.
It is necessary for TLS-in-TLS so that it is possible to
send HTTPS queries through HTTPS proxies.
This doesn't affect regular HTTP requests, though.
start_tls
uAn HTTPS request is being sent through an HTTPS proxy. This needs support for TLS in TLS but it is not implemented in your runtime for the stdlib asyncio.
Please upgrade to Python 3.11 or higher. For more details, please see:
* https://bugs.python.org/issue37179
* https://github.com/python/cpython/pull/28073
* https://docs.aiohttp.org/en/stable/client_advanced.html#proxy-support
* https://github.com/aio-libs/aiohttp/discussions/6044
request_info
url
a_start_tls_compatible
uAn HTTPS request is being sent through an HTTPS proxy. This support for TLS in TLS is known to be disabled in the stdlib asyncio (Python <3.11). This is why you'll probably see an error in the log below.
It is possible to enable it via monkeypatching. For more details, see:
* https://bugs.python.org/issue37179
* https://github.com/python/cpython/pull/28073
You can temporarily patch this as follows:
* https://docs.aiohttp.org/en/stable/client_advanced.html#proxy-support
* https://github.com/aio-libs/aiohttp/discussions/6044
aRuntimeWarning
l T asource
stacklevel
uIssue a warning if the requested URL has HTTPS scheme.
uWrap the raw TCP transport with TLS.
a_get_ssl_context
underlying_transport
server_hostname
total
T aserver_hostname
ssl_handshake_timeout
aTransport
a_get_fingerprint
check
aServerFingerprintMismatch
uCannot initialize a TLS-in-TLS connection to host
w:wdu through an underlying connection to an HTTPS proxy
u ssl:
default
u [
w]atls_transport
uFailed to start TLS (possibly caused by closing transport)
connection_made
a_start_tls_connection
uTCPConnector._start_tls_connection
socket
aAF_INET6
aAF_INET
aSOCK_STREAM
aIPPROTO_TCP
uConverts the list of hosts to a list of addr_infos.
The list of hosts is the result of a DNS lookup. The list of
ddr_infos is the result of a call to `socket.getaddrinfo()`.
raw_host
endswith
T u..
rstrip
T w.w.T atraces
aClientConnectorDNSError
a_convert_hosts_to_addr_infos
T atimeout
ssl
addr_infos
server_hostname
req
client_error
aClientConnectorError
pop_addr_infos_interleave
fingerprint
get_extra_info
T asocket
getpeername
remove_addr_infos
last_exc
uTCPConnector._create_direct_connection
a_fail_on_no_start_tls
a_loop_supports_start_tls
proxy_headers
headers
hdrs
aHOST
aClientRequest
aMETH_GET
proxy_auth
T aheaders
auth
loop
ssl
aClientProxyConnectionError
T aclient_error
aAUTHORIZATION
aPROXY_AUTHORIZATION
a_warn_about_tls_in_tls
aMETH_CONNECT
method
a_replace
T aproxy
proxy_auth
proxy_headers_hash
send
set_response_params
T aread_until_eof
timeout_ceil_threshold
start
status
l  areason
aHTTPStatus
phrase
aClientHttpProxyError
history
T astatus
message
headers
T asocket
nT adefault
uTransport does not expose socket instance
dup
rawsock
T atimeout
ssl
sock
server_hostname
req
T areq
timeout
uTCPConnector._create_proxy_connection
T aforce_close
keepalive_timeout
limit
limit_per_host
loop
a_path
uPath to unix socket.
create_unix_connection
aUnixClientConnectorError
path
uUnixConnector._create_connection
aProactorEventLoop
uNamed Pipes only available in proactor loop under windows
uPath to the named pipe.
create_pipe_connection
sleep
T l
uNamedPipeConnector._create_connection
a__doc__
a__file__
origin
has_location
a__cached__
functools
sys
collections
T aOrderedDict
defaultdict
deque
contextlib
T asuppress
http
T aHTTPStatus
itertools
T achain
cycle
islice
time
T amonotonic
aTracebackType
aTYPE_CHECKING
aAny
aAwaitable
aCallable
aDefaultDict
aDeque
aDict
aIterator
aList
aLiteral
aOptional
aSequence
aSet
aTuple
aType
aUnion
T ahdrs
helpers
abc
T aAbstractResolver
aResolveResult
aAbstractResolver
aResolveResult
client_exceptions
T aClientConnectionError
aClientConnectorCertificateError
aClientConnectorDNSError
aClientConnectorError
aClientConnectorSSLError
aClientHttpProxyError
aClientProxyConnectionError
aServerFingerprintMismatch
aUnixClientConnectorError
cert_errors
ssl_errors
client_proto
T aResponseHandler
client_reqrep
T aClientRequest
aFingerprint
a_merge_ssl_params
T aceil_timeout
is_ip_address
noop
sentinel
set_exception
set_result
resolver
T aDefaultResolver
P u
aEMPTY_SCHEMA_SET
P ahttps
http
aHTTP_SCHEMA_SET
P aws
wss
aWS_SCHEMA_SET
aHTTP_AND_EMPTY_SCHEMA_SET
aHIGH_LEVEL_SCHEMA_SET
T aBaseConnector
aTCPConnector
aUnixConnector
aNamedPipeConnector
a__all__
