# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.base_protocol

a__qualname__
T a_loop
a_paused
a_drain_waiter
a_connection_lost
a_reading_paused
transport
a__slots__
loop
aAbstractEventLoop
return
a__init__
uBaseProtocol.__init__
property
bool
connected
uBaseProtocol.connected
writing_paused
uBaseProtocol.writing_paused
D areturn
napause_writing
uBaseProtocol.pause_writing
resume_writing
uBaseProtocol.resume_writing
uBaseProtocol.pause_reading
uBaseProtocol.resume_reading
aBaseTransport
connection_made
uBaseProtocol.connection_made
exc
aBaseException
connection_lost
uBaseProtocol.connection_lost
a__orig_bases__
uaiohttp\base_protocol.py
u<module aiohttp.base_protocol>
T a__class__
T aself
loop
T aself
waiter
T aself
T aself
exc
waiter
T aself
transport
tr

a__spec__
.aiohttp.client
sE
j a_connector
a_loop
asyncio
get_running_loop
aURL
a_base_url
origin
a_base_url_origin
absolute
T uOnly absolute URLs are supported
path
endswith
T w/ubase_url must have a trailing '/'
sentinel
aDEFAULT_TIMEOUT
a_timeout
warnings
warn
uread_timeout is deprecated, use timeout argument instead
aDeprecationWarning
D astacklevel
l aattr
evolve
T atotal
T aconnect
uconn_timeout is deprecated, use timeout argument instead
aClientTimeout
utimeout parameter cannot be of

u type, please use 'timeout=ClientTimeout(...)'
uread_timeout and timeout parameters conflict, please setup timeout.read
uconn_timeout and timeout parameters conflict, please setup timeout.connect
aTCPConnector
T aloop
connector
uSession and connector has to use same event loop
get_debug
traceback
extract_stack
a_getframe
T l a_source_traceback
aCookieJar
a_cookie_jar
update_cookies
a_connector_owner
a_default_auth
a_version
a_json_serialize
a_raise_for_status
a_auto_decompress
a_trust_env
a_requote_redirect_url
a_read_bufsize
a_max_line_size
a_max_field_size
aCIMultiDict
a_default_headers
a_skip_auto_headers
P
a_request_class
a_response_class
a_ws_response_class
a_trace_configs
freeze
a_resolve_charset
a_default_proxy
a_default_proxy_auth
a_retry_connection
istr
u<genexpr>
uClientSession.__init__.<locals>.<genexpr>
uInheritance class {} from ClientSession is discouraged
a__name__
aATTRS
uSetting custom ClientSession.{} attribute is discouraged
a__class__
a__setattr__
closed
source
uUnclosed client session
aResourceWarning
client_session
message
uUnclosed client session
source_traceback
call_exception_handler
a_RequestContextManager
a_request
uPerform HTTP request.
join
self
uSession is closed
a_merge_ssl_params
ssl
verify_ssl
ssl_context
fingerprint
data
json
udata and json parameters can not be used at the same time
payload
aJsonPayload
T adumps
chunked
uChunk size is deprecated #1615
params
a_prepare_headers
headers
a_build_url
str_or_url
aInvalidUrlClientError
scheme
allowed_protocol_schema_set
aNonHttpUrlClientError
skip_auto_headers
proxy
proxy_auth
proxy_headers
aInvalidURL
timeout
aTimeoutHandle
total
ceil_threshold
T aceil_threshold
start
read_bufsize
auto_decompress
max_line_size
max_field_size
aTrace
trace_config_ctx
trace_request_ctx
T atrace_request_ctx
send_request_start
method
url
update_query
timer
a__enter__
a__exit__
aIDEMPOTENT_METHODS
strip_auth_from_url
raw_host
redirects
aInvalidUrlRedirectClientError
history
auth
uCannot combine AUTH argument with credentials encoded in URL
hdrs
aAUTHORIZATION
uCannot combine AUTHORIZATION header with AUTH argument or credentials encoded in URL
filter_cookies
cookies
quote_cookie
T aquote_cookie
load
suppress
T ELookupError
get_env_proxy_for_url
T nnnaskip_headers
version
compress
expect100
server_hostname
traces
trust_env
T aparams
headers
skip_auto_headers
data
cookies
auth
version
compress
chunked
expect100
loop
response_class
proxy
proxy_auth
timer
session
ssl
server_hostname
proxy_headers
traces
trust_env
connect
real_timeout
T atraces
timeout
aTimeoutError
aConnectionTimeoutError
uConnection timeout to host
transport
protocol
set_response_params
aEMPTY_BODY_METHODS
read_until_eof
sock_read
a_timeout_ceil_threshold
T	atimer
skip_payload
read_until_eof
auto_decompress
read_timeout
read_bufsize
timeout_ceil_threshold
max_line_size
max_field_size
send
close
aClientOSError
aServerDisconnectedError
retry_persistent_connection
aClientError
errno
args
a_cookies
status
T l  l  l  l  l  aallow_redirects
send_request_redirect
resp
max_redirects
aTooManyRedirects
request_info
l  aMETH_HEAD
T l  l  aMETH_POST
aMETH_GET
get
aCONTENT_LENGTH
pop
aLOCATION
aURI
release
T aencoded
uServer attempted redirecting to a location that does not look like a URL
aHTTP_AND_EMPTY_SCHEMA_SET
aNonHttpUrlRedirectClientError
parsed_redirect_url
uInvalid redirect URL origin
raise_for_status
callable
connection
add_callback
cancel
a_history
send_request_end
handle
send_request_exception
weuClientSession._request
a_WSRequestContextManager
a_ws_connect
T amethod
protocols
timeout
receive_timeout
autoclose
autoping
heartbeat
auth
origin
params
headers
proxy
proxy_auth
ssl
verify_ssl
fingerprint
ssl_context
server_hostname
proxy_headers
compress
max_msg_size
uInitiate websocket connection.
aClientWSTimeout
uparameter 'timeout' of type 'float' is deprecated, please use 'timeout=ClientWSTimeout(ws_close=...)'
T aws_close
aDEFAULT_WS_CLIENT_TIMEOUT
receive_timeout
ufloat parameter 'receive_timeout' is deprecated, please use parameter 'timeout=ClientWSTimeout(ws_receive=...)'
T aws_receive
aUPGRADE
websocket
aCONNECTION
aUpgrade
aSEC_WEBSOCKET_VERSION
u13
real_headers
setdefault
base64
b64encode
urandom
T l adecode
aSEC_WEBSOCKET_KEY
protocols
w,aSEC_WEBSOCKET_PROTOCOL
aORIGIN
ws_ext_gen
T acompress
aSEC_WEBSOCKET_EXTENSIONS
ussl=None is deprecated, please use ssl=True
request
T	aparams
headers
read_until_eof
auth
proxy
proxy_auth
ssl
server_hostname
proxy_headers
leaWSServerHandshakeError
uInvalid response status
T amessage
status
headers
lower
uInvalid upgrade header
upgrade
uInvalid connection header
aSEC_WEBSOCKET_ACCEPT
hashlib
sha1
aWS_KEY
digest
uInvalid challenge response
split
T w,astrip
ws_ext_parse
aWSHandshakeError
ws_receive
read_timeout
max
aWebSocketDataQueue
conn_proto
l   aset_parser
aWebSocketReader
max_msg_size
aWebSocketWriter
T ause_mask
compress
notakeover
autoclose
autoping
heartbeat
T aheartbeat
compress
client_notakeover
uClientSession._ws_connect
aMultiDictProxy
aMultiDict
items
added_names
result
add
uAdd default headers and transform it to CIMultiDict
uPerform HTTP GET request.
aMETH_OPTIONS
uPerform HTTP OPTIONS request.
uPerform HTTP HEAD request.
uPerform HTTP POST request.
aMETH_PUT
uPerform HTTP PUT request.
aMETH_PATCH
uPerform HTTP PATCH request.
aMETH_DELETE
uPerform HTTP DELETE request.
uClose underlying connector.
Release all acquired resources.
uClientSession.close
uIs client session closed.
A readonly property.
uConnector instance used for the session.
uThe session cookies.
uThe session HTTP protocol version.
uDo URL requoting on redirection handling.
usession.requote_redirect_url modification is deprecated #2778
uclient.loop property is deprecated
uSession's loop.
uTimeout for the session.
uThe default headers of the client session.
uHeaders for which autogeneration should be skipped
uAn object that represents HTTP Basic Authorization
uJson serializer callable
uShould connector be closed on session closing
uShould `ClientResponse.raise_for_status()` be called for each response.
uShould the body response be automatically decompressed.

Should proxies information from environment or netrc be trusted.
Information is from HTTP_PROXY / HTTPS_PROXY environment variables
or ~/.netrc file if present.
uA list of TraceConfig instances used for client tracing
uDetach connector from session without closing the former.
Session is switched to closed state anyway.
uUse async with instead
a__aenter__
uClientSession.__aenter__
a__aexit__
uClientSession.__aexit__
a_coro
throw
a__await__
a_resp
u_BaseRequestContextManager.__aenter__
exc_type
exc
tb
u_BaseRequestContextManager.__aexit__
a_session
u_SessionRequestContextManager.__aenter__
u_SessionRequestContextManager.__aexit__
T aloop
force_close
aClientSession
T aloop
cookies
version
timeout
connector
connector_owner
a_SessionRequestContextManager
uConstructs and sends a request.
Returns response object.
method - HTTP method
url - request url
params - (optional) Dictionary or bytes to be sent in the query
string of the new request
data - (optional) Dictionary, bytes, or file-like object to
send in the body of the request
json - (optional) Any json compatible python object
headers - (optional) Dictionary of HTTP Headers to send with
the request
cookies - (optional) Dict object to send with the request
uth - (optional) BasicAuth named tuple represent HTTP Basic Auth
uth - aiohttp.helpers.BasicAuth
llow_redirects - (optional) If set to False, do not follow
redirects
version - Request HTTP version.
compress - Set to True if request has to be compressed
with deflate encoding.
chunked - Set to chunk size for chunked transfer encoding.
expect100 - Expect 100-continue response from server.
connector - BaseConnector sub-class instance to support
connection pooling.
read_until_eof - Read response until eof if response
does not have Content-Length header.
loop - Optional event loop.
timeout - Optional ClientTimeout settings structure, 5min
total timeout by default.
Usage::
>>> import aiohttp
>>> async with aiohttp.request('GET', 'http://python.org/') as resp:
...    print(resp)
...    data = await resp.read()
<ClientResponse(https://www.python.org/) [200 OK]>
uHTTP Client for asyncio.
a__doc__
a__file__
has_location
a__cached__
a__annotations__
os
sys
contextlib
T asuppress
aTracebackType
aTYPE_CHECKING
aAny
aAwaitable
aCallable
aCoroutine
aFinal
aFrozenSet
aGenerator
aGeneric
aIterable
aList
aMapping
aOptional
aSet
aTuple
aType
aTypedDict
aTypeVar
aUnion
multidict
T aCIMultiDict
aMultiDict
aMultiDictProxy
istr
yarl
T aURL
T ahdrs
http
payload
http
u_websocket.reader
T aWebSocketDataQueue
abc
T aAbstractCookieJar
aAbstractCookieJar
client_exceptions
T aClientConnectionError
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
aClientResponseError
aClientSSLError
aConnectionTimeoutError
aContentTypeError
aInvalidURL
aInvalidUrlClientError
aInvalidUrlRedirectClientError
aNonHttpUrlClientError
aNonHttpUrlRedirectClientError
aRedirectClientError
aServerConnectionError
aServerDisconnectedError
aServerFingerprintMismatch
aServerTimeoutError
aSocketTimeoutError
aTooManyRedirects
aWSMessageTypeError
aWSServerHandshakeError
aClientConnectionError
aClientConnectionResetError
aClientConnectorCertificateError
aClientConnectorDNSError
aClientConnectorError
aClientConnectorSSLError
aClientHttpProxyError
aClientPayloadError
aClientProxyConnectionError
aClientResponseError
aClientSSLError
aContentTypeError
aRedirectClientError
aServerConnectionError
aServerFingerprintMismatch
aServerTimeoutError
aSocketTimeoutError
aWSMessageTypeError
client_reqrep
T aClientRequest
aClientResponse
aFingerprint
aRequestInfo
a_merge_ssl_params
aClientRequest
aClientResponse
aFingerprint
aRequestInfo
client_ws
T aDEFAULT_WS_CLIENT_TIMEOUT
aClientWebSocketResponse
aClientWSTimeout
aClientWebSocketResponse
T aHTTP_AND_EMPTY_SCHEMA_SET
aBaseConnector
aNamedPipeConnector
aTCPConnector
aUnixConnector
aBaseConnector
aNamedPipeConnector
aUnixConnector
cookiejar
T aCookieJar
helpers
T a_SENTINEL
aDEBUG
aEMPTY_BODY_METHODS
aBasicAuth
aTimeoutHandle
get_env_proxy_for_url
sentinel
strip_auth_from_url
a_SENTINEL
aDEBUG
aBasicAuth
T aWS_KEY
aHttpVersion
aWebSocketReader
aWebSocketWriter
aHttpVersion
http_websocket
T aWSHandshakeError
ws_ext_gen
ws_ext_parse
tracing
T aTrace
aTraceConfig
aTraceConfig
typedefs
T aJSONEncoder
aLooseCookies
aLooseHeaders
aQuery
aStrOrURL
aJSONEncoder
aLooseCookies
aLooseHeaders
aQuery
aStrOrURL
T*aClientConnectionError
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
aClientResponseError
aClientSSLError
aConnectionTimeoutError
aContentTypeError
aInvalidURL
aInvalidUrlClientError
aRedirectClientError
aNonHttpUrlClientError
aInvalidUrlRedirectClientError
aNonHttpUrlRedirectClientError
aServerConnectionError
aServerDisconnectedError
aServerFingerprintMismatch
aServerTimeoutError
aSocketTimeoutError
aTooManyRedirects
aWSServerHandshakeError
aClientRequest
aClientResponse
aFingerprint
aRequestInfo
aBaseConnector
aTCPConnector
aUnixConnector
aNamedPipeConnector
aClientWebSocketResponse
aClientSession
aClientTimeout
aClientWSTimeout
request
aWSMessageTypeError
a__all__
aSSLContext
D atotal
Fa__prepare__
a_RequestOptions
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
