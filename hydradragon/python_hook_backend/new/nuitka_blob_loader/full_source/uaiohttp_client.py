# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.client

a__qualname__
str
bool
int
uUnion[ClientTimeout, _SENTINEL, None]
a__orig_bases__
wsT tppT aauto_attribs
frozen
slots
sock_connect
l T l  l T atotal
sock_connect
P aGET
aPUT
aDELETE
aHEAD
aOPTIONS
aTRACE
a_RetType
a_CharsetResolver
uFirst-class interface for making HTTP requests.
P a_json_serialize
a_version
a_resolve_charset
a_cookie_jar
a_source_traceback
a_connector_owner
a_retry_connection
a_base_url
a_base_url_origin
a_raise_for_status
a_request_class
a_default_proxy_auth
a_skip_auto_headers
a_requote_redirect_url
a_default_proxy
a_ws_response_class
a_max_line_size
a_max_field_size
a_connector
a_response_class
a_trace_configs
a_default_auth
a_read_bufsize
a_timeout
a_loop
a_auto_decompress
a_default_headers
requote_redirect_url
a_trust_env
aStackSummary
T naloop
json_serialize
dumps
request_class
response_class
ws_response_class
aHttpVersion11
cookie_jar
connector_owner
conn_timeout
requote_redirect_url
trace_configs
l ?afallback_charset_resolver
uutf-8
u<lambda>
uClientSession.<lambda>
base_url
aAbstractEventLoop
return
a__init__
uClientSession.__init__
cls
a__init_subclass__
uClientSession.__init_subclass__
name
val
uClientSession.__setattr__
a_warnings
a__del__
uClientSession.__del__
kwargs
uClientSession.request
uClientSession._build_url
l
T Ostr
Obool
nl    aws_connect
uClientSession.ws_connect
uCIMultiDict[str]
uClientSession._prepare_headers
D aallow_redirects
tuClientSession.get
options
uClientSession.options
D aallow_redirects
Fahead
uClientSession.head
D adata
napost
uClientSession.post
put
uClientSession.put
patch
uClientSession.patch
delete
uClientSession.delete
D areturn
nD areturn
Obool
uClientSession.closed
uClientSession.connector
uClientSession.cookie_jar
T Oint
puClientSession.version
uClientSession.requote_redirect_url
setter
D aval
return
Obool
nuClientSession.loop
uClientSession.timeout
D areturn
uCIMultiDict[str]
uClientSession.headers
uClientSession.skip_auto_headers
uClientSession.auth
uClientSession.json_serialize
uClientSession.connector_owner
uClientSession.raise_for_status
uClientSession.auto_decompress
uClientSession.trust_env
uClientSession.trace_configs
detach
uClientSession.detach
uClientSession.__enter__
exc_val
exc_tb
uClientSession.__exit__
D areturn
aClientSession
a_BaseRequestContextManager
T a_coro
a_resp
a__slots__
coro
uasyncio.Future[Any]
u_BaseRequestContextManager.__init__
D aarg
return
nuasyncio.Future[Any]
u_BaseRequestContextManager.send
u_BaseRequestContextManager.throw
u_BaseRequestContextManager.close
u_BaseRequestContextManager.__await__
a__iter__
u_BaseRequestContextManager.__iter__
aBaseException
T a_coro
a_resp
a_session
session
u_SessionRequestContextManager.__init__
uaiohttp\client.py
T a.0
wiT wrwbu<module aiohttp.client>
T a__class__
T aself
T aself
exc_type
exc_val
exc_tb
T aself
exc_type
exc
tb
T aself
ret
T aself
a_warnings
kwargs
context
T aself
base_url
connector
loop
cookies
headers
proxy
proxy_auth
skip_auto_headers
auth
json_serialize
request_class
response_class
ws_response_class
version
cookie_jar
connector_owner
raise_for_status
read_timeout
conn_timeout
timeout
auto_decompress
trust_env
requote_redirect_url
trace_configs
read_bufsize
max_line_size
max_field_size
fallback_charset_resolver
real_headers
trace_config
T aself
coro
T aself
coro
session
T acls
T aself
name
val
a__class__
T aself
str_or_url
url
T aself
headers
added_names
result
key
value
T:aself
method
str_or_url
params
data
json
cookies
headers
skip_auto_headers
auth
allow_redirects
max_redirects
compress
chunked
expect100
raise_for_status
read_until_eof
proxy
proxy_auth
timeout
verify_ssl
fingerprint
ssl_context
ssl
server_hostname
proxy_headers
trace_request_ctx
read_bufsize
auto_decompress
max_line_size
max_field_size
history
skip_headers
real_timeout
redirects
version
url
weatm
handle
traces
trace
timer
retry_persistent_connection
auth_from_url
err_exc_cls
all_cookies
tmp_cookie_jar
req_cookies
req
conn
exc
resp
r_url
parsed_redirect_url
scheme
redirect_origin
origin_val_err
T,aself
url
method
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
real_headers
ws_timeout
default_headers
key
value
sec_key
extstr
resp
r_key
match
protocol
resp_protocols
proto
notakeover
compress_hdrs
exc
conn
conn_proto
transport
reader
writer
T aself
url
kwargs
T aself
url
allow_redirects
kwargs
T aself
url
data
kwargs
T aself
method
url
kwargs
T amethod
url
version
connector
loop
kwargs
connector_owner
session
T aself
val
T aself
arg
T aself
args
kwargs
T aself
url
method
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
a__spec__
.aiohttp.client_exceptions
request_info
uBoth code and status arguments are provided; code is deprecated, use status instead
warnings
warn
ucode argument is deprecated, use status instead
aDeprecationWarning
D astacklevel
l astatus
message
headers
history
args
u{}, message={!r}, url={!r}
real_url

u,
u, status=
u, message=
u, headers=
a__name__
w(w)ucode property is deprecated, use status instead
a_conn_key
a_os_error
a__class__
a__init__
errno
strerror
host
port
ssl
uCannot connect to host {0.host}:{0.port} ssl:{1} [{2}]
default
a_path
uCannot connect to unix socket {0.path} ssl:{1} [{2}]
uServer disconnected
expected
got
u<{} expected={!r} got={!r} host={!r} port={!r}>
a_url
a_description
w<w w>u -
a_certificate_error
is_ssl
uCannot connect to host {0.host}:{0.port} ssl:{0.ssl} [{0.certificate_error.__class__.__name__}: {0.certificate_error.args}]
uHTTP related errors.
a__doc__
a__file__
origin
has_location
a__cached__
asyncio
aTYPE_CHECKING
aOptional
aTuple
aUnion
multidict
T aMultiMapping
aMultiMapping
typedefs
T aStrOrURL
aStrOrURL
aSSLContext
aRequestInfo
aClientResponse
aConnectionKey
aRawResponseMessage
T aClientError
aClientConnectionError
aClientConnectionResetError
aClientOSError
aClientConnectorError
aClientProxyConnectionError
aClientSSLError
aClientConnectorDNSError
aClientConnectorSSLError
aClientConnectorCertificateError
aConnectionTimeoutError
aSocketTimeoutError
aServerConnectionError
aServerTimeoutError
aServerDisconnectedError
aServerFingerprintMismatch
aClientResponseError
aClientHttpProxyError
aWSServerHandshakeError
aContentTypeError
aClientPayloadError
aInvalidURL
aInvalidUrlClientError
aRedirectClientError
aNonHttpUrlClientError
aInvalidUrlRedirectClientError
aNonHttpUrlRedirectClientError
aWSMessageTypeError
a__all__
T EException
a__prepare__
aClientError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
