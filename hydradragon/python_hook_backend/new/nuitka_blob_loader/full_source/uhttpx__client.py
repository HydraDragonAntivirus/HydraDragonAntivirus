# Reconstructed from integrated Nuitka blob
# Module: uhttpx._client


For some parameters such as `auth=...` and `timeout=...` we need to be able
to indicate the default "unset" state, in a way that is distinctly different
to using `None`.
The default "unset" state indicates that whatever default is set on the
client should be used. This is different to setting `None`, which
explicitly disables the parameter, possibly overriding a client default.
For example we use `timeout=USE_CLIENT_DEFAULT` in the `request()` signature.
Omitting the `timeout` parameter will send a request using whatever default
timeout has been configured on the client. Including `timeout=None` will
ensure no timeout is used.
Note that user code shouldn't need to use the `USE_CLIENT_DEFAULT` constant,
but it is used internally when a parameter is not included.
a__qualname__
getLogger
T ahttpx
upython-httpx/
u,
keys
identity
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
l l a__orig_bases__

A byte stream that is bound to a given response instance, and that
ensures the `response.elapsed` is set once the response is closed.
D astream
response
start
return
aSyncByteStream
aResponse
float
aNone
uBoundSyncStream.__init__
D areturn
utyping.Iterator[bytes]
D areturn
aNone
uBoundSyncStream.close

An async byte stream that is bound to a given response instance, and that
ensures the `response.elapsed` is set once the response is closed.
D astream
response
start
return
aAsyncByteStream
aResponse
float
aNone
uBoundAsyncStream.__init__
D areturn
utyping.AsyncIterator[bytes]
aCallable
aAny
aEventHook
aBaseClient
event_hooks
uutf-8
D aauth
params
headers
cookies
timeout
follow_redirects
max_redirects
event_hooks
base_url
trust_env
default_encoding
return
uAuthTypes | None
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
aTimeoutTypes
bool
int
uNone | typing.Mapping[str, list[EventHook]]
uURL | str
bool
ustr | typing.Callable[[bytes], str]
aNone
uBaseClient.__init__
D areturn
bool
is_closed
uBaseClient.is_closed
uBaseClient.trust_env
D aurl
return
aURL
puBaseClient._enforce_trailing_slash
D aproxy
allow_env_proxies
return
uProxyTypes | None
bool
udict[str, Proxy | None]
uBaseClient._get_proxy_map
D areturn
aTimeout
uBaseClient.timeout
setter
D atimeout
return
aTimeoutTypes
aNone
D areturn
udict[str, list[EventHook]]
uBaseClient.event_hooks
D aevent_hooks
return
udict[str, list[EventHook]]
aNone
D areturn
uAuth | None
uBaseClient.auth
D aauth
return
aAuthTypes
aNone
D areturn
aURL
uBaseClient.base_url
D aurl
return
uURL | str
aNone
D areturn
aHeaders
uBaseClient.headers
D aheaders
return
aHeaderTypes
aNone
D areturn
aCookies
uBaseClient.cookies
D acookies
return
aCookieTypes
aNone
D areturn
aQueryParams
uBaseClient.params
D aparams
return
aQueryParamTypes
aNone
D amethod
url
content
data
files
json
params
headers
cookies
timeout
extensions
return
str
uURL | str
uRequestContent | None
uRequestData | None
uRequestFiles | None
utyping.Any | None
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uTimeoutTypes | UseClientDefault
uRequestExtensions | None
aRequest
uBaseClient.build_request
D aurl
return
uURL | str
aURL
uBaseClient._merge_url
T nD acookies
return
uCookieTypes | None
uCookieTypes | None
uBaseClient._merge_cookies
D aheaders
return
uHeaderTypes | None
uHeaderTypes | None
uBaseClient._merge_headers
D aparams
return
uQueryParamTypes | None
uQueryParamTypes | None
uBaseClient._merge_queryparams
D aauth
return
uAuthTypes | None
uAuth | None
uBaseClient._build_auth
D arequest
auth
return
aRequest
uAuthTypes | UseClientDefault | None
aAuth
uBaseClient._build_request_auth
D arequest
response
return
aRequest
aResponse
aRequest
uBaseClient._build_redirect_request
D arequest
response
return
aRequest
aResponse
str
uBaseClient._redirect_method
D arequest
response
return
aRequest
aResponse
aURL
uBaseClient._redirect_url
D arequest
url
method
return
aRequest
aURL
str
aHeaders
uBaseClient._redirect_headers
D arequest
method
return
aRequest
str
uSyncByteStream | AsyncByteStream | None
uBaseClient._redirect_stream
D arequest
return
aRequest
aNone
uBaseClient._set_timeout

An HTTP client, with connection pooling, HTTP/2, redirects, cookie persistence, etc.
It can be shared between threads.
Usage:
```python
>>> client = httpx.Client()
>>> response = client.get('https://example.org')
```
**Parameters:**
* **auth** - *(optional)* An authentication class to use when sending
requests.
* **params** - *(optional)* Query parameters to include in request URLs, as
a string, dictionary, or sequence of two-tuples.
* **headers** - *(optional)* Dictionary of HTTP headers to include when
sending requests.
* **cookies** - *(optional)* Dictionary of Cookie items to include when
sending requests.
* **verify** - *(optional)* Either `True` to use an SSL context with the
default CA bundle, `False` to disable verification, or an instance of
`ssl.SSLContext` to use a custom context.
* **http2** - *(optional)* A boolean indicating if HTTP/2 support should be
enabled. Defaults to `False`.
* **proxy** - *(optional)* A proxy URL where all the traffic should be routed.
* **timeout** - *(optional)* The timeout configuration to use when sending
requests.
* **limits** - *(optional)* The limits configuration to use.
* **max_redirects** - *(optional)* The maximum number of redirect responses
that should be followed.
* **base_url** - *(optional)* A URL to use as the base when building
request URLs.
* **transport** - *(optional)* A transport class to use for sending requests
over the network.
* **trust_env** - *(optional)* Enables or disables usage of environment
variables for configuration.
* **default_encoding** - *(optional)* The default encoding to use for decoding
response text, if no charset information is included in a response Content-Type
header. Set to a callable for automatic character set detection. Default: "utf-8".
proxy
mounts
transport
D aauth
params
headers
cookies
verify
cert
trust_env
http1
http2
proxy
mounts
timeout
follow_redirects
limits
max_redirects
event_hooks
base_url
transport
default_encoding
return
uAuthTypes | None
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
ussl.SSLContext | str | bool
uCertTypes | None
bool
ppuProxyTypes | None
uNone | typing.Mapping[str, BaseTransport | None]
aTimeoutTypes
bool
aLimits
int
uNone | typing.Mapping[str, list[EventHook]]
uURL | str
uBaseTransport | None
ustr | typing.Callable[[bytes], str]
aNone
uClient.__init__
D averify
cert
trust_env
http1
http2
limits
transport
return
ussl.SSLContext | str | bool
uCertTypes | None
bool
ppaLimits
uBaseTransport | None
aBaseTransport
uClient._init_transport
D aproxy
verify
cert
trust_env
http1
http2
limits
return
aProxy
ussl.SSLContext | str | bool
uCertTypes | None
bool
ppaLimits
aBaseTransport
uClient._init_proxy_transport
D aurl
return
aURL
aBaseTransport
uClient._transport_for_url
D amethod
url
content
data
files
json
params
headers
cookies
auth
follow_redirects
timeout
extensions
return
str
uURL | str
uRequestContent | None
uRequestData | None
uRequestFiles | None
utyping.Any | None
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | UseClientDefault | None
ubool | UseClientDefault
uTimeoutTypes | UseClientDefault
uRequestExtensions | None
aResponse
uClient.request
D amethod
url
content
data
files
json
params
headers
cookies
auth
follow_redirects
timeout
extensions
return
str
uURL | str
uRequestContent | None
uRequestData | None
uRequestFiles | None
utyping.Any | None
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | UseClientDefault | None
ubool | UseClientDefault
uTimeoutTypes | UseClientDefault
uRequestExtensions | None
utyping.Iterator[Response]
D arequest
stream
auth
follow_redirects
return
aRequest
bool
uAuthTypes | UseClientDefault | None
ubool | UseClientDefault
aResponse
uClient.send
D arequest
auth
follow_redirects
history
return
aRequest
aAuth
bool
ulist[Response]
aResponse
uClient._send_handling_auth
D arequest
follow_redirects
history
return
aRequest
bool
ulist[Response]
aResponse
uClient._send_handling_redirects
D arequest
return
aRequest
aResponse
uClient._send_single_request
D	aurl
params
headers
cookies
auth
follow_redirects
timeout
extensions
return
uURL | str
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | UseClientDefault | None
ubool | UseClientDefault
uTimeoutTypes | UseClientDefault
uRequestExtensions | None
aResponse
uClient.get
D	aurl
params
headers
cookies
auth
follow_redirects
timeout
extensions
return
uURL | str
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | UseClientDefault
ubool | UseClientDefault
uTimeoutTypes | UseClientDefault
uRequestExtensions | None
aResponse
uClient.options
uClient.head
Daurl
content
data
files
json
params
headers
cookies
auth
follow_redirects
timeout
extensions
return
uURL | str
uRequestContent | None
uRequestData | None
uRequestFiles | None
utyping.Any | None
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | UseClientDefault
ubool | UseClientDefault
uTimeoutTypes | UseClientDefault
uRequestExtensions | None
aResponse
uClient.post
uClient.put
uClient.patch
uClient.delete
uClient.close
D aself
return
wTpuClient.__enter__
D aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
aNone
uClient.__exit__

An asynchronous HTTP client, with connection pooling, HTTP/2, redirects,
cookie persistence, etc.
It can be shared between tasks.
Usage:
```python
>>> async with httpx.AsyncClient() as client:
>>>     response = await client.get('https://example.org')
```
**Parameters:**
* **auth** - *(optional)* An authentication class to use when sending
requests.
* **params** - *(optional)* Query parameters to include in request URLs, as
a string, dictionary, or sequence of two-tuples.
* **headers** - *(optional)* Dictionary of HTTP headers to include when
sending requests.
* **cookies** - *(optional)* Dictionary of Cookie items to include when
sending requests.
* **verify** - *(optional)* Either `True` to use an SSL context with the
default CA bundle, `False` to disable verification, or an instance of
`ssl.SSLContext` to use a custom context.
* **http2** - *(optional)* A boolean indicating if HTTP/2 support should be
enabled. Defaults to `False`.
* **proxy** - *(optional)* A proxy URL where all the traffic should be routed.
* **timeout** - *(optional)* The timeout configuration to use when sending
requests.
* **limits** - *(optional)* The limits configuration to use.
* **max_redirects** - *(optional)* The maximum number of redirect responses
that should be followed.
* **base_url** - *(optional)* A URL to use as the base when building
request URLs.
* **transport** - *(optional)* A transport class to use for sending requests
over the network.
* **trust_env** - *(optional)* Enables or disables usage of environment
variables for configuration.
* **default_encoding** - *(optional)* The default encoding to use for decoding
response text, if no charset information is included in a response Content-Type
header. Set to a callable for automatic character set detection. Default: "utf-8".
D aauth
params
headers
cookies
verify
cert
http1
http2
proxy
mounts
timeout
follow_redirects
limits
max_redirects
event_hooks
base_url
transport
trust_env
default_encoding
return
uAuthTypes | None
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
ussl.SSLContext | str | bool
uCertTypes | None
bool
puProxyTypes | None
uNone | typing.Mapping[str, AsyncBaseTransport | None]
aTimeoutTypes
bool
aLimits
int
uNone | typing.Mapping[str, list[EventHook]]
uURL | str
uAsyncBaseTransport | None
bool
ustr | typing.Callable[[bytes], str]
aNone
uAsyncClient.__init__
D averify
cert
trust_env
http1
http2
limits
transport
return
ussl.SSLContext | str | bool
uCertTypes | None
bool
ppaLimits
uAsyncBaseTransport | None
aAsyncBaseTransport
uAsyncClient._init_transport
D aproxy
verify
cert
trust_env
http1
http2
limits
return
aProxy
ussl.SSLContext | str | bool
uCertTypes | None
bool
ppaLimits
aAsyncBaseTransport
uAsyncClient._init_proxy_transport
D aurl
return
aURL
aAsyncBaseTransport
uAsyncClient._transport_for_url
D amethod
url
content
data
files
json
params
headers
cookies
auth
follow_redirects
timeout
extensions
return
str
uURL | str
uRequestContent | None
uRequestData | None
uRequestFiles | None
utyping.Any | None
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | UseClientDefault | None
ubool | UseClientDefault
uTimeoutTypes | UseClientDefault
uRequestExtensions | None
utyping.AsyncIterator[Response]
D aself
return
wUpuhttpx\_client.py
u<module httpx._client>
T a__class__
T aself
msg
proxy
T aself
exc_type
exc_value
traceback
proxy
T aself
chunk
T aself
msg
transport
T aself
exc_type
exc_value
traceback
transport
T aself
auth
params
headers
cookies
verify
cert
http1
http2
proxy
mounts
timeout
follow_redirects
limits
max_redirects
event_hooks
base_url
transport
trust_env
default_encoding
h2
allow_env_proxies
proxy_map
a__class__
T aself
auth
params
headers
cookies
timeout
follow_redirects
max_redirects
event_hooks
base_url
trust_env
default_encoding
T aself
stream
response
start
T aself
auth
params
headers
cookies
verify
cert
trust_env
http1
http2
proxy
mounts
timeout
follow_redirects
limits
max_redirects
event_hooks
base_url
transport
default_encoding
h2
allow_env_proxies
proxy_map
a__class__
T aself
auth
T aself
request
response
method
url
headers
stream
cookies
T aself
request
auth
username
password
T aself
url
T aself
proxy
allow_env_proxies
T aself
proxy
verify
cert
trust_env
http1
http2
limits
T aself
verify
cert
trust_env
http1
http2
limits
transport
T aurl
location
T aself
cookies
merged_cookies
T aself
headers
merged_headers
T aself
params
merged_queryparams
T aself
url
merge_url
merge_raw_path
T aself
request
url
method
headers
T aself
request
response
method
T aself
request
method
T aself
request
response
location
url
exc
T aurl
other
T	aself
request
auth
follow_redirects
history
auth_flow
response
next_request
exc
T aself
request
follow_redirects
history
hook
response
exc
T aself
request
transport
start
response
T aself
request
timeout
T aself
url
pattern
transport
T aself
proxy
T aself
elapsed
T aself
T aself
method
url
content
data
files
json
params
headers
cookies
timeout
extensions
T aself
transport
T aself
cookies
T	aself
url
params
headers
cookies
auth
follow_redirects
timeout
extensions
T aself
event_hooks
T aself
headers
client_headers
T aself
params
Taself
url
content
data
files
json
params
headers
cookies
auth
follow_redirects
timeout
extensions
T aself
method
url
content
data
files
json
params
headers
cookies
auth
follow_redirects
timeout
extensions
message
request
T aself
request
stream
auth
follow_redirects
response
exc
T aself
method
url
content
data
files
json
params
headers
cookies
auth
follow_redirects
timeout
extensions
request
response
T aself
timeout
a__spec__
.httpx._config
ssl
warnings
certifi
environ
get
T aSSL_CERT_FILE
create_default_context
aSSL_CERT_FILE
T acafile
T aSSL_CERT_DIR
aSSL_CERT_DIR
T acapath
where
aSSLContext
aPROTOCOL_TLS_CLIENT
check_hostname
aCERT_NONE
verify_mode
warn
u`verify=<str>` is deprecated. Use `verify=ssl.create_default_context(cafile=...)` or `verify=ssl.create_default_context(capath=...)` instead.
aDeprecationWarning
u`cert=...` is deprecated. Use `verify=<ssl_context>` instead,with `.load_cert_chain()` to configure the certificate chain.
ctx
load_cert_chain
aTimeout
aUNSET
connect
read
write
pool
l l aUnsetType
uhttpx.Timeout must either include a default, or set all four parameters explicitly.
a__name__

u(timeout=
w)u(connect=
u, read=
u, write=
u, pool=
max_connections
max_keepalive_connections
keepalive_expiry
u(max_connections=
u, max_keepalive_connections=
u, keepalive_expiry=
aURL
aHeaders
scheme
T ahttp
https
socks5
socks5h
uUnknown scheme for proxy URL
username
password
copy_with
T nnT ausername
password
url
auth
headers
ssl_context
encode
T uutf-8
u********
u, auth=
u, headers=
uProxy(
a__doc__
a__file__
origin
has_location
a__cached__
annotations
os
typing
a_models
T aHeaders
a_types
T aCertTypes
aHeaderTypes
aTimeoutTypes
aCertTypes
aHeaderTypes
aTimeoutTypes
a_urls
T aURL
L aLimits
aProxy
aTimeout
create_ssl_context
a__all__
