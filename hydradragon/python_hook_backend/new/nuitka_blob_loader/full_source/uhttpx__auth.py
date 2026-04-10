# Reconstructed from integrated Nuitka blob
# Module: uhttpx._auth


Base class for all authentication schemes.
To implement a custom authentication scheme, subclass `Auth` and override
the `.auth_flow()` method.
If the authentication scheme does I/O such as disk access or network calls, or uses
synchronization primitives such as locks, you should override `.sync_auth_flow()`
nd/or `.async_auth_flow()` instead of `.auth_flow()` to provide specialized
implementations that will be used by `Client` and `AsyncClient` respectively.
aAuth
a__qualname__
D arequest
return
aRequest
utyping.Generator[Request, Response, None]
D arequest
return
aRequest
utyping.AsyncGenerator[Request, Response]
a__prepare__
aFunctionAuth
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Allows the 'auth' argument to be passed as a simple callable function,
that takes the request, and returns a new, modified request.
D afunc
return
utyping.Callable[[Request], Request]
aNone
a__init__
uFunctionAuth.__init__
a__orig_bases__
aBasicAuth

Allows the 'auth' argument to be passed as a (username, password) pair,
nd uses HTTP Basic authentication.
D ausername
password
return
ustr | bytes
ustr | bytes
aNone
uBasicAuth.__init__
D ausername
password
return
ustr | bytes
ustr | bytes
str
uBasicAuth._build_auth_header
aNetRCAuth

Use a 'netrc' file to lookup basic auth credentials based on the url host.
T nD afile
return
ustr | None
aNone
uNetRCAuth.__init__
uNetRCAuth._build_auth_header
aDigestAuth
a__annotations__
md5
uMD5-SESS
aSHA
uSHA-SESS
uSHA-256
sha256
uSHA-256-SESS
uSHA-512
sha512
uSHA-512-SESS
udict[str, typing.Callable[[bytes], _Hash]]
uDigestAuth.__init__
D arequest
response
auth_header
return
aRequest
aResponse
str
a_DigestAuthChallenge
uDigestAuth._parse_challenge
D arequest
challenge
return
aRequest
a_DigestAuthChallenge
str
uDigestAuth._build_auth_header
D anonce_count
nonce
return
int
bytes
puDigestAuth._get_client_nonce
D aheader_fields
return
udict[str, bytes]
str
uDigestAuth._get_header_value
D aqop
request
return
ubytes | None
aRequest
ubytes | None
uDigestAuth._resolve_qop
aNamedTuple
bytes
str
ubytes | None
uhttpx\_auth.py
u<module httpx._auth>
T a__class__
T aself
username
password
T aself
func
T aself
file
netrc
T aself
username
password
userpass
token
T aself
request
challenge
hash_func
digest
aA1
path
aA2
aHA2
nc_value
cnonce
aHA1
qop
digest_data
format_args
T aself
nonce_count
nonce
wsT
self
header_fields
aNON_QUOTED_FIELDS
aQUOTED_TEMPLATE
aNON_QUOTED_TEMPLATE
header_value
wiafield
value
template
T aself
request
response
auth_header
header_dict
scheme
w_afields
field
key
value
realm
nonce
algorithm
opaque
qop
exc
message
T aself
qop
request
qops
message
T aself
request
flow
response
T aself
request
T aself
request
response
auth_header
T aself
request
auth_info
T adata
hash_func
T ahash_func
a__spec__
.httpx._client
g
' ahost
scheme
http
a_port_or_default
lPahttps
l  u
Return 'True' if 'location' is a HTTPS upgrade of 'url'
port
D ahttp
https
lPl  u
Return 'True' if the given URLs share the same origin.
a_stream
a_response
a_start
self
a__iter__
uBoundSyncStream.__iter__
time
perf_counter
datetime
timedelta
T aseconds
elapsed
close
a__aiter__
uBoundAsyncStream.__aiter__
aclose
uBoundAsyncStream.aclose
a_enforce_trailing_slash
aURL
a_base_url
a_build_auth
a_auth
aQueryParams
a_params
aHeaders
headers
aCookies
a_cookies
aTimeout
a_timeout
follow_redirects
max_redirects
request
get
response
a_event_hooks
a_trust_env
a_default_encoding
aClientState
aUNOPENED
a_state
aCLOSED

Check if the client being closed
raw_path
endswith
T d/acopy_with
d/T araw_path
get_environment_proxies
items
aProxy
T aurl
uall://

Authentication class used when none is passed at the request-level.
See also [Authentication][0].
[0]: /quickstart/#authentication

Base URL to use when sending requests with relative URLs.
a_headers

HTTP headers to include when sending requests.
cAccept
c*/*
cAccept-Encoding
aACCEPT_ENCODING
encode
T aascii
cConnection
ckeep-alive
cUser-Agent
aUSER_AGENT
update

Cookie values to include when sending requests.

Query parameters to include in the URL when sending requests.
a_merge_url
a_merge_headers
a_merge_cookies
a_merge_queryparams
timeout
aUseClientDefault
as_dict
aRequest
T acontent
data
files
json
params
headers
cookies
extensions

Build and return a request instance.
* The `params`, `headers` and `cookies` arguments
re merged with any values set on the client.
* The `url` argument is merged with any `base_url` set on the client.
See also: [Request instances][0]
[0]: /advanced/clients/#request-instances
is_relative_url
base_url
lstrip

Merge a URL argument together with any 'base_url' on the client,
to create the URL used for the outgoing request.
cookies

Merge a cookies argument together with any cookies on the client,
to create the cookies used for the outgoing request.

Merge a headers argument together with any headers on the client,
to create the headers used for the outgoing request.
params
merge

Merge a queryparams argument together with any queryparams on the client,
to create the queryparams used for the outgoing request.
aBasicAuth
T ausername
password
aAuth
callable
aFunctionAuth
T afunc
uInvalid "auth" argument:

url
username
password
a_redirect_method
a_redirect_url
a_redirect_headers
a_redirect_stream
extensions
T amethod
url
headers
cookies
stream
extensions

Given a request and a redirect response, return a new request that
should be used to effect the redirect.
method
status_code
codes
aSEE_OTHER
aHEAD
aGET
aFOUND
aMOVED_PERMANENTLY
aPOST

When being redirected we may want to change the method of the request
based on certain specs or browser behavior.
aLocation
aInvalidURL
aRemoteProtocolError
uInvalid URL in location header:
w.T arequest
T ahost
join
fragment
T afragment

Return the URL for the redirect to follow.
a_same_origin
a_is_https_redirect
pop
T aAuthorization
nanetloc
decode
aHost
T uContent-Length
nT uTransfer-Encoding
nT aCookie
nu
Return the headers that should be used for the redirect request.
stream

Return the body that should be used for the redirect request.
a__class__
a__init__
T aauth
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
h2
uUsing http2=True, but the 'h2' package is not installed. Make sure to install httpx using `pip install httpx[http2]`.
a_get_proxy_map
a_init_transport
T averify
cert
trust_env
http1
http2
limits
transport
a_transport
aURLPattern
a_init_proxy_transport
verify
cert
trust_env
http1
http2
limits
T averify
cert
trust_env
http1
http2
limits
a_mounts
sorted
aHTTPTransport
T averify
cert
trust_env
http1
http2
limits
proxy
matches

Returns the transport instance that should be used for a given URL.
This will either be the standard connection pool, or a proxy.
warnings
warn
uSetting per-request cookies=<...> is being deprecated, because the expected behaviour on cookie persistence is ambiguous. Set cookies directly on the client instance instead.
aDeprecationWarning
D astacklevel
l abuild_request
T amethod
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
send
T aauth
follow_redirects

Build and send a request.
Equivalent to:
```python
request = client.build_request(...)
response = client.send(request, ...)
```
See `Client.build_request()`, `Client.send()` and
[Merging of configuration][0] for how the various parameters
re merged with client-level configuration.
[0]: /advanced/clients/#merging-of-configuration

Alternative to `httpx.request()` that streams the response body
instead of loading it into memory at once.
**Parameters**: See `httpx.request`.
See also: [Streaming Responses][0]
[0]: /quickstart#streaming-responses
content
data
files
json
auth
T arequest
auth
follow_redirects
stream
uClient.stream
uCannot send a request, as the client has been closed.
aOPENED
a_set_timeout
a_build_request_auth
a_send_handling_auth
T aauth
follow_redirects
history
read

Send a request.
The request is sent as-is, unmodified.
Typically you'll want to build one with `Client.build_request()`
so that any client-level configuration is merged into the request,
but passing an explicit `httpx.Request()` is supported as well.
See also: [Request instances][0]
[0]: /advanced/clients/#request-instances
sync_auth_flow
a_send_handling_redirects
history
T afollow_redirects
history
auth_flow
append
aTooManyRedirects
T uExceeded maximum allowed redirects.
a_send_single_request
has_redirect_location
a_build_redirect_request
next_request
a_transport_for_url
aSyncByteStream
uAttempted to send an async request with a sync Client instance.
request_context
a__enter__
a__exit__
handle_request
T nnnaBoundSyncStream
T aresponse
start
extract_cookies
default_encoding
logger
info
uHTTP Request: %s %s "%s %d %s"
http_version
reason_phrase

Sends a single request, without handling any redirections.
T aparams
headers
cookies
auth
follow_redirects
timeout
extensions

Send a `GET` request.
**Parameters**: See `httpx.request`.
aOPTIONS

Send an `OPTIONS` request.
**Parameters**: See `httpx.request`.

Send a `HEAD` request.
**Parameters**: See `httpx.request`.
T acontent
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

Send a `POST` request.
**Parameters**: See `httpx.request`.
aPUT

Send a `PUT` request.
**Parameters**: See `httpx.request`.
aPATCH

Send a `PATCH` request.
**Parameters**: See `httpx.request`.
aDELETE

Send a `DELETE` request.
**Parameters**: See `httpx.request`.
values

Close transport and proxies.
uCannot open a client instance more than once.
uCannot reopen a client instance, once it has been closed.
exc_type
exc_value
traceback
aAsyncHTTPTransport

Build and send a request.
Equivalent to:
```python
request = client.build_request(...)
response = await client.send(request, ...)
```
See `AsyncClient.build_request()`, `AsyncClient.send()`
nd [Merging of configuration][0] for how the various parameters
re merged with client-level configuration.
[0]: /advanced/clients/#merging-of-configuration
uAsyncClient.request
uAsyncClient.stream

Send a request.
The request is sent as-is, unmodified.
Typically you'll want to build one with `AsyncClient.build_request()`
so that any client-level configuration is merged into the request,
but passing an explicit `httpx.Request()` is supported as well.
See also: [Request instances][0]
[0]: /advanced/clients/#request-instances
aread
uAsyncClient.send
async_auth_flow
a__anext__
asend
uAsyncClient._send_handling_auth
uAsyncClient._send_handling_redirects
aAsyncByteStream
uAttempted to send an sync request with an AsyncClient instance.
handle_async_request
aBoundAsyncStream
uAsyncClient._send_single_request
uAsyncClient.get
options
uAsyncClient.options
head
uAsyncClient.head
post
uAsyncClient.post
put
uAsyncClient.put
patch
uAsyncClient.patch
delete
uAsyncClient.delete
uAsyncClient.aclose
a__aenter__
uAsyncClient.__aenter__
a__aexit__
uAsyncClient.__aexit__
a__doc__
a__file__
origin
has_location
a__cached__
annotations
enum
logging
typing
contextlib
T aasynccontextmanager
contextmanager
asynccontextmanager
contextmanager
aTracebackType
a__version__
T a__version__
T aAuth
aBasicAuth
aFunctionAuth
a_config
T aDEFAULT_LIMITS
aDEFAULT_MAX_REDIRECTS
aDEFAULT_TIMEOUT_CONFIG
aLimits
aProxy
aTimeout
aDEFAULT_LIMITS
aDEFAULT_MAX_REDIRECTS
aDEFAULT_TIMEOUT_CONFIG
aLimits
a_decoders
T aSUPPORTED_DECODERS
aSUPPORTED_DECODERS
a_exceptions
T aInvalidURL
aRemoteProtocolError
aTooManyRedirects
request_context
a_models
T aCookies
aHeaders
aRequest
aResponse
aResponse
a_status_codes
T acodes
u_transports.base
T aAsyncBaseTransport
aBaseTransport
aAsyncBaseTransport
aBaseTransport
u_transports.default
T aAsyncHTTPTransport
aHTTPTransport
a_types
TaAsyncByteStream
aAuthTypes
aCertTypes
aCookieTypes
aHeaderTypes
aProxyTypes
aQueryParamTypes
aRequestContent
aRequestData
aRequestExtensions
aRequestFiles
aSyncByteStream
aTimeoutTypes
aAuthTypes
aCertTypes
aCookieTypes
aHeaderTypes
aProxyTypes
aQueryParamTypes
aRequestContent
aRequestData
aRequestExtensions
aRequestFiles
aTimeoutTypes
a_urls
T aURL
aQueryParams
a_utils
T aURLPattern
get_environment_proxies
aUSE_CLIENT_DEFAULT
aAsyncClient
aClient
a__all__
aTypeVar
T wTaClient
T abound
wTT wUaAsyncClient
wUD aurl
location
return
aURL
pabool
D aurl
return
aURL
uint | None
D aurl
other
return
aURL
pabool
