# Reconstructed from integrated Nuitka blob
# Module: httpcore

a__qualname__
a__init__
uAnyIOBackend.__init__
u_backends.trio
T aTrioBackend
aTrioBackend
uTrioBackend.__init__
L1arequest
stream
aOrigin
aURL
aRequest
aResponse
aProxy
aAsyncHTTPConnection
aAsyncConnectionPool
aAsyncHTTPProxy
aAsyncHTTP11Connection
aAsyncHTTP2Connection
aAsyncConnectionInterface
aAsyncSOCKSProxy
aHTTPConnection
aConnectionPool
aHTTPProxy
aHTTP11Connection
aHTTP2Connection
aConnectionInterface
aSOCKSProxy
aSyncBackend
aAnyIOBackend
aTrioBackend
aAsyncMockBackend
aAsyncMockStream
aMockBackend
aMockStream
aAsyncNetworkStream
aAsyncNetworkBackend
aNetworkStream
aNetworkBackend
default_ssl_context
aSOCKET_OPTION
aConnectionNotAvailable
aProxyError
aProtocolError
aLocalProtocolError
aRemoteProtocolError
aUnsupportedProtocol
aTimeoutException
aPoolTimeout
aConnectTimeout
aReadTimeout
aWriteTimeout
aNetworkError
aConnectError
aReadError
aWriteError
a__all__
u1.0.7
a__version__
a__locals
a__name
startswith
T a__
uhttpcore\__init__.py
u<module httpcore>
T aself
args
kwargs
msg

a__spec__
.httpx.__version__
a__doc__
a__file__
origin
has_location
a__cached__
httpx
a__title__
uA next generation HTTP client, for Python 3.
a__description__
u0.28.1
a__version__
uhttpx\__version__.py
u<module httpx.__version__>

a__spec__
.httpx._api
`
aClient
T acookies
proxy
verify
timeout
trust_env
a__enter__
a__exit__
request
T
method
url
content
data
files
json
params
headers
auth
follow_redirects
T nnnu
Sends an HTTP request.
**Parameters:**
* **method** - HTTP method for the new `Request` object: `GET`, `OPTIONS`,
`HEAD`, `POST`, `PUT`, `PATCH`, or `DELETE`.
* **url** - URL for the new `Request` object.
* **params** - *(optional)* Query parameters to include in the URL, as a
string, dictionary, or sequence of two-tuples.
* **content** - *(optional)* Binary content to include in the body of the
request, as bytes or a byte iterator.
* **data** - *(optional)* Form data to include in the body of the request,
s a dictionary.
* **files** - *(optional)* A dictionary of upload files to include in the
body of the request.
* **json** - *(optional)* A JSON serializable object to include in the body
of the request.
* **headers** - *(optional)* Dictionary of HTTP headers to include in the
request.
* **cookies** - *(optional)* Dictionary of Cookie items to include in the
request.
* **auth** - *(optional)* An authentication class to use when sending the
request.
* **proxy** - *(optional)* A proxy URL where all the traffic should be routed.
* **timeout** - *(optional)* The timeout configuration to use when sending
the request.
* **follow_redirects** - *(optional)* Enables or disables HTTP redirects.
* **verify** - *(optional)* Either `True` to use an SSL context with the
default CA bundle, `False` to disable verification, or an instance of
`ssl.SSLContext` to use a custom context.
* **trust_env** - *(optional)* Enables or disables usage of environment
variables for configuration.
**Returns:** `Response`
Usage:
```
>>> import httpx
>>> response = httpx.request('GET', 'https://httpbin.org/get')
>>> response
<Response [200 OK]>
```

Alternative to `httpx.request()` that streams the response body
instead of loading it into memory at once.
**Parameters**: See `httpx.request`.
See also: [Streaming Responses][0]
[0]: /quickstart#streaming-responses
cookies
proxy
verify
timeout
trust_env
stream
method
url
content
data
files
json
params
headers
auth
follow_redirects
aGET
T	aparams
headers
cookies
auth
proxy
follow_redirects
verify
timeout
trust_env

Sends a `GET` request.
**Parameters**: See `httpx.request`.
Note that the `data`, `files`, `json` and `content` parameters are not available
on this function, as `GET` requests should not include a request body.
aOPTIONS

Sends an `OPTIONS` request.
**Parameters**: See `httpx.request`.
Note that the `data`, `files`, `json` and `content` parameters are not available
on this function, as `OPTIONS` requests should not include a request body.
aHEAD

Sends a `HEAD` request.
**Parameters**: See `httpx.request`.
Note that the `data`, `files`, `json` and `content` parameters are not available
on this function, as `HEAD` requests should not include a request body.
aPOST
Tacontent
data
files
json
params
headers
cookies
auth
proxy
follow_redirects
verify
timeout
trust_env

Sends a `POST` request.
**Parameters**: See `httpx.request`.
aPUT

Sends a `PUT` request.
**Parameters**: See `httpx.request`.
aPATCH

Sends a `PATCH` request.
**Parameters**: See `httpx.request`.
aDELETE

Sends a `DELETE` request.
**Parameters**: See `httpx.request`.
Note that the `data`, `files`, `json` and `content` parameters are not available
on this function, as `DELETE` requests should not include a request body.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
typing
contextlib
T acontextmanager
contextmanager
a_client
T aClient
a_config
T aDEFAULT_TIMEOUT_CONFIG
aDEFAULT_TIMEOUT_CONFIG
a_models
T aResponse
aResponse
a_types
T	aAuthTypes
aCookieTypes
aHeaderTypes
aProxyTypes
aQueryParamTypes
aRequestContent
aRequestData
aRequestFiles
aTimeoutTypes
aAuthTypes
aCookieTypes
aHeaderTypes
aProxyTypes
aQueryParamTypes
aRequestContent
aRequestData
aRequestFiles
aTimeoutTypes
a_urls
T aURL
aURL
L	adelete
get
head
options
patch
post
put
request
stream
a__all__
D amethod
url
params
content
data
files
json
headers
cookies
auth
proxy
timeout
follow_redirects
verify
trust_env
return
str
uURL | str
uQueryParamTypes | None
uRequestContent | None
uRequestData | None
uRequestFiles | None
utyping.Any | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | None
uProxyTypes | None
aTimeoutTypes
bool
ussl.SSLContext | str | bool
bool
aResponse
D amethod
url
params
content
data
files
json
headers
cookies
auth
proxy
timeout
follow_redirects
verify
trust_env
return
str
uURL | str
uQueryParamTypes | None
uRequestContent | None
uRequestData | None
uRequestFiles | None
utyping.Any | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | None
uProxyTypes | None
aTimeoutTypes
bool
ussl.SSLContext | str | bool
bool
utyping.Iterator[Response]
D aurl
params
headers
cookies
auth
proxy
follow_redirects
verify
timeout
trust_env
return
uURL | str
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | None
uProxyTypes | None
bool
ussl.SSLContext | str | bool
aTimeoutTypes
bool
aResponse
get
options
head
D aurl
content
data
files
json
params
headers
cookies
auth
proxy
follow_redirects
verify
timeout
trust_env
return
uURL | str
uRequestContent | None
uRequestData | None
uRequestFiles | None
utyping.Any | None
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | None
uProxyTypes | None
bool
ussl.SSLContext | str | bool
aTimeoutTypes
bool
aResponse
post
put
patch
D aurl
params
headers
cookies
auth
proxy
follow_redirects
timeout
verify
trust_env
return
uURL | str
uQueryParamTypes | None
uHeaderTypes | None
uCookieTypes | None
uAuthTypes | None
uProxyTypes | None
bool
aTimeoutTypes
ussl.SSLContext | str | bool
bool
aResponse
delete
uhttpx\_api.py
u<module httpx._api>
T
url
params
headers
cookies
auth
proxy
follow_redirects
timeout
verify
trust_env
T
url
params
headers
cookies
auth
proxy
follow_redirects
verify
timeout
trust_env
T aurl
content
data
files
json
params
headers
cookies
auth
proxy
follow_redirects
verify
timeout
trust_env
T amethod
url
params
content
data
files
json
headers
cookies
auth
proxy
timeout
follow_redirects
verify
trust_env
client
T amethod
url
params
content
data
files
json
headers
cookies
auth
proxy
timeout
follow_redirects
verify
trust_env
client
response

a__spec__
.httpx._auth
#

Execute the authentication flow.
To dispatch a request, `yield` it:
```
yield request
```
The client will `.send()` the response back into the flow generator. You can
ccess it like so:
```
response = yield request
```
A `return` (or reaching the end of the generator) will result in the
client returning the last response obtained from the server.
You can dispatch as many requests as is necessary.
request
auth_flow
uAuth.auth_flow

Execute the authentication flow synchronously.
By default, this defers to `.auth_flow()`. You should override this method
when the authentication scheme does I/O and/or uses concurrency primitives.
self
requires_request_body
read
requires_response_body
flow
send
sync_auth_flow
uAuth.sync_auth_flow

Execute the authentication flow asynchronously.
By default, this defers to `.auth_flow()`. You should override this method
when the authentication scheme does I/O and/or uses concurrency primitives.
aread
async_auth_flow
uAuth.async_auth_flow
a_func
uFunctionAuth.auth_flow
a_build_auth_header
a_auth_header
headers
aAuthorization
uBasicAuth.auth_flow
d:ato_bytes
b64encode
decode
uBasic

netrc
a_netrc_info
authenticators
url
host
l T ausername
password
uNetRCAuth.auth_flow
a_username
a_password
a_last_challenge
a_nonce_count
status_code
l  uwww-authenticate
get_list
T uwww-authenticate
lower
startswith
T udigest
a_parse_challenge
auth_header
cookies
aCookies
set_cookie_header
T arequest
uDigestAuth.auth_flow
partition
T w adigest
parse_http_list
strip
split
T w=l aunquote
header_dict
realm
encode
nonce
algorithm
aMD5
opaque
qop
a_DigestAuthChallenge
T arealm
nonce
algorithm
opaque
qop
aProtocolError
T uMalformed Digest WWW-Authenticate header

Returns a challenge from a Digest WWW-Authenticate header.
These take the form of:
`Digest realm="realm@host.com",qop="auth,auth-int",nonce="abc",opaque="xyz"`
a_ALGORITHM_TO_HASH_FUNCTION
upper
D adata
return
bytes
puDigestAuth._build_auth_header.<locals>.digest
raw_path
method
c%08x
a_get_client_nonce
endswith
T u-sess
a_resolve_qop
username
uri
response
cauth
nc
cnonce
uDigest
a_get_header_value
hash_func
hexdigest
time
ctime
urandom
T l ahashlib
sha1
:nl naitems
header_value
u,
T aalgorithm
qop
nc
u{}="{}"
u{}={}
to_str
re
c, ?
cauth-int
uDigest auth-int support is not yet implemented
uUnexpected qop value "
u" in digest auth
a__doc__
a__file__
origin
has_location
a__cached__
annotations
os
typing
base64
T ab64encode
uurllib.request
T aparse_http_list
a_exceptions
T aProtocolError
a_models
T aCookies
aRequest
aResponse
aRequest
aResponse
a_utils
T ato_bytes
to_str
unquote
L aAuth
aBasicAuth
aDigestAuth
aNetRCAuth
a__all__
