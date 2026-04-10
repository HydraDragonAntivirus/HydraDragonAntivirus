# Reconstructed from integrated Nuitka blob
# Module: uhttpx._utils


A utility class currently used for making lookups against proxy keys...
# Wildcard matching...
>>> pattern = URLPattern("all://")
>>> pattern.matches(httpx.URL("http://example.com"))
True
# Witch scheme matching...
>>> pattern = URLPattern("https://")
>>> pattern.matches(httpx.URL("https://example.com"))
True
>>> pattern.matches(httpx.URL("http://example.com"))
False
# With domain matching...
>>> pattern = URLPattern("https://example.com")
>>> pattern.matches(httpx.URL("https://example.com"))
True
>>> pattern.matches(httpx.URL("http://example.com"))
False
>>> pattern.matches(httpx.URL("https://other.com"))
False
# Wildcard scheme, with domain matching...
>>> pattern = URLPattern("all://example.com")
>>> pattern.matches(httpx.URL("https://example.com"))
True
>>> pattern.matches(httpx.URL("http://example.com"))
True
>>> pattern.matches(httpx.URL("https://other.com"))
False
# With port matching...
>>> pattern = URLPattern("https://example.com:1234")
>>> pattern.matches(httpx.URL("https://example.com:1234"))
True
>>> pattern.matches(httpx.URL("https://example.com"))
False
a__qualname__
D apattern
return
str
aNone
a__init__
uURLPattern.__init__
D aother
return
aURL
bool
matches
uURLPattern.matches
D areturn
utuple[int, int, int]
uURLPattern.priority
D areturn
int
a__hash__
uURLPattern.__hash__
D aother
return
aURLPattern
bool
a__lt__
uURLPattern.__lt__
D aother
return
utyping.Any
bool
a__eq__
uURLPattern.__eq__
D ahostname
return
str
bool
uhttpx\_utils.py
u<module httpx._utils>
T a__class__
T aself
other
T aself
T aself
pattern
aURL
url
domain
T amounts
proxy_info
scheme
hostname
no_proxy_hosts
T ahostname
T astream
fd
length
offset
T avalue
T aself
port_priority
host_priority
scheme_priority
T avalue
encoding
T avalue
match_type_of
a__spec__
.httpx
1
1
print
T uThe httpx command line client could not run because the required dependencies were not installed.
Make sure you've installed everything with: pip install 'httpx[cli]'
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_httpx
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
a__version__
T a__description__
a__title__
a__version__
a__description__
a__title__
a_api
T w*a_auth
a_client
a_config
a_content
a_exceptions
a_models
a_status_codes
a_transports
a_types
a_urls
a_main
T amain
main
aImportError
D areturn
nLEa__description__
a__title__
a__version__
aASGITransport
aAsyncBaseTransport
aAsyncByteStream
aAsyncClient
aAsyncHTTPTransport
aAuth
aBaseTransport
aBasicAuth
aByteStream
aClient
aCloseError
codes
aConnectError
aConnectTimeout
aCookieConflict
aCookies
create_ssl_context
aDecodingError
delete
aDigestAuth
get
head
aHeaders
aHTTPError
aHTTPStatusError
aHTTPTransport
aInvalidURL
aLimits
aLocalProtocolError
main
aMockTransport
aNetRCAuth
aNetworkError
options
patch
aPoolTimeout
post
aProtocolError
aProxy
aProxyError
put
aQueryParams
aReadError
aReadTimeout
aRemoteProtocolError
request
aRequest
aRequestError
aRequestNotRead
aResponse
aResponseNotRead
stream
aStreamClosed
aStreamConsumed
aStreamError
aSyncByteStream
aTimeout
aTimeoutException
aTooManyRedirects
aTransportError
aUnsupportedProtocol
aURL
aUSE_CLIENT_DEFAULT
aWriteError
aWriteTimeout
aWSGITransport
a__all__
a__locals
a__name
startswith
T a__
