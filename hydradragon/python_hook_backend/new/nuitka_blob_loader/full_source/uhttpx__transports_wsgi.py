# Reconstructed from integrated Nuitka blob
# Module: uhttpx._transports.wsgi

a__qualname__
D aresult
return
utyping.Iterable[bytes]
aNone
a__init__
uWSGIByteStream.__init__
D areturn
utyping.Iterator[bytes]
D areturn
aNone
uWSGIByteStream.close
a__orig_bases__

A custom transport that handles sending requests directly to an WSGI app.
The simplest way to use this functionality is to use the `app` argument.
```
client = httpx.Client(app=app)
```
Alternatively, you can setup the transport instance explicitly.
This allows you to include any additional configuration arguments specific
to the WSGITransport class:
```
transport = httpx.WSGITransport(
pp=app,
script_name="/submount",
remote_addr="1.2.3.4"
)
client = httpx.Client(transport=transport)
```
Arguments:
* `app` - The WSGI application.
* `raise_app_exceptions` - Boolean indicating if exceptions in the application
should be raised. Default to `True`. Can be set to `False` for use cases
such as testing the content of a client 500 response.
* `script_name` - The root path on which the WSGI application should be mounted.
* `remote_addr` - A string indicating the client IP of incoming requests.
```
T tu
u127.0.0.1
nD aapp
raise_app_exceptions
script_name
remote_addr
wsgi_errors
return
aWSGIApplication
bool
str
putyping.TextIO | None
aNone
uWSGITransport.__init__
D arequest
return
aRequest
aResponse
handle_request
uWSGITransport.handle_request
uhttpx\_transports\wsgi.py
T w_u<module httpx._transports.wsgi>
T a__class__
T aself
result
T aself
app
raise_app_exceptions
script_name
remote_addr
wsgi_errors
T aself
part
T abody
chunk
T aself
T aself
request
wsgi_input
port
environ
header_key
header_value
key
seen_status
seen_response_headers
seen_exc_info
start_response
result
stream
status_code
headers
T astatus
response_headers
exc_info
seen_status
seen_response_headers
seen_exc_info
T aseen_exc_info
seen_response_headers
seen_status

a__spec__
.httpx._types
O
uThe '__iter__' method must be implemented.
a__iter__
uSyncByteStream.__iter__
uThe '__aiter__' method must be implemented.
a__aiter__
uAsyncByteStream.__aiter__
aclose
uAsyncByteStream.aclose

Type definitions for type checking purposes.
a__doc__
a__file__
origin
has_location
a__cached__
uhttp.cookiejar
T aCookieJar
aCookieJar
aIO
aTYPE_CHECKING
aAny
aAsyncIterable
aAsyncIterator
aCallable
aDict
aIterable
aIterator
aList
aMapping
aOptional
aSequence
aTuple
aUnion
T Ostr
Oint
Ofloat
Obool
aPrimitiveData
T aURL
Ostr
aURLTypes
aQueryParams
aQueryParamTypes
aHeaders
T Ostr
pT Obytes
paHeaderTypes
aCookies
aCookieTypes
aTimeout
aTimeoutTypes
T aURL
Ostr
aProxy
aProxyTypes
T Ostr
ppaCertTypes
T Ostr
Obytes
T L aRequest
aRequest
aAuth
aAuthTypes
aRequestContent
aResponseContent
aResponseExtensions
aRequestData
aFileContent
aFileTypes
aRequestFiles
aRequestExtensions
aAsyncByteStream
aSyncByteStream
a__all__
