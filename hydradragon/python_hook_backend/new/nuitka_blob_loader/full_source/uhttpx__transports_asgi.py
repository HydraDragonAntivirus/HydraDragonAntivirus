# Reconstructed from integrated Nuitka blob
# Module: uhttpx._transports.asgi

a__qualname__
D abody
return
ulist[bytes]
aNone
a__init__
uASGIResponseStream.__init__
D areturn
utyping.AsyncIterator[bytes]
a__orig_bases__

A custom AsyncTransport that handles sending requests directly to an ASGI app.
```python
transport = httpx.ASGITransport(
pp=app,
root_path="/submount",
client=("1.2.3.4", 123)
)
client = httpx.AsyncClient(transport=transport)
```
Arguments:
* `app` - The ASGI application.
* `raise_app_exceptions` - Boolean indicating if exceptions in the application
should be raised. Default to `True`. Can be set to `False` for use cases
such as testing the content of a client 500 response.
* `root_path` - The root path on which the ASGI application should be mounted.
* `client` - A two-tuple indicating the client IP and port of incoming requests.
```
T tu
T u127.0.0.1
l{D aapp
raise_app_exceptions
root_path
client
return
a_ASGIApp
bool
str
utuple[str, int]
aNone
uASGITransport.__init__
D arequest
return
aRequest
aResponse
uhttpx\_transports\asgi.py
u<module httpx._transports.asgi>
T a__class__
T aself
T aself
body
T aself
app
raise_app_exceptions
root_path
client
T atrio
asyncio
Taself
request
scope
request_body_chunks
request_complete
status_code
response_headers
body_parts
response_started
response_complete
receive
send
stream
T asniffio
T arequest_complete
body
response_complete
request_body_chunks
T arequest_body_chunks
request_complete
response_complete
T	amessage
status_code
response_headers
response_started
body
more_body
response_complete
request
body_parts
T abody_parts
request
response_complete
response_headers
response_started
status_code

a__spec__
.httpx._transports.base
:
close
uThe 'handle_request' method must be implemented.

Send a single HTTP request and return a response.
Developers shouldn't typically ever need to call into this API directly,
since the Client class provides all the higher level user-facing API
niceties.
In order to properly release any network resources, the response
stream should *either* be consumed immediately, with a call to
`response.stream.read()`, or else the `handle_request` call should
be followed with a try/finally block to ensuring the stream is
lways closed.
Example usage:
with httpx.HTTPTransport() as transport:
req = httpx.Request(
method=b"GET",
url=(b"https", b"www.example.com", 443, b"/"),
headers=[(b"Host", b"www.example.com")],
)
resp = transport.handle_request(req)
body = resp.stream.read()
print(resp.status_code, resp.headers, body)
Takes a `Request` instance as the only argument.
Returns a `Response` instance.
self
a__aenter__
uAsyncBaseTransport.__aenter__
aclose
a__aexit__
uAsyncBaseTransport.__aexit__
uThe 'handle_async_request' method must be implemented.
handle_async_request
uAsyncBaseTransport.handle_async_request
uAsyncBaseTransport.aclose
a__doc__
a__file__
origin
has_location
a__cached__
annotations
typing
aTracebackType
a_models
T aRequest
aResponse
l aRequest
aResponse
aTypeVar
T wTaBaseTransport
T abound
wTT wAaAsyncBaseTransport
wAaAsyncBaseTransport
aBaseTransport
a__all__
