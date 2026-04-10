# Reconstructed from integrated Nuitka blob
# Module: uh11._util

uException indicating a violation of the HTTP/1.1 protocol.
This as an abstract base class, with two concrete base classes:
:exc:`LocalProtocolError`, which indicates that you tried to do something
that HTTP/1.1 says is illegal, and :exc:`RemoteProtocolError`, which
indicates that the remote peer tried to do something that HTTP/1.1 says is
illegal. See :ref:`error-handling` for details.
In addition to the normal :exc:`Exception` features, it has one attribute:
.. attribute:: error_status_hint
This gives a suggestion as to what status code a server might use if
this error occurred as part of a request.
For a :exc:`RemoteProtocolError`, this is useful as a suggestion for
how you might want to respond to a misbehaving peer, if you're
implementing a server.
For a :exc:`LocalProtocolError`, this can be taken as a suggestion for
how your peer might have responded to *you* if h11 had allowed you to
continue.
The default is 400 Bad Request, a generic catch-all for protocol
violations.
a__qualname__
T l  amsg
str
int
return
uProtocolError.__init__
a__orig_bases__
a_reraise_as_remote_protocol_error
uLocalProtocolError._reraise_as_remote_protocol_error
T umalformed data
regex
data
format_args
T Ostr
Obytes
validate
T a_T_Sentinel
aSentinel
T abound
a_T_Sentinel
T Otype
cls
name
bases
type
namespace
kwds
uSentinel.__new__
a__repr__
uSentinel.__repr__
wsT Obytes
Obytearray
Omemoryview
Oint
Ostr
bytesify
uh11\_util.py
u<module h11._util>
T a__class__
T aself
msg
error_status_hint
T acls
name
bases
namespace
kwds
wva__class__
T aself
T wsT aregex
data
msg
format_args
match

a__spec__
.h11._version
a__doc__
a__file__
origin
has_location
a__cached__
u0.14.0
a__version__
uh11\_version.py
u<module h11._version>

a__spec__
.h11._writers
t
a_full_items
chost
write
c%s: %s
T c
http_version
c1.1
aLocalProtocolError
T uI only send HTTP/1.1
c%s %s HTTP/1.1
method
target
write_headers
headers
status_code
encode
T aascii
cHTTP/1.1 %s %s
reason
aData
send_data
data
aEndOfMessage
send_eom
a_length
T uToo much data for declared Content-Length
T uToo little data for declared Content-Length
T uContent-Length and trailers don't mix
c%x
T c0
T ucan't send trailers to HTTP/1.0 client
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
aAny
aCallable
aDict
aList
aTuple
aType
aUnion
a_events
T aData
aEndOfMessage
aEvent
aInformationalResponse
aRequest
aResponse
aEvent
aInformationalResponse
aRequest
aResponse
a_headers
T aHeaders
aHeaders
a_state
T aCLIENT
aIDLE
aSEND_BODY
aSEND_RESPONSE
aSERVER
aCLIENT
aIDLE
aSEND_BODY
aSEND_RESPONSE
aSERVER
a_util
T aLocalProtocolError
aSentinel
aSentinel
aWRITERS
a__all__
aWriter
return
request
write_request
response
write_any_response
