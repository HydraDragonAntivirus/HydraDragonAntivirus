# Reconstructed from integrated Nuitka blob
# Module: uhttpx._status_codes

uHTTP status codes and reason phrases
Status codes from the following RFCs are all observed:
* RFC 7231: Hypertext Transfer Protocol (HTTP/1.1), obsoletes 2616
* RFC 6585: Additional HTTP Status Codes
* RFC 3229: Delta encoding in HTTP
* RFC 4918: HTTP Extensions for WebDAV, obsoletes 2518
* RFC 5842: Binding Extensions to WebDAV
* RFC 7238: Permanent Redirect
* RFC 2295: Transparent Content Negotiation in HTTP
* RFC 2774: An HTTP Extension Framework
* RFC 7540: Hypertext Transfer Protocol Version 2 (HTTP/2)
* RFC 2324: Hyper Text Coffee Pot Control Protocol (HTCPCP/1.0)
* RFC 7725: An HTTP Status Code to Report Legal Obstacles
* RFC 8297: An HTTP Status Code for Indicating Hints
* RFC 8470: Using Early Data in HTTP
a__qualname__
T u
D avalue
phrase
return
int
str
codes
ucodes.__new__
D areturn
str
a__str__
ucodes.__str__
classmethod
D avalue
return
int
str
get_reason_phrase
ucodes.get_reason_phrase
D avalue
return
int
bool
is_informational
ucodes.is_informational
is_success
ucodes.is_success
is_redirect
ucodes.is_redirect
is_client_error
ucodes.is_client_error
is_server_error
ucodes.is_server_error
is_error
ucodes.is_error
T ldaContinue
aCONTINUE
T leuSwitching Protocols
aSWITCHING_PROTOCOLS
T lfaProcessing
aPROCESSING
T lguEarly Hints
aEARLY_HINTS
T l  aOK
aOK
T l  aCreated
aCREATED
T l  aAccepted
aACCEPTED
T l  uNon-Authoritative Information
aNON_AUTHORITATIVE_INFORMATION
T l  uNo Content
aNO_CONTENT
T l  uReset Content
aRESET_CONTENT
T l  uPartial Content
aPARTIAL_CONTENT
T l  uMulti-Status
aMULTI_STATUS
T l  uAlready Reported
aALREADY_REPORTED
T l  uIM Used
aIM_USED
T l  uMultiple Choices
aMULTIPLE_CHOICES
T l  uMoved Permanently
aMOVED_PERMANENTLY
T l  aFound
aFOUND
T l  uSee Other
aSEE_OTHER
T l  uNot Modified
aNOT_MODIFIED
T l  uUse Proxy
aUSE_PROXY
T l  uTemporary Redirect
aTEMPORARY_REDIRECT
T l  uPermanent Redirect
aPERMANENT_REDIRECT
T l  uBad Request
aBAD_REQUEST
T l  aUnauthorized
aUNAUTHORIZED
T l  uPayment Required
aPAYMENT_REQUIRED
T l  aForbidden
aFORBIDDEN
T l  uNot Found
aNOT_FOUND
T l  uMethod Not Allowed
aMETHOD_NOT_ALLOWED
T l  uNot Acceptable
aNOT_ACCEPTABLE
T l  uProxy Authentication Required
aPROXY_AUTHENTICATION_REQUIRED
T l  uRequest Timeout
aREQUEST_TIMEOUT
T l  aConflict
aCONFLICT
T l  aGone
aGONE
T l  uLength Required
aLENGTH_REQUIRED
T l  uPrecondition Failed
aPRECONDITION_FAILED
T l  uRequest Entity Too Large
aREQUEST_ENTITY_TOO_LARGE
T l  uRequest-URI Too Long
aREQUEST_URI_TOO_LONG
T l  uUnsupported Media Type
aUNSUPPORTED_MEDIA_TYPE
T l  uRequested Range Not Satisfiable
aREQUESTED_RANGE_NOT_SATISFIABLE
T l  uExpectation Failed
aEXPECTATION_FAILED
T l  uI'm a teapot
aIM_A_TEAPOT
T l  uMisdirected Request
aMISDIRECTED_REQUEST
T l  uUnprocessable Entity
aUNPROCESSABLE_ENTITY
T l  aLocked
aLOCKED
T l  uFailed Dependency
aFAILED_DEPENDENCY
T l  uToo Early
aTOO_EARLY
T l  uUpgrade Required
aUPGRADE_REQUIRED
T l  uPrecondition Required
aPRECONDITION_REQUIRED
T l  uToo Many Requests
aTOO_MANY_REQUESTS
T l  uRequest Header Fields Too Large
aREQUEST_HEADER_FIELDS_TOO_LARGE
T l  uUnavailable For Legal Reasons
aUNAVAILABLE_FOR_LEGAL_REASONS
T l  uInternal Server Error
aINTERNAL_SERVER_ERROR
T l  uNot Implemented
aNOT_IMPLEMENTED
T l  uBad Gateway
aBAD_GATEWAY
T l  uService Unavailable
aSERVICE_UNAVAILABLE
T l  uGateway Timeout
aGATEWAY_TIMEOUT
T l  uHTTP Version Not Supported
aHTTP_VERSION_NOT_SUPPORTED
T l  uVariant Also Negotiates
aVARIANT_ALSO_NEGOTIATES
T l  uInsufficient Storage
aINSUFFICIENT_STORAGE
T l  uLoop Detected
aLOOP_DETECTED
T l  uNot Extended
aNOT_EXTENDED
T l  uNetwork Authentication Required
aNETWORK_AUTHENTICATION_REQUIRED
a__orig_bases__
code
a_name_
lower
uhttpx\_status_codes.py
u<module httpx._status_codes>
T acls
value
phrase
obj
T aself
T a__class__
T acls
value
a__spec__
.httpx._transports.asgi
sniffio
current_async_library
trio
is_running_trio
aEvent
asyncio
a_body
c
self
a__aiter__
uASGIResponseStream.__aiter__
app
raise_app_exceptions
root_path
client
request
stream
aAsyncByteStream
type
http
asgi
D aversion
u3.0
http_version
u1.1
method
headers
raw
lower
scheme
url
path
raw_path
split
T d?aquery_string
query
server
host
port
create_event
D areturn
udict[str, typing.Any]
receive
uASGITransport.handle_async_request.<locals>.receive
D amessage
return
utyping.MutableMapping[str, typing.Any]
aNone
send
uASGITransport.handle_async_request.<locals>.send
set
status_code
l  aresponse_headers
is_set
aASGIResponseStream
aResponse
T aheaders
stream
handle_async_request
uASGITransport.handle_async_request
request_complete
response_complete
wait
D atype
uhttp.disconnect
request_body_chunks
a__anext__
D atype
body
more_body
uhttp.request
c
Fuhttp.request
body
more_body
message
uhttp.response.start
response_started
status
get
uhttp.response.body
T abody
c
T amore_body
FaHEAD
body_parts
append
a__doc__
a__file__
origin
has_location
a__cached__
annotations
typing
a_models
T aRequest
aResponse
l aRequest
a_types
T aAsyncByteStream
base
T aAsyncBaseTransport
aAsyncBaseTransport
aMutableMapping
aAny
a_Message
aCallable
aAwaitable
a_Receive
a_Send
a_ASGIApp
aASGITransport
a__all__
D areturn
bool
D areturn
aEvent
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
