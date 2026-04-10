# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.formdata

uHelper class for form body generation.
Supports multipart/form-data and application/x-www-form-urlencoded.
aFormData
a__qualname__
T T
tnD adefault_to_multipart
Fafields
charset
default_to_multipart
return
a__init__
uFormData.__init__
D areturn
Obool
is_multipart
uFormData.is_multipart
D acontent_type
filename
content_transfer_encoding
nnnacontent_type
content_transfer_encoding
uFormData.add_field
uFormData.add_fields
uFormData._gen_form_urlencoded
uFormData._gen_form_data
a__call__
uFormData.__call__
uaiohttp\formdata.py
u<module aiohttp.formdata>
T a__class__
T aself
T aself
fields
quote_fields
charset
default_to_multipart
T aself
dispparams
headers
value
part
exc
T aself
data
type_options
w_avalue
charset
content_type
T	aself
name
value
content_type
filename
content_transfer_encoding
type_options
msg
headers
T aself
fields
to_add
rec
wkafp
a__spec__
.aiohttp.hdrs

uHTTP Headers constants.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
itertools
aFinal
aSet
multidict
T aistr
istr
w*aMETH_ANY
aCONNECT
aMETH_CONNECT
aHEAD
aMETH_HEAD
aGET
aMETH_GET
aDELETE
aMETH_DELETE
aOPTIONS
aMETH_OPTIONS
aPATCH
aMETH_PATCH
aPOST
aMETH_POST
aPUT
aMETH_PUT
aTRACE
aMETH_TRACE
aMETH_ALL
T aAccept
aACCEPT
T uAccept-Charset
aACCEPT_CHARSET
T uAccept-Encoding
aACCEPT_ENCODING
T uAccept-Language
aACCEPT_LANGUAGE
T uAccept-Ranges
aACCEPT_RANGES
T uAccess-Control-Max-Age
aACCESS_CONTROL_MAX_AGE
T uAccess-Control-Allow-Credentials
aACCESS_CONTROL_ALLOW_CREDENTIALS
T uAccess-Control-Allow-Headers
aACCESS_CONTROL_ALLOW_HEADERS
T uAccess-Control-Allow-Methods
aACCESS_CONTROL_ALLOW_METHODS
T uAccess-Control-Allow-Origin
aACCESS_CONTROL_ALLOW_ORIGIN
T uAccess-Control-Expose-Headers
aACCESS_CONTROL_EXPOSE_HEADERS
T uAccess-Control-Request-Headers
aACCESS_CONTROL_REQUEST_HEADERS
T uAccess-Control-Request-Method
aACCESS_CONTROL_REQUEST_METHOD
T aAge
aAGE
T aAllow
aALLOW
T aAuthorization
aAUTHORIZATION
T uCache-Control
aCACHE_CONTROL
T aConnection
aCONNECTION
T uContent-Disposition
aCONTENT_DISPOSITION
T uContent-Encoding
aCONTENT_ENCODING
T uContent-Language
aCONTENT_LANGUAGE
T uContent-Length
aCONTENT_LENGTH
T uContent-Location
aCONTENT_LOCATION
T uContent-MD5
aCONTENT_MD5
T uContent-Range
aCONTENT_RANGE
T uContent-Transfer-Encoding
aCONTENT_TRANSFER_ENCODING
T uContent-Type
aCONTENT_TYPE
T aCookie
aCOOKIE
T aDate
aDATE
T aDestination
aDESTINATION
T aDigest
aDIGEST
T aEtag
aETAG
T aExpect
aEXPECT
T aExpires
aEXPIRES
T aForwarded
aFORWARDED
T aFrom
aFROM
T aHost
aHOST
T uIf-Match
aIF_MATCH
T uIf-Modified-Since
aIF_MODIFIED_SINCE
T uIf-None-Match
aIF_NONE_MATCH
T uIf-Range
aIF_RANGE
T uIf-Unmodified-Since
aIF_UNMODIFIED_SINCE
T uKeep-Alive
aKEEP_ALIVE
T uLast-Event-ID
aLAST_EVENT_ID
T uLast-Modified
aLAST_MODIFIED
T aLink
aLINK
T aLocation
aLOCATION
T uMax-Forwards
aMAX_FORWARDS
T aOrigin
aORIGIN
T aPragma
aPRAGMA
T uProxy-Authenticate
aPROXY_AUTHENTICATE
T uProxy-Authorization
aPROXY_AUTHORIZATION
T aRange
aRANGE
T aReferer
aREFERER
T uRetry-After
aRETRY_AFTER
T uSec-WebSocket-Accept
aSEC_WEBSOCKET_ACCEPT
T uSec-WebSocket-Version
aSEC_WEBSOCKET_VERSION
T uSec-WebSocket-Protocol
aSEC_WEBSOCKET_PROTOCOL
T uSec-WebSocket-Extensions
aSEC_WEBSOCKET_EXTENSIONS
T uSec-WebSocket-Key
aSEC_WEBSOCKET_KEY
T uSec-WebSocket-Key1
aSEC_WEBSOCKET_KEY1
T aServer
aSERVER
T uSet-Cookie
aSET_COOKIE
T aTE
aTE
T aTrailer
aTRAILER
T uTransfer-Encoding
aTRANSFER_ENCODING
T aUpgrade
aUPGRADE
T aURI
aURI
T uUser-Agent
aUSER_AGENT
T aVary
aVARY
T aVia
aVIA
T uWant-Digest
aWANT_DIGEST
T aWarning
aWARNING
T uWWW-Authenticate
aWWW_AUTHENTICATE
T uX-Forwarded-For
aX_FORWARDED_FOR
T uX-Forwarded-Host
aX_FORWARDED_HOST
T uX-Forwarded-Proto
aX_FORWARDED_PROTO

join
product
upper
lower
aMETH_HEAD_ALL
aMETH_CONNECT_ALL
aHOST_ALL
uaiohttp\hdrs.py
u<module aiohttp.hdrs>
a__spec__
.aiohttp.helpers
.
N a__await__
unoop.__await__
uNone is not allowed as login value
uNone is not allowed as password value
w:uA ":" is not allowed in login (RFC 1945#section-11.1)
a__class__
a__new__
split
T w l uCould not parse authorization header.
lower
basic
uUnknown authorization method %s
base64
b64decode
encode
T aascii
D avalidate
tadecode
binascii
aError
uInvalid base64 encoding.
T w:l uInvalid credentials.
T aencoding
uCreate a BasicAuth object from an Authorization HTTP header.
aURL
uurl should be yarl.URL instance
raw_user
raw_password
user

password
uCreate BasicAuth from url.
login
encoding
uBasic %s
b64encode
uEncode credentials.
with_user
T naBasicAuth
uRemove user and password from URL if present and return BasicAuth object.
environ
get
T aNETRC
aPath
home
client_logger
debug
uCould not resolve home directory when trying to look for .netrc file: %s
aIS_WINDOWS
a_netrc
u.netrc
netrc
aNetrcParseError
warning
uCould not parse .netrc file: %s
contextlib
suppress
T EOSError
a__enter__
a__exit__
is_file
T nnnuCould not read .netrc file: %s
uLoad netrc from file.
Attempt to load it from the path specified by the env-var
NETRC or in the default location in the user's home directory.
Returns None if it couldn't be found or fails to parse.
uNo .netrc file found
authenticators
uNo entry for
u found in the `.netrc` file.

Return :py:class:`~aiohttp.BasicAuth` credentials for ``host`` from ``netrc_obj``.
:raises LookupError: if ``netrc_obj`` is :py:data:`None` or if no
entry is found for the ``host``.
getproxies
items
T ahttp
https
ws
wss
netrc_from_env
strip_auth_from_url
scheme
T ahttps
wss
u%s proxies %s are not supported, ignoring
upper
netrc_obj
host
basicauth_from_netrc
aProxyInfo
ret
proxy_bypass
uProxying is disallowed for `
w`aproxies_from_env
uNo proxies found for `
u` in the env
proxy
proxy_auth
uGet a permitted proxy for the given URL from the env.
aMimeType
aMultiDictProxy
aMultiDict
T atype
subtype
suffix
parameters
T w;:l nnapartition
T w=aparams
add
strip
T u "
w*u*/*
T w/T w+uParses a MIME type into its components.
mimetype is a MIME type string.
Returns a MimeType object.
Example:
>>> parse_mimetype('text/html; charset=utf-8')
MimeType(type='text', subtype='html', suffix='',
parameters={'charset': 'utf-8'})
name
w<w>aQCONTENT
ubad content for quoted-string
not_qtext_re
sub
u<lambda>
uquoted_string.<locals>.<lambda>
uReturn 7-bit content as quoted-string.
Format content into a quoted-string as defined in RFC5322 for
Internet Message Format. Notice that this is not the 8-bit HTTP
format, but the 7-bit email format. Content must be in usascii or
a ValueError is raised.
w\agroup
T l
aTOKEN
ubad content disposition type
ubad content disposition parameter
w=afilename
quote
a_charset
lparams
u"%s"
quoted_string
u''
append
qval
replace
T w\u\\
T w"u\"
u;
uSets ``Content-Disposition`` header for MIME.
This is the MIME payload Content-Disposition header from RFC 2183
nd RFC 7579 section 4.2, not the HTTP Content-Disposition from
RFC 6266.
disptype is a disposition type: inline, attachment, form-data.
Should be valid extension token (see RFC 2183)
quote_fields performs value quoting to 7-bit MIME headers
ccording to RFC 7578. Set to quote_fields to False if recipient
can take 8-bit file names and field values.
_charset specifies the charset to use when quote_fields is True.
params is a dict with disposition params.
u<genexpr>
ucontent_disposition_header.<locals>.<genexpr>
T w.u
isdigit
uCheck if host looks like an IP Address.
This check is only meant as a heuristic to ensure that
a host is not a domain name.
time
a_cached_current_datetime
gmtime
unot enough values to unpack (expected at least 7, got %d)
u%s, %02d %3s %4d %02d:%02d:%02d GMT
T aMon
aTue
aWed
aThu
aFri
aSat
aSun
Tu
aJan
aFeb
aMar
aApr
aMay
aJun
aJul
aAug
aSep
aOct
aNov
aDec
a_cached_formatted_datetime
T EException
ceil
call_at
a_weakref_handle
weakref
ref
calculate_timeout_when
uCalculate when to execute a timeout.
a_timeout
a_loop
a_ceil_threshold
a_callbacks
clear
a__call__
aTimerContext
register
timeout
aTimerNoop
a_tasks
a_cancelled
a_cancelling
asyncio
aTimeoutError
uRaise TimeoutError if timer has already been cancelled.
current_task
T aloop
uTimeout context manager should be used inside a task
pop
aCancelledError
cancel
async_timeout
get_running_loop
timeout_at
a_stored_content_type
uapplication/octet-stream
a_content_type
a_content_dict
aHeaderParser
parsestr
uContent-Type:
get_content_type
get_params
T T
a_headers
hdrs
aCONTENT_TYPE
a_parse_content_type
uThe value of content part for Content-Type HTTP header.
T acharset
uThe value of charset part for Content-Type HTTP header.
aCONTENT_LENGTH
uThe value of Content-Length HTTP header.
done
set_result
isfuture
a_EXC_SENTINEL
a__cause__
set_exception
uSet future exception.
If the future is marked as complete, this function is a no-op.
:param exc_cause: An exception that is a direct cause of ``exc``.
Only set if provided.
inspect
currentframe
frame
f_code
co_name
u<module>
f_globals
a__name__
f_back
module
w.a_name
a_t
aAppKey
T EAttributeError
get_args
a__orig_class__
