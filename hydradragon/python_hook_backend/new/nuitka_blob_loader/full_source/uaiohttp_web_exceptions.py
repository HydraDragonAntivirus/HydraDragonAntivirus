# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.web_exceptions

uWarning when not using AppKey in Application.
a__qualname__
a__orig_bases__
aHTTPException
a__http_exception__
D aheaders
reason
body
text
content_type
nnnnnastr
content_type
return
uHTTPException.__init__
bool
a__bool__
uHTTPException.__bool__
aHTTPError
uBase class for exceptions with status codes in the 400s and 500s.
aHTTPRedirection
uBase class for exceptions with status codes in the 300s.
aHTTPSuccessful
uBase class for exceptions with status codes in the 200s.
aHTTPOk
l  aHTTPCreated
l  aHTTPAccepted
l  aHTTPNonAuthoritativeInformation
l  aHTTPNoContent
l  aHTTPResetContent
l  aHTTPPartialContent
l  aHTTPMove
uHTTPMove.__init__
aHTTPMultipleChoices
l  aHTTPMovedPermanently
l  aHTTPFound
l  aHTTPSeeOther
l  aHTTPNotModified
l  aHTTPUseProxy
l  aHTTPTemporaryRedirect
l  aHTTPPermanentRedirect
l  aHTTPClientError
aHTTPBadRequest
l  aHTTPUnauthorized
l  aHTTPPaymentRequired
l  aHTTPForbidden
l  aHTTPNotFound
l  aHTTPMethodNotAllowed
l  uHTTPMethodNotAllowed.__init__
aHTTPNotAcceptable
l  aHTTPProxyAuthenticationRequired
l  aHTTPRequestTimeout
l  aHTTPConflict
l  aHTTPGone
l  aHTTPLengthRequired
l  aHTTPPreconditionFailed
l  aHTTPRequestEntityTooLarge
l  amax_size
float
actual_size
kwargs
uHTTPRequestEntityTooLarge.__init__
aHTTPRequestURITooLong
l  aHTTPUnsupportedMediaType
l  aHTTPRequestRangeNotSatisfiable
l  aHTTPExpectationFailed
l  aHTTPMisdirectedRequest
l  aHTTPUnprocessableEntity
l  aHTTPFailedDependency
l  aHTTPUpgradeRequired
l  aHTTPPreconditionRequired
l  aHTTPTooManyRequests
l  aHTTPRequestHeaderFieldsTooLarge
l  aHTTPUnavailableForLegalReasons
l  alink
uHTTPUnavailableForLegalReasons.__init__
property
uHTTPUnavailableForLegalReasons.link
aHTTPServerError
aHTTPInternalServerError
l  aHTTPNotImplemented
l  aHTTPBadGateway
l  aHTTPServiceUnavailable
l  aHTTPGatewayTimeout
l  aHTTPVersionNotSupported
l  aHTTPVariantAlsoNegotiates
l  aHTTPInsufficientStorage
l  aHTTPNotExtended
l  aHTTPNetworkAuthenticationRequired
l  uaiohttp\web_exceptions.py
u<module aiohttp.web_exceptions>
T a__class__
T aself
T aself
headers
reason
body
text
content_type
T
self
method
allowed_methods
headers
reason
body
text
content_type
allow
a__class__
T aself
location
headers
reason
body
text
content_type
a__class__
T aself
max_size
actual_size
kwargs
a__class__
T aself
link
headers
reason
body
text
content_type
a__class__
a__spec__
.aiohttp.web_fileresponse
}
a__class__
a__init__
T astatus
reason
headers
pathlib
aPath
a_path
a_chunk_size
seek
read
self
asyncio
get_event_loop
run_in_executor
a_seek_and_read
fobj
offset
chunk
writer
write
count
chunk_size
loop
min
drain
a_sendfile_fallback
uFileResponse._sendfile_fallback
prepare
request
aNOSENDFILE
compression
a_loop
transport
sendfile
write_eof
a_sendfile
uFileResponse._sendfile
value
aETAG_ANY
weak
is_weak
etag_value
u<genexpr>
uFileResponse._etag_match.<locals>.<genexpr>
set_status
aHTTPNotModified
status_code
a_length_check
etag
last_modified
a_not_modified
uFileResponse._not_modified
aHTTPPreconditionFailed
content_length
a_precondition_failed
uFileResponse._precondition_failed
a_get_file_path_stat_encoding
a_FileResponseResult
aNOT_ACCEPTABLE
st_mtime_ns
wxw-ast_size

if_match
a_etag_match
D aweak
FaPRE_CONDITION_FAILED
if_unmodified_since
st_mtime
timestamp
if_none_match
D aweak
taNOT_MODIFIED
if_modified_since
open
T arb
suppress
T EOSError
a__enter__
a__exit__
fileno
T nnnaSEND_FILE
ast
uReturn the response result, io object, stat result, and encoding.
If an uncompressed file is returned, the encoding is set to
:py:data:`None`.
This method should be called from a thread executor
since it calls os.stat which may block.
aENCODING_EXTENSIONS
items
file_path
with_suffix
suffix
lstat
aS_ISREG
st_mode
stat
get_running_loop
headers
get
hdrs
aACCEPT_ENCODING
lower
a_make_response
aHTTPForbidden
aHTTPNotFound
a_prepare_open_file
close
a_CLOSE_FUTURES
add
add_done_callback
remove
uFileResponse.prepare
a_status
if_range
http_range
start
stop
ubytes */
a_headers
aCONTENT_RANGE
aHTTPRequestRangeNotSatisfiable
aHTTPPartialContent
aCONTENT_TYPE
aCONTENT_TYPES
guess_type
aFALLBACK_CONTENT_TYPE
content_type
file_encoding
aCONTENT_ENCODING
aVARY
a_compression
bytes
aACCEPT_RANGES
status
ubytes {}-{}/{}
must_be_empty_body
method
uFileResponse._prepare_open_file
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
io
os
sys
contextlib
T asuppress
enum
T aEnum
auto
aEnum
auto
mimetypes
T aMimeTypes
aMimeTypes
T aS_ISREG
aMappingProxyType
aIO
aTYPE_CHECKING
aAny
aAwaitable
aCallable
aFinal
aIterator
aList
aOptional
aSet
aTuple
aUnion
cast
T ahdrs
abc
T aAbstractStreamWriter
aAbstractStreamWriter
helpers
T aETAG_ANY
aETag
must_be_empty_body
aETag
typedefs
T aLooseHeaders
aPathLike
aLooseHeaders
aPathLike
web_exceptions
T aHTTPForbidden
aHTTPNotFound
aHTTPNotModified
aHTTPPartialContent
aHTTPPreconditionFailed
aHTTPRequestRangeNotSatisfiable
web_response
T aStreamResponse
aStreamResponse
T aFileResponse
a__all__
a_T_OnChunkSent
environ
T aAIOHTTP_NOSENDFILE
T u.br
u.gz
encodings_map
uapplication/octet-stream
D uapplication/gzip
uapplication/x-brotli
uapplication/x-bzip2
uapplication/x-compress
uapplication/x-xz
u.gz
u.br
u.bz2
u.Z
u.xz
aADDITIONAL_CONTENT_TYPES
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
