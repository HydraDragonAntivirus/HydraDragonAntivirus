# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.web_log

uHelper object to log access.
Usage:
log = logging.getLogger("spam")
log_format = "%a %{User-Agent}i"
ccess_logger = AccessLogger(log, log_format)
ccess_logger.log(request, response, time)
Format:
%%  The percent sign
%a  Remote IP-address (IP-address of proxy if using reverse proxy)
%t  Time when the request was started to process
%P  The process ID of the child that serviced the request
%r  First line of request
%s  Response status code
%b  Size of response in bytes, including HTTP headers
%T  Time taken to serve the request, in seconds
%Tf Time taken to serve the request, in seconds with floating fraction
in .06f format
%D  Time taken to serve the request, in microseconds
%{FOO}i  request.headers['FOO']
%{FOO}o  response.headers['FOO']
%{FOO}e  os.environ['FOO']
a__qualname__
a__annotations__
D wawtwPwrwswbwTaTf
wDwiwoaremote_address
request_start_time
process_id
first_request_line
response_status
response_size
request_time
request_time_frac
request_time_micro
request_header
response_header
u%a %t "%r" %s %b "%{Referer}i" "%{User-Agent}i"
aLOG_FORMAT
compile
T u%(\{([A-Za-z0-9\-_]+)\}([ioe])|[atPrsbOD]|Tf?)
T u(%[^s])
str
aLogger
log_format
return
uAccessLogger.__init__
uAccessLogger.compile_format
staticmethod
key
float
a_format_i
uAccessLogger._format_i
a_format_o
uAccessLogger._format_o
a_format_a
uAccessLogger._format_a
a_format_t
uAccessLogger._format_t
a_format_P
uAccessLogger._format_P
a_format_r
uAccessLogger._format_r
int
a_format_s
uAccessLogger._format_s
a_format_b
uAccessLogger._format_b
a_format_T
uAccessLogger._format_T
a_format_Tf
uAccessLogger._format_Tf
a_format_D
uAccessLogger._format_D
uAccessLogger._format_line
property
bool
enabled
uAccessLogger.enabled
log
uAccessLogger.log
a__orig_bases__
uaiohttp\web_log.py
u<module aiohttp.web_log>
T a__class__
T aself
logger
log_format
a_compiled_format
a__class__
T arequest
response
time
T arequest
response
time
ip
T akey
request
response
time
T aself
request
response
time
T arequest
response
time
tz
now
start_time
T aself
log_format
methods
atom
format_key1
wmakey_method
format_key2
T aself
T aself
request
response
time
fmt_info
values
extra
key
value
k1
k2
dct
a__spec__
.aiohttp.web_middlewares
T
request
clone
path
T arel_url
app
router
resolve
a_match_info
http_exception
a_check_request_resolves
a__middleware_version__
T uCannot both remove and append slash
middleware
aRequest
handler
aHandler
return
aStreamResponse
impl
unormalize_path_middleware.<locals>.impl
uFactory for producing a middleware that normalizes the path of a request.
Normalizing means:
- Add or remove a trailing slash to the path.
- Double slashes are replaced by one.
The middleware returns as soon as it finds a path that resolves
correctly. The order if both merge and append/remove are enabled is
1) merge slashes
2) append/remove slash
3) both merge slashes and append/remove slash.
If the path resolves with at least one of those conditions, it will
redirect to the new path.
Only one of `append_slash` and `remove_slash` can be enabled. If both
re `True` the factory will raise an assertion error
If `append_slash` is `True` the middleware will append a slash when
needed. If a resource is defined with trailing slash and the request
comes without it, it will append it automatically.
If `remove_slash` is `True`, `append_slash` must be `False`. When enabled
the middleware will remove trailing slashes and redirect if the resource
is defined
If merge_slashes is True, merge multiple consecutive slashes in the
path into one.
match_info
route
aSystemRoute
w?araw_path
split
T w?l u
merge_slashes
re
sub
u//+
w/aappend_slash
endswith
T w/aremove_slash
:nq nu^//+
redirect_class
u_fix_request_current_app.<locals>.impl
current_app
a__doc__
a__file__
origin
has_location
a__cached__
aTYPE_CHECKING
aTuple
aType
aTypeVar
typedefs
T aHandler
aMiddleware
aMiddleware
web_exceptions
T aHTTPMove
aHTTPPermanentRedirect
aHTTPMove
aHTTPPermanentRedirect
web_request
T aRequest
web_response
T aStreamResponse
web_urldispatcher
T aSystemRoute
T amiddleware
normalize_path_middleware
a__all__
T a_Func
a_Func
wfanormalize_path_middleware
aApplication
a_fix_request_current_app
uaiohttp\web_middlewares.py
u<module aiohttp.web_middlewares>
T arequest
path
alt_request
match_info
T aapp
impl
T arequest
handler
match_info
prev
app
T aapp
T arequest
handler
paths_to_check
path
query
merged_slashes
resolves
merge_slashes
append_slash
remove_slash
redirect_class
T aappend_slash
merge_slashes
redirect_class
remove_slash
T wfT aappend_slash
remove_slash
merge_slashes
redirect_class
correct_configuration
impl
a__spec__
.aiohttp.web_protocol
o#
f a__class__
a__init__
a_request_count
a_keepalive
a_current_request
a_manager
request_handler
a_request_handler
request_factory
a_request_factory
a_tcp_keepalive
Z
a_next_keepalive_close_time
a_keepalive_handle
a_keepalive_timeout
a_lingering_time
deque
a_messages
c
a_message_tail
a_waiter
a_handler_waiter
a_task_handler
a_upgrade
a_payload_parser
aHttpRequestParser
aRequestPayloadError
T amax_line_size
max_field_size
max_headers
payload_exception
auto_decompress
a_request_parser
l a_timeout_ceil_threshold
T ETypeError
EValueError
logger
debug
access_log
access_logger
a_close
a_force_close
a_request_in_progress
u<{} {}>
a__name__
transport
connected
disconnected
uDo worker process exit preparations.
We need to clean up everything and stop accepting requests.
It is especially important for keep-alive connections.
self
cancel
a_loop
create_future
ceil_timeout
timeout
a__aenter__
a__aexit__
T nnnaasyncio
aCancelledError
aTimeoutError
a_cancel
done
shield
force_close
shutdown
uRequestHandler.shutdown
connection_made
cast
aTransport
tcp_keepalive
create_task
start
connection_lost
handler_cancellation
uConnection lost
exc
feed_eof
feed_data
aHttpProcessingError
a_ErrInfo
l  amessage
T astatus
exc
message
aEMPTY_PAYLOAD
append
set_result
T naclose
uSet keep-alive connection mode.
:param bool val: new state.
uClose connection.
Stop accepting new pipelining messages and close
connection when handlers done processing messages.
uForcefully close connection.
enabled
log
time
exception
call_at
a_process_keepalive
request
aHTTPException
finish_response
start_time
log_debug
T uRequest handler timed out.
T aexc_info
handle_error
l  l  a__http_exception__
warnings
warn
ureturning HTTPException object is deprecated (#2415) and will be removed, please raise the exception instead
aDeprecationWarning
reset
a_handle_request
uRequestHandler._handle_request
uProcess incoming request.
It reads request line, request headers and request payload, then
calls handle_request() method. Subclass has to override
handle_request(). start() handles various exceptions in request
or response handling. Connection is being closed always unless
keep_alive(True) specified.
current_task
loop
popleft
manager
requests_count
aStreamWriter
a_make_error_handler
aERROR
handler
T uIgnored premature client disconnection
T uIgnored premature client disconnection 2
keep_alive
is_eof
uStart lingering close timer for %s sec.
payload
now
end_t
readany
T uUncompleted request.
set_exception
a_PAYLOAD_ACCESS_ERROR
log_exception
T uUnhandled exception
resp
T uIgnored premature client disconnection.
keepalive_timeout
uRequestHandler.start
uPrepare the response and write_eof, then log access.
This has to
be called within the context of any exception so the access logger
can get exception information. Returns True if the client disconnects
prematurely.
a_finish
set_upgraded
T Faprepare
T uMissing return statement on request handler
uWeb-handler should return a response instance, got {!r}
aHTTPInternalServerError
aResponse
status
reason
text
headers
T astatus
reason
text
headers
write_eof
log_access
uRequestHandler.finish_response
aBadHttpMethod
uError handling request from %s
remote
writer
output_size
uResponse is sent already, cannot send another response with the error message
utext/plain
aHTTPStatus
aINTERNAL_SERVER_ERROR
u{0.value} {0.phrase}
description
suppress
T EException
a__enter__
a__exit__
traceback
format_exc
utext/html
get
T aAccept

html_escape
u<h2>Traceback:</h2>
<pre>

u</pre>
u<html><head><title>{title}</title></head><body>
<h1>{title}</h1>
{msg}
</body></html>
T atitle
msg

T astatus
text
content_type
uHandle errors.
Returns HTTP response with specific status code. Logs additional
information. It always closes current connection.
aBaseRequest
return
aStreamResponse
uRequestHandler._make_error_handler.<locals>.handler
err_info
a__doc__
a__file__
origin
has_location
a__cached__
uasyncio.streams
sys
collections
T adeque
contextlib
T asuppress
html
T aescape
escape
http
T aHTTPStatus
logging
T aLogger
aLogger
aTYPE_CHECKING
aAny
aAwaitable
aCallable
aDeque
aOptional
aSequence
aTuple
aType
aUnion
attr
yarl
abc
T aAbstractAccessLogger
aAbstractStreamWriter
aAbstractAccessLogger
aAbstractStreamWriter
base_protocol
T aBaseProtocol
aBaseProtocol
helpers
T aceil_timeout
T aHttpProcessingError
aHttpRequestParser
aHttpVersion10
aRawRequestMessage
aStreamWriter
aHttpVersion10
aRawRequestMessage
http_exceptions
T aBadHttpMethod
T aaccess_logger
server_logger
server_logger
streams
T aEMPTY_PAYLOAD
aStreamReader
aStreamReader
tcp_helpers
T atcp_keepalive
web_exceptions
T aHTTPException
aHTTPInternalServerError
web_log
T aAccessLogger
aAccessLogger
web_request
T aBaseRequest
web_response
T aResponse
aStreamResponse
T aRequestHandler
aRequestPayloadError
aPayloadAccessError
a__all__
aRequestHandler
uasyncio.Task[None]
a_RequestFactory
a_RequestHandler
aUNKNOWN
w/aURL
T w/a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
