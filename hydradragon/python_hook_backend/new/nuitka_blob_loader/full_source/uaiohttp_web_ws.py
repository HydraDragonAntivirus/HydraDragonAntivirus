# Reconstructed from integrated Nuitka blob
# Module: uaiohttp.web_ws

a__qualname__
D areturn
Obool
a__bool__
uWebSocketReady.__bool__
a__prepare__
aWebSocketResponse
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
a_length_check
bool
str
int
aAbstractEventLoop
aFuture
aBaseException
Z
float
aTimerHandle
aTask
f
$@aautoclose
autoping
heartbeat
protocols
max_msg_size
l    awriter_limit
return
uWebSocketResponse.__init__
D areturn
nuWebSocketResponse._cancel_heartbeat
uWebSocketResponse._cancel_pong_response_cb
uWebSocketResponse._reset_heartbeat
uWebSocketResponse._send_heartbeat
D atask
return
uasyncio.Task[None]
nuWebSocketResponse._ping_task_done
uWebSocketResponse._pong_not_received
uWebSocketResponse._handle_ping_pong_exception
uWebSocketResponse._set_closed
uCIMultiDict[str]
uWebSocketResponse._handshake
uWebSocketResponse._pre_start
writer
uWebSocketResponse._post_start
can_prepare
uWebSocketResponse.can_prepare
property
closed
uWebSocketResponse.closed
close_code
uWebSocketResponse.close_code
ws_protocol
uWebSocketResponse.ws_protocol
uWebSocketResponse.compress
T naname
default
uWebSocketResponse.get_extra_info
uWebSocketResponse.exception
T c
bytes
uWebSocketResponse._set_closing
uWebSocketResponse._set_code_close_transport
uWebSocketResponse._close_transport
D atimeout
nD areturn
aWebSocketResponse
a__aiter__
uWebSocketResponse.__aiter__
a_cancel
uWebSocketResponse._cancel
a__orig_bases__
uaiohttp\web_ws.py
u<module aiohttp.web_ws>
T a__class__
T aself
T aself
msg
T aself
timeout
receive_timeout
autoclose
autoping
heartbeat
protocols
compress
max_msg_size
writer_limit
a__class__
T aself
exc
T aself
request
protocol
headers
req_protocols
proto
version
key
accept_val
response_headers
notakeover
compress
extensions
enabledext
T aself
task
exc
T aself
request
protocol
writer
loop
T aself
request
headers
protocol
compress
notakeover
transport
writer
T aself
req
timeout_ceil_threshold
loop
now
when
T aself
loop
now
req
timeout_ceil_threshold
when
coro
ping_task
T aself
code
T aself
request
w_aprotocol
T aself
code
message
drain
writer
exc
reader
msg
T aself
name
default
writer
transport
T aself
message
T aself
request
protocol
writer
payload_writer
a__class__
T aself
timeout
receive_timeout
msg
exc
T aself
timeout
msg
T aself
loads
timeout
data
T aself
data
compress
T aself
message
opcode
compress
T aself
data
compress
dumps
T aself
data
a__spec__
.aiohttp.worker
a__class__
a__init__
a_task
exit_code
a_notify_waiter
asyncio
get_event_loop
close
new_event_loop
loop
set_event_loop
init_process
create_task
a_run
run_until_complete
log
exception
T uException in gunicorn worker
shutdown_asyncgens
self
wsgi
aApplication
iscoroutinefunction
web
aAppRunner
app
uwsgi app should be either Application or async function returning Application, got {}
runner
cfg
accesslog
access_log
keepalive
a_get_valid_log_format
access_log_format
graceful_timeout
ldl_T alogger
keepalive_timeout
access_log
access_log_format
shutdown_timeout
setup
is_ssl
a_create_ssl_context
server
sockets
aSockSite
ctx
T assl_context
start
getpid
alive
notify
requests_count
max_requests
info
uMax requests, shutting down: %s
ppid
getppid
uParent changed, shutting down: %s
a_wait_next_notify
cleanup
uGunicornWebWorker._run
a_notify_waiter_done
create_future
call_later
f
?aset_result
add_signal_handler
signal
aSIGQUIT
handle_quit
aSIGTERM
handle_exit
aSIGINT
aSIGWINCH
handle_winch
aSIGUSR1
handle_usr1
aSIGABRT
handle_abort
siginterrupt
worker_int
worker_abort
ssl
uSSL is not supported.
aSSLContext
ssl_version
load_cert_chain
certfile
keyfile
cert_reqs
verify_mode
ca_certs
load_verify_locations
ciphers
set_ciphers
uCreates SSLContext instance for usage in asyncio.create_server.
See ssl.SSLSocket.__init__ for more details.
aDEFAULT_GUNICORN_LOG_FORMAT
aDEFAULT_AIOHTTP_LOG_FORMAT
re
search
u%\([^\)]+\)
uGunicorn's style options in form of `%(name)s` are not supported for the log formatting. Please use aiohttp's format specification to configure access log formatting: http://docs.aiohttp.org/en/stable/logging.html#format-specification
uvloop
set_event_loop_policy
aEventLoopPolicy
uAsync gunicorn worker for aiohttp.web
a__doc__
a__file__
origin
has_location
a__cached__
os
sys
aFrameType
aTYPE_CHECKING
aAny
aOptional
ugunicorn.config
T aAccessLogFormat
aAccessLogFormat
aGunicornAccessLogFormat
ugunicorn.workers
T abase
base
aiohttp
T aweb
helpers
T aset_result
web_app
T aApplication
web_log
T aAccessLogger
aAccessLogger
T aGunicornWebWorker
aGunicornUVLoopWebWorker
a__all__
aWorker
a__prepare__
aGunicornWebWorker
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
