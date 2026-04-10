# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._async.http11

a__qualname__
l a__orig_bases__
aAsyncHTTP11Connection
l   l   T nD aorigin
stream
keepalive_expiry
return
aOrigin
aAsyncNetworkStream
ufloat | None
aNone
a__init__
uAsyncHTTP11Connection.__init__
D arequest
return
aRequest
aResponse
D arequest
return
aRequest
aNone
D aevent
timeout
return
uh11.Event
ufloat | None
aNone
D arequest
return
aRequest
utuple[bytes, int, bytes, list[tuple[bytes, bytes]], bytes]
D arequest
return
aRequest
utyping.AsyncIterator[bytes]
D atimeout
return
ufloat | None
uh11.Event | type[h11.PAUSED]
D areturn
aNone
D aorigin
return
aOrigin
bool
uAsyncHTTP11Connection.can_handle_request
D areturn
bool
is_available
uAsyncHTTP11Connection.is_available
has_expired
uAsyncHTTP11Connection.has_expired
is_idle
uAsyncHTTP11Connection.is_idle
is_closed
uAsyncHTTP11Connection.is_closed
D areturn
str
info
uAsyncHTTP11Connection.info
a__repr__
uAsyncHTTP11Connection.__repr__
D areturn
aAsyncHTTP11Connection
D aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
aNone
D aconnection
request
return
aAsyncHTTP11Connection
aRequest
aNone
uHTTP11ConnectionByteStream.__init__
D areturn
utyping.AsyncIterator[bytes]
D astream
leading_data
return
aAsyncNetworkStream
bytes
aNone
uAsyncHTTP11UpgradeStream.__init__
D amax_bytes
timeout
return
int
ufloat | None
bytes
D abuffer
timeout
return
bytes
ufloat | None
aNone
T nnD assl_context
server_hostname
timeout
return
ussl.SSLContext
ustr | None
ufloat | None
aAsyncNetworkStream
D ainfo
return
str
utyping.Any
uAsyncHTTP11UpgradeStream.get_extra_info
uhttpcore\_async\http11.py
u<module httpcore._async.http11>
T a__class__
T aself
T aself
exc_type
exc_value
traceback
T aself
kwargs
chunk
exc
T aself
origin
stream
keepalive_expiry
T aself
stream
leading_data
T aself
connection
request
T aself
class_name
origin
T aself
timeout
event
data
msg
T aself
request
timeouts
timeout
event
T	aself
request
timeouts
timeout
event
http_version
headers
trailing_data
w_T aself
now
T aself
event
timeout
bytes_to_send
T aself
request
timeouts
timeout
chunk
event
T aself
origin
T aself
info
T aself
request
kwargs
trace
http_version
status
reason_phrase
headers
trailing_data
network_stream
exc
T aself
now
keepalive_expired
server_disconnected
T aself
max_bytes
timeout
buffer
T aself
ssl_context
server_hostname
timeout
T aself
buffer
timeout
a__spec__
.httpcore._async.http2
t
N aheaders
lower
ccontent-length
ctransfer-encoding
u<genexpr>
uhas_body_headers.<locals>.<genexpr>
a_origin
a_network_stream
a_keepalive_expiry
h2
connection
aH2Connection
aCONFIG
T aconfig
a_h2_state
aHTTPConnectionState
aIDLE
a_state
a_expire_at
a_request_count
aAsyncLock
a_init_lock
a_state_lock
a_read_lock
a_write_lock
a_sent_connection_init
a_used_all_stream_ids
a_connection_error
a_events
a_connection_terminated
a_read_exception
a_write_exception
self
can_handle_request
request
url
origin
uAttempted to send request to

u on connection to
a__aenter__
a__aexit__
aACTIVE
aConnectionNotAvailable
T nnnaTrace
send_connection_init
logger
a_send_connection_init
aAsyncShieldCancellation
a__enter__
a__exit__
aclose
a_max_streams
local_settings
max_concurrent_streams
aAsyncSemaphore
a_max_streams_semaphore
acquire
get_next_available_stream_id
exceptions
aNoAvailableStreamIDError
stream_id
send_request_headers
a_send_request_headers
T arequest
stream_id
send_request_body
a_send_request_body
receive_response_headers
a_receive_response
return_value
aResponse
status
aHTTP2ConnectionByteStream
T astream_id
http_version
cHTTP/2
network_stream
T astatus
headers
content
extensions
response_closed
a_response_closed
aProtocolError
aRemoteProtocolError
aLocalProtocolError
handle_async_request
uAsyncHTTP2Connection.handle_async_request

The HTTP/2 connection requires some initial setup before we can start
using individual request/response streams on it.
settings
aSettings
aSettingCodes
aENABLE_PUSH
aMAX_CONCURRENT_STREAMS
ldaMAX_HEADER_LIST_SIZE
l   T aclient
initial_values
aENABLE_CONNECT_PROTOCOL
initiate_connection
increment_flow_control_window
T l    a_write_outgoing_data
uAsyncHTTP2Connection._send_connection_init

Send the request headers to a given stream ID.
has_body_headers
chost
c:method
method
c:authority
c:scheme
scheme
c:path
target
T chost
ctransfer-encoding
send_headers
T aend_stream
uAsyncHTTP2Connection._send_request_headers

Iterate over the request body sending it to a given stream ID.
stream
aAsyncIterable
a_send_stream_data
a_send_end_stream
uAsyncHTTP2Connection._send_request_body

Send a single chunk of data in one or more data frames.
data
a_wait_for_outgoing_flow
min
send_data
uAsyncHTTP2Connection._send_stream_data

Send an empty data frame on on a given stream ID with the END_STREAM flag set.
end_stream
uAsyncHTTP2Connection._send_end_stream

Return the response status code and headers for a given stream ID.
a_receive_stream_event
events
aResponseReceived
l  c:status
decode
T aascii
ignore
T aerrors
startswith
T d:astatus_code
uAsyncHTTP2Connection._receive_response

Iterator that returns the bytes of the response body for a given stream ID.
aDataReceived
flow_controlled_length
acknowledge_received_data
aStreamEnded
a_receive_response_body
uAsyncHTTP2Connection._receive_response_body

Return the next available event for a given stream ID.
Will read more data from the network if required.
get
a_receive_events
pop
T l
aStreamReset
uAsyncHTTP2Connection._receive_stream_event

Read some data from the network until we see one or more events
for a given stream ID.
last_stream_id
a_read_incoming_data
aRemoteSettingsChanged
receive_remote_settings
a_receive_remote_settings_change
append
aConnectionTerminated
uAsyncHTTP2Connection._receive_events
event
changed_settings
new_value
release
uAsyncHTTP2Connection._receive_remote_settings_change
time
monotonic
uAsyncHTTP2Connection._response_closed
close_connection
aCLOSED
uAsyncHTTP2Connection.aclose
extensions
timeout
T aread
naread
aREAD_NUM_BYTES
c
T uServer disconnected
receive_data
uAsyncHTTP2Connection._read_incoming_data
T awrite
nadata_to_send
write
uAsyncHTTP2Connection._write_outgoing_data

Returns the maximum allowable outgoing flow for a given stream.
If the allowable flow is zero, then waits on the network until
WindowUpdated frames have increased the flow rate.
https://tools.ietf.org/html/rfc7540#section-6.9
local_flow_control_window
max_outbound_frame_size
flow
uAsyncHTTP2Connection._wait_for_outgoing_flow
state_machine
state
aConnectionState
u, HTTP/2,
name
u, Request Count:
a__name__
w<u [
u,
u]>
uAsyncHTTP2Connection.__aenter__
uAsyncHTTP2Connection.__aexit__
a_connection
a_request
a_stream_id
a_closed
receive_response_body
a__aiter__
uHTTP2ConnectionByteStream.__aiter__
uHTTP2ConnectionByteStream.aclose
a__doc__
a__file__
has_location
a__cached__
annotations
enum
logging
types
typing
uh2.config
uh2.connection
uh2.events
uh2.exceptions
uh2.settings
u_backends.base
T aAsyncNetworkStream
l aAsyncNetworkStream
a_exceptions
T aConnectionNotAvailable
aLocalProtocolError
aRemoteProtocolError
a_models
T aOrigin
aRequest
aResponse
aOrigin
aRequest
a_synchronization
T aAsyncLock
aAsyncSemaphore
aAsyncShieldCancellation
a_trace
T aTrace
interfaces
T aAsyncConnectionInterface
aAsyncConnectionInterface
getLogger
T uhttpcore.http2
D arequest
return
aRequest
bool
aIntEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
