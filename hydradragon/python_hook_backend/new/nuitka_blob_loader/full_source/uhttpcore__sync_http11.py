# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._sync.http11

a__qualname__
l a__orig_bases__
aHTTP11Connection
l   l   T nD aorigin
stream
keepalive_expiry
return
aOrigin
aNetworkStream
ufloat | None
aNone
a__init__
uHTTP11Connection.__init__
D arequest
return
aRequest
aResponse
handle_request
uHTTP11Connection.handle_request
D arequest
return
aRequest
aNone
uHTTP11Connection._send_request_headers
uHTTP11Connection._send_request_body
D aevent
timeout
return
uh11.Event
ufloat | None
aNone
uHTTP11Connection._send_event
D arequest
return
aRequest
utuple[bytes, int, bytes, list[tuple[bytes, bytes]], bytes]
uHTTP11Connection._receive_response_headers
D arequest
return
aRequest
utyping.Iterator[bytes]
D atimeout
return
ufloat | None
uh11.Event | type[h11.PAUSED]
uHTTP11Connection._receive_event
D areturn
aNone
uHTTP11Connection._response_closed
uHTTP11Connection.close
D aorigin
return
aOrigin
bool
uHTTP11Connection.can_handle_request
D areturn
bool
is_available
uHTTP11Connection.is_available
has_expired
uHTTP11Connection.has_expired
is_idle
uHTTP11Connection.is_idle
is_closed
uHTTP11Connection.is_closed
D areturn
str
info
uHTTP11Connection.info
a__repr__
uHTTP11Connection.__repr__
D areturn
aHTTP11Connection
uHTTP11Connection.__enter__
D aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
aNone
uHTTP11Connection.__exit__
D aconnection
request
return
aHTTP11Connection
aRequest
aNone
uHTTP11ConnectionByteStream.__init__
D areturn
utyping.Iterator[bytes]
uHTTP11ConnectionByteStream.close
D astream
leading_data
return
aNetworkStream
bytes
aNone
uHTTP11UpgradeStream.__init__
D amax_bytes
timeout
return
int
ufloat | None
bytes
uHTTP11UpgradeStream.read
D abuffer
timeout
return
bytes
ufloat | None
aNone
uHTTP11UpgradeStream.write
uHTTP11UpgradeStream.close
T nnD assl_context
server_hostname
timeout
return
ussl.SSLContext
ustr | None
ufloat | None
aNetworkStream
uHTTP11UpgradeStream.start_tls
D ainfo
return
str
utyping.Any
uHTTP11UpgradeStream.get_extra_info
uhttpcore\_sync\http11.py
u<module httpcore._sync.http11>
T a__class__
T aself
T aself
exc_type
exc_value
traceback
T aself
origin
stream
keepalive_expiry
T aself
connection
request
T aself
stream
leading_data
T aself
kwargs
chunk
exc
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
.httpcore._sync.http2
i
K aheaders
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
aLock
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
can_handle_request
url
origin
uAttempted to send request to

u on connection to
a__enter__
a__exit__
aACTIVE
aConnectionNotAvailable
T nnnarequest
aTrace
send_connection_init
logger
a_send_connection_init
aShieldCancellation
close
a_max_streams
local_settings
max_concurrent_streams
aSemaphore
a_max_streams_semaphore
self
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

The HTTP/2 connection requires some initial setup before we can start
using individual request/response streams on it.
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

Send the request headers to a given stream ID.
stream
aIterable
a_send_stream_data
a_send_end_stream

Iterate over the request body sending it to a given stream ID.
data
a_wait_for_outgoing_flow
min
send_data

Send a single chunk of data in one or more data frames.
end_stream

Send an empty data frame on on a given stream ID with the END_STREAM flag set.
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

Return the response status code and headers for a given stream ID.

Iterator that returns the bytes of the response body for a given stream ID.
aDataReceived
flow_controlled_length
acknowledge_received_data
aStreamEnded
a_receive_response_body
uHTTP2Connection._receive_response_body
get
a_receive_events
pop
T l
aStreamReset

Return the next available event for a given stream ID.
Will read more data from the network if required.
last_stream_id
a_read_incoming_data
aRemoteSettingsChanged
receive_remote_settings
a_receive_remote_settings_change
append
aConnectionTerminated

Read some data from the network until we see one or more events
for a given stream ID.
changed_settings
new_value
release
time
monotonic
close_connection
aCLOSED
extensions
timeout
T aread
naread
aREAD_NUM_BYTES
c
T uServer disconnected
receive_data
T awrite
nadata_to_send
write
local_flow_control_window
max_outbound_frame_size
flow

Returns the maximum allowable outgoing flow for a given stream.
If the allowable flow is zero, then waits on the network until
WindowUpdated frames have increased the flow rate.
https://tools.ietf.org/html/rfc7540#section-6.9
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
a_connection
a_request
a_stream_id
a_closed
receive_response_body
a__iter__
uHTTP2ConnectionByteStream.__iter__
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
T aNetworkStream
l aNetworkStream
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
T aLock
aSemaphore
aShieldCancellation
a_trace
T aTrace
interfaces
T aConnectionInterface
aConnectionInterface
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
