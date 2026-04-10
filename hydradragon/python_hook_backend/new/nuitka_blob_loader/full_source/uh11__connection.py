# Reconstructed from integrated Nuitka blob
# Module: uh11._connection

a__qualname__
a__orig_bases__
l   aDEFAULT_MAX_INCOMPLETE_EVENT_SIZE
return
request_method
uAn object encapsulating the state of an HTTP connection.
Args:
our_role: If you're implementing a client, pass :data:`h11.CLIENT`. If
you're implementing a server, pass :data:`h11.SERVER`.
max_incomplete_event_size (int):
The maximum number of bytes we're willing to buffer of an
incomplete event. In practice this mostly sets a limit on the
maximum size of the request/response line + headers. If this is
exceeded, then :meth:`next_event` will raise
:exc:`RemoteProtocolError`.
max_incomplete_event_size
a__init__
uConnection.__init__
uConnection.states
uConnection.our_state
uConnection.their_state
D areturn
Obool
they_are_waiting_for_100_continue
uConnection.they_are_waiting_for_100_continue
D areturn
nuConnection.start_next_cycle
role
uConnection._process_error
uConnection._server_switch_event
uConnection._process_event
io_dict
uConnection._get_io_object
T naold_states
uConnection._respond_to_state_changes
T Obytes
Obool
trailing_data
uConnection.trailing_data
D adata
return
Obytes
nareceive_data
uConnection.receive_data
uConnection._extract_next_receive_event
next_event
uConnection.next_event
send
uConnection.send
uConnection.send_with_data_passthrough
send_failed
uConnection.send_failed
response
uConnection._clean_up_response_headers_for_sending
uh11\_connection.py
u<module h11._connection>
T a__class__
T aself
our_role
max_incomplete_event_size
T arequest_method
event
transfer_encodings
content_lengths
T aself
response
headers
need_close
method_for_choosing_headers
framing_type
w_aconnection
T aself
state
event
T aself
role
event
io_dict
state
framing_type
args
T aevent
connection
T aself
role
old_states
T aself
role
event
old_states
server_switch_event
T aself
old_states
event
T aself
event
T aself
event
exc
T aself
T aself
data
T aself
event
data_list
T aself
event
data_list
writer
T aself
old_states

a__spec__
.h11._events
}
a__class__
a__init__
aHeaders
a__setattr__
headers
normalize_and_validate
T a_parsed
self
method
bytesify
target
http_version
chost
host_count
c1.1
aLocalProtocolError
T uMissing mandatory Host: header
T uFound multiple Host: headers
validate
method_re
uIllegal method characters
request_target_re
uIllegal target characters
reason
T ustatus code must be integer
status_code
a__post_init__
ldl  uInformationalResponse status_code should be in range [100, 200), not {}
l  uResponse status_code should be in range [200, 1000), not {}
data
chunk_start
chunk_end
a__doc__
a__file__
origin
has_location
a__cached__
re
abc
T aABC
aABC
dataclasses
T adataclass
field
dataclass
field
aAny
cast
aDict
aList
aTuple
aUnion
a_abnf
T amethod
request_target
request_target
a_headers
T aHeaders
normalize_and_validate
a_util
T abytesify
aLocalProtocolError
validate
L aEvent
aRequest
aInformationalResponse
aResponse
aData
aEndOfMessage
aConnectionClosed
a__all__
compile
encode
T aascii
a__prepare__
aEvent
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
