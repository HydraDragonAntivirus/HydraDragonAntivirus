# Reconstructed from integrated Nuitka blob
# Module: frozenlist

a__qualname__
T a_frozen
a_items
a__slots__
version_info
T l l	aclassmethod
aGenericAlias
a__class_getitem__
cls
cls_item
return
uFrozenList.__class_getitem__
T na__init__
uFrozenList.__init__
property
frozen
uFrozenList.frozen
freeze
uFrozenList.freeze
uFrozenList.__getitem__
a__setitem__
uFrozenList.__setitem__
a__delitem__
uFrozenList.__delitem__
uFrozenList.__len__
uFrozenList.__iter__
uFrozenList.__reversed__
a__eq__
uFrozenList.__eq__
a__le__
uFrozenList.__le__
uFrozenList.insert
a__repr__
uFrozenList.__repr__
a__hash__
uFrozenList.__hash__
a__orig_bases__
aPyFrozenList
a_frozenlist
T aFrozenList
aCFrozenList
ufrozenlist\__init__.py
u<module frozenlist>
T a__class__
T acls
cls_item
T aself
index
T aself
other
T aself
T aself
items
T aself
index
value
T aself
pos
item
a__spec__
.h11._abnf
s
/
a__doc__
a__file__
origin
has_location
a__cached__
u[ \t]*
aOWS
u[-!#$%&'*+.^_`|~0-9a-zA-Z]+
token
field_name
u[\x21-\x7e]
vchar
u[^\x00\s]
vchar_or_obs_text
field_vchar
u{field_vchar}+(?:[ \t]+{field_vchar}+)*
format
field_content
u({field_content})?
field_value
u(?P<field_name>{field_name}):{OWS}(?P<field_value>{field_value}){OWS}
header_field
method
u{vchar}+
request_target
uHTTP/(?P<http_version>[0-9]\.[0-9])
http_version
u(?P<method>{method}) (?P<target>{request_target}) {http_version}
request_line
u[0-9]{3}
status_code
u([ \t]|{vchar_or_obs_text})*
reason_phrase
u{http_version} (?P<status_code>{status_code})(?: (?P<reason>{reason_phrase}))?
status_line
u[0-9A-Fa-f]
aHEXDIG
u({HEXDIG}){{1,20}}
chunk_size
u;.*
chunk_ext
u(?P<chunk_size>{chunk_size})(?P<chunk_ext>{chunk_ext})?{OWS}\r\n
chunk_header
uh11\_abnf.py
u<module h11._abnf>

a__spec__
.h11._connection
(
get_comma_header
headers
cconnection
cclose
http_version
c1.1
aRequest
aResponse
status_code
T l  l  cHEAD
cCONNECT
l  l  T ucontent-length
T l
ctransfer-encoding
cchunked
T achunked
T
ccontent-length
ucontent-length
T uhttp/1.0
T
a_max_incomplete_event_size
aCLIENT
aSERVER
uexpected CLIENT or SERVER, not {!r}
our_role
their_role
aConnectionState
a_cstate
a_get_io_object
aWRITERS
a_writer
aREADERS
a_reader
aReceiveBuffer
a_receive_buffer
a_receive_buffer_closed
their_http_version
a_request_method
client_is_waiting_for_100_continue
states
uA dictionary like::
{CLIENT: <client state>, SERVER: <server state>}
See :ref:`state-machine` for details.
uThe current state of whichever role we are playing. See
:ref:`state-machine` for details.
uThe current state of whichever role we are NOT playing. See
:ref:`state-machine` for details.
start_next_cycle
a_respond_to_state_changes
uAttempt to reset our connection state for a new request/response
cycle.
If both client and server are in :data:`DONE` state, then resets them
both to :data:`IDLE` state in preparation for a new request/response
cycle on this same connection. Otherwise, raises a
:exc:`LocalProtocolError`.
See :ref:`keepalive-and-pipelining`.
process_error
aInformationalResponse
lea_SWITCH_UPGRADE
a_SWITCH_CONNECT
pending_switch_proposals
method
process_client_switch_proposal
cupgrade
a_server_switch_event
process_event
cast
aUnion
event
a_keep_alive
process_keep_alive_disabled
has_expect_100_continue
aData
aEndOfMessage
aSEND_BODY
a_body_framing
get
our_state
their_state
uData that has been received, but not yet processed, represented as
a tuple with two elements, where the first is a byte-string containing
the unprocessed data itself, and the second is a bool that is True if
the receive connection was closed.
See :ref:`switching-protocols` for discussion of why you'd want this.
ureceived close, then received more data?
uAdd data to our internal receive buffer.
This does not actually do any processing on the data, just stores
it. To trigger processing, you have to call :meth:`next_event`.
Args:
data (:term:`bytes-like object`):
The new data that was just received.
Special case: If *data* is an empty byte-string like ``b""``,
then this indicates that the remote side has closed the
connection (end of file). Normally this is convenient, because
standard Python APIs like :meth:`file.read` or
:meth:`socket.recv` use ``b""`` to indicate end-of-file, while
other failures to read are indicated using other mechanisms
like raising :exc:`TimeoutError`. When using such an API you
can just blindly pass through whatever you get from ``read``
to :meth:`receive_data`, and everything will work.
But, if you have an API where reading an empty string is a
valid non-EOF condition, then you need to be aware of this and
make sure to check for such strings and avoid passing them to
:meth:`receive_data`.
Returns:
Nothing, but after calling this you should call :meth:`next_event`
to parse the newly received data.
Raises:
RuntimeError:
Raised if you pass an empty *data*, indicating EOF, and then
pass a non-empty *data*, indicating more data that somehow
rrived after the EOF.
(Calling ``receive_data(b"")`` multiple times is fine,
nd equivalent to calling it once.)
aDONE
aPAUSED
aMIGHT_SWITCH_PROTOCOL
aSWITCHED_PROTOCOL
read_eof
aConnectionClosed
aNEED_DATA
aERROR
aRemoteProtocolError
T uCan't receive data when peer state is ERROR
a_extract_next_receive_event
a_process_event
aEvent
T uReceive buffer too long
l  T aerror_status_hint
T upeer unexpectedly closed connection
a_process_error
aLocalProtocolError
a_reraise_as_remote_protocol_error
uParse the next event out of our receive buffer, update our internal
state, and return it.
This is a mutating operation -- think of it like calling :func:`next`
on an iterator.
Returns:
: One of three things:
1) An event object -- see :ref:`events`.
2) The special constant :data:`NEED_DATA`, which indicates that
you need to read more data from your socket and pass it to
:meth:`receive_data` before this method will be able to return
ny more events.
3) The special constant :data:`PAUSED`, which indicates that we
re not in a state where we can process incoming data (usually
because the peer has finished their part of the current
request/response cycle, and you have not yet called
:meth:`start_next_cycle`). See :ref:`flow-control` for details.
Raises:
RemoteProtocolError:
The peer has misbehaved. You should close the connection
(possibly after sending some kind of 4xx response).
Once this method returns :class:`ConnectionClosed` once, then all
subsequent calls will also return :class:`ConnectionClosed`.
If this method raises any exception besides :exc:`RemoteProtocolError`
then that's a bug -- if it happens please file a bug report!
If this method raises any exception then it also sets
:attr:`Connection.their_state` to :data:`ERROR` -- see
:ref:`error-handling` for discussion.
send_with_data_passthrough
c
uConvert a high-level event into bytes that can be sent to the peer,
while updating our internal state machine.
Args:
event: The :ref:`event <events>` to send.
Returns:
If ``type(event) is ConnectionClosed``, then returns
``None``. Otherwise, returns a :term:`bytes-like object`.
Raises:
LocalProtocolError:
Sending this event at this time would violate our
understanding of the HTTP/1.1 protocol.
If this method raises any exception then it also sets
:attr:`Connection.our_state` to :data:`ERROR` -- see
:ref:`error-handling` for discussion.
T uCan't send data when our state is ERROR
a_clean_up_response_headers_for_sending
append
uIdentical to :meth:`send`, except that in situations where
:meth:`send` returns a single :term:`bytes-like object`, this instead
returns a list of them -- and when sending a :class:`Data` event, this
list is guaranteed to contain the exact object you passed in as
:attr:`Data.data`. See :ref:`sendfile` for discussion.
uNotify the state machine that we failed to send the data it gave
us.
This causes :attr:`Connection.our_state` to immediately become
:data:`ERROR` -- see :ref:`error-handling` for discussion.
cGET
T achunked
uhttp/1.0
set_comma_header
keep_alive
discard
T ckeep-alive
add
T cclose
sorted
reason
T aheaders
status_code
http_version
reason
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aCallable
aDict
aList
aOptional
aTuple
aType
a_events
T aConnectionClosed
aData
aEndOfMessage
aEvent
aInformationalResponse
aRequest
aResponse
a_headers
T aget_comma_header
has_expect_100_continue
set_comma_header
a_readers
T aREADERS
aReadersType
aReadersType
a_receivebuffer
T aReceiveBuffer
a_state
T
a_SWITCH_CONNECT
a_SWITCH_UPGRADE
aCLIENT
aConnectionState
aDONE
aERROR
aMIGHT_SWITCH_PROTOCOL
aSEND_BODY
aSERVER
aSWITCHED_PROTOCOL
a_util
T aLocalProtocolError
aRemoteProtocolError
aSentinel
aSentinel
a_writers
T aWRITERS
aWritersType
aWritersType
aConnection
a__all__
metaclass
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
