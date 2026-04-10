# Reconstructed from integrated Nuitka blob
# Module: uanyio.streams.stapled


Combines two byte streams into a single, bidirectional byte stream.
Extra attributes will be provided from both streams, with the receive stream
providing the values in case of a conflict.
:param ByteSendStream send_stream: the sending byte stream
:param ByteReceiveStream receive_stream: the receiving byte stream
a__qualname__
a__annotations__
T l   D amax_bytes
return
int
bytes
D aitem
return
bytes
aNone
D areturn
aNone
property
D areturn
uMapping[Any, Callable[[], Any]]
uStapledByteStream.extra_attributes
a__orig_bases__
aStapledObjectStream

Combines two object streams into a single, bidirectional object stream.
Extra attributes will be provided from both streams, with the receive stream
providing the values in case of a conflict.
:param ObjectSendStream send_stream: the sending object stream
:param ObjectReceiveStream receive_stream: the receiving object stream
uObjectSendStream[T_Item]
uObjectReceiveStream[T_Item]
D areturn
aT_Item
D aitem
return
aT_Item
aNone
uStapledObjectStream.extra_attributes

Combines multiple listeners into one, serving connections from all of them at once.
Any MultiListeners in the given collection of listeners will have their listeners
moved into this one.
Extra attributes are provided from each listener, with each successive listener
overriding any conflicting attributes from the previous one.
:param listeners: listeners to serve
:type listeners: Sequence[Listener[T_Stream]]
uSequence[Listener[T_Stream]]
a__post_init__
uMultiListener.__post_init__
T nD ahandler
task_group
return
uCallable[[T_Stream], Any]
uTaskGroup | None
aNone
uMultiListener.extra_attributes
uanyio\streams\stapled.py
u<module anyio.streams.stapled>
T a__class__
T aself
listeners
listener
T aself
listener
T aself
T aself
attributes
listener
T aself
max_bytes
T aself
item
T aself
handler
task_group
create_task_group
tg
listener
a__spec__
.anyio.streams.tls

Wrap an existing stream with Transport Layer Security.
This performs a TLS handshake with the peer.
:param transport_stream: a bytes-transporting stream to wrap
:param server_side: ``True`` if this is the server side of the connection,
``False`` if this is the client side (if omitted, will be set to ``False``
if ``hostname`` has been provided, ``False`` otherwise). Used only to create
a default context when an explicit context has not been provided.
:param hostname: host name of the peer (if host name checking is desired)
:param ssl_context: the SSLContext object to use (if not provided, a secure
default will be created)
:param standard_compatible: if ``False``, skip the closing handshake when
closing the connection, and don't raise an exception if the peer does the
same
:raises ~ssl.SSLError: if the TLS handshake fails
server_side
hostname
ssl_context
ssl
aPurpose
aCLIENT_AUTH
aSERVER_AUTH
create_default_context
aOP_IGNORE_UNEXPECTED_EOF
options
aMemoryBIO
wrap_bio
T aserver_side
server_hostname
cls
transport_stream
standard_compatible
T atransport_stream
standard_compatible
a_ssl_object
a_read_bio
a_write_bio
a_call_sslobject_method
do_handshake
wrap
uTLSStream.wrap
func
args
aSSLWantReadError
self
a_write_bio
pending
send
read
receive
aEndOfStream
a_read_bio
write_eof
aBrokenResourceError
write
data
aSSLWantWriteError
aSSLSyscallError
aSSLError
aSSLEOFError
strerror
aUNEXPECTED_EOF_WHILE_READING
result
uTLSStream._call_sslobject_method

Does the TLS closing handshake.
:return: a tuple of (wrapped byte stream, bytes left in the read buffer)
a_ssl_object
unwrap
uTLSStream.unwrap
aclose_forcefully
aclose
uTLSStream.aclose
max_bytes
uTLSStream.receive
item
uTLSStream.send
extra
aTLSAttribute
tls_version
re
match
uTLSv(\d+)(?:\.(\d+))?
group
T l T l T l l usend_eof() requires at least TLSv1.3; current session uses

usend_eof() has not yet been implemented for TLS streams
send_eof
uTLSStream.send_eof
extra_attributes
alpn_protocol
selected_alpn_protocol
channel_binding_tls_unique
get_channel_binding
cipher
peer_certificate
u<lambda>
uTLSStream.extra_attributes.<locals>.<lambda>
peer_certificate_binary
shared_ciphers
ssl_object
version
getpeercert
T FT tu
Handle an exception raised during the TLS handshake.
This method does 3 things:
#. Forcefully closes the original stream
#. Logs the exception (unless it was a cancellation exception) using the
``anyio.streams.tls`` logger
#. Reraises the exception if it was a base exception or a cancellation exception
:param exc: the exception
:param stream: the original stream
stream
exc
get_cancelled_exc_class
logging
getLogger
T uanyio.streams.tls
exception
T uError during TLS handshake
T aexc_info
handle_handshake_error
uTLSListener.handle_handshake_error
wraps
handler
D astream
return
aAnyByteStream
aNone
handler_wrapper
uTLSListener.serve.<locals>.handler_wrapper
listener
serve
task_group
uTLSListener.serve
T afail_after
l afail_after
handshake_timeout
a__enter__
a__exit__
aTLSStream
T assl_context
standard_compatible
T nnnawrapped_stream
uTLSListener.aclose
uTLSListener.extra_attributes.<locals>.<lambda>
a__doc__
a__file__
origin
has_location
a__cached__
annotations
sys
ucollections.abc
T aCallable
aMapping
aCallable
aMapping
dataclasses
T adataclass
dataclass
aAny
aTypeVar
T aBrokenResourceError
aEndOfStream
aclose_forcefully
get_cancelled_exc_class
u_core._typedattr
T aTypedAttributeSet
typed_attribute
aTypedAttributeSet
typed_attribute
abc
T aAnyByteStream
aByteStream
aListener
aTaskGroup
aAnyByteStream
aByteStream
aListener
aTaskGroup
typing_extensions
T aTypeVarTuple
aUnpack
aTypeVarTuple
aUnpack
T aT_Retval
aT_Retval
T aPosArgsT
aPosArgsT
T AOtuple
T Ostr
pQ
a_PCTRTT
a_PCTRTTT
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
