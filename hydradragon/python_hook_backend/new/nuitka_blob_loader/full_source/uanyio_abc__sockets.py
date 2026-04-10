# Reconstructed from integrated Nuitka blob
# Module: uanyio.abc._sockets

a_NullAsyncContextManager
a__qualname__
D areturn
aNone
D aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
ubool | None
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
a__annotations__
int
usocket.socket
a__orig_bases__
a_SocketProvider
property
D areturn
uMapping[Any, Callable[[], Any]]
extra_attributes
u_SocketProvider.extra_attributes
D areturn
usocket.socket
u_SocketProvider._raw_socket
aSocketStream

Transports bytes over a socket.
Supports all relevant extra attributes from :class:`~SocketAttribute`.
aUNIXSocketStream
D amessage
fds
return
bytes
uCollection[int | IOBase]
aNone
D amsglen
maxfds
return
int
putuple[bytes, list[int]]
aSocketListener

Listens to incoming socket connections.
Supports all relevant extra attributes from :class:`~SocketAttribute`.
D areturn
aSocketStream
T nD ahandler
task_group
return
uCallable[[SocketStream], Any]
uTaskGroup | None
aNone
aUDPSocket

Represents an unconnected UDP socket.
Supports all relevant extra attributes from :class:`~SocketAttribute`.
D adata
host
port
return
bytes
str
int
aNone
aConnectedUDPSocket

Represents an connected UDP socket.
Supports all relevant extra attributes from :class:`~SocketAttribute`.
aUNIXDatagramSocket

Represents an unconnected Unix datagram socket.
Supports all relevant extra attributes from :class:`~SocketAttribute`.
D adata
path
return
bytes
str
aNone
aConnectedUNIXDatagramSocket

Represents a connected Unix datagram socket.
Supports all relevant extra attributes from :class:`~SocketAttribute`.
uanyio\abc\_sockets.py
T aconvert
self
T apeername
T aremote_port
T aself
u<module anyio.abc._sockets>
T a__class__
T aself
exc_type
exc_val
exc_tb
T aself
attributes
peername
convert
remote_port
T aself
msglen
maxfds
T aself
message
fds
T aself
data
host
port
T aself
data
path
T aself
handler
task_group
create_task_group
stack
stream
a__spec__
.anyio.abc._streams
,
t
self
receive
aEndOfStream
a__anext__
uUnreliableObjectReceiveStream.__anext__

Receive the next item.
:raises ~anyio.ClosedResourceError: if the receive stream has been explicitly
closed
:raises ~anyio.EndOfStream: if this stream has been closed from the other end
:raises ~anyio.BrokenResourceError: if this stream has been rendered unusable
due to external causes
uUnreliableObjectReceiveStream.receive

Send an item to the peer(s).
:param item: the item to send
:raises ~anyio.ClosedResourceError: if the send stream has been explicitly
closed
:raises ~anyio.BrokenResourceError: if this stream has been rendered unusable
due to external causes
send
uUnreliableObjectSendStream.send

Send an end-of-file indication to the peer.
You should not try to send any further data to this stream after calling this
method. This method is idempotent (does nothing on successive calls).
send_eof
uObjectStream.send_eof
uByteReceiveStream.__anext__

Receive at most ``max_bytes`` bytes from the peer.
.. note:: Implementors of this interface should not return an empty
:class:`bytes` object, and users should ignore them.
:param max_bytes: maximum number of bytes to receive
:return: the received bytes
:raises ~anyio.EndOfStream: if this stream has been closed from the other end
uByteReceiveStream.receive

Send the given bytes to the peer.
:param item: the bytes to send
uByteSendStream.send
uByteStream.send_eof

Accept incoming connections as they come in and start tasks to handle them.
:param handler: a callable that will be used to handle each accepted connection
:param task_group: the task group that will be used to start tasks for handling
each accepted connection (if omitted, an ad-hoc task group will be created)
serve
uListener.serve
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
T aabstractmethod
abstractmethod
ucollections.abc
T aCallable
aCallable
aAny
aGeneric
aTypeVar
aUnion
u_core._exceptions
T aEndOfStream
l u_core._typedattr
T aTypedAttributeProvider
aTypedAttributeProvider
a_resources
T aAsyncResource
aAsyncResource
a_tasks
T aTaskGroup
aTaskGroup
T aT_Item
aT_Item
T aT_co
tT acovariant
aT_co
T aT_contra
tT acontravariant
aT_contra
a__prepare__
aUnreliableObjectReceiveStream
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
