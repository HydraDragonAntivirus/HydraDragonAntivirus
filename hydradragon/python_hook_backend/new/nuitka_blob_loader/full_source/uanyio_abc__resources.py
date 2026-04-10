# Reconstructed from integrated Nuitka blob
# Module: uanyio.abc._resources


Abstract base class for all closeable asynchronous resources.
Works as an asynchronous context manager which returns the instance itself on enter,
nd calls :meth:`aclose` on exit.
aAsyncResource
a__qualname__
a__slots__
D aself
return
wTpD aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
aNone
D areturn
aNone
uanyio\abc\_resources.py
u<module anyio.abc._resources>
T a__class__
T aself
T aself
exc_type
exc_val
exc_tb

a__spec__
.anyio.abc._sockets
a__aenter__
u_NullAsyncContextManager.__aenter__
a__aexit__
u_NullAsyncContextManager.__aexit__
u_core._sockets
T aconvert_ipv6_sockaddr
l aconvert_ipv6_sockaddr
aSocketAttribute
family
u<lambda>
u_SocketProvider.extra_attributes.<locals>.<lambda>
local_address
raw_socket
a_raw_socket
getpeername
remote_address
aAddressFamily
aAF_INET
aAF_INET6
local_port
remote_port
self
convert
getsockname
peername

Send file descriptors along with a message to the peer.
:param message: a non-empty bytestring
:param fds: a collection of files (either numeric file descriptors or open file
or socket objects)
send_fds
uUNIXSocketStream.send_fds

Receive file descriptors along with a message from the peer.
:param msglen: length of the message to expect from the peer
:param maxfds: maximum number of file descriptors to expect from the peer
:return: a tuple of (message, file descriptors)
receive_fds
uUNIXSocketStream.receive_fds
uAccept an incoming connection.
accept
uSocketListener.accept

T acreate_task_group
create_task_group
aAsyncExitStack
task_group
enter_async_context
start_soon
handler
T nnnaserve
uSocketListener.serve

Alias for :meth:`~.UnreliableObjectSendStream.send` ((data, (host, port))).
send
data
host
port
sendto
uUDPSocket.sendto
uAlias for :meth:`~.UnreliableObjectSendStream.send` ((data, path)).
path
uUNIXDatagramSocket.sendto
a__doc__
a__file__
origin
has_location
a__cached__
annotations
socket
abc
T aabstractmethod
abstractmethod
ucollections.abc
T aCallable
aCollection
aMapping
aCallable
aCollection
aMapping
contextlib
T aAsyncExitStack
aIOBase
ipaddress
T aIPv4Address
aIPv6Address
aIPv4Address
aIPv6Address
T aAddressFamily
aTracebackType
aAny
aTypeVar
aUnion
u_core._typedattr
T aTypedAttributeProvider
aTypedAttributeSet
typed_attribute
aTypedAttributeProvider
aTypedAttributeSet
typed_attribute
a_streams
T aByteStream
aListener
aUnreliableObjectStream
aByteStream
aListener
aUnreliableObjectStream
a_tasks
T aTaskGroup
aTaskGroup
aIPAddressType
T Ostr
Oint
aIPSockAddrType
aSockAddrType
aUDPPacketType
T Obytes
Ostr
aUNIXDatagramPacketType
T aT_Retval
aT_Retval
