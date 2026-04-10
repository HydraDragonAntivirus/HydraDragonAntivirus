# Reconstructed from integrated Nuitka blob
# Module: uanyio.abc._streams


An interface for receiving objects.
This interface makes no guarantees that the received messages arrive in the order in
which they were sent, or that no messages are missed.
Asynchronously iterating over objects of this type will yield objects matching the
given type parameter.
a__qualname__
D areturn
uUnreliableObjectReceiveStream[T_co]
a__aiter__
uUnreliableObjectReceiveStream.__aiter__
D areturn
aT_co
a__orig_bases__
aUnreliableObjectSendStream

An interface for sending objects.
This interface makes no guarantees that the messages sent will reach the
recipient(s) in the same order in which they were sent, or at all.
D aitem
return
aT_contra
aNone
aUnreliableObjectStream

A bidirectional message stream which does not guarantee the order or reliability of
message delivery.
aObjectReceiveStream

A receive message stream which guarantees that messages are received in the same
order in which they were sent, and that no messages are missed.
aObjectSendStream

A send message stream which guarantees that messages are delivered in the same order
in which they were sent, without missing any messages in the middle.
aObjectStream

A bidirectional message stream which guarantees the order and reliability of message
delivery.
D areturn
aNone
aByteReceiveStream

An interface for receiving bytes from a single peer.
Iterating this byte stream will yield a byte string of arbitrary length, but no more
than 65536 bytes.
D areturn
aByteReceiveStream
uByteReceiveStream.__aiter__
D areturn
bytes
T l   D amax_bytes
return
int
bytes
aByteSendStream
uAn interface for sending bytes to a single peer.
D aitem
return
bytes
aNone
aByteStream
uA bidirectional byte stream.
aAnyUnreliableByteReceiveStream
aAnyUnreliableByteSendStream
aAnyUnreliableByteStream
aAnyByteReceiveStream
aAnyByteSendStream
aAnyByteStream
aListener
uAn interface for objects that let you accept incoming connections.
T nD ahandler
task_group
return
uCallable[[T_co], Any]
uTaskGroup | None
aNone
uanyio\abc\_streams.py
u<module anyio.abc._streams>
T a__class__
T aself
T aself
max_bytes
T aself
item
T aself
handler
task_group

a__spec__
.anyio.abc._subprocesses
G

Wait until the process exits.
:return: the exit code of the process
wait
uProcess.wait
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
T aabstractmethod
abstractmethod
signal
T aSignals
aSignals
a_resources
T aAsyncResource
aAsyncResource
a_streams
T aByteReceiveStream
aByteSendStream
aByteReceiveStream
aByteSendStream
a__prepare__
aProcess
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
