# Reconstructed from integrated Nuitka blob
# Module: uanyio.abc._testing


Encapsulates a running event loop. Every call made through this object will use the
same event loop.
aTestRunner
a__qualname__
D areturn
aTestRunner
a__enter__
uTestRunner.__enter__
D aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
ubool | None
a__exit__
uTestRunner.__exit__
D afixture_func
kwargs
return
uCallable[..., AsyncGenerator[_T, Any]]
udict[str, Any]
uIterable[_T]

Run an async generator fixture.
:param fixture_func: the fixture function
:param kwargs: keyword arguments to call the fixture function with
:return: an iterator yielding the value yielded from the async generator
run_asyncgen_fixture
uTestRunner.run_asyncgen_fixture
D afixture_func
kwargs
return
uCallable[..., Coroutine[Any, Any, _T]]
udict[str, Any]
a_T

Run an async fixture.
:param fixture_func: the fixture function
:param kwargs: keyword arguments to call the fixture function with
:return: the return value of the fixture function
run_fixture
uTestRunner.run_fixture
D atest_func
kwargs
return
uCallable[..., Coroutine[Any, Any, Any]]
udict[str, Any]
aNone

Run an async test function.
:param test_func: the test function
:param kwargs: keyword arguments to call the test function with
run_test
uTestRunner.run_test
uanyio\abc\_testing.py
u<module anyio.abc._testing>
T a__class__
T aself
T aself
exc_type
exc_val
exc_tb
T aself
fixture_func
kwargs
T aself
test_func
kwargs

a__spec__
.anyio.abc
s
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_anyio
u\not_existing
abc
T aNUITKA_PACKAGE_anyio_abc
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
annotations
a_eventloop
T aAsyncBackend
aAsyncBackend
a_resources
T aAsyncResource
aAsyncResource
a_sockets
T aConnectedUDPSocket
aConnectedUDPSocket
T aConnectedUNIXDatagramSocket
aConnectedUNIXDatagramSocket
T aIPAddressType
aIPAddressType
T aIPSockAddrType
aIPSockAddrType
T aSocketAttribute
aSocketAttribute
T aSocketListener
aSocketListener
T aSocketStream
aSocketStream
T aUDPPacketType
aUDPPacketType
T aUDPSocket
aUDPSocket
T aUNIXDatagramPacketType
aUNIXDatagramPacketType
T aUNIXDatagramSocket
aUNIXDatagramSocket
T aUNIXSocketStream
aUNIXSocketStream
a_streams
T aAnyByteReceiveStream
aAnyByteReceiveStream
T aAnyByteSendStream
aAnyByteSendStream
T aAnyByteStream
aAnyByteStream
T aAnyUnreliableByteReceiveStream
aAnyUnreliableByteReceiveStream
T aAnyUnreliableByteSendStream
aAnyUnreliableByteSendStream
T aAnyUnreliableByteStream
aAnyUnreliableByteStream
T aByteReceiveStream
aByteReceiveStream
T aByteSendStream
aByteSendStream
T aByteStream
aByteStream
T aListener
aListener
T aObjectReceiveStream
aObjectReceiveStream
T aObjectSendStream
aObjectSendStream
T aObjectStream
aObjectStream
T aUnreliableObjectReceiveStream
aUnreliableObjectReceiveStream
T aUnreliableObjectSendStream
aUnreliableObjectSendStream
T aUnreliableObjectStream
aUnreliableObjectStream
a_subprocesses
T aProcess
aProcess
a_tasks
T aTaskGroup
aTaskGroup
T aTaskStatus
aTaskStatus
a_testing
T aTestRunner
aTestRunner
u_core._synchronization
T aCapacityLimiter
aCondition
aEvent
aLock
aSemaphore
l aCapacityLimiter
aCondition
aEvent
aLock
aSemaphore
u_core._tasks
T aCancelScope
aCancelScope
from_thread
T aBlockingPortal
aBlockingPortal
values
