# Reconstructed from integrated Nuitka blob
# Module: a_run_until_complete_cb

uuvloop.loop
set
cast
asyncio
aTask
current_task
a_task_states
cancel_scope
a_parent_scope
a_host_task
a__qualname__
w.aget_coro
getcoroutinestate
aCORO_RUNNING
aCORO_SUSPENDED
uCannot determine if task
u has started or not
uReturn ``True`` if the task has been started and has not finished.
exc
args
startswith
T uCancelled by cancel scope
a__context__
a__new__
a_deadline
a_shield
a_child_scopes
a_cancel_called
a_cancelled_caught
a_active
a_timeout_handle
a_cancel_handle
a_tasks
a_pending_uncancellations
uEach CancelScope may only be used for a single 'with' block
add
aTaskState
task_state
discard
a_timeout
a_deliver_cancellation
uThis cancel scope is not active
uAttempted to exit cancel scope in a different task than it was entered in
uAttempted to exit a cancel scope that isn't the current tasks's current cancel scope
remove
a_restart_cancellation_in_parent
a_parent_cancellation_is_visible_to_us
self
iterate_exceptions
is_anyio_cancellation
cannot_swallow_exc_val
shield
a_effectively_cancelled
math
inf
get_running_loop
time
call_at
a_must_cancel
a_task_started
a_fut_waiter
aFuture
uCancelled by cancel scope
origin
wxacancel_called
should_retry
call_soon

Deliver cancellation to directly contained tasks and nested cancel scopes.
Schedule another run at the end if we still have tasks eligible for
cancellation.
:param origin: the cancel scope that originated the cancellation
:return: ``True`` if the delivery needs to be retried on the next cycle
scope

Restart the cancellation effort in the closest directly cancelled parent scope.
parent_id
a_future
a_parent_id
aInvalidStateError
ucalled 'started' twice on the same task status
aCancelScope
a_exceptions
a_on_completed_fut
a__enter__
a__aenter__
uTaskGroup.__aenter__
exc_val
append
a__exit__
wait_scope
T nnnaAsyncIOBackend
cancel_shielded_checkpoint
aBaseExceptionGroup
uunhandled errors in a TaskGroup
a__traceback__
exc_type
exc_tb
a__aexit__
uTaskGroup.__aexit__
D a_task
return
uasyncio.Task
aNone
task_done
uTaskGroup._spawn.<locals>.task_done
uThis task group is not active; no new tasks can be started.
a_AsyncioTaskStatus
task_status
uExpected
u() to return a coroutine, but the return value (
u) is not a coroutine object
get_callable_name
get_task_factory
a__code__
a_eager_task_factory_code
a__closure__
closure
cell_contents
T aloop
name
T aname
T aparent_id
cancel_scope
add_done_callback
weatask_status_future
uChild exited without calling task_status.started()
a_spawn
func
name
T ashield
suppress
uTaskGroup.start
a__class__
a__init__
T uAnyIO worker thread
root_task
workers
idle_workers
aQueue
T l aqueue
current_time
idle_since
stopping
ucoroutine raised StopIteration
a__cause__
claim_worker_thread
threadlocals
current_cancel_scope
is_closed
a_report_result
put_nowait
run_sync_from_thread
a_task_group
start_soon
a_call_func
a_stream
read
max_bytes
aEndOfStream
receive
uStreamReaderWrapper.receive
aClosedResourceError
checkpoint
aclose
uStreamReaderWrapper.aclose
write
item
drain
send
uStreamWriterWrapper.send
uStreamWriterWrapper.aclose
a_stdin
a_stdout
a_stderr
wait
kill
uProcess.aclose
a_process
uProcess.wait
terminate
send_signal
pid
returncode
get_event_loop_policy
get_child_watcher
a_transport
child_watcher
remove_child_handler

Forcibly shuts down worker processes belonging to this event loop.

Shuts down worker processes belonging to this event loop.
NOTE: this only works when the event loop was started using asyncio.run() or
nyio.run().
sleep
a_shutdown_process_pool_on_exit
deque
read_queue
aEvent
read_event
write_event
aTransport
set_write_buffer_limits
T l
aBrokenResourceError
is_at_eof
T ldT amaxlen
convert_ipv6_sockaddr
clear
a_protocol
aResourceGuard
T ureading from
a_receive_guard
T uwriting to
a_send_guard
a_closed
get_extra_info
T asocket
is_set
is_closing
resume_reading
pause_reading
popleft
appendleft
chunk
uSocketStream.receive
uSocketStream.send
write_eof
send_eof
uSocketStream.send_eof
abort
uSocketStream.aclose
a_RawSocketMixin__raw_socket
D wfareturn
object
aNone
callback
u_RawSocketMixin._wait_until_readable.<locals>.callback
a_receive_future
add_reader
remove_reader
u_RawSocketMixin._wait_until_writable.<locals>.callback
a_send_future
add_writer
remove_writer
a_closing
fileno
u_RawSocketMixin.aclose
a_raw_socket
socket
aSHUT_WR
uUNIXSocketStream.send_eof
recv
a_wait_until_readable
data
uUNIXSocketStream.receive
view
a_wait_until_writable
bytes_sent
uUNIXSocketStream.send
msglen
umsglen must be a non-negative integer
maxfds
umaxfds must be a positive integer
array
T wiarecvmsg
aCMSG_LEN
fds
itemsize
ancdata
aSOL_SOCKET
aSCM_RIGHTS
uReceived unexpected ancillary data; message =
u, cmsg_level =
u, cmsg_type =
frombytes
receive_fds
uUNIXSocketStream.receive_fds
umessage must not be empty
ufds must not be empty
filenos
aIOBase
wiasendmsg
fdarray
send_fds
uUNIXSocketStream.send_fds
a_TCPSocketListener__raw_socket
aBaseEventLoop
T uaccepting connections from
a_accept_guard
a_accept_scope
sock_accept
T EValueError
ENotImplementedError
client_sock
setsockopt
aIPPROTO_TCP
aTCP_NODELAY
connect_accepted_socket
aStreamProtocol
aSocketStream
accept
uTCPSocketListener.accept
uTCPSocketListener.aclose
a_UNIXSocketListener__raw_socket
setblocking
T FaUNIXSocketStream
uUNIXSocketListener.accept.<locals>.<lambda>
uUNIXSocketListener.accept
uUNIXSocketListener.aclose
uUDPSocket.aclose
uUDPSocket.receive
sendto
uUDPSocket.send
uConnectedUDPSocket.aclose
uConnectedUDPSocket.receive
uConnectedUDPSocket.send
recvfrom
T l   uUNIXDatagramSocket.receive
uUNIXDatagramSocket.send
uConnectedUNIXDatagramSocket.receive
uConnectedUNIXDatagramSocket.send
a_event
uEvent.wait
aEventStatistics
a_waiters
a_fast_acquire
a_owner_task
checkpoint_if_cancelled
release
uAttempted to acquire an already held Lock
acquire
uLock.acquire
aWouldBlock
uThe current task is not holding this lock
aAsyncIOTaskInfo
aLockStatistics
locked
T amax_value
a_value
a_max_value
uSemaphore.acquire
usemaphore released too many times
aSemaphoreStatistics
a_borrowers
aOrderedDict
a_wait_queue
total_tokens
uCapacityLimiter.__aenter__
uCapacityLimiter.__aexit__
a_total_tokens
isinf
utotal_tokens must be an int or math.inf
utotal_tokens must be >= 1
max
waiters_to_notify
popitem
T alast
acquire_on_behalf_of_nowait
uthis borrower is already holding one of this CapacityLimiter's tokens
acquire_on_behalf_of
uCapacityLimiter.acquire
borrower
pop
uCapacityLimiter.acquire_on_behalf_of
release_on_behalf_of
uthis borrower isn't holding any of this CapacityLimiter's tokens
aCapacityLimiterStatistics
borrowed_tokens
a_signals
a_signal_queue
a_handled_signals
add_signal_handler
a_deliver
remove_signal_handler
a__anext__
u_SignalReceiver.__anext__
T ucreated TaskInfo from a completed Task
get_name
weakref
ref
a_task
uvloop
aRunner
T adebug
loop_factory
a_runner
a_runner_task
get_loop
set_exception_handler
a_exception_handler
T aexception
default_exception_handler
uMultiple exceptions occurred in asynchronous callbacks
u_pytest.outcomes
T aOutcomeException
aOutcomeException
receive_stream
a_send_stream
retval
a_run_tests_and_fixtures
uTestRunner._run_tests_and_fixtures
create_memory_object_stream
aAwaitable
aAny
T l akwargs
send_nowait
a_call_in_runner_task
uTestRunner._call_in_runner_task
fixture_func
asend
a_raise_async_exceptions
uAsync generator fixture did not stop
run_asyncgen_fixture
uTestRunner.run_asyncgen_fixture
wraps
D areturn
aT_Retval
wrapper
uAsyncIOBackend.run.<locals>.wrapper
T adebug
nT aloop_factory
nT ause_uvloop
Faset_name
T nnuAsyncIOBackend.checkpoint
uAsyncIOBackend.checkpoint_if_cancelled
uAsyncIOBackend.cancel_shielded_checkpoint
delay
uAsyncIOBackend.sleep
T adeadline
shield
min
deadline
aTaskGroup
aLock
T afast_acquire
aSemaphore
T amax_value
fast_acquire
aCapacityLimiter
cls
a_threadpool_idle_workers
a_threadpool_workers
limiter
current_default_thread_limiter
abandon_on_cancel
aT_Retval
find_root_task
aWorkerThread
stop
now
aMAX_IDLE_TIME
remove_done_callback
sniffio
current_async_library_cvar
worker
run_sync_in_worker_thread
uAsyncIOBackend.run_sync_in_worker_thread
D ascope
return
aCancelScope
aT_Retval
task_wrapper
uAsyncIOBackend.run_async_from_thread.<locals>.task_wrapper
aAbstractEventLoop
run_coroutine_threadsafe
result
concurrent
futures
D areturn
aNone
uAsyncIOBackend.run_sync_from_thread.<locals>.wrapper
T aasyncio
wfaBlockingPortal
command
aPathLike
fspath
T Ostr
Obytes
create_subprocess_shell
stdin
stdout
stderr
create_subprocess_exec
aStreamWriterWrapper
aStreamReaderWrapper
aProcess
open_process
uAsyncIOBackend.open_process
D aname
uAnyIO process pool shutdown task
a_forcibly_shutdown_process_pool_on_exit
create_connection
host
port
local_address
T alocal_addr
connect_tcp
uAsyncIOBackend.connect_tcp
aAF_UNIX
raw_socket
connect
path
uAsyncIOBackend.connect_unix.<locals>.<lambda>
connect_unix
uAsyncIOBackend.connect_unix
aTCPSocketListener
aUNIXSocketListener
create_datagram_endpoint
aDatagramProtocol
remote_address
family
reuse_port
T alocal_addr
remote_addr
family
reuse_port
aUDPSocket
aConnectedUDPSocket
create_udp_socket
uAsyncIOBackend.create_udp_socket
remote_path
uAsyncIOBackend.create_unix_datagram_socket.<locals>.<lambda>
aConnectedUNIXDatagramSocket
aUNIXDatagramSocket
create_unix_datagram_socket
uAsyncIOBackend.create_unix_datagram_socket
getaddrinfo
type
proto
flags
T afamily
type
proto
flags
uAsyncIOBackend.getaddrinfo
getnameinfo
sockaddr
uAsyncIOBackend.getnameinfo
a_read_events
obj
read_events
aBusyResourceError
uanyio._core._asyncio_selector_thread
T aget_selector
get_selector
wait_readable
uAsyncIOBackend.wait_readable
a_write_events
write_events
wait_writable
uAsyncIOBackend.wait_writable
a_default_thread_limiter
T l(a_SignalReceiver
T f       ?await_all_tasks_blocked
uAsyncIOBackend.wait_all_tasks_blocked
aTestRunner
a__doc__
a__file__
has_location
a__cached__
a__annotations__
annotations
uconcurrent.futures
os
sys
T aAbstractEventLoop
aCancelledError
all_tasks
create_task
current_task
get_running_loop
sleep
uasyncio.base_events
T a_run_until_complete_cb
collections
T aOrderedDict
deque
ucollections.abc
T aAsyncGenerator
aAsyncIterator
aAwaitable
aCallable
aCollection
aCoroutine
aIterable
aSequence
aAsyncGenerator
aAsyncIterator
aCallable
aCollection
aCoroutine
aIterable
aSequence
T aFuture
contextlib
T aAbstractContextManager
suppress
aAbstractContextManager
T aContext
copy_context
aContext
dataclasses
T adataclass
dataclass
inspect
T aCORO_RUNNING
aCORO_SUSPENDED
getcoroutinestate
iscoroutine
T aQueue
T aSignals
aSignals
T aAddressFamily
aSocketKind
aAddressFamily
aSocketKind
T aThread
aCodeType
aTracebackType
aIO
aTYPE_CHECKING
aOptional
aTypeVar
T aWeakKeyDictionary
aWeakKeyDictionary
T aCapacityLimiterStatistics
aEventStatistics
aLockStatistics
aTaskInfo
abc
l aTaskInfo
abc
u_core._eventloop
T aclaim_worker_thread
threadlocals
u_core._exceptions
T aBrokenResourceError
aBusyResourceError
aClosedResourceError
aEndOfStream
aWouldBlock
iterate_exceptions
u_core._sockets
T aconvert_ipv6_sockaddr
u_core._streams
T acreate_memory_object_stream
u_core._synchronization
T aCapacityLimiter
aBaseCapacityLimiter
T aEvent
aBaseEvent
T aLock
aBaseLock
T aResourceGuard
aSemaphoreStatistics
T aSemaphore
aBaseSemaphore
u_core._tasks
T aCancelScope
aBaseCancelScope
T aAsyncBackend
aIPSockAddrType
aSocketListener
aUDPPacketType
aUNIXDatagramPacketType
aAsyncBackend
aIPSockAddrType
aSocketListener
aUDPPacketType
aUNIXDatagramPacketType
uabc._eventloop
T aStrOrBytesPath
aStrOrBytesPath
lowlevel
T aRunVar
aRunVar
ustreams.memory
T aMemoryObjectReceiveStream
aMemoryObjectSendStream
aMemoryObjectReceiveStream
aMemoryObjectSendStream
aFileDescriptorLike
aParamSpec
enum
T acoroutines
events
exceptions
tasks
exceptiongroup
T aBaseExceptionGroup
typing_extensions
T aTypeVarTuple
aUnpack
aTypeVarTuple
aUnpack
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uanyio._backends._asyncio
created
initialized
closed
a__orig_bases__
D adebug
loop_factory
nnD adebug
loop_factory
ubool | None
uCallable[[], AbstractEventLoop] | None
uRunner.__init__
D areturn
aRunner
uRunner.__enter__
D aexc_type
exc_val
exc_tb
return
utype[BaseException]
aBaseException
aTracebackType
aNone
uRunner.__exit__
uRunner.close
D areturn
aAbstractEventLoop
uRunner.get_loop
D acontext
nD acoro
return
uCoroutine[T_Retval]
aT_Retval
uRunner.run
uRunner._lazy_init
D amain_task
return
uasyncio.Task
aNone
uRunner._on_sigint
D aloop
return
aAbstractEventLoop
aNone
T aT_Retval
T aT_contra
tT acontravariant
aT_contra
T aPosArgsT
aPosArgsT
T wPwPT a_root_task
uRunVar[asyncio.Task | None]
D areturn
uasyncio.Task
D afunc
return
aCallable
str
a_run_vars
uWeakKeyDictionary[asyncio.AbstractEventLoop, Any]
D atask
return
uasyncio.Task
bool
D aexc
return
aCancelledError
bool
D adeadline
shield
return
float
bool
aCancelScope
uCancelScope.__new__
D adeadline
shield
float
bool
uCancelScope.__init__
D areturn
aCancelScope
uCancelScope.__enter__
D aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
bool
uCancelScope.__exit__
property
D areturn
bool
uCancelScope._effectively_cancelled
uCancelScope._parent_cancellation_is_visible_to_us
uCancelScope._timeout
D aorigin
return
aCancelScope
bool
uCancelScope._deliver_cancellation
uCancelScope._restart_cancellation_in_parent
uCancelScope.cancel
D areturn
float
uCancelScope.deadline
setter
D avalue
return
float
aNone
uCancelScope.cancel_called
cancelled_caught
uCancelScope.cancelled_caught
uCancelScope.shield
D avalue
return
bool
aNone

Encapsulates auxiliary task information that cannot be added to the Task instance
itself because there are no guarantees about its implementation.
T aparent_id
cancel_scope
a__weakref__
a__slots__
D aparent_id
cancel_scope
uint | None
uCancelScope | None
uTaskState.__init__
uWeakKeyDictionary[asyncio.Task, TaskState]
aTaskStatus
D afuture
parent_id
uasyncio.Future
int
u_AsyncioTaskStatus.__init__
D avalue
return
uT_contra | None
aNone
started
u_AsyncioTaskStatus.started
uTaskGroup.__init__
D areturn
aTaskGroup
D aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
ubool | None
D afunc
args
name
task_status_future
return
uCallable[[Unpack[PosArgsT]], Awaitable[Any]]
utuple[Unpack[PosArgsT]]
object
uasyncio.Future | None
uasyncio.Task
uTaskGroup._spawn
D aname
nD afunc
name
args
return
uCallable[[Unpack[PosArgsT]], Awaitable[Any]]
object
uUnpack[PosArgsT]
aNone
uTaskGroup.start_soon
D afunc
name
args
return
uCallable[..., Awaitable[Any]]
object
paAny
a_Retval_Queue_Type
l
D aroot_task
workers
idle_workers
uasyncio.Task
uset[WorkerThread]
udeque[WorkerThread]
uWorkerThread.__init__
D afuture
result
exc
return
uasyncio.Future
aAny
uBaseException | None
aNone
uWorkerThread._report_result
uWorkerThread.run
D wfareturn
uasyncio.Task | None
aNone
uWorkerThread.stop
T a_threadpool_idle_workers
uRunVar[deque[WorkerThread]]
T a_threadpool_workers
uRunVar[set[WorkerThread]]
D areturn
aBlockingPortal
uBlockingPortal.__new__
uBlockingPortal.__init__
D afunc
args
kwargs
name
future
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval] | T_Retval]
utuple[Unpack[PosArgsT]]
udict[str, Any]
object
uFuture[T_Retval]
aNone
a_spawn_task_from_thread
uBlockingPortal._spawn_task_from_thread
aByteReceiveStream
T aeq
uasyncio.StreamReader
D amax_bytes
return
int
bytes
aByteSendStream
uasyncio.StreamWriter
D aitem
return
bytes
aNone
uasyncio.subprocess.Process
uStreamWriterWrapper | None
uStreamReaderWrapper | None
D areturn
int
uProcess.terminate
uProcess.kill
D asignal
return
int
aNone
uProcess.send_signal
uProcess.pid
D areturn
uint | None
uProcess.returncode
D areturn
uabc.ByteSendStream | None
uProcess.stdin
D areturn
uabc.ByteReceiveStream | None
uProcess.stdout
uProcess.stderr
D aworkers
a_task
return
uset[Process]
object
aNone
D aworkers
return
uset[abc.Process]
aNone
aProtocol
udeque[bytes]
uasyncio.Event
uException | None
bool
D atransport
return
uasyncio.BaseTransport
aNone
connection_made
uStreamProtocol.connection_made
D aexc
return
uException | None
aNone
connection_lost
uStreamProtocol.connection_lost
D adata
return
bytes
aNone
data_received
uStreamProtocol.data_received
D areturn
ubool | None
eof_received
uStreamProtocol.eof_received
pause_writing
uStreamProtocol.pause_writing
resume_writing
uStreamProtocol.resume_writing
udeque[tuple[bytes, IPSockAddrType]]
uDatagramProtocol.connection_made
uDatagramProtocol.connection_lost
D adata
addr
return
bytes
aIPSockAddrType
aNone
datagram_received
uDatagramProtocol.datagram_received
D aexc
return
aException
aNone
error_received
uDatagramProtocol.error_received
uDatagramProtocol.pause_writing
uDatagramProtocol.resume_writing
D atransport
protocol
uasyncio.Transport
aStreamProtocol
uSocketStream.__init__
D areturn
usocket.socket
uSocketStream._raw_socket
a_RawSocketMixin
uasyncio.Future | None
D araw_socket
usocket.socket
u_RawSocketMixin.__init__
u_RawSocketMixin._raw_socket
D aloop
return
uasyncio.AbstractEventLoop
uasyncio.Future
u_RawSocketMixin._wait_until_readable
u_RawSocketMixin._wait_until_writable
D amsglen
maxfds
return
int
putuple[bytes, list[int]]
D amessage
fds
return
bytes
uCollection[int | IOBase]
aNone
uCancelScope | None
uTCPSocketListener.__init__
uTCPSocketListener._raw_socket
D areturn
uabc.SocketStream
uUNIXSocketListener.__init__
uUNIXSocketListener._raw_socket
D atransport
protocol
uasyncio.DatagramTransport
aDatagramProtocol
uUDPSocket.__init__
uUDPSocket._raw_socket
D areturn
utuple[bytes, IPSockAddrType]
D aitem
return
aUDPPacketType
aNone
uConnectedUDPSocket.__init__
uConnectedUDPSocket._raw_socket
D areturn
bytes
D areturn
aUNIXDatagramPacketType
D aitem
return
aUNIXDatagramPacketType
aNone
T aread_events
uRunVar[dict[int, asyncio.Event]]
T awrite_events
D areturn
aEvent
uEvent.__new__
uEvent.__init__
uEvent.set
uEvent.is_set
D areturn
aEventStatistics
statistics
uEvent.statistics
D afast_acquire
FD afast_acquire
return
bool
aLock
uLock.__new__
D afast_acquire
return
bool
aNone
uLock.__init__
acquire_nowait
uLock.acquire_nowait
uLock.locked
uLock.release
D areturn
aLockStatistics
uLock.statistics
D amax_value
fast_acquire
nFD ainitial_value
max_value
fast_acquire
return
int
uint | None
bool
aSemaphore
uSemaphore.__new__
D ainitial_value
max_value
fast_acquire
int
uint | None
bool
uSemaphore.__init__
uSemaphore.acquire_nowait
uSemaphore.release
value
uSemaphore.value
max_value
uSemaphore.max_value
D areturn
aSemaphoreStatistics
uSemaphore.statistics
float
D atotal_tokens
return
float
aCapacityLimiter
uCapacityLimiter.__new__
D atotal_tokens
float
uCapacityLimiter.__init__
D aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
aNone
uCapacityLimiter.total_tokens
uCapacityLimiter.borrowed_tokens
available_tokens
uCapacityLimiter.available_tokens
uCapacityLimiter.acquire_nowait
D aborrower
return
object
aNone
uCapacityLimiter.acquire_on_behalf_of_nowait
uCapacityLimiter.release
uCapacityLimiter.release_on_behalf_of
D areturn
aCapacityLimiterStatistics
uCapacityLimiter.statistics
T a_default_thread_limiter
uRunVar[CapacityLimiter]
D asignals
utuple[Signals, ...]
u_SignalReceiver.__init__
D asignum
return
aSignals
aNone
u_SignalReceiver._deliver
D areturn
a_SignalReceiver
u_SignalReceiver.__enter__
u_SignalReceiver.__exit__
a__aiter__
u_SignalReceiver.__aiter__
D areturn
aSignals
D atask
uasyncio.Task
uAsyncIOTaskInfo.__init__
has_pending_cancellation
uAsyncIOTaskInfo.has_pending_cancellation
uMemoryObjectSendStream[tuple[Awaitable[Any], asyncio.Future[Any]]]
D adebug
use_uvloop
loop_factory
nFnD adebug
use_uvloop
loop_factory
return
ubool | None
bool
uCallable[[], AbstractEventLoop] | None
aNone
uTestRunner.__init__
D areturn
aTestRunner
uTestRunner.__enter__
uTestRunner.__exit__
uTestRunner.get_loop
D aloop
context
return
uasyncio.AbstractEventLoop
udict[str, Any]
aNone
uTestRunner._exception_handler
uTestRunner._raise_async_exceptions
D areceive_stream
return
uMemoryObjectReceiveStream[tuple[Awaitable[T_Retval], asyncio.Future[T_Retval]]]
aNone
D afunc
args
kwargs
return
uCallable[P, Awaitable[T_Retval]]
uP.args
uP.kwargs
aT_Retval
D afixture_func
kwargs
return
uCallable[..., AsyncGenerator[T_Retval, Any]]
udict[str, Any]
uIterable[T_Retval]
D afixture_func
kwargs
return
uCallable[..., Coroutine[Any, Any, T_Retval]]
udict[str, Any]
aT_Retval
run_fixture
uTestRunner.run_fixture
D atest_func
kwargs
return
uCallable[..., Coroutine[Any, Any, Any]]
udict[str, Any]
aNone
run_test
uTestRunner.run_test
classmethod
D afunc
args
kwargs
options
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval]]
utuple[Unpack[PosArgsT]]
udict[str, Any]
udict[str, Any]
aT_Retval
uAsyncIOBackend.run
D areturn
object
current_token
uAsyncIOBackend.current_token
uAsyncIOBackend.current_time
D areturn
utype[BaseException]
cancelled_exception_class
uAsyncIOBackend.cancelled_exception_class
D adelay
return
float
aNone
create_cancel_scope
uAsyncIOBackend.create_cancel_scope
current_effective_deadline
uAsyncIOBackend.current_effective_deadline
D areturn
uabc.TaskGroup
create_task_group
uAsyncIOBackend.create_task_group
D areturn
uabc.Event
create_event
uAsyncIOBackend.create_event
D afast_acquire
return
bool
uabc.Lock
create_lock
uAsyncIOBackend.create_lock
D ainitial_value
max_value
fast_acquire
return
int
uint | None
bool
uabc.Semaphore
create_semaphore
uAsyncIOBackend.create_semaphore
D atotal_tokens
return
float
uabc.CapacityLimiter
create_capacity_limiter
uAsyncIOBackend.create_capacity_limiter
T FnD afunc
args
abandon_on_cancel
limiter
return
uCallable[[Unpack[PosArgsT]], T_Retval]
utuple[Unpack[PosArgsT]]
bool
uabc.CapacityLimiter | None
aT_Retval
check_cancelled
uAsyncIOBackend.check_cancelled
D afunc
args
token
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval]]
utuple[Unpack[PosArgsT]]
object
aT_Retval
run_async_from_thread
uAsyncIOBackend.run_async_from_thread
D afunc
args
token
return
uCallable[[Unpack[PosArgsT]], T_Retval]
utuple[Unpack[PosArgsT]]
object
aT_Retval
uAsyncIOBackend.run_sync_from_thread
D areturn
uabc.BlockingPortal
create_blocking_portal
uAsyncIOBackend.create_blocking_portal
D acommand
stdin
stdout
stderr
kwargs
return
uStrOrBytesPath | Sequence[StrOrBytesPath]
uint | IO[Any] | None
uint | IO[Any] | None
uint | IO[Any] | None
aAny
aProcess
setup_process_pool_exit_at_shutdown
uAsyncIOBackend.setup_process_pool_exit_at_shutdown
D ahost
port
local_address
return
str
int
uIPSockAddrType | None
uabc.SocketStream
D apath
return
ustr | bytes
uabc.UNIXSocketStream
D asock
return
usocket.socket
aSocketListener
create_tcp_listener
uAsyncIOBackend.create_tcp_listener
create_unix_listener
uAsyncIOBackend.create_unix_listener
D afamily
local_address
remote_address
reuse_port
return
aAddressFamily
uIPSockAddrType | None
uIPSockAddrType | None
bool
uUDPSocket | ConnectedUDPSocket
D araw_socket
remote_path
return
usocket.socket
ustr | bytes | None
uabc.UNIXDatagramSocket | abc.ConnectedUNIXDatagramSocket
D afamily
type
proto
flags
l
pppD ahost
port
family
type
proto
flags
return
ubytes | str | None
ustr | int | None
uint | AddressFamily
uint | SocketKind
int
pulist[tuple[AddressFamily, SocketKind, int, str, tuple[str, int] | tuple[str, int, int, int]]]
D asockaddr
flags
return
aIPSockAddrType
int
utuple[str, str]
D aobj
return
aFileDescriptorLike
aNone
D areturn
aCapacityLimiter
uAsyncIOBackend.current_default_thread_limiter
D asignals
return
aSignals
uAbstractContextManager[AsyncIterator[Signals]]
open_signal_receiver
uAsyncIOBackend.open_signal_receiver
D areturn
aTaskInfo
get_current_task
uAsyncIOBackend.get_current_task
D areturn
uSequence[TaskInfo]
get_running_tasks
uAsyncIOBackend.get_running_tasks
D aoptions
return
udict[str, Any]
aTestRunner
create_test_runner
uAsyncIOBackend.create_test_runner
backend_class
uanyio\_backends\_asyncio.py
T w_aloop
raw_socket
T aloop
raw_socket
T w_aself
T aself
u<module anyio._backends._asyncio>
T a__class__
T aself
exc_type
exc_val
exc_tb
T aself
exc_type
exc_val
exc_tb
loop
wait_scope
exc
T aself
host_task
task_state
T aself
sig
T aself
exc_type
exc_val
exc_tb
host_task_state
cannot_swallow_exc_val
exc
T aself
exc_type
exc_val
exc_tb
sig
T aself
task
task_state
parent_id
coro
a__class__
T aself
a__class__
T aself
deadline
shield
T aself
total_tokens
T aself
transport
protocol
T aself
fast_acquire
T aself
debug
loop_factory
T aself
initial_value
max_value
fast_acquire
a__class__
T aself
raw_socket
T aself
parent_id
cancel_scope
T aself
debug
use_uvloop
loop_factory
uvloop
T aself
root_task
workers
idle_workers
a__class__
T aself
future
parent_id
T aself
signals
T acls
T acls
deadline
shield
T acls
total_tokens
T acls
fast_acquire
T acls
initial_value
max_value
fast_acquire
T aself
func
args
kwargs
future
receive_stream
coro
T aloop
to_cancel
task
T aself
signum
T aself
origin
should_retry
current
task
waiter
scope
T afuture
ex
loop
T aloop
T aself
cancel_scope
T aself
loop
context
T aworkers
a_task
child_watcher
process
T aself
signum
frame
main_task
T aself
exceptions
T aself
future
result
exc
new_exc
T aself
scope
T aself
receive_stream
aOutcomeException
coro
future
retval
exc
T aloop
a_do_shutdown
future
thread
T aworkers
process
T aself
func
args
name
task_status_future
task_done
kwargs
parent_id
coro
prefix
loop
factory
closure
custom_task_constructor
task
T aself
func
args
kwargs
name
future
T atask
coro
T aself
loop
T aself
loop
callback
wfT aself
client_sock
a_addr
transport
protocol
T aself
wfaclient_sock
w_aexc
T aself
fut
task
item
T aself
fut
T aself
task
T aself
borrower
event
T aself
borrower
T wfaself
loop
T aloop
self
T acls
scope
T acls
task
cancel_scope
T acls
host
port
local_address
transport
protocol
T acls
path
wfaloop
raw_socket
T aself
exc
T aself
transport
T acls
sock
T acls
options
T acls
family
local_address
remote_address
reuse_port
transport
protocol
T acls
raw_socket
remote_path
wfaloop
T acls
limiter
T acls
task
cancel_scope
deadline
T aself
data
T aself
data
addr
T aself
value
T aroot_task
task
callbacks
cb
state
cancel_scope
T afunc
module
qualname
T acls
host
port
family
type
proto
flags
T acls
sockaddr
flags
T aself
task
task_state
cancel_scope
T aexc
T
cls
command
stdin
stdout
stderr
kwargs
process
stdin_stream
stdout_stream
stderr_stream
T acls
signals
T aself
packet
T aself
loop
data
exc
T aself
max_bytes
chunk
leftover
T aself
max_bytes
data
T aself
max_bytes
loop
data
exc
Taself
msglen
maxfds
loop
fds
message
ancdata
flags
addr
exc
cmsg_level
cmsg_type
cmsg_data
T aself
task
fut
T
cls
func
args
kwargs
options
wrapper
debug
loop_factory
uvloop
runner
T aself
coro
context
task
sigint_handler
uncancel
T
self
exception
item
context
func
args
future
cancel_scope
result
exc
T	acls
func
args
token
wfatask_wrapper
loop
context
wrapper
T aself
fixture_func
kwargs
fixturevalue
asyncgen
T aself
fixture_func
kwargs
retval
T acls
func
args
token
wfawrapper
loop
T acls
func
args
abandon_on_cancel
limiter
idle_workers
workers
scope
future
root_task
worker
now
expired_worker
context
worker_scope
T aself
test_func
kwargs
exc
T aself
item
T aself
item
loop
exc
T aself
item
exc
T aself
item
loop
view
bytes_sent
exc
T aself
message
fds
filenos
loop
fd
fdarray
exc
T aself
signal
T acls
workers
T acls
delay
T aself
func
name
args
future
task
T aself
func
name
args
T aself
value
task
T aself
task_info
T aself
wfT a_task
task_state
exc
weaself
task
task_status_future
T aself
task
task_status_future
T ascope
a__tracebackhide__
task
exc
func
args
T aargs
func
T aself
value
waiters_to_notify
event
T acls
this_task
task
waiter
T acls
obj
read_events
loop
event
get_selector
selector
remove_reader
T acls
obj
write_events
loop
event
get_selector
selector
remove_writer
T atask
func
args
T aexc
wfafunc
args
T aargs
wfafunc
a__spec__
.anyio._backends
'
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_anyio
u\not_existing
a_backends
T aNUITKA_PACKAGE_anyio__backends
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uanyio\_backends\__init__.py
u<module anyio._backends>

a__spec__
.anyio._core._asyncio_selector_thread
F
f
threading
aThread
run
uAnyIO socket selector
T atarget
name
a_thread
aDefaultSelector
a_selector
socket
socketpair
a_send
a_receive
setblocking
T Fasetsockopt
aSOL_SOCKET
aSO_RCVBUF
aSO_SNDBUF
aIPPROTO_TCP
aTCP_NODELAY
register
aEVENT_READ
a_closed
start
a_register_atexit
a_stop
a_notify_self
close
join
unregister
get_map
T uselector still has registered file descriptors after shutdown
send
T d
asyncio
get_running_loop
get_key
key
data
uthis file descriptor is already registered for reading
modify
events
aEVENT_WRITE
uthis file descriptor is already registered for writing
self
select
fileobj
recv
T l  aremove_reader
fd
call_soon_threadsafe
remove_writer
a_selector_lock
a__enter__
a__exit__
aSelector
T nnna__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
ucollections.abc
T aCallable
aCallable
selectors
T aEVENT_READ
aEVENT_WRITE
aDefaultSelector
aTYPE_CHECKING
aAny
aLock
uSelector | None
