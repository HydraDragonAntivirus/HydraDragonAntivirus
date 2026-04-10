# Reconstructed from integrated Nuitka blob
# Module: uanyio.abc._eventloop

aAsyncBackend
a__qualname__
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

Run the given coroutine function in an asynchronous event loop.
The current thread must not be already running an event loop.
:param func: a coroutine function
:param args: positional arguments to ``func``
:param kwargs: positional arguments to ``func``
:param options: keyword arguments to call the backend ``run()`` implementation
with
:return: the return value of the coroutine function
run
uAsyncBackend.run
D areturn
object

:return:
current_token
uAsyncBackend.current_token
D areturn
float

Return the current value of the event loop's internal clock.
:return: the clock value (seconds)
current_time
uAsyncBackend.current_time
D areturn
utype[BaseException]
uReturn the exception class that is raised in a task if it's cancelled.
cancelled_exception_class
uAsyncBackend.cancelled_exception_class
D areturn
aNone
D adelay
return
float
aNone
deadline
shield
D adeadline
shield
return
float
bool
aCancelScope
uAsyncBackend.create_cancel_scope

Return the nearest deadline among all the cancel scopes effective for the
current task.
:return:
- a clock value from the event loop's internal clock
- ``inf`` if there is no deadline in effect
- ``-inf`` if the current scope has been cancelled
:rtype: float
uAsyncBackend.current_effective_deadline
D areturn
aTaskGroup
create_task_group
uAsyncBackend.create_task_group
D areturn
aEvent
create_event
uAsyncBackend.create_event
D afast_acquire
return
bool
aLock
create_lock
uAsyncBackend.create_lock
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
create_semaphore
uAsyncBackend.create_semaphore
D atotal_tokens
return
float
aCapacityLimiter
create_capacity_limiter
uAsyncBackend.create_capacity_limiter
T FnD afunc
args
abandon_on_cancel
limiter
return
uCallable[[Unpack[PosArgsT]], T_Retval]
utuple[Unpack[PosArgsT]]
bool
uCapacityLimiter | None
aT_Retval
check_cancelled
uAsyncBackend.check_cancelled
D afunc
args
token
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval]]
utuple[Unpack[PosArgsT]]
object
aT_Retval
run_async_from_thread
uAsyncBackend.run_async_from_thread
D afunc
args
token
return
uCallable[[Unpack[PosArgsT]], T_Retval]
utuple[Unpack[PosArgsT]]
object
aT_Retval
run_sync_from_thread
uAsyncBackend.run_sync_from_thread
D areturn
aBlockingPortal
create_blocking_portal
uAsyncBackend.create_blocking_portal
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
D aworkers
return
uset[Process]
aNone
setup_process_pool_exit_at_shutdown
uAsyncBackend.setup_process_pool_exit_at_shutdown
T nD ahost
port
local_address
return
str
int
uIPSockAddrType | None
aSocketStream
D apath
return
ustr | bytes
aUNIXSocketStream
D asock
return
socket
aSocketListener
create_tcp_listener
uAsyncBackend.create_tcp_listener
create_unix_listener
uAsyncBackend.create_unix_listener
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
socket
aNone
aUNIXDatagramSocket
D araw_socket
remote_path
return
socket
ustr | bytes
aConnectedUNIXDatagramSocket
D araw_socket
remote_path
return
socket
ustr | bytes | None
uUNIXDatagramSocket | ConnectedUNIXDatagramSocket
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
uHasFileno | int
aNone
D areturn
aCapacityLimiter
current_default_thread_limiter
uAsyncBackend.current_default_thread_limiter
D asignals
return
aSignals
uAbstractContextManager[AsyncIterator[Signals]]
open_signal_receiver
uAsyncBackend.open_signal_receiver
D areturn
aTaskInfo
get_current_task
uAsyncBackend.get_current_task
D areturn
uSequence[TaskInfo]
get_running_tasks
uAsyncBackend.get_running_tasks
D aoptions
return
udict[str, Any]
aTestRunner
create_test_runner
uAsyncBackend.create_test_runner
uanyio\abc\_eventloop.py
u<module anyio.abc._eventloop>
T a__class__
T acls
T acls
host
port
local_address
T acls
path
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
T acls
sock
T acls
options
T acls
family
local_address
remote_address
reuse_port
T acls
raw_socket
remote_path
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
T acls
command
stdin
stdout
stderr
kwargs
T acls
signals
T acls
func
args
kwargs
options
T acls
func
args
token
T acls
func
args
abandon_on_cancel
limiter
T acls
workers
T acls
delay
T acls
obj

a__spec__
.anyio.abc._resources
-
self
a__aenter__
uAsyncResource.__aenter__
aclose
a__aexit__
uAsyncResource.__aexit__
uClose the resource.
uAsyncResource.aclose
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
T aABCMeta
abstractmethod
aABCMeta
abstractmethod
aTracebackType
aTypeVar
T wTwTametaclass
a__prepare__
T aAsyncResource
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
