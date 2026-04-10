# Reconstructed from integrated Nuitka blob
# Module: a__value


startswith
T uanyio.abc.
uanyio.abc
uanyio\abc\__init__.py
u<module anyio.abc>
a__spec__
.anyio
+
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_anyio
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
annotations
u_core._eventloop
T acurrent_time
current_time
T aget_all_backends
get_all_backends
T aget_cancelled_exc_class
get_cancelled_exc_class
T arun
run
T asleep
sleep
T asleep_forever
sleep_forever
T asleep_until
sleep_until
u_core._exceptions
T aBrokenResourceError
aBrokenResourceError
T aBrokenWorkerIntepreter
aBrokenWorkerIntepreter
T aBrokenWorkerProcess
aBrokenWorkerProcess
T aBusyResourceError
aBusyResourceError
T aClosedResourceError
aClosedResourceError
T aDelimiterNotFound
aDelimiterNotFound
T aEndOfStream
aEndOfStream
T aIncompleteRead
aIncompleteRead
T aTypedAttributeLookupError
aTypedAttributeLookupError
T aWouldBlock
aWouldBlock
u_core._fileio
T aAsyncFile
aAsyncFile
T aPath
aPath
T aopen_file
open_file
T awrap_file
wrap_file
u_core._resources
T aaclose_forcefully
aclose_forcefully
u_core._signals
T aopen_signal_receiver
open_signal_receiver
u_core._sockets
T aconnect_tcp
connect_tcp
T aconnect_unix
connect_unix
T acreate_connected_udp_socket
create_connected_udp_socket
T acreate_connected_unix_datagram_socket
create_connected_unix_datagram_socket
T acreate_tcp_listener
create_tcp_listener
T acreate_udp_socket
create_udp_socket
T acreate_unix_datagram_socket
create_unix_datagram_socket
T acreate_unix_listener
create_unix_listener
T agetaddrinfo
getaddrinfo
T agetnameinfo
getnameinfo
T await_readable
wait_readable
T await_socket_readable
wait_socket_readable
T await_socket_writable
wait_socket_writable
T await_writable
wait_writable
u_core._streams
T acreate_memory_object_stream
create_memory_object_stream
u_core._subprocesses
T aopen_process
open_process
T arun_process
run_process
u_core._synchronization
T aCapacityLimiter
aCapacityLimiter
T aCapacityLimiterStatistics
aCapacityLimiterStatistics
T aCondition
aCondition
T aConditionStatistics
aConditionStatistics
T aEvent
aEvent
T aEventStatistics
aEventStatistics
T aLock
aLock
T aLockStatistics
aLockStatistics
T aResourceGuard
aResourceGuard
T aSemaphore
aSemaphore
T aSemaphoreStatistics
aSemaphoreStatistics
u_core._tasks
T aTASK_STATUS_IGNORED
aTASK_STATUS_IGNORED
T aCancelScope
aCancelScope
T acreate_task_group
create_task_group
T acurrent_effective_deadline
current_effective_deadline
T afail_after
fail_after
T amove_on_after
move_on_after
u_core._testing
T aTaskInfo
aTaskInfo
T aget_current_task
get_current_task
T aget_running_tasks
get_running_tasks
T await_all_tasks_blocked
wait_all_tasks_blocked
u_core._typedattr
T aTypedAttributeProvider
aTypedAttributeProvider
T aTypedAttributeSet
aTypedAttributeSet
T atyped_attribute
typed_attribute
values

startswith
T uanyio.
anyio
uanyio\__init__.py
u<module anyio>
a__spec__
.anyio.from_thread
b-
threadlocals
current_async_backend
current_token
uThis function can only be run from an AnyIO worker thread
run_async_from_thread
T atoken

Call a coroutine function from a worker thread.
:param func: a coroutine function
:param args: positional arguments for the callable
:return: the return value of the coroutine function
run_sync_from_thread

Call a function in the event loop thread from a worker thread.
:param func: a callable
:param args: positional arguments for the callable
:return: the return value of the callable
a_async_cm
a_portal
aEvent
self
a_exit_event
a__aenter__
a_enter_future
set_exception
set_result
wait
a__aexit__
a_exit_exc_info
run_async_cm
u_BlockingAsyncContextManager.run_async_cm
aFuture
start_task_soon
a_exit_future
result
call
set
a_future
get_async_backend
create_blocking_portal
get_ident
a_event_loop_thread_id
a_stop_event
create_task_group
a_task_group
get_cancelled_exc_class
a_cancelled_exc_class
uBlockingPortal.__aenter__
stop
exc_type
exc_val
exc_tb
uBlockingPortal.__aexit__
uThis portal is not running
uThis method cannot be called from the event loop thread
uSleep until :meth:`stop` is called.
sleep_until_stopped
uBlockingPortal.sleep_until_stopped

Signal the portal to shut down.
This marks the portal as no longer accepting new calls and exits from
:meth:`sleep_until_stopped`.
:param cancel_remaining: ``True`` to cancel all the remaining tasks, ``False``
to let them finish before returning
cancel_remaining
cancel_scope
cancel
uBlockingPortal.stop
D wfareturn
uFuture[T_Retval]
aNone
callback
uBlockingPortal._call_func.<locals>.callback
func
args
kwargs
isawaitable
aCancelScope
a__enter__
a__exit__
future
cancelled
add_done_callback
T nnnaset_running_or_notify_cancel
retval
a_call_func
uBlockingPortal._call_func
scope

Spawn a new task using the given callable.
Implementors must ensure that the future is resolved when the task finishes.
:param func: a callable
:param args: positional arguments to be passed to the callable
:param kwargs: keyword arguments to be passed to the callable
:param name: name of the task (will be coerced to a string if not ``None``)
:param future: a future that will resolve to the return value of the callable,
or the exception raised during its execution
cast
aT_Retval

Call the given function in the event loop thread.
If the callable returns a coroutine object, it is awaited on.
:param func: any callable
:raises RuntimeError: if the portal is not running or if this method is called
from within the event loop thread
a_check_running
a_spawn_task_from_thread

Start a task in the portal's task group.
The task will be run inside a cancel scope which can be cancelled by cancelling
the returned future.
:param func: the target function
:param args: positional arguments passed to ``func``
:param name: name of the task (will be coerced to a string if not ``None``)
:return: a future that resolves with the return value of the callable if the
task completes successfully, or with the exception raised in the task
:raises RuntimeError: if the portal is not running or if this method is called
from within the event loop thread
:rtype: concurrent.futures.Future[T_Retval]
.. versionadded:: 3.0
D afuture
return
uFuture[T_Retval]
aNone
task_done
uBlockingPortal.start_task.<locals>.task_done
a_BlockingPortalTaskStatus
task_status

Start a task in the portal's task group and wait until it signals for readiness.
This method works the same way as :meth:`.abc.TaskGroup.start`.
:param func: the target function
:param args: positional arguments passed to ``func``
:param name: name of the task (will be coerced to a string if not ``None``)
:return: a tuple of (future, task_status_value) where the ``task_status_value``
is the value passed to ``task_status.started()`` from within the target
function
:rtype: tuple[concurrent.futures.Future[T_Retval], Any]
.. versionadded:: 3.0
task_status_future
done
exception
uTask exited without calling task_status.started()
a_BlockingAsyncContextManager

Wrap an async context manager as a synchronous context manager via this portal.
Spawns a task that will call both ``__aenter__()`` and ``__aexit__()``, stopping
in the middle until the synchronous context manager exits.
:param cm: an asynchronous context manager
:return: a synchronous context manager
.. versionadded:: 2.1
a_lock
a_portal_cm
start_blocking_portal
backend
backend_options
a_leases

Start a new event loop in a new thread and run a blocking portal in its main task.
The parameters are the same as for :func:`~anyio.run`.
:param backend: name of the backend
:param backend_options: backend options
:return: a context manager that yields a blocking portal
.. versionchanged:: 3.0
Usage as a context manager is now required.
D areturn
aNone
run_portal
ustart_blocking_portal.<locals>.run_portal
run_blocking_portal
ustart_blocking_portal.<locals>.run_blocking_portal
aThread
T atarget
daemon
start
join
aBlockingPortal
a_eventloop
run
T abackend
backend_options
check_cancelled

Check if the cancel scope of the host task's running the current worker thread has
been cancelled.
If the host task's current cancel scope has indeed been cancelled, the
backend-specific cancellation exception will be raised.
:raises RuntimeError: if the current thread was not spawned by
:func:`.to_thread.run_sync`
a__doc__
a__file__
origin
has_location
a__cached__
annotations
sys
ucollections.abc
T aAwaitable
aCallable
aGenerator
aAwaitable
aCallable
aGenerator
uconcurrent.futures
T aFuture
contextlib
T aAbstractAsyncContextManager
aAbstractContextManager
contextmanager
aAbstractAsyncContextManager
aAbstractContextManager
contextmanager
dataclasses
T adataclass
field
dataclass
field
inspect
T aisawaitable
threading
T aLock
aThread
get_ident
aLock
aTracebackType
aAny
aGeneric
aTypeVar
overload
a_core
T a_eventloop
u_core._eventloop
T aget_async_backend
get_cancelled_exc_class
threadlocals
u_core._synchronization
T aEvent
u_core._tasks
T aCancelScope
create_task_group
abc
T aAsyncBackend
aAsyncBackend
uabc._tasks
T aTaskStatus
aTaskStatus
typing_extensions
T aTypeVarTuple
aUnpack
aTypeVarTuple
aUnpack
T aT_Retval
T aT_co
tT acovariant
aT_co
T aPosArgsT
aPosArgsT
D afunc
args
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval]]
uUnpack[PosArgsT]
aT_Retval
D afunc
args
return
uCallable[[Unpack[PosArgsT]], T_Retval]
uUnpack[PosArgsT]
aT_Retval
run_sync
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
