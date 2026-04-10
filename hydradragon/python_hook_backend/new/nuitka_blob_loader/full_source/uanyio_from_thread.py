# Reconstructed from integrated Nuitka blob
# Module: uanyio.from_thread

a__qualname__
a__annotations__
uFuture[T_co]
uFuture[bool | None]
utuple[type[BaseException] | None, BaseException | None, TracebackType | None]
D aasync_cm
portal
uAbstractAsyncContextManager[T_co]
aBlockingPortal
a__init__
u_BlockingAsyncContextManager.__init__
D areturn
ubool | None
D areturn
aT_co
u_BlockingAsyncContextManager.__enter__
D a_BlockingAsyncContextManager__exc_type
a_BlockingAsyncContextManager__exc_value
a_BlockingAsyncContextManager__traceback
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
ubool | None
u_BlockingAsyncContextManager.__exit__
a__orig_bases__
D afuture
aFuture
u_BlockingPortalTaskStatus.__init__
T nD avalue
return
object
aNone
started
u_BlockingPortalTaskStatus.started
uAn object that lets external threads run code in an asynchronous event loop.
D areturn
aBlockingPortal
a__new__
uBlockingPortal.__new__
uBlockingPortal.__init__
D aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
ubool | None
uBlockingPortal._check_running
T FD acancel_remaining
return
bool
aNone
D afunc
args
kwargs
future
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval] | T_Retval]
utuple[Unpack[PosArgsT]]
udict[str, Any]
uFuture[T_Retval]
aNone
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
uBlockingPortal._spawn_task_from_thread
uBlockingPortal.call
D afunc
args
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval] | T_Retval]
uUnpack[PosArgsT]
aT_Retval
D aname
nD afunc
name
args
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval]]
object
uUnpack[PosArgsT]
uFuture[T_Retval]
uBlockingPortal.start_task_soon
D afunc
name
args
return
uCallable[[Unpack[PosArgsT]], T_Retval]
object
uUnpack[PosArgsT]
uFuture[T_Retval]
D afunc
name
args
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval] | T_Retval]
object
uUnpack[PosArgsT]
uFuture[T_Retval]
D afunc
name
args
return
uCallable[..., Awaitable[T_Retval]]
object
putuple[Future[T_Retval], Any]
start_task
uBlockingPortal.start_task
D acm
return
uAbstractAsyncContextManager[T_co]
uAbstractContextManager[T_co]
wrap_async_context_manager
uBlockingPortal.wrap_async_context_manager

A manager for a blocking portal. Used as a context manager. The first thread to
enter this context manager causes a blocking portal to be started with the specific
parameters, and the last thread to exit causes the portal to be shut down. Thus,
there will be exactly one blocking portal running in this context as long as at
least one thread has entered this context manager.
The parameters are the same as for :func:`~anyio.run`.
:param backend: name of the backend
:param backend_options: backend options
.. versionadded:: 4.4
aBlockingPortalProvider
asyncio
str
udict[str, Any] | None
T ainit
default_factory
T Fl
T ainit
default
int
T ainit
T FnuAbstractContextManager[BlockingPortal] | None
uBlockingPortalProvider.__enter__
D aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
aNone
uBlockingPortalProvider.__exit__
T aasyncio
nD abackend
backend_options
return
str
udict[str, Any] | None
uGenerator[BlockingPortal, Any, None]
uanyio\from_thread.py
u<module anyio.from_thread>
T a__class__
T aself
T aself
exc_type
exc_val
exc_tb
T aself
exc_type
exc_val
exc_tb
portal_cm
T aself
a_BlockingAsyncContextManager__exc_type
a_BlockingAsyncContextManager__exc_value
a_BlockingAsyncContextManager__traceback
T aself
async_cm
portal
T aself
future
T acls
T
self
func
args
kwargs
future
callback
retval_or_awaitable
scope
retval
exc
T aself
func
args
kwargs
name
future
T aself
func
args
T wfaself
scope
T ascope
self
T aasync_backend
T afunc
args
async_backend
token
T aself
value
exc
result
T aexc
future
run_portal
backend
backend_options
T abackend
backend_options
future
run_portal
T aportal_
future
T afuture
T abackend
backend_options
future
run_portal
run_blocking_portal
thread
cancel_remaining_tasks
portal
T aself
func
name
args
task_status_future
wfatask_done
task_status
T aself
func
name
args
T aself
func
name
args
wfT aself
value
T aself
cancel_remaining
T afuture
exc
task_status_future
T atask_status_future
T aself
cm

a__spec__
.anyio.lowlevel
q

Check for cancellation and allow the scheduler to switch to another task.
Equivalent to (but more efficient than)::
wait checkpoint_if_cancelled()
wait cancel_shielded_checkpoint()
.. versionadded:: 3.0
get_async_backend
checkpoint

Enter a checkpoint if the enclosing cancel scope has been cancelled.
This does not allow the scheduler to switch to a different task.
.. versionadded:: 3.0
checkpoint_if_cancelled

Allow the scheduler to switch to another task but without checking for cancellation.
Equivalent to (but potentially more efficient than)::
with CancelScope(shield=True):
wait checkpoint()
.. versionadded:: 3.0
cancel_shielded_checkpoint
current_token

Return a backend specific token object that can be used to get back to the event
loop.
a_var
a_value
a_redeemed
a_name
a_default
a_run_vars
a_current_vars
aRunVar
aNO_VALUE_SET
uRun variable "

u" has no value and no default set
aRunvarToken
get
uThis token does not belong to this RunVar
uThis token has already been used
a_NoValueSet
u<RunVar name=
w>a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
enum
dataclasses
T adataclass
dataclass
aAny
aGeneric
aLiteral
aTypeVar
overload
weakref
T aWeakKeyDictionary
aWeakKeyDictionary
u_core._eventloop
T aget_async_backend
T wTwTT wDwDD areturn
aNone
D areturn
object
uWeakKeyDictionary[Any, dict[str, Any]]
a_token_wrappers
udict[Any, _TokenWrapper]
T tT afrozen
