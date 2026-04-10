# Reconstructed from integrated Nuitka blob
# Module: uanyio.abc._tasks

a__qualname__
D aself
return
uTaskStatus[None]
aNone
started
uTaskStatus.started
D avalue
return
aT_contra
aNone
T nD avalue
return
uT_contra | None
aNone

Signal that the task has started.
:param value: object passed back to the starter of the task
a__orig_bases__
metaclass
T aTaskGroup
T

Groups several asynchronous tasks together.
:ivar cancel_scope: the cancel scope inherited by all child tasks
:vartype cancel_scope: CancelScope
.. note:: On asyncio, support for eager task factories is considered to be
**experimental**. In particular, they don't follow the usual semantics of new
tasks being scheduled on the next iteration of the event loop, and may thus
cause unexpected behavior in code that wasn't written with such semantics in
mind.
aTaskGroup
a__annotations__
aCancelScope
cancel_scope
D aname
nD afunc
name
args
return
uCallable[[Unpack[PosArgsT]], Awaitable[Any]]
object
uUnpack[PosArgsT]
aNone

Start a new task in this task group.
:param func: a coroutine function
:param args: positional arguments to call the function with
:param name: name of the task, for the purposes of introspection and debugging
.. versionadded:: 3.0
start_soon
uTaskGroup.start_soon
D afunc
name
args
return
uCallable[..., Awaitable[Any]]
object
paAny
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
uanyio\abc\_tasks.py
u<module anyio.abc._tasks>
T a__class__
T aself
T aself
exc_type
exc_val
exc_tb
T aself
func
name
args
T aself
value

a__spec__
.anyio.abc._testing
<
a__doc__
a__file__
origin
has_location
a__cached__
annotations
types
abc
T aABCMeta
abstractmethod
aABCMeta
abstractmethod
ucollections.abc
T aAsyncGenerator
aCallable
aCoroutine
aIterable
aAsyncGenerator
aCallable
aCoroutine
aIterable
aAny
aTypeVar
T a_T
a_T
metaclass
a__prepare__
T aTestRunner
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
