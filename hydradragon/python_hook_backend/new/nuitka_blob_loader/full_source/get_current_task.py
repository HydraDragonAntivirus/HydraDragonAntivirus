# Reconstructed from integrated Nuitka blob
# Module: get_current_task


w.a__qualname__
a_name
id
parent_id
name
coro
aTaskInfo
a__name__
u(id=
u, name=
w)aget_async_backend

Return the current task.
:return: a representation of the current task
cast
ulist[TaskInfo]
get_running_tasks

Return a list of running tasks in the current event loop.
:return: a list of task info objects
uWait until all other tasks are waiting for something.
wait_all_tasks_blocked
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ucollections.abc
T aAwaitable
aGenerator
aAwaitable
aGenerator
aAny
a_eventloop
T aget_async_backend
uanyio._core._testing

Represents an asynchronous task.
:ivar int id: the unique identifier of the task
:ivar parent_id: the identifier of the parent task, if any
:vartype parent_id: Optional[int]
:ivar str name: the description of the task (if any)
:ivar ~collections.abc.Coroutine coro: the coroutine object of the task
T a_name
id
parent_id
name
coro
a__slots__
D aid
parent_id
name
coro
int
uint | None
ustr | None
uGenerator[Any, Any, Any] | Awaitable[Any]
a__init__
uTaskInfo.__init__
D aother
return
object
bool
a__eq__
uTaskInfo.__eq__
D areturn
int
a__hash__
uTaskInfo.__hash__
D areturn
str
a__repr__
uTaskInfo.__repr__
D areturn
bool

Return ``True`` if the task has a cancellation pending, ``False`` otherwise.
has_pending_cancellation
uTaskInfo.has_pending_cancellation
D areturn
aTaskInfo
D areturn
ulist[TaskInfo]
D areturn
aNone
uanyio\_core\_testing.py
u<module anyio._core._testing>
T aself
other
T aself
T aself
id
parent_id
name
coro
func
a__spec__
.anyio._core._typedattr
U
>
uReturn a unique object, used to mark typed attributes.
a__annotations__
startswith
T w_uAttribute

u is missing its type annotation
a__class__
a__init_subclass__

A mapping of the extra attributes to callables that return the corresponding
values.
If the provider wraps another provider, the attributes from that wrapper should
lso be included in the returned mapping (but the wrapper may override the
callables from the wrapped instance).
extra_attributes
undefined
aTypedAttributeLookupError
T uAttribute not found

extra(attribute, default=undefined)
Return the value of the given typed extra attribute.
:param attribute: the attribute (member of a :class:`~TypedAttributeSet`) to
look for
:param default: the value that should be returned if no value is found for the
ttribute
:raises ~anyio.TypedAttributeLookupError: if the search failed and no default
value was given
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ucollections.abc
T aCallable
aMapping
aCallable
aMapping
aAny
aTypeVar
final
overload
a_exceptions
T aTypedAttributeLookupError
T aT_Attr
aT_Attr
T aT_Default
aT_Default
D areturn
aAny
typed_attribute
