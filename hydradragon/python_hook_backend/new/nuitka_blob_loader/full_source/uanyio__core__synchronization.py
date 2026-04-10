# Reconstructed from integrated Nuitka blob
# Module: uanyio._core._synchronization


:ivar int tasks_waiting: number of tasks waiting on :meth:`~.Event.wait`
a__qualname__
a__annotations__
int
tasks_waiting

:ivar int borrowed_tokens: number of tokens currently borrowed by tasks
:ivar float total_tokens: total number of available tokens
:ivar tuple borrowers: tasks or other objects currently holding tokens borrowed from
this limiter
:ivar int tasks_waiting: number of tasks waiting on
:meth:`~.CapacityLimiter.acquire` or
:meth:`~.CapacityLimiter.acquire_on_behalf_of`
float
utuple[object, ...]
borrowers

:ivar bool locked: flag indicating if this lock is locked or not
:ivar ~anyio.TaskInfo owner: task currently holding the lock (or ``None`` if the
lock is not held by any task)
:ivar int tasks_waiting: number of tasks waiting on :meth:`~.Lock.acquire`
bool
uTaskInfo | None
owner

:ivar int tasks_waiting: number of tasks blocked on :meth:`~.Condition.wait`
:ivar ~anyio.LockStatistics lock_statistics: statistics of the underlying
:class:`~.Lock`
lock_statistics

:ivar int tasks_waiting: number of tasks waiting on :meth:`~.Semaphore.acquire`
D areturn
aEvent
uEvent.__new__
D areturn
aNone
uEvent.set
D areturn
bool
uEvent.is_set
D areturn
aEventStatistics
uEvent.statistics
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uEvent | None
D areturn
aEventAdapter
uEventAdapter.__new__
property
uEventAdapter._event
uEventAdapter.set
uEventAdapter.is_set
uEventAdapter.statistics
a__orig_bases__
D afast_acquire
FD afast_acquire
return
bool
aLock
uLock.__new__
D aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
aNone
uLock.acquire_nowait
uLock.release
uLock.locked
D areturn
aLockStatistics
uLock.statistics
uLock | None
D afast_acquire
return
bool
aLockAdapter
uLockAdapter.__new__
D afast_acquire
bool
uLockAdapter.__init__
D areturn
aLock
uLockAdapter._lock
uLockAdapter.acquire_nowait
uLockAdapter.release
uLockAdapter.locked
uLockAdapter.statistics
aCondition
T nD alock
uLock | None
uCondition.__init__
uCondition._check_acquired
uCondition.acquire_nowait
uCondition.release
uCondition.locked
T l D wnareturn
int
aNone
notify
uCondition.notify
notify_all
uCondition.notify_all
D areturn
aConditionStatistics
uCondition.statistics
aSemaphore
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
D areturn
aSemaphore
uSemaphore.acquire_nowait
uSemaphore.release
D areturn
int
uSemaphore.value
D areturn
uint | None
max_value
uSemaphore.max_value
D areturn
aSemaphoreStatistics
uSemaphore.statistics
uSemaphore | None
D ainitial_value
max_value
fast_acquire
return
int
uint | None
bool
aSemaphoreAdapter
uSemaphoreAdapter.__new__
D ainitial_value
max_value
fast_acquire
return
int
uint | None
bool
aNone
uSemaphoreAdapter.__init__
uSemaphoreAdapter._semaphore
uSemaphoreAdapter.acquire_nowait
uSemaphoreAdapter.release
uSemaphoreAdapter.value
uSemaphoreAdapter.max_value
uSemaphoreAdapter.statistics
aCapacityLimiter
D atotal_tokens
return
float
aCapacityLimiter
uCapacityLimiter.__new__
D aexc_type
exc_val
exc_tb
return
utype[BaseException] | None
uBaseException | None
uTracebackType | None
ubool | None
D areturn
float
uCapacityLimiter.total_tokens
setter
D avalue
return
float
aNone
uCapacityLimiter.borrowed_tokens
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
uCapacityLimiter | None
D atotal_tokens
return
float
aCapacityLimiterAdapter
uCapacityLimiterAdapter.__new__
D atotal_tokens
return
float
aNone
uCapacityLimiterAdapter.__init__
D areturn
aCapacityLimiter
uCapacityLimiterAdapter._limiter
uCapacityLimiterAdapter.total_tokens
uCapacityLimiterAdapter.borrowed_tokens
uCapacityLimiterAdapter.available_tokens
uCapacityLimiterAdapter.acquire_nowait
uCapacityLimiterAdapter.acquire_on_behalf_of_nowait
uCapacityLimiterAdapter.release
uCapacityLimiterAdapter.release_on_behalf_of
uCapacityLimiterAdapter.statistics

A context manager for ensuring that a resource is only used by a single task at a
time.
Entering this context manager while the previous has not exited it yet will trigger
:exc:`BusyResourceError`.
:param action: the action to guard against (visible in the :exc:`BusyResourceError`
when triggered, e.g. "Another task is already {action} this resource")
.. versionadded:: 4.1
aResourceGuard
T aaction
a_guarded
a__slots__
T ausing
D aaction
str
uResourceGuard.__init__
uResourceGuard.__enter__
uResourceGuard.__exit__
uanyio\_core\_synchronization.py
u<module anyio._core._synchronization>
T a__class__
T aself
T aself
exc_type
exc_val
exc_tb
T aself
total_tokens
T aself
lock
T aself
fast_acquire
T aself
action
T aself
initial_value
max_value
fast_acquire
T aself
initial_value
max_value
fast_acquire
a__class__
T acls
total_tokens
T acls
T acls
fast_acquire
T acls
initial_value
max_value
fast_acquire
T aself
borrower
T aself
wnw_aevent
T aself
event
T aself
value

a__spec__
.anyio._core._tasks
?
c
get_async_backend
create_cancel_scope
T ashield
deadline
uCancel this scope immediately.

The time (clock value) when this scope is cancelled automatically.
Will be ``float('inf')`` if no timeout has been set.
u``True`` if :meth:`cancel` has been called.

``True`` if this scope suppressed a cancellation exception it itself raised.
This is typically used to check if any work was interrupted, or to see if the
scope was cancelled due to its deadline being reached. The value will, however,
only be ``True`` if the cancellation was triggered by the scope itself (and not
n outer scope).

``True`` if this scope is shielded from external cancellation.
While a scope is shielded, it will not receive cancellations from outside.

Create a context manager which raises a :class:`TimeoutError` if does not finish in
time.
:param delay: maximum allowed time (in seconds) before raising the exception, or
``None`` to disable the timeout
:param shield: ``True`` to shield the cancel scope from external cancellation
:return: a context manager that yields a cancel scope
:rtype: :class:`~typing.ContextManager`\[:class:`~anyio.CancelScope`\]
current_time
delay
math
inf
shield
T adeadline
shield
a__enter__
a__exit__
T nnnacancelled_caught
deadline
fail_after

Create a cancel scope with a deadline that expires after the given delay.
:param delay: maximum allowed time (in seconds) before exiting the context block, or
``None`` to disable the timeout
:param shield: ``True`` to shield the cancel scope from external cancellation
:return: a cancel scope
current_effective_deadline

Return the nearest deadline among all the cancel scopes effective for the current
task.
:return: a clock value from the event loop's internal clock (or ``float('inf')`` if
there is no deadline in effect, or ``float('-inf')`` if the current scope has
been cancelled)
:rtype: float
create_task_group

Create a task group.
:return: a task group
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ucollections.abc
T aGenerator
aGenerator
contextlib
T acontextmanager
contextmanager
aTracebackType
uabc._tasks
T aTaskGroup
aTaskStatus
l aTaskGroup
aTaskStatus
a_eventloop
T aget_async_backend
a__prepare__
a_IgnoredTaskStatus
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
