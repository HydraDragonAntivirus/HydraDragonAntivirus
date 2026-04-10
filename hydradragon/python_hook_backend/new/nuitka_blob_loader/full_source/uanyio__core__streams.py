# Reconstructed from integrated Nuitka blob
# Module: uanyio._core._streams


Create a memory object stream.
The stream's item type can be annotated like
:func:`create_memory_object_stream[T_Item]`.
:param max_buffer_size: number of items held in the buffer until ``send()`` starts
blocking
:param item_type: old way of marking the streams with the right generic type for
static typing (does nothing on AnyIO 4)
.. deprecated:: 4.0
Use ``create_memory_object_stream[YourItemType](...)`` instead.
:return: a tuple of (send stream, receive stream)
a__qualname__
T l
nD amax_buffer_size
item_type
return
float
object
utuple[MemoryObjectSendStream[T_Item], MemoryObjectReceiveStream[T_Item]]
a__new__
ucreate_memory_object_stream.__new__
a__orig_bases__
uanyio\_core\_streams.py
u<module anyio._core._streams>
T acls
max_buffer_size
item_type
state
T a__class__

a__spec__
.anyio._core._subprocesses
W

Run an external command in a subprocess and wait until it completes.
.. seealso:: :func:`subprocess.run`
:param command: either a string to pass to the shell, or an iterable of strings
containing the executable name or path and its arguments
:param input: bytes passed to the standard input of the subprocess
:param stdout: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`,
a file-like object, or `None`
:param stderr: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`,
:data:`subprocess.STDOUT`, a file-like object, or `None`
:param check: if ``True``, raise :exc:`~subprocess.CalledProcessError` if the
process terminates with a return code other than 0
:param cwd: If not ``None``, change the working directory to this before running the
command
:param env: if not ``None``, this mapping replaces the inherited environment
variables from the parent process
:param startupinfo: an instance of :class:`subprocess.STARTUPINFO` that can be used
to specify process startup parameters (Windows only)
:param creationflags: flags that can be used to control the creation of the
subprocess (see :class:`subprocess.Popen` for the specifics)
:param start_new_session: if ``true`` the setsid() system call will be made in the
child process prior to the execution of the subprocess. (POSIX only)
:param pass_fds: sequence of file descriptors to keep open between the parent and
child processes. (POSIX only)
:param user: effective user to run the process as (Python >= 3.9, POSIX only)
:param group: effective group to run the process as (Python >= 3.9, POSIX only)
:param extra_groups: supplementary groups to set in the subprocess (Python >= 3.9,
POSIX only)
:param umask: if not negative, this umask is applied in the child process before
running the given command (Python >= 3.9, POSIX only)
:return: an object representing the completed process
:raises ~subprocess.CalledProcessError: if ``check`` is ``True`` and the process
exits with a nonzero return code
D astream
index
return
uAsyncIterable[bytes]
int
aNone
drain_stream
urun_process.<locals>.drain_stream
open_process
command
input
aPIPE
aDEVNULL
stdout
stderr
cwd
env
startupinfo
creationflags
start_new_session
pass_fds
user
group
extra_groups
umask
Tastdin
stdout
stderr
cwd
env
startupinfo
creationflags
start_new_session
pass_fds
user
group
extra_groups
umask
a__aenter__
a__aexit__
create_task_group
start_soon
stdin
send
aclose
wait
T nnnacheck
returncode
aCalledProcessError
cast
aCompletedProcess
run_process
aBytesIO
stream
buffer
write
getvalue
stream_contents
index

Start an external command in a subprocess.
.. seealso:: :class:`subprocess.Popen`
:param command: either a string to pass to the shell, or an iterable of strings
containing the executable name or path and its arguments
:param stdin: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`, a
file-like object, or ``None``
:param stdout: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`,
a file-like object, or ``None``
:param stderr: one of :data:`subprocess.PIPE`, :data:`subprocess.DEVNULL`,
:data:`subprocess.STDOUT`, a file-like object, or ``None``
:param cwd: If not ``None``, the working directory is changed before executing
:param env: If env is not ``None``, it must be a mapping that defines the
environment variables for the new process
:param creationflags: flags that can be used to control the creation of the
subprocess (see :class:`subprocess.Popen` for the specifics)
:param startupinfo: an instance of :class:`subprocess.STARTUPINFO` that can be used
to specify process startup parameters (Windows only)
:param start_new_session: if ``true`` the setsid() system call will be made in the
child process prior to the execution of the subprocess. (POSIX only)
:param pass_fds: sequence of file descriptors to keep open between the parent and
child processes. (POSIX only)
:param user: effective user to run the process as (POSIX only)
:param group: effective group to run the process as (POSIX only)
:param extra_groups: supplementary groups to set in the subprocess (POSIX only)
:param umask: if not negative, this umask is applied in the child process before
running the given command (POSIX only)
:return: an asynchronous process object
get_async_backend
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
sys
ucollections.abc
T aAsyncIterable
aIterable
aMapping
aSequence
aAsyncIterable
aIterable
aMapping
aSequence
aPathLike
subprocess
T aDEVNULL
aPIPE
aCalledProcessError
aCompletedProcess
aIO
aAny
aUnion
abc
T aProcess
l aProcess
a_eventloop
T aget_async_backend
a_tasks
T acreate_task_group
aTypeAlias
T Ostr
Obytes
uPathLike[str]
uPathLike[bytes]
aStrOrBytesPath
D acommand
input
stdout
stderr
check
cwd
env
startupinfo
creationflags
start_new_session
pass_fds
user
group
extra_groups
umask
return
uStrOrBytesPath | Sequence[StrOrBytesPath]
ubytes | None
uint | IO[Any] | None
uint | IO[Any] | None
bool
uStrOrBytesPath | None
uMapping[str, str] | None
aAny
int
bool
uSequence[int]
ustr | int | None
ustr | int | None
uIterable[str | int] | None
int
uCompletedProcess[bytes]
D acommand
stdin
stdout
stderr
cwd
env
startupinfo
creationflags
start_new_session
pass_fds
user
group
extra_groups
umask
return
uStrOrBytesPath | Sequence[StrOrBytesPath]
uint | IO[Any] | None
uint | IO[Any] | None
uint | IO[Any] | None
uStrOrBytesPath | None
uMapping[str, str] | None
aAny
int
bool
uSequence[int]
ustr | int | None
ustr | int | None
uIterable[str | int] | None
int
aProcess
uanyio\_core\_subprocesses.py
u<module anyio._core._subprocesses>
T astream
index
buffer
chunk
stream_contents
T astream_contents
T acommand
stdin
stdout
stderr
cwd
env
startupinfo
creationflags
start_new_session
pass_fds
user
group
extra_groups
umask
kwargs
T acommand
input
stdout
stderr
check
cwd
env
startupinfo
creationflags
start_new_session
pass_fds
user
group
extra_groups
umask
stream_contents
drain_stream
process
tg
output
errors

a__spec__
.anyio._core._synchronization
?*
S aget_async_backend
create_event
aAsyncLibraryNotFoundError
aEventAdapter
uSet the flag, notifying all listeners.
uReturn ``True`` if the flag is set, ``False`` if not.

Wait until the flag has been set.
If the flag has already been set when this method is called, it returns
immediately.
wait
uEvent.wait
uReturn statistics about the current state of this event.
a__new__
a_internal_event
a_is_set
set
a_event
is_set
self
uEventAdapter.wait
aEventStatistics
T l
T atasks_waiting
statistics
create_lock
T afast_acquire
aLockAdapter
acquire
a__aenter__
uLock.__aenter__
release
a__aexit__
uLock.__aexit__
uAcquire the lock.
uLock.acquire

Acquire the lock, without blocking.
:raises ~anyio.WouldBlock: if the operation would block
uRelease the lock.
uReturn True if the lock is currently held.

Return statistics about the current state of this lock.
.. versionadded:: 3.0
a_fast_acquire
a_internal_lock
a_lock
uLockAdapter.__aenter__
uLockAdapter.__aexit__
uLockAdapter.acquire
acquire_nowait
locked
aLockStatistics
T Fnl

Return statistics about the current state of this lock.
.. versionadded:: 3.0
aLock
deque
a_waiters
uCondition.__aenter__
uCondition.__aexit__
a_owner_task
get_current_task
uThe current task is not holding the underlying lock
uAcquire the underlying lock.
uCondition.acquire

Acquire the underlying lock, without blocking.
:raises ~anyio.WouldBlock: if the operation would block
uRelease the underlying lock.
uReturn True if the lock is set.
a_check_acquired
popleft
uNotify exactly n listeners.
clear
uNotify all the listeners.
uWait for a notification.
checkpoint
aEvent
append
remove
aCancelScope
T tT ashield
a__enter__
a__exit__
T nnnuCondition.wait
aConditionStatistics

Return statistics about the current state of this condition.
.. versionadded:: 3.0
create_semaphore
T amax_value
fast_acquire
aSemaphoreAdapter
T amax_value
uinitial_value must be an integer
uinitial_value must be >= 0
umax_value must be an integer or None
umax_value must be equal to or higher than initial_value
uSemaphore.__aenter__
uSemaphore.__aexit__
uDecrement the semaphore value, blocking if necessary.
uSemaphore.acquire
uIncrement the semaphore value.
uThe current value of the semaphore.
uThe maximum value of the semaphore.

Return statistics about the current state of this semaphore.
.. versionadded:: 3.0
a__class__
a__init__
a_initial_value
a_max_value
a_internal_semaphore
a_semaphore
uSemaphoreAdapter.acquire
value
aSemaphoreStatistics
create_capacity_limiter
aCapacityLimiterAdapter
uCapacityLimiter.__aenter__
uCapacityLimiter.__aexit__

The total number of tokens available for borrowing.
This is a read-write property. If the total number of tokens is increased, the
proportionate number of tasks waiting on this limiter will be granted their
tokens.
.. versionchanged:: 3.0
The property is now writable.
uThe number of tokens that have currently been borrowed.
uThe number of tokens currently available to be borrowed

Acquire a token for the current task without waiting for one to become
vailable.
:raises ~anyio.WouldBlock: if there are no tokens available for borrowing

Acquire a token without waiting for one to become available.
:param borrower: the entity borrowing a token
:raises ~anyio.WouldBlock: if there are no tokens available for borrowing

Acquire a token for the current task, waiting if necessary for one to become
vailable.
uCapacityLimiter.acquire

Acquire a token, waiting if necessary for one to become available.
:param borrower: the entity borrowing a token
acquire_on_behalf_of
uCapacityLimiter.acquire_on_behalf_of

Release the token held by the current task.
:raises RuntimeError: if the current task has not borrowed a token from this
limiter.

Release the token held by the given borrower.
:raises RuntimeError: if the borrower has not borrowed a token from this
limiter.

Return statistics about the current state of this limiter.
.. versionadded:: 3.0
total_tokens
a_internal_limiter
a_total_tokens
a_limiter
uCapacityLimiterAdapter.__aenter__
exc_type
exc_val
exc_tb
uCapacityLimiterAdapter.__aexit__
math
inf
utotal_tokens must be an int or math.inf
utotal_tokens must be >= 1
borrowed_tokens
available_tokens
acquire_on_behalf_of_nowait
uCapacityLimiterAdapter.acquire
borrower
uCapacityLimiterAdapter.acquire_on_behalf_of
release_on_behalf_of
aCapacityLimiterStatistics
T aborrowed_tokens
total_tokens
borrowers
tasks_waiting
action
a_guarded
aBusyResourceError
a__doc__
a__file__
origin
has_location
a__cached__
annotations
collections
T adeque
dataclasses
T adataclass
dataclass
aTracebackType
sniffio
T aAsyncLibraryNotFoundError
lowlevel
T acheckpoint
l a_eventloop
T aget_async_backend
a_exceptions
T aBusyResourceError
a_tasks
T aCancelScope
a_testing
T aTaskInfo
get_current_task
aTaskInfo
T afrozen
