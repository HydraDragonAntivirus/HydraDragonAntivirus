# Reconstructed from integrated Nuitka blob
# Module: uanyio._core._asyncio_selector_thread

a__qualname__
D areturn
aNone
a__init__
uSelector.__init__
uSelector.start
uSelector._stop
uSelector._notify_self
D afd
callback
return
aFileDescriptorLike
uCallable[[], Any]
aNone
add_reader
uSelector.add_reader
add_writer
uSelector.add_writer
D afd
return
aFileDescriptorLike
bool
uSelector.remove_reader
uSelector.remove_writer
uSelector.run
D areturn
aSelector
get_selector
uanyio\_core\_asyncio_selector_thread.py
u<module anyio._core._asyncio_selector_thread>
T aself
T aself
fd
callback
loop
key
T aself
fd
key
new_events
T aself
key
events
loop
callback

a__spec__
.anyio._core._eventloop
]
sniffio
current_async_library
aAsyncLibraryNotFoundError
uAlready running
asynclib_name

u in this thread
get_async_backend
uNo such backend:
current_async_library_cvar
get
T naset
run
reset

Run the given coroutine function in an asynchronous event loop.
The current thread must not be already running an event loop.
:param func: a coroutine function
:param args: positional arguments to ``func``
:param backend: name of the asynchronous event loop implementation     currently
either ``asyncio`` or ``trio``
:param backend_options: keyword arguments to call the backend ``run()``
implementation with (documented :ref:`here <backend options>`)
:return: the return value of the coroutine function
:raises RuntimeError: if an asynchronous event loop is already running in this
thread
:raises LookupError: if the named backend is not found

Pause the current task for the specified duration.
:param delay: the duration, in seconds
sleep
delay

Pause the current task until it's cancelled.
This is a shortcut for ``sleep(math.inf)``.
.. versionadded:: 3.1
math
inf
sleep_forever

Pause the current task until the given time.
:param deadline: the absolute time to wake up at (according to the internal
monotonic clock of the event loop)
.. versionadded:: 3.1
current_time
max
deadline
sleep_until

Return the current value of the event loop's internal clock.
:return: the clock value (seconds)
aBACKENDS
uReturn a tuple of the names of all built-in backends.
cancelled_exception_class
uReturn the current async library's cancellation exception class.
backend_class
threadlocals
current_async_backend
token
current_token
claim_worker_thread
loaded_backends
uanyio._backends._
import_module
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
sys
threading
ucollections.abc
T aAwaitable
aCallable
aGenerator
aAwaitable
aCallable
aGenerator
contextlib
T acontextmanager
contextmanager
aTYPE_CHECKING
aAny
aTypeVar
typing_extensions
T aTypeVarTuple
aUnpack
aTypeVarTuple
aUnpack
T aasyncio
trio
T aT_Retval
aT_Retval
T aPosArgsT
aPosArgsT
local
udict[str, type[AsyncBackend]]
D abackend
backend_options
asyncio
nD afunc
backend
backend_options
args
return
uCallable[[Unpack[PosArgsT]], Awaitable[T_Retval]]
str
udict[str, Any] | None
uUnpack[PosArgsT]
aT_Retval
D adelay
return
float
aNone
D areturn
aNone
D adeadline
return
float
aNone
D areturn
float
D areturn
utuple[str, ...]
get_all_backends
D areturn
utype[BaseException]
get_cancelled_exc_class
D abackend_class
token
return
utype[AsyncBackend]
object
uGenerator[Any, None, None]
D aasynclib_name
return
ustr | None
utype[AsyncBackend]
uanyio\_core\_eventloop.py
u<module anyio._core._eventloop>
T abackend_class
token
T aasynclib_name
module
T afunc
backend
backend_options
args
asynclib_name
async_backend
exc
token
T adelay
T adeadline
now
a__spec__
.anyio._core._exceptions
Y
formatted
type
msg
a__name__

u:
a__class__
a__init__
excinfo
errdisplay
a__str__
dedent


Uncaught in the interpreter:
uAnother task is already
u this resource
uThe delimiter was not found among the first
u bytes
T uThe stream was closed before the read operation could be completed
exception
aBaseExceptionGroup
exceptions
iterate_exceptions
a__doc__
a__file__
origin
has_location
a__cached__
annotations
sys
ucollections.abc
T aGenerator
aGenerator
textwrap
T adedent
aAny
exceptiongroup
T aBaseExceptionGroup
T EException
a__prepare__
aBrokenResourceError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
