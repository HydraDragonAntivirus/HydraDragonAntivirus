# Reconstructed from integrated Nuitka blob
# Module: uanyio.lowlevel

a_TokenWrapper
a__qualname__
T a_token
a__weakref__
a__slots__
object
a_token
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
auto
a__orig_bases__
T a_var
a_value
a_redeemed
D avar
value
uRunVar[T]
uT | Literal[_NoValueSet.NO_VALUE_SET]
a__init__
uRunvarToken.__init__

Like a :class:`~contextvars.ContextVar`, except scoped to the running event loop.
T a_name
a_default
uLiteral[_NoValueSet.NO_VALUE_SET]
set
uset[_TokenWrapper]
D aname
default
str
uT | Literal[_NoValueSet.NO_VALUE_SET]
uRunVar.__init__
property
D areturn
udict[str, T]
uRunVar._current_vars
D adefault
return
wDuT | D
uRunVar.get
D areturn
wTD adefault
return
uD | Literal[_NoValueSet.NO_VALUE_SET]
uT | D
D avalue
return
wTuRunvarToken[T]
uRunVar.set
D atoken
return
uRunvarToken[T]
aNone
reset
uRunVar.reset
D areturn
str
a__repr__
uRunVar.__repr__
uanyio\lowlevel.py
u<module anyio.lowlevel>
T a__class__
T aself
name
default
T aself
var
value
T aself
T aself
token
run_vars
T aself
default
T aself
token
T aself
value
current_vars
token
a__spec__
.anyio.streams
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_anyio
u\not_existing
streams
T aNUITKA_PACKAGE_anyio_streams
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uanyio\streams\__init__.py
u<module anyio.streams>

a__spec__
.anyio.streams.memory
item
a__name__

u(task_info=
task_info
u, item=
w)aMemoryObjectStreamStatistics
buffer
max_buffer_size
open_send_channels
open_receive_channels
waiting_senders
waiting_receivers
a_state
a_closed
aClosedResourceError
popitem
T FT alast
append
set
popleft
aEndOfStream
aWouldBlock

Receive the next item if it can be done without waiting.
:return: the received item
:raises ~anyio.ClosedResourceError: if this send stream has been closed
:raises ~anyio.EndOfStream: if the buffer is empty and this stream has been
closed from the sending end
:raises ~anyio.WouldBlock: if there are no items in the buffer and no tasks
waiting to send
checkpoint
self
receive_nowait
aEvent
aMemoryObjectItemReceiver
aT_co
wait
pop
receive
uMemoryObjectReceiveStream.receive
aMemoryObjectReceiveStream
T a_state

Create a clone of this receive stream.
Each clone can be closed separately. Only when all clones have been closed will
the receiving end of the memory stream be considered closed by the sending ends.
:return: the cloned stream
keys

Close the stream.
This works the exact same way as :meth:`aclose`, but is provided as a special
case for the benefit of synchronous callbacks.
close
aclose
uMemoryObjectReceiveStream.aclose
statistics

Return statistics about the current state of this stream.
.. versionadded:: 3.0
warnings
warn
uUnclosed <
u at
wxw>aResourceWarning
T asource
aBrokenResourceError
has_pending_cancellation

Send an item immediately if it can be done without waiting.
:param item: the item to send
:raises ~anyio.ClosedResourceError: if this send stream has been closed
:raises ~anyio.BrokenResourceError: if the stream has been closed from the
receiving end
:raises ~anyio.WouldBlock: if the buffer is full and there are no tasks waiting
to receive

Send an item to the stream.
If the buffer is full, this method blocks until there is again room in the
buffer or the item can be sent directly to a receiver.
:param item: the item to send
:raises ~anyio.ClosedResourceError: if this send stream has been closed
:raises ~anyio.BrokenResourceError: if the stream has been closed from the
receiving end
send_nowait
send
uMemoryObjectSendStream.send
aMemoryObjectSendStream

Create a clone of this send stream.
Each clone can be closed separately. Only when all clones have been closed will
the sending end of the memory stream be considered closed by the receiving ends.
:return: the cloned stream
clear
uMemoryObjectSendStream.aclose
a__doc__
a__file__
origin
has_location
a__cached__
annotations
collections
T aOrderedDict
deque
aOrderedDict
deque
dataclasses
T adataclass
field
dataclass
field
aTracebackType
aGeneric
aNamedTuple
aTypeVar
T aBrokenResourceError
aClosedResourceError
aEndOfStream
aWouldBlock
l u_core._testing
T aTaskInfo
get_current_task
aTaskInfo
get_current_task
abc
T aEvent
aObjectReceiveStream
aObjectSendStream
aObjectReceiveStream
aObjectSendStream
lowlevel
T acheckpoint
T aT_Item
aT_Item
T aT_co
tT acovariant
T aT_contra
tT acontravariant
aT_contra
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
