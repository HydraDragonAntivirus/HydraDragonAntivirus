# Reconstructed from integrated Nuitka blob
# Module: uanyio._core._typedattr


Superclass for typed attribute collections.
Checks that every public attribute of every subclass has a type annotation.
aTypedAttributeSet
a__qualname__
D areturn
aNone
uTypedAttributeSet.__init_subclass__
uBase class for classes that wish to provide typed extra attributes.
aTypedAttributeProvider
D areturn
uMapping[T_Attr, Callable[[], T_Attr]]
uTypedAttributeProvider.extra_attributes
D aattribute
return
aT_Attr
paextra
uTypedAttributeProvider.extra
D aattribute
default
return
aT_Attr
aT_Default
uT_Attr | T_Default
D aattribute
default
return
aAny
object
puanyio\_core\_typedattr.py
u<module anyio._core._typedattr>
T a__class__
T acls
annotations
attrname
a__class__
T aself
attribute
T aself
attribute
default
T aself
attribute
default
getter
T aself
a__spec__
.anyio._core
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_anyio
u\not_existing
a_core
T aNUITKA_PACKAGE_anyio__core
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uanyio\_core\__init__.py
u<module anyio._core>

a__spec__
.anyio.abc._eventloop
6

Check if the task has been cancelled, and allow rescheduling of other tasks.
This is effectively the same as running :meth:`checkpoint_if_cancelled` and then
:meth:`cancel_shielded_checkpoint`.
checkpoint
uAsyncBackend.checkpoint

Check if the current task group has been cancelled.
This will check if the task has been cancelled, but will not allow other tasks
to be scheduled if not.
cls
current_effective_deadline
math
inf
checkpoint_if_cancelled
uAsyncBackend.checkpoint_if_cancelled

Allow the rescheduling of other tasks.
This will give other tasks the opportunity to run, but without checking if the
current task group has been cancelled, unlike with :meth:`checkpoint`.
create_cancel_scope
T tT ashield
a__enter__
a__exit__
sleep
T l
T nnnacancel_shielded_checkpoint
uAsyncBackend.cancel_shielded_checkpoint

Pause the current task for the specified duration.
:param delay: the duration, in seconds
uAsyncBackend.sleep
run_sync_in_worker_thread
uAsyncBackend.run_sync_in_worker_thread
open_process
uAsyncBackend.open_process
connect_tcp
uAsyncBackend.connect_tcp
connect_unix
uAsyncBackend.connect_unix
create_udp_socket
uAsyncBackend.create_udp_socket
create_unix_datagram_socket
uAsyncBackend.create_unix_datagram_socket
getaddrinfo
uAsyncBackend.getaddrinfo
getnameinfo
uAsyncBackend.getnameinfo
wait_readable
uAsyncBackend.wait_readable
wait_writable
uAsyncBackend.wait_writable
wait_all_tasks_blocked
uAsyncBackend.wait_all_tasks_blocked
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
sys
abc
T aABCMeta
abstractmethod
aABCMeta
abstractmethod
ucollections.abc
T aAsyncIterator
aAwaitable
aCallable
aSequence
aAsyncIterator
aAwaitable
aCallable
aSequence
contextlib
T aAbstractContextManager
aAbstractContextManager
aPathLike
signal
T aSignals
aSignals
socket
T aAddressFamily
aSocketKind
socket
aAddressFamily
aSocketKind
aIO
aTYPE_CHECKING
aAny
aTypeVar
aUnion
overload
typing_extensions
T aTypeVarTuple
aUnpack
aTypeVarTuple
aUnpack
aTypeAlias
T aT_Retval
aT_Retval
T aPosArgsT
aPosArgsT
T Ostr
Obytes
uPathLike[str]
uPathLike[bytes]
aStrOrBytesPath
metaclass
a__prepare__
T aAsyncBackend
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
