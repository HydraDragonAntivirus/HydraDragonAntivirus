# Reconstructed from integrated Nuitka blob
# Module: uanyio.streams.tls

uContains Transport Layer Security related attributes.
a__qualname__
a__annotations__
ustr | None
bytes
utuple[str, str, int]
uNone | dict[str, str | _PCTRTTT | _PCTRTT]
ubytes | None
bool
ulist[tuple[str, str, int]] | None
ussl.SSLObject
str
a__orig_bases__
T aeq

A stream wrapper that encrypts all sent data and decrypts received data.
This class has no public initializer; use :meth:`wrap` instead.
All extra attributes from :class:`~TLSAttribute` are supported.
:var AnyByteStream transport_stream: the wrapped stream
ussl.MemoryBIO
classmethod
D aserver_side
hostname
ssl_context
standard_compatible
nnntD atransport_stream
server_side
hostname
ssl_context
standard_compatible
return
aAnyByteStream
ubool | None
ustr | None
ussl.SSLContext | None
bool
aTLSStream
D afunc
args
return
uCallable[[Unpack[PosArgsT]], T_Retval]
uUnpack[PosArgsT]
aT_Retval
D areturn
utuple[AnyByteStream, bytes]
D areturn
aNone
T l   D amax_bytes
return
int
bytes
D aitem
return
bytes
aNone
property
D areturn
uMapping[Any, Callable[[], Any]]
uTLSStream.extra_attributes
aTLSListener

A convenience listener that wraps another listener and auto-negotiates a TLS session
on every accepted connection.
If the TLS handshake times out or raises an exception,
:meth:`handle_handshake_error` is called to do whatever post-mortem processing is
deemed necessary.
Supports only the :attr:`~TLSAttribute.standard_compatible` extra attribute.
:param Listener listener: the listener to wrap
:param ssl_context: the SSL context object
:param standard_compatible: a flag passed through to :meth:`TLSStream.wrap`
:param handshake_timeout: time limit for the TLS handshake
(passed to :func:`~anyio.fail_after`)
uListener[Any]
ussl.SSLContext
l afloat
staticmethod
D aexc
stream
return
aBaseException
aAnyByteStream
aNone
T nD ahandler
task_group
return
uCallable[[TLSStream], Any]
uTaskGroup | None
aNone
uTLSListener.extra_attributes
uanyio\streams\tls.py
T aself
u<module anyio.streams.tls>
T a__class__
T aself
func
args
result
data
exc
T aexc
stream
T astream
fail_after
wrapped_stream
exc
self
handler
T ahandler
self
T aself
max_bytes
data
T aself
item
T aself
tls_version
match
major
minor
T aself
handler
task_group
handler_wrapper
T acls
transport_stream
server_side
hostname
ssl_context
standard_compatible
purpose
bio_in
bio_out
ssl_object
wrapper
a__spec__
.anyio.to_thread
{
2

Call the given function with the given arguments in a worker thread.
If the ``cancellable`` option is enabled and the task waiting for its completion is
cancelled, the thread will still run its course but its return value (or any raised
exception) will be ignored.
:param func: a callable
:param args: positional arguments for the callable
:param abandon_on_cancel: ``True`` to abandon the thread (leaving it to run
unchecked on own) if the host task is cancelled, ``False`` to ignore
cancellations in the host task until the operation has completed in the worker
thread
:param cancellable: deprecated alias of ``abandon_on_cancel``; will override
``abandon_on_cancel`` if both parameters are passed
:param limiter: capacity limiter to use to limit the total amount of threads running
(if omitted, the default limiter is used)
:return: an awaitable that yields the return value of the function.
cancellable
warn
uThe `cancellable=` keyword argument to `anyio.to_thread.run_sync` is deprecated since AnyIO 4.1.0; use `abandon_on_cancel=` instead
aDeprecationWarning
D astacklevel
l aget_async_backend
run_sync_in_worker_thread
func
args
abandon_on_cancel
limiter
T aabandon_on_cancel
limiter
run_sync
current_default_thread_limiter

Return the capacity limiter that is used by default to limit the number of
concurrent threads.
:return: a capacity limiter object
a__doc__
a__file__
origin
has_location
a__cached__
annotations
sys
ucollections.abc
T aCallable
aCallable
aTypeVar
warnings
T awarn
u_core._eventloop
T aget_async_backend
abc
T aCapacityLimiter
aCapacityLimiter
typing_extensions
T aTypeVarTuple
aUnpack
aTypeVarTuple
aUnpack
T aT_Retval
aT_Retval
T aPosArgsT
aPosArgsT
D aabandon_on_cancel
cancellable
limiter
FnnD afunc
abandon_on_cancel
cancellable
limiter
args
return
uCallable[[Unpack[PosArgsT]], T_Retval]
bool
ubool | None
uCapacityLimiter | None
uUnpack[PosArgsT]
aT_Retval
D areturn
aCapacityLimiter
uanyio\to_thread.py
u<module anyio.to_thread>
T afunc
abandon_on_cancel
cancellable
limiter
args

a__spec__
.asn1crypto._errors
'
textwrap
dedent
find
T w
re
sub
u(?<=\S)
(?=[^
\d\*\-=])
w aoutput
strip

Takes a multi-line string and does the following:
- dedents
- converts newlines with text before and after into a single line
- strips leading and trailing whitespace
:param string:
The string to format
:param *params:
Params to interpolate into the string
:return:
The formatted string

Exports the following items:
- unwrap()
- APIException()
a__doc__
a__file__
origin
has_location
a__cached__
unicode_literals
division
absolute_import
print_function
T EException
a__prepare__
aAPIException
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
