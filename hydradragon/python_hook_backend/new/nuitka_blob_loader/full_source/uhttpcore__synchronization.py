# Reconstructed from integrated Nuitka blob
# Module: uhttpcore._synchronization


This is a standard lock.
In the sync case `Lock` provides thread locking.
In the async case `AsyncLock` provides async locking.
aAsyncLock
a__qualname__
D areturn
aNone
a__init__
uAsyncLock.__init__
uAsyncLock.setup
D areturn
aAsyncLock
D aexc_type
exc_value
traceback
return
utype[BaseException] | None
uBaseException | None
utypes.TracebackType | None
aNone

This is a threading-only lock for no-I/O contexts.
In the sync case `ThreadLock` provides thread locking.
In the async case `AsyncThreadLock` is a no-op.
aAsyncThreadLock
D areturn
aAsyncThreadLock
uAsyncThreadLock.__enter__
uAsyncThreadLock.__exit__
aAsyncEvent
uAsyncEvent.__init__
uAsyncEvent.setup
uAsyncEvent.set
T nD atimeout
return
ufloat | None
aNone
aAsyncSemaphore
D abound
return
int
aNone
uAsyncSemaphore.__init__
uAsyncSemaphore.setup
aAsyncShieldCancellation
uAsyncShieldCancellation.__init__
D areturn
aAsyncShieldCancellation
uAsyncShieldCancellation.__enter__
uAsyncShieldCancellation.__exit__
uLock.__init__
D areturn
aLock
uLock.__enter__
uLock.__exit__
aThreadLock
uThreadLock.__init__
D areturn
aThreadLock
uThreadLock.__enter__
uThreadLock.__exit__
uEvent.__init__
uEvent.set
uEvent.wait
uSemaphore.__init__
uSemaphore.acquire
uSemaphore.release
aShieldCancellation
D areturn
aShieldCancellation
uShieldCancellation.__enter__
uShieldCancellation.__exit__
uhttpcore\_synchronization.py
u<module httpcore._synchronization>
T aself
T aself
exc_type
exc_value
traceback
T aself
bound
T asniffio
environment
T aself
timeout
trio_exc_map
anyio_exc_map
timeout_or_inf
T aself
timeout
a__spec__
.httpcore._trace
K
name
logger
extensions
get
T atrace
trace_extension
isEnabledFor
logging
aDEBUG
debug
kwargs
return_value
should_trace
split
T w.aprefix

w.ainspect
iscoroutine
uIf you are using a synchronous interface, the callback of the `trace` extension should be a normal function instead of an asynchronous function.
w aitems
w=atrace
u.started
u.complete
exception
u.failed
self
info
uIf you're using an asynchronous interface, the callback of the `trace` extension should be an asynchronous function rather than a normal function.
atrace
uTrace.atrace
a__aenter__
uTrace.__aenter__
exc_value
a__aexit__
uTrace.__aexit__
a__doc__
a__file__
origin
has_location
a__cached__
annotations
types
typing
a_models
T aRequest
aRequest
