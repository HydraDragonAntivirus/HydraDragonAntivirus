# Reconstructed from integrated Nuitka blob
# Module: uanyio.abc._subprocesses

uAn asynchronous version of :class:`subprocess.Popen`.
a__qualname__
D areturn
int
D areturn
aNone

Terminates the process, gracefully if possible.
On Windows, this calls ``TerminateProcess()``.
On POSIX systems, this sends ``SIGTERM`` to the process.
.. seealso:: :meth:`subprocess.Popen.terminate`
terminate
uProcess.terminate

Kills the process.
On Windows, this calls ``TerminateProcess()``.
On POSIX systems, this sends ``SIGKILL`` to the process.
.. seealso:: :meth:`subprocess.Popen.kill`
kill
uProcess.kill
D asignal
return
aSignals
aNone

Send a signal to the subprocess.
.. seealso:: :meth:`subprocess.Popen.send_signal`
:param signal: the signal number (e.g. :data:`signal.SIGHUP`)
send_signal
uProcess.send_signal
property
uThe process ID of the process.
pid
uProcess.pid
D areturn
uint | None

The return code of the process. If the process has not yet terminated, this will
be ``None``.
returncode
uProcess.returncode
D areturn
uByteSendStream | None
uThe stream for the standard input of the process.
stdin
uProcess.stdin
D areturn
uByteReceiveStream | None
uThe stream for the standard output of the process.
stdout
uProcess.stdout
uThe stream for the standard error output of the process.
stderr
uProcess.stderr
a__orig_bases__
uanyio\abc\_subprocesses.py
u<module anyio.abc._subprocesses>
T a__class__
T aself
T aself
signal

a__spec__
.anyio.abc._tasks
q
R

Start a new task and wait until it signals for readiness.
:param func: a coroutine function
:param args: positional arguments to call the function with
:param name: name of the task, for the purposes of introspection and debugging
:return: the value passed to ``task_status.started()``
:raises RuntimeError: if the task finishes without calling
``task_status.started()``
.. versionadded:: 3.0
start
uTaskGroup.start
uEnter the task group context and allow starting new tasks.
a__aenter__
uTaskGroup.__aenter__
uExit the task group context waiting for all tasks to finish.
a__aexit__
uTaskGroup.__aexit__
a__doc__
a__file__
origin
has_location
a__cached__
annotations
sys
abc
T aABCMeta
abstractmethod
aABCMeta
abstractmethod
ucollections.abc
T aAwaitable
aCallable
aAwaitable
aCallable
aTracebackType
aTYPE_CHECKING
aAny
aProtocol
aTypeVar
overload
typing_extensions
T aTypeVarTuple
aUnpack
aTypeVarTuple
aUnpack
T aT_Retval
aT_Retval
T aT_contra
tT acontravariant
aT_contra
T aPosArgsT
aPosArgsT
a__prepare__
aTaskStatus
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
