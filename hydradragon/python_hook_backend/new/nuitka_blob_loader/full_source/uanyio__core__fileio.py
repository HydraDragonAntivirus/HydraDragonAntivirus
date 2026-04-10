# Reconstructed from integrated Nuitka blob
# Module: uanyio._core._fileio


An asynchronous file object.
This class wraps a standard file object and provides async friendly versions of the
following blocking methods (where available on the original file object):
* read
* read1
* readline
* readlines
* readinto
* readinto1
* write
* writelines
* truncate
* seek
* tell
* flush
All other methods are directly passed through.
This class supports the asynchronous context manager protocol which closes the
underlying file at the end of the context block.
This class also supports asynchronous iteration::
sync with await open_file(...) as f:
sync for line in f:
print(line)
a__qualname__
D afp
return
uIO[AnyStr]
aNone
a__init__
uAsyncFile.__init__
D aname
return
str
object
a__getattr__
uAsyncFile.__getattr__
property
D areturn
uIO[AnyStr]
wrapped
uAsyncFile.wrapped
D areturn
uAsyncIterator[AnyStr]
D areturn
aNone
T q D asize
return
int
aAnyStr
D aself
size
return
uAsyncFile[bytes]
int
bytes
D areturn
aAnyStr
D areturn
ulist[AnyStr]
D aself
wbareturn
uAsyncFile[bytes]
aWriteableBuffer
int
D aself
wbareturn
uAsyncFile[bytes]
aReadableBuffer
int
D aself
wbareturn
uAsyncFile[str]
str
int
D wbareturn
uReadableBuffer | str
int
D aself
lines
return
uAsyncFile[bytes]
uIterable[ReadableBuffer]
aNone
D aself
lines
return
uAsyncFile[str]
uIterable[str]
aNone
D alines
return
uIterable[ReadableBuffer] | Iterable[str]
aNone
T nD asize
return
uint | None
int
aSEEK_SET
D aoffset
whence
return
int
uint | None
int
a__orig_bases__
T Q
Q
Q
Q
Q
Q
D	afile
mode
buffering
encoding
errors
newline
closefd
opener
return
ustr | PathLike[str] | int
aOpenBinaryMode
int
ustr | None
ustr | None
ustr | None
bool
uCallable[[str, int], int] | None
uAsyncFile[bytes]
T Q
Q
Q
Q
Q
Q
Q
D	afile
mode
buffering
encoding
errors
newline
closefd
opener
return
ustr | PathLike[str] | int
aOpenTextMode
int
ustr | None
ustr | None
ustr | None
bool
uCallable[[str, int], int] | None
uAsyncFile[str]
T wrq nnntnD	afile
mode
buffering
encoding
errors
newline
closefd
opener
return
ustr | PathLike[str] | int
str
int
ustr | None
ustr | None
ustr | None
bool
uCallable[[str, int], int] | None
uAsyncFile[Any]
D afile
return
uIO[AnyStr]
uAsyncFile[AnyStr]
wrap_file
T FT aeq
a__annotations__
uIterator[PathLike[str]]
D areturn
aPath

An asynchronous version of :class:`pathlib.Path`.
This class cannot be substituted for :class:`pathlib.Path` or
:class:`pathlib.PurePath`, but it is compatible with the :class:`os.PathLike`
interface.
It implements the Python 3.10 version of :class:`pathlib.Path` interface, except for
the deprecated :meth:`~pathlib.Path.link_to` method.
Some methods may be unavailable or have limited functionality, based on the Python
version:
* :meth:`~pathlib.Path.copy` (available on Python 3.14 or later)
* :meth:`~pathlib.Path.copy_into` (available on Python 3.14 or later)
* :meth:`~pathlib.Path.from_uri` (available on Python 3.13 or later)
* :meth:`~pathlib.Path.full_match` (available on Python 3.13 or later)
* :meth:`~pathlib.Path.is_junction` (available on Python 3.12 or later)
* :meth:`~pathlib.Path.match` (the ``case_sensitive`` paramater is only available on
Python 3.13 or later)
* :meth:`~pathlib.Path.move` (available on Python 3.14 or later)
* :meth:`~pathlib.Path.move_into` (available on Python 3.14 or later)
* :meth:`~pathlib.Path.relative_to` (the ``walk_up`` parameter is only available on
Python 3.12 or later)
* :meth:`~pathlib.Path.walk` (available on Python 3.12 or later)
Any methods that do disk I/O need to be awaited on. These methods are:
* :meth:`~pathlib.Path.absolute`
* :meth:`~pathlib.Path.chmod`
* :meth:`~pathlib.Path.cwd`
* :meth:`~pathlib.Path.exists`
* :meth:`~pathlib.Path.expanduser`
* :meth:`~pathlib.Path.group`
* :meth:`~pathlib.Path.hardlink_to`
* :meth:`~pathlib.Path.home`
* :meth:`~pathlib.Path.is_block_device`
* :meth:`~pathlib.Path.is_char_device`
* :meth:`~pathlib.Path.is_dir`
* :meth:`~pathlib.Path.is_fifo`
* :meth:`~pathlib.Path.is_file`
* :meth:`~pathlib.Path.is_junction`
* :meth:`~pathlib.Path.is_mount`
* :meth:`~pathlib.Path.is_socket`
* :meth:`~pathlib.Path.is_symlink`
* :meth:`~pathlib.Path.lchmod`
* :meth:`~pathlib.Path.lstat`
* :meth:`~pathlib.Path.mkdir`
* :meth:`~pathlib.Path.open`
* :meth:`~pathlib.Path.owner`
* :meth:`~pathlib.Path.read_bytes`
* :meth:`~pathlib.Path.read_text`
* :meth:`~pathlib.Path.readlink`
* :meth:`~pathlib.Path.rename`
* :meth:`~pathlib.Path.replace`
* :meth:`~pathlib.Path.resolve`
* :meth:`~pathlib.Path.rmdir`
* :meth:`~pathlib.Path.samefile`
* :meth:`~pathlib.Path.stat`
* :meth:`~pathlib.Path.symlink_to`
* :meth:`~pathlib.Path.touch`
* :meth:`~pathlib.Path.unlink`
* :meth:`~pathlib.Path.walk`
* :meth:`~pathlib.Path.write_bytes`
* :meth:`~pathlib.Path.write_text`
Additionally, the following methods return an async iterator yielding
:class:`~.Path` objects:
* :meth:`~pathlib.Path.glob`
* :meth:`~pathlib.Path.iterdir`
* :meth:`~pathlib.Path.rglob`
T a_path
a__weakref__
a__slots__
a__weakref__
D aargs
return
ustr | PathLike[str]
aNone
uPath.__init__
D areturn
str
uPath.__fspath__
uPath.__str__
a__repr__
uPath.__repr__
D areturn
bytes
uPath.__bytes__
uPath.__hash__
D aother
return
object
bool
uPath.__eq__
D aother
return
upathlib.PurePath | Path
bool
uPath.__lt__
uPath.__le__
uPath.__gt__
uPath.__ge__
D aother
return
ustr | PathLike[str]
aPath
a__truediv__
uPath.__truediv__
a__rtruediv__
uPath.__rtruediv__
D areturn
utuple[str, ...]
uPath.parts
uPath.drive
uPath.root
uPath.anchor
D areturn
uSequence[Path]
uPath.parents
uPath.parent
uPath.name
uPath.suffix
D areturn
ulist[str]
uPath.suffixes
uPath.stem
uPath.as_posix
uPath.as_uri
D apath_pattern
return
str
bool
uPath.match
D aother
return
ustr | PathLike[str]
bool
is_relative_to
uPath.is_relative_to
D afollow_symlinks
tD amode
follow_symlinks
return
int
bool
aNone
D areturn
bool
D apattern
return
str
uAsyncIterator[Path]
uPath.glob
D atarget
return
ustr | bytes | PathLike[str] | PathLike[bytes]
aNone
uPath.is_absolute
uPath.is_reserved
D areturn
uAsyncIterator[Path]
uPath.iterdir
D aargs
return
ustr | PathLike[str]
aPath
uPath.joinpath
D amode
return
int
aNone
D areturn
uos.stat_result
T l  FpD amode
parents
exist_ok
return
int
bool
paNone
T Q
Q
Q
Q
D amode
buffering
encoding
errors
newline
return
aOpenBinaryMode
int
ustr | None
ustr | None
ustr | None
uAsyncFile[bytes]
T Q
Q
Q
Q
Q
D amode
buffering
encoding
errors
newline
return
aOpenTextMode
int
ustr | None
ustr | None
ustr | None
uAsyncFile[str]
T wrq nnnD amode
buffering
encoding
errors
newline
return
str
int
ustr | None
ustr | None
ustr | None
uAsyncFile[Any]
T nnD aencoding
errors
return
ustr | None
ustr | None
str
uPath.relative_to
D atarget
return
ustr | pathlib.PurePath | Path
aPath
D astrict
return
bool
aPath
uPath.rglob
D aother_path
return
ustr | PathLike[str]
bool
D afollow_symlinks
return
bool
uos.stat_result
D atarget
target_is_directory
return
ustr | bytes | PathLike[str] | PathLike[bytes]
bool
aNone
T l  tD amode
exist_ok
return
int
bool
aNone
D amissing_ok
return
bool
aNone
D aname
return
str
aPath
uPath.with_name
D astem
return
str
aPath
with_stem
uPath.with_stem
D asuffix
return
str
aPath
uPath.with_suffix
D apathsegments
return
ustr | PathLike[str]
aPath
with_segments
uPath.with_segments
D adata
return
bytes
int
D adata
encoding
errors
newline
return
str
ustr | None
ustr | None
ustr | None
int
register
uanyio\_core\_fileio.py
T a.0
wpu<module anyio._core._fileio>
T a__class__
T aself
line
T aself
nextval
T aself
T aself
other
target
T aself
name
T aself
fp
T aself
args
T aself
other
T aself
path
T aself
mode
follow_symlinks
func
T acls
path
T aself
pattern
gen
T aself
target
T acls
home_path
T aself
gen
T aself
mode
T aself
path_pattern
T aself
mode
parents
exist_ok
T aself
mode
buffering
encoding
errors
newline
T aself
mode
buffering
encoding
errors
newline
fp
T afile
mode
buffering
encoding
errors
newline
closefd
opener
T	afile
mode
buffering
encoding
errors
newline
closefd
opener
fp
T aself
size
T aself
encoding
errors
T aself
wbT aself
strict
func
T aself
other_path
T aself
offset
whence
T aself
follow_symlinks
func
T aself
target
target_is_directory
T afp
self
encoding
errors
newline
data
T adata
encoding
errors
newline
self
T aself
mode
exist_ok
T aself
missing_ok
T aself
pathsegments
T aself
stem
T aself
suffix
T afile
T aself
data
T aself
data
encoding
errors
newline
sync_write_text
T aself
lines
a__spec__
.anyio._core._resources

Close an asynchronous resource in a cancelled scope.
Doing this closes the resource without waiting on anything.
:param resource: the resource to close
aCancelScope
a__enter__
a__exit__
cancel
resource
aclose
T nnnaaclose_forcefully
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
T aAsyncResource
l aAsyncResource
a_tasks
T aCancelScope
D aresource
return
aAsyncResource
aNone
uanyio\_core\_resources.py
u<module anyio._core._resources>
T aresource
scope

a__spec__
.anyio._core._signals
get_async_backend
open_signal_receiver

Start receiving operating system signals.
:param signals: signals to receive (e.g. ``signal.SIGINT``)
:return: an asynchronous context manager for an asynchronous iterator which yields
signal numbers
.. warning:: Windows does not support signals natively so it is best to avoid
relying on this in cross-platform applications.
.. warning:: On asyncio, this permanently replaces any previous signal handler for
the given signals, as set via :meth:`~asyncio.loop.add_signal_handler`.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ucollections.abc
T aAsyncIterator
aAsyncIterator
contextlib
T aAbstractContextManager
aAbstractContextManager
signal
T aSignals
aSignals
a_eventloop
T aget_async_backend
D asignals
return
aSignals
uAbstractContextManager[AsyncIterator[Signals]]
uanyio\_core\_signals.py
u<module anyio._core._signals>
T asignals

a__spec__
.anyio._core._sockets
%H
connect_tcp

Connect to a host using the TCP protocol.
This function implements the stateless version of the Happy Eyeballs algorithm (RFC
6555). If ``remote_host`` is a host name that resolves to multiple IP addresses,
each one is tried until one connection attempt succeeds. If the first attempt does
not connected within 250 milliseconds, a second attempt is started using the next
ddress in the list, and so on. On IPv6 enabled systems, an IPv6 address (if
vailable) is tried first.
When the connection has been established, a TLS handshake will be done if either
``ssl_context`` or ``tls_hostname`` is not ``None``, or if ``tls`` is ``True``.
:param remote_host: the IP address or host name to connect to
:param remote_port: port on the target host to connect to
:param local_host: the interface address or name to bind the socket to before
connecting
:param tls: ``True`` to do a TLS handshake with the connected stream and return a
:class:`~anyio.streams.tls.TLSStream` instead
:param ssl_context: the SSL context object to use (if omitted, a default context is
created)
:param tls_standard_compatible: If ``True``, performs the TLS shutdown handshake
before closing the stream and requires that the server does this as well.
Otherwise, :exc:`~ssl.SSLEOFError` may be raised during reads from the stream.
Some protocols, such as HTTP, require this option to be ``False``.
See :meth:`~ssl.SSLContext.wrap_socket` for details.
:param tls_hostname: host name to check the server certificate against (defaults to
the value of ``remote_host``)
:param happy_eyeballs_delay: delay (in seconds) before starting the next connection
ttempt
:return: a socket stream object if no TLS handshake was done, otherwise a TLS stream
:raises OSError: if the connection attempt fails
D aremote_host
event
return
str
aEvent
aNone
try_connect
uconnect_tcp.<locals>.try_connect
get_async_backend
socket
aAF_UNSPEC
local_host
getaddrinfo
unot enough values to unpack (expected at least 2, got %d)
remote_host
ip_address
aIPv6Address
aAF_INET6
compressed
aAF_INET
remote_port
aSOCK_STREAM
T afamily
type
v6_found
target_addrs
v4_found
create_task_group
a__aenter__
a__aexit__
aEvent
tg
start_soon
move_on_after
happy_eyeballs_delay
a__enter__
a__exit__
wait
T nnnaconnected_stream
aExceptionGroup
umultiple connection attempts failed
uAll connection attempts failed
tls
tls_hostname
ssl_context
aTLSStream
wrap
tls_standard_compatible
T aserver_side
hostname
ssl_context
standard_compatible
aclose_forcefully
asynclib
local_address
oserrors
append
cancel_scope
cancel
aclose
event
set

Connect to the given UNIX socket.
Not available on Windows.
:param path: path to the socket
:return: a socket stream object
fspath
path
connect_unix

Create a TCP socket listener.
:param local_port: port number to listen on
:param local_host: IP address of the interface to listen on. If omitted, listen on
ll IPv4 and IPv6 interfaces. To listen on all interfaces on a specific address
family, use ``0.0.0.0`` for IPv4 or ``::`` for IPv6.
:param family: address family (used if ``local_host`` was omitted)
:param backlog: maximum number of queued incoming connections (up to a maximum of
2**16, or 65536)
:param reuse_port: ``True`` to allow multiple sockets to bind to the same
ddress/port (not supported on Windows)
:return: a list of listener objects
min
backlog
l   alocal_port
family
aSocketKind
aAI_PASSIVE
aAI_ADDRCONFIG
T afamily
type
flags
sorted
unot enough values to unpack (expected at least 3, got %d)
setblocking
T Fasetsockopt
aSOL_SOCKET
aSO_EXCLUSIVEADDRUSE
reuse_port
aSO_REUSEPORT
aIPPROTO_IPV6
aIPV6_V6ONLY
w%asplit
T w%l abind
listen
create_tcp_listener
listeners
aMultiListener

Create a UNIX socket listener.
Not available on Windows.
:param path: path of the socket
:param mode: permissions to set on the socket
:param backlog: maximum number of queued incoming connections (up to a maximum of
2**16, or 65536)
:return: a listener object
.. versionchanged:: 3.0
If a socket already exists on the file system in the given path, it will be
removed first.
setup_unix_local_socket
mode
create_unix_listener
close

Create a UDP socket.
If ``port`` has been given, the socket will be bound to this port on the local
machine, making this socket suitable for providing UDP based services.
:param family: address family (``AF_INET`` or ``AF_INET6``)     automatically
determined from ``local_host`` if omitted
:param local_host: IP address or host name of the local interface to bind to
:param local_port: local port to bind to
:param reuse_port: ``True`` to allow multiple sockets to bind to the same
ddress/port (not supported on Windows)
:return: a UDP socket
aAddressFamily
uEither "family" or "local_host" must be given
aSOCK_DGRAM
cast
aAnyIPAddressFamily
T u::
l
T u0.0.0.0
l
create_udp_socket
aUDPSocket

Create a connected UDP socket.
Connected UDP sockets can only communicate with the specified remote host/port, an
ny packets sent from other sources are dropped.
:param remote_host: remote host to set as the default target
:param remote_port: port on the remote host to set as the default target
:param family: address family (``AF_INET`` or ``AF_INET6``)     automatically
determined from ``local_host`` or ``remote_host`` if omitted
:param local_host: IP address or host name of the local interface to bind to
:param local_port: local port to bind to
:param reuse_port: ``True`` to allow multiple sockets to bind to the same
ddress/port (not supported on Windows)
:return: a connected UDP socket
aConnectedUDPSocket
create_connected_udp_socket

Create a UNIX datagram socket.
Not available on Windows.
If ``local_path`` has been given, the socket will be bound to this path, making this
socket suitable for receiving datagrams from other processes. Other processes can
send datagrams to this socket only if ``local_path`` is set.
If a socket already exists on the file system in the ``local_path``, it will be
removed first.
:param local_path: the path on which to bind to
:param local_mode: permissions to set on the local socket
:return: a UNIX datagram socket
local_path
local_mode
create_unix_datagram_socket

Create a connected UNIX datagram socket.
Connected datagram sockets can only communicate with the specified remote path.
If ``local_path`` has been given, the socket will be bound to this path, making
this socket suitable for receiving datagrams from other processes. Other processes
can send datagrams to this socket only if ``local_path`` is set.
If a socket already exists on the file system in the ``local_path``, it will be
removed first.
:param remote_path: the path to set as the default target
:param local_path: the path on which to bind to
:param local_mode: permissions to set on the local socket
:return: a connected UNIX datagram socket
remote_path
create_connected_unix_datagram_socket

Look up a numeric IP address given a host name.
Internationalized domain names are translated according to the (non-transitional)
IDNA 2008 standard.
.. note:: 4-tuple IPv6 socket addresses are automatically converted to 2-tuples of
(host, port), unlike what :func:`socket.getaddrinfo` does.
:param host: host name
:param port: port number
:param family: socket family (`'AF_INET``, ...)
:param type: socket type (``SOCK_STREAM``, ...)
:param proto: protocol number
:param flags: flags to pass to upstream ``getaddrinfo()``
:return: list of tuples containing (family, type, proto, canonname, sockaddr)
.. seealso:: :func:`socket.getaddrinfo`
host
encode
T aascii
idna
D auts46
taport
type
proto
flags
T afamily
type
proto
flags
convert_ipv6_sockaddr
getnameinfo

Look up the host name of an IP address.
:param sockaddr: socket address (e.g. (ipaddress, port) for IPv4)
:param flags: flags to pass to upstream ``getnameinfo()``
:return: a tuple of (host name, service name)
.. seealso:: :func:`socket.getnameinfo`
wait_readable
fileno

.. deprecated:: 4.7.0
Use :func:`wait_readable` instead.
Wait until the given socket has data to be read.
.. warning:: Only use this on raw sockets that have not been wrapped by any higher
level constructs like socket streams!
:param sock: a socket object
:raises ~anyio.ClosedResourceError: if the socket was closed while waiting for the
socket to become readable
:raises ~anyio.BusyResourceError: if another task is already waiting for the socket
to become readable
wait_writable

.. deprecated:: 4.7.0
Use :func:`wait_writable` instead.
Wait until the given socket can be written to.
This does **NOT** work on Windows when using the asyncio backend with a proactor
event loop (default on py3.8+).
.. warning:: Only use this on raw sockets that have not been wrapped by any higher
level constructs like socket streams!
:param sock: a socket object
:raises ~anyio.ClosedResourceError: if the socket was closed while waiting for the
socket to become writable
:raises ~anyio.BusyResourceError: if another task is already waiting for the socket
to become writable

Wait until the given object has data to be read.
On Unix systems, ``obj`` must either be an integer file descriptor, or else an
object with a ``.fileno()`` method which returns an integer file descriptor. Any
kind of file descriptor can be passed, though the exact semantics will depend on
your kernel. For example, this probably won't do anything useful for on-disk files.
On Windows systems, ``obj`` must either be an integer ``SOCKET`` handle, or else an
object with a ``.fileno()`` method which returns an integer ``SOCKET`` handle. File
descriptors aren't supported, and neither are handles that refer to anything besides
a ``SOCKET``.
On backends where this functionality is not natively provided (asyncio
``ProactorEventLoop`` on Windows), it is provided using a separate selector thread
which is set to shut down when the interpreter shuts down.
.. warning:: Don't use this on raw sockets that have been wrapped by any higher
level constructs like socket streams!
:param obj: an object with a ``.fileno()`` method or an integer handle
:raises ~anyio.ClosedResourceError: if the object was closed while waiting for the
object to become readable
:raises ~anyio.BusyResourceError: if another task is already waiting for the object
to become readable

Wait until the given object can be written to.
:param obj: an object with a ``.fileno()`` method or an integer handle
:raises ~anyio.ClosedResourceError: if the object was closed while waiting for the
object to become writable
:raises ~anyio.BusyResourceError: if another task is already waiting for the object
to become writable
.. seealso:: See the documentation of :func:`wait_readable` for the definition of
``obj`` and notes on backend compatibility.
.. warning:: Don't use this on raw sockets that have been wrapped by any higher
level constructs like socket streams!
T w%u

Convert a 4-tuple IPv6 socket address to a 2-tuple (address, port) format.
If the scope ID is nonzero, it is added to the address, separated with ``%``.
Otherwise the flow id and scope id are simply cut off from the tuple.
Any other kinds of socket addresses are returned as-is.
:param sockaddr: the result of :meth:`~socket.socket.getsockname`
:return: the converted socket address

Create a UNIX local socket object, deleting the socket at the given path if it
exists.
Not available on Windows.
:param path: path of the socket
:param mode: permissions to set on the socket
:param socktype: socket.SOCK_STREAM or socket.SOCK_DGRAM
fsdecode
startswith
T w
errno
aENOENT
aENOTDIR
aEBADF
aELOOP
stat
aS_ISSOCK
stat_result
st_mode
unlink
aAF_UNIX
socktype
path_str
to_thread
run_sync
D aabandon_on_cancel
tachmod
a__doc__
a__file__
origin
has_location
a__cached__
annotations
os
ssl
sys
ucollections.abc
T aAwaitable
aAwaitable
ipaddress
T aIPv6Address
ip_address
aPathLike
T aAddressFamily
aSocketKind
aTYPE_CHECKING
aAny
aLiteral
overload
T ato_thread
l aabc
T	aConnectedUDPSocket
aConnectedUNIXDatagramSocket
aIPAddressType
aIPSockAddrType
aSocketListener
aSocketStream
aUDPSocket
aUNIXDatagramSocket
aUNIXSocketStream
aConnectedUNIXDatagramSocket
aIPAddressType
aIPSockAddrType
aSocketListener
aSocketStream
aUNIXDatagramSocket
aUNIXSocketStream
ustreams.stapled
T aMultiListener
ustreams.tls
T aTLSStream
a_eventloop
T aget_async_backend
a_resources
T aaclose_forcefully
a_synchronization
T aEvent
a_tasks
T acreate_task_group
move_on_after
aFileDescriptorLike
exceptiongroup
T aExceptionGroup
typing_extensions
T adeprecated
deprecated
l)aIPAddressFamily
D alocal_host
ssl_context
tls_standard_compatible
happy_eyeballs_delay
Q
Q
Q
Q
D aremote_host
remote_port
local_host
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
return
aIPAddressType
int
uIPAddressType | None
ussl.SSLContext | None
bool
str
float
aTLSStream
D alocal_host
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
Q
Q
Q
Q
D aremote_host
remote_port
local_host
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
return
aIPAddressType
int
uIPAddressType | None
ussl.SSLContext
bool
ustr | None
float
aTLSStream
D alocal_host
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
Q
Q
Q
Q
Q
D	aremote_host
remote_port
local_host
tls
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
return
aIPAddressType
int
uIPAddressType | None
uLiteral[True]
ussl.SSLContext | None
bool
ustr | None
float
aTLSStream
D	aremote_host
remote_port
local_host
tls
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
return
aIPAddressType
int
uIPAddressType | None
uLiteral[False]
ussl.SSLContext | None
bool
ustr | None
float
aSocketStream
D alocal_host
happy_eyeballs_delay
Q
Q
D aremote_host
remote_port
local_host
happy_eyeballs_delay
return
aIPAddressType
int
uIPAddressType | None
float
aSocketStream
D alocal_host
tls
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
nFntnf
?D	aremote_host
remote_port
local_host
tls
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
return
aIPAddressType
int
uIPAddressType | None
bool
ussl.SSLContext | None
bool
ustr | None
float
uSocketStream | TLSStream
D apath
return
ustr | bytes | PathLike[Any]
aUNIXSocketStream
D alocal_host
local_port
family
backlog
reuse_port
return
uIPAddressType | None
int
aAnyIPAddressFamily
int
bool
uMultiListener[SocketStream]
D amode
backlog
nl   D apath
mode
backlog
return
ustr | bytes | PathLike[Any]
uint | None
int
aSocketListener
D alocal_host
local_port
reuse_port
nl
FD afamily
local_host
local_port
reuse_port
return
aAnyIPAddressFamily
uIPAddressType | None
int
bool
aUDPSocket
D aremote_host
remote_port
family
local_host
local_port
reuse_port
return
aIPAddressType
int
aAnyIPAddressFamily
uIPAddressType | None
int
bool
aConnectedUDPSocket
D alocal_path
local_mode
nnD alocal_path
local_mode
return
uNone | str | bytes | PathLike[Any]
uint | None
aUNIXDatagramSocket
D aremote_path
local_path
local_mode
return
ustr | bytes | PathLike[Any]
uNone | str | bytes | PathLike[Any]
uint | None
aConnectedUNIXDatagramSocket
D afamily
type
proto
flags
l
pppD ahost
port
family
type
proto
flags
return
ubytes | str | None
ustr | int | None
uint | AddressFamily
uint | SocketKind
int
pulist[tuple[AddressFamily, SocketKind, int, str, tuple[str, int]]]
T l
D asockaddr
flags
return
aIPSockAddrType
int
uAwaitable[tuple[str, str]]
T uThis function is deprecated; use `wait_readable` instead
D asock
return
usocket.socket
uAwaitable[None]
wait_socket_readable
T uThis function is deprecated; use `wait_writable` instead
wait_socket_writable
D aobj
return
aFileDescriptorLike
uAwaitable[None]
D asockaddr
return
utuple[str, int, int, int] | tuple[str, int]
utuple[str, int]
D apath
mode
socktype
return
uNone | str | bytes | PathLike[Any]
uint | None
int
usocket.socket
uanyio\_core\_sockets.py
u<module anyio._core._sockets>
T aremote_host
remote_port
local_host
happy_eyeballs_delay
T aremote_host
remote_port
local_host
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
T aremote_host
remote_port
local_host
tls
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
T aremote_host
remote_port
local_host
tls
ssl_context
tls_standard_compatible
tls_hostname
happy_eyeballs_delay
connected_stream
local_address
oserrors
try_connect
asynclib
family
gai_res
w_atarget_host
addr_obj
target_addrs
v6_found
v4_found
af
rest
sa
tg
wiaaddr
event
cause
T apath
T asockaddr
host
port
flowinfo
scope_id
T
remote_host
remote_port
family
local_host
local_port
reuse_port
local_address
gai_res
remote_address
sock
T aremote_path
local_path
local_mode
raw_socket
T alocal_host
local_port
family
backlog
reuse_port
listeners
sockaddr
asynclib
gai_res
fam
kind
w_araw_socket
addr
scope_id
listener
T afamily
local_host
local_port
reuse_port
gai_res
local_address
sock
T alocal_path
local_mode
raw_socket
T apath
mode
backlog
raw_socket
T	ahost
port
family
type
proto
flags
encoded_host
idna
gai_res
T asockaddr
flags
T apath
mode
socktype
path_str
stat_result
wearaw_socket
T
remote_host
event
connected_stream
stream
exc
asynclib
remote_port
local_address
oserrors
tg
T aasynclib
connected_stream
local_address
oserrors
remote_port
tg
T aobj
T asock
a__spec__
.anyio._core._streams
(
.
math
inf
umax_buffer_size must be either an integer or math.inf
umax_buffer_size cannot be negative
warn
uThe item_type argument has been deprecated in AnyIO 4.0. Use create_memory_object_stream[YourItemType](...) instead.
aDeprecationWarning
D astacklevel
l aMemoryObjectStreamState
aT_Item
aMemoryObjectSendStream
aMemoryObjectReceiveStream
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aTypeVar
warnings
T awarn
ustreams.memory
T aMemoryObjectReceiveStream
aMemoryObjectSendStream
aMemoryObjectStreamState
l T aT_Item
a__prepare__
create_memory_object_stream
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
