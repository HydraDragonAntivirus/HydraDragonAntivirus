# Reconstructed from integrated Nuitka blob
# Module: uanyio._core._exceptions


Raised when trying to use a resource that has been rendered unusable due to external
causes (e.g. a send stream whose peer has disconnected).
a__qualname__
a__orig_bases__
aBrokenWorkerProcess

Raised by :meth:`~anyio.to_process.run_sync` if the worker process terminates abruptly or
otherwise misbehaves.
aBrokenWorkerIntepreter

Raised by :meth:`~anyio.to_interpreter.run_sync` if an unexpected exception is
raised in the subinterpreter.
D aexcinfo
aAny
uBrokenWorkerIntepreter.__init__
D areturn
str
uBrokenWorkerIntepreter.__str__
aBusyResourceError

Raised when two tasks are trying to read from or write to the same resource
concurrently.
D aaction
str
uBusyResourceError.__init__
aClosedResourceError
uRaised when trying to use a resource that has been closed.
aDelimiterNotFound

Raised during
:meth:`~anyio.streams.buffered.BufferedByteReceiveStream.receive_until` if the
maximum number of bytes has been read without the delimiter being found.
D amax_bytes
return
int
aNone
uDelimiterNotFound.__init__
aEndOfStream

Raised when trying to read from a stream that has been closed from the other end.
aIncompleteRead

Raised during
:meth:`~anyio.streams.buffered.BufferedByteReceiveStream.receive_exactly` or
:meth:`~anyio.streams.buffered.BufferedByteReceiveStream.receive_until` if the
connection is closed before the requested amount of bytes has been read.
D areturn
aNone
uIncompleteRead.__init__
T ELookupError
aTypedAttributeLookupError

Raised by :meth:`~anyio.TypedAttributeProvider.extra` when the given typed attribute
is not found and no default value has been given.
aWouldBlock
uRaised by ``X_nowait`` functions if ``X()`` would block.
D aexception
return
aBaseException
uGenerator[BaseException, None, None]
uanyio\_core\_exceptions.py
u<module anyio._core._exceptions>
T a__class__
T aself
excinfo
msg
a__class__
T aself
action
a__class__
T aself
max_bytes
a__class__
T aself
a__class__
T aself
formatted
a__class__
T aexception
exc
a__spec__
.anyio._core._fileio
.
a_fp
uThe wrapped file object.
self
readline
a__aiter__
uAsyncFile.__aiter__
to_thread
run_sync
close
aclose
uAsyncFile.aclose
read
size
uAsyncFile.read
read1
uAsyncFile.read1
uAsyncFile.readline
readlines
uAsyncFile.readlines
readinto
wbuAsyncFile.readinto
readinto1
uAsyncFile.readinto1
write
uAsyncFile.write
writelines
uAsyncFile.writelines
lines
truncate
uAsyncFile.truncate
seek
offset
whence
uAsyncFile.seek
tell
uAsyncFile.tell
flush
uAsyncFile.flush
open_file

Open a file asynchronously.
The arguments are exactly the same as for the builtin :func:`open`.
:return: an asynchronous file object
open
file
mode
buffering
encoding
errors
newline
closefd
opener
aAsyncFile

Wrap an existing file as an asynchronous file.
:param file: an existing file-like object
:return: an asynchronous file object
anext
iterator
D aabandon_on_cancel
taPath
a__anext__
u_PathIterator.__anext__
pathlib
a_path
a__fspath__
a__str__
a__name__

w(aas_posix
w)a__bytes__
a__hash__
a__eq__
a__lt__
a__le__
a__gt__
a__ge__
parts
drive
root
anchor
parents
u<genexpr>
uPath.parents.<locals>.<genexpr>
parent
name
suffix
suffixes
stem
absolute
uPath.absolute
as_uri
match
relative_to
partial
chmod
follow_symlinks
T afollow_symlinks
uPath.chmod
cwd
cls
uPath.cwd
exists
uPath.exists
expanduser
uPath.expanduser
glob
a_PathIterator
group
uPath.group
target
link
hardlink_to
uPath.hardlink_to
home
uPath.home
is_absolute
is_block_device
uPath.is_block_device
is_char_device
uPath.is_char_device
is_dir
uPath.is_dir
is_fifo
uPath.is_fifo
is_file
uPath.is_file
ismount
is_mount
uPath.is_mount
is_reserved
is_socket
uPath.is_socket
is_symlink
uPath.is_symlink
iterdir
joinpath
lchmod
uPath.lchmod
lstat
uPath.lstat
mkdir
exist_ok
uPath.mkdir
uPath.open
owner
uPath.owner
read_bytes
uPath.read_bytes
read_text
uPath.read_text
readlink
uPath.readlink
rename
uPath.rename
replace
uPath.replace
resolve
strict
T astrict
uPath.resolve
rglob
rmdir
uPath.rmdir
other_path
samefile
uPath.samefile
stat
uPath.stat
symlink_to
target_is_directory
uPath.symlink_to
touch
uPath.touch
unlink
missing_ok
uPath.unlink
with_name
with_suffix
write_bytes
data
uPath.write_bytes
D areturn
int
sync_write_text
uPath.write_text.<locals>.sync_write_text
write_text
uPath.write_text
T wwT aencoding
errors
newline
a__enter__
a__exit__
T nnna__doc__
a__file__
origin
has_location
a__cached__
annotations
os
sys
ucollections.abc
T aAsyncIterator
aCallable
aIterable
aIterator
aSequence
aAsyncIterator
aCallable
aIterable
aIterator
aSequence
dataclasses
T adataclass
dataclass
aPathLike
aIO
aTYPE_CHECKING
aAny
aAnyStr
aFinal
aGeneric
overload
T ato_thread
l aabc
T aAsyncResource
aAsyncResource
aReadableBuffer
aOpenBinaryMode
aOpenTextMode
aWriteableBuffer
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
