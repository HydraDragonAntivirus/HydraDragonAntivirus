# Reconstructed from integrated Nuitka blob
# Module: upsutil.tests

ufake_pytest.raises.<locals>.ExceptionInfo
a__qualname__
a_exc
value
ufake_pytest.raises.<locals>.ExceptionInfo.value
aExceptionInfo
contextlib
contextmanager
T nacontext
ufake_pytest.raises.<locals>.context
T amatch
exc
match
re
search
w"u
u" does not match "
u not raised
aTestCase
assertWarnsRegex
assertWarns
aSkipTest
fail
skipIf
a__class__
a__init__
a_running
f    MbP?a_interval
threading
aEvent
a_flag
a__name__
w<u running=
u at
u#x
w>astart
stop
ualready started
aThread
wait
set
self
time
sleep
ualready stopped
join
wraps
wrapper
u_reap_children_on_err.<locals>.wrapper
fun
reap_children
stdin
aDEVNULL
setdefault
stdout
cwd
getcwd
env
aPYTHON_EXE_ENV
T acreationflags
l   @aget_testfn
T adir
safe_rmpath
uimport time;open(r'
u', 'w').close();[time.sleep(0.1) for x in range(100)];
aPYTHON_EXE
aPopen
a_subprocesses_started
add
wait_for_file
D adelete
empty
tpawait_for_pid
pid
sproc
textwrap
dedent
u            import subprocess, os, sys, time
s = "import os, time;"
s += "f = open('
u', 'w');"
s += "f.write(str(os.getpid()));"
s += "f.close();"
s += "[time.sleep(0.1) for x in range(100 * 6)];"
p = subprocess.Popen([r'
u', '-c', s])
p.wait()
pyrun
D acreationflags
l
utoo many values to unpack (expected 2)
D adelete
empty
tFa_pids_started
u        import os, sys, time, socket, contextlib
child_pid = os.fork()
if child_pid > 0:
time.sleep(3000)
else:
# this is the zombie process
with socket.socket(socket.AF_UNIX) as s:
s.connect('
u')
pid = bytes(str(os.getpid()), 'ascii')
s.sendall(pid)
bind_unix_socket
settimeout
aGLOBAL_TIMEOUT
accept
select
fileno
recv
T l  acall_until
u<lambda>
uspawn_zombie.<locals>.<lambda>
close
zombie
status
aSTATUS_ZOMBIE
T astderr
nwwa__enter__
a__exit__
write
T nnnaspawn_subproc
name
l   @astderr
T auniversal_newlines
tacreationflags
shlex
communicate
T atimeout
returncode
endswith
T w
:nq nuterminate.<locals>.wait
sendsig
uterminate.<locals>.sendsig
term_subprocess_proc
uterminate.<locals>.term_subprocess_proc
term_psutil_proc
uterminate.<locals>.term_psutil_proc
term_pid
uterminate.<locals>.term_pid
flush_popen
uterminate.<locals>.flush_popen
uwrong type
wpaNoSuchProcess
signal
aSIGKILL
aPOSIX
send_signal
aSIGCONT
sig
winerror
l await_pid
proc
children
T arecursive
pop
terminate
D await_timeout
nawait_procs
ucouldn't terminate process
u; attempting kill()
T asig
unot POSIX
ucannot import name 'uname' from <ModuleName 'os'>
unot WINDOWS
getwindowsversion
service_pack_major
l utimeout and retries args are mutually exclusive
exception
timeout
retries
interval
logfun
a__iter__
uretry.__iter__
uretry.__call__.<locals>.wrapper
decorator
pids
rb
read
data
retry_fun
usafe_rmpath.<locals>.retry_fun
stat
aS_ISDIR
st_mode
partial
rmtree
remove
uignoring
T f{  G z ?aerr
mkdir
chdir
dirname
copyfile
chmod
aS_IEXEC
T agcc
pytest
skip
T ugcc is not installed
T u
#include <unistd.h>
int main() {
pause();
return 1;
}
T u.c
T asuffix
gcc
u-o
tempfile
mktemp
aTESTFN_PREFIX
suffix
dir
T aprefix
suffix
dir
startswith
T upsutil.
upsutil.tests.
u{}.{}.{}
fqmod
a_testMethodName
T asuffix
dir
addCleanup
assert_pid_gone
spawn_children_pair
spawn_zombie
aZombieProcess
ppid
uwasn't supposed to raise ZombieProcess
udid not raise NoSuchProcess (
w)aprocess_namespace
aiter
all
D aclear_cache
tasubTest
T aproc
name
a_check_proc_exc
uProcess.
u() didn't raise NSP and returned
ret
T l
assert_in_pids
uPsutilTestCase.assert_proc_zombie.<locals>.assert_in_pids
aOPENBSD
aNETBSD
aSUNOS
as_dict
aAccessDenied
aLINUX
raises
cmdline
memory_maps
suspend
resume
kill
a_pmap
a_set_debug
T Fa_psutil_debug_orig
a_thisproc
memory_full_info
uss
rss
num_fds
num_handles
verbose
print_color
yellow
T acolor
file
a_get_num_fds
call
unegative diff
u (gc probably collected a resource from a previous test)
fd
handle
wsu unclosed
u after calling
gc
collect
T l T ageneration
a_get_mem
a_call_ntimes
times
uRun #{}: extra-mem={}, per-call={}, calls={}
bytes2human
messages
prev_mem
a_log
print
increase
u.
warmup_times
tolerance
a_check_fds
a_check_mem
T atimes
retries
tolerance
uTestMemoryLeak.execute_w_exc.<locals>.call
execute
u did not raise
memoize
get_procs
uis_win_secure_system_proc.<locals>.get_procs
uSecure System
sh
T utasklist.exe /NH /FO csv
splitlines
:l nnT w,areplace
T w"u
cpu_num
cpu_affinity
random
choice
a_proc
ls
shuffle
utoo many values to unpack (expected 3)
clear_cache
uprocess_namespace.iter
a_init
D a_ignore_nsp
tatest_
u class should define a
u method
ignored
w_uuncovered Process class names:
usystem_namespace.iter
uretry_on_failure.<locals>.logfun
retry
aException
T aexception
timeout
retries
logfun
u, retrying
T afile
uskip_on_access_denied.<locals>.decorator
uskip_on_access_denied.<locals>.decorator.<locals>.wrapper
only_if
T uraises AccessDenied
uskip_on_not_implemented.<locals>.decorator
uskip_on_not_implemented.<locals>.decorator.<locals>.wrapper
u was skipped because it raised NotImplementedError
socket
bind
getsockname
aAF_INET
aAF_INET6
T u
l
aSOCK_STREAM
listen
T l aAF_UNIX
connect
all
T atype
setblocking
server
client
bind_socket
aSOCK_DGRAM
supports_ipv6
aHAS_NET_CONNECTIONS_UNIX
unix_socketpair
socks
fname1
fname2
create_sockets
ipaddress
aIPv4Address
aIPv6Address
aAF_LINK
uunknown family
check_ntuple
ucheck_connection_ntuple.<locals>.check_ntuple
check_family
ucheck_connection_ntuple.<locals>.check_family
check_type
ucheck_connection_ntuple.<locals>.check_type
check_addrs
ucheck_connection_ntuple.<locals>.check_addrs
check_status
ucheck_connection_ntuple.<locals>.check_status
family
type
laddr
errno
aEADDRNOTAVAIL
aSOCK_SEQPACKET
raddr
conn
check_net_address
ip
T aCONN_
u/syslog
debug
uskipping
new
reload
splitext
util
spec_from_file_location
module_from_spec
loader
exec_module
D astacklevel
l a__bases__
a_fields
u<genexpr>
uis_namedtuple.<locals>.<genexpr>
aPYPY
pypy
python
u.so
path
lower
aCDLL
copyload_shared_lib
aWinError
u.dll
ext
wow64
aWinDLL
windll
kernel32
aFreeLibrary
aHMODULE
argtypes
a_handle
T ta__doc__
a__file__
get
T aNUITKA_PACKAGE_psutil
u\not_existing
tests
T aNUITKA_PACKAGE_psutil_tests
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
ctypes
enum
functools
importlib
os
sys
traceback
unittest
T aAF_INET
T aAF_INET6
T aSOCK_STREAM
T aAIX
aAIX
T aLINUX
T aMACOS
T aNETBSD
T aOPENBSD
T aPOSIX
T aSUNOS
T aWINDOWS
upsutil._common
T abytes2human
T adebug
T amemoize
T aprint_color
T asupports_ipv6
upsutil._psposix
T await_pid
LJaDEVNULL
aGLOBAL_TIMEOUT
aTOLERANCE_SYS_MEM
aNO_RETRIES
aPYPY
aPYTHON_EXE
aPYTHON_EXE_ENV
aROOT_DIR
aSCRIPTS_DIR
aTESTFN_PREFIX
aUNICODE_SUFFIX
aINVALID_UNICODE_SUFFIX
aCI_TESTING
aVALID_PROC_STATUSES
aTOLERANCE_DISK_USAGE
aIS_64BIT
aHAS_CPU_AFFINITY
aHAS_CPU_FREQ
aHAS_ENVIRON
aHAS_PROC_IO_COUNTERS
aHAS_IONICE
aHAS_MEMORY_MAPS
aHAS_PROC_CPU_NUM
aHAS_RLIMIT
aHAS_SENSORS_BATTERY
aHAS_BATTERY
aHAS_SENSORS_FANS
aHAS_SENSORS_TEMPERATURES
aHAS_NET_CONNECTIONS_UNIX
aMACOS_11PLUS
aMACOS_12PLUS
aCOVERAGE
aAARCH64
aPYTEST_PARALLEL
pyrun
terminate
reap_children
spawn_subproc
spawn_zombie
spawn_children_pair
aThreadTask
unittest
skip_on_access_denied
skip_on_not_implemented
retry_on_failure
aTestMemoryLeak
aPsutilTestCase
process_namespace
system_namespace
is_win_secure_system_proc
fake_pytest
chdir
safe_rmpath
create_py_exe
create_c_exe
get_testfn
get_winver
kernel_version
call_until
wait_for_pid
wait_for_file
check_net_address
filter_proc_net_connections
get_free_port
bind_socket
bind_unix_socket
tcp_socketpair
unix_socketpair
create_sockets
reload_module
import_module_by_path
warn
copyload_shared_lib
is_namedtuple
a__all__
aCIBUILDWHEEL
aCI_TESTING
aCOVERAGE_RUN
aCOVERAGE
aPYTEST_XDIST_WORKER
aPYTEST_PARALLEL
aIS_64BIT
machine
P aaarch64
arm64
aAARCH64
riscv64
aRISCV64
macos_version
T l
l aMACOS_11PLUS
T l l
aMACOS_12PLUS
l
aNO_RETRIES
l    aTOLERANCE_SYS_MEM
l    aTOLERANCE_DISK_USAGE
l l l u@psutil-
getpid
w-u-
aUNICODE_SUFFIX
cf
utf8
surrogateescape
aINVALID_UNICODE_SUFFIX
getfilesystemencoding
P aascii
uus-ascii
aASCII_FS
T aPSUTIL_ROOT_DIR
u..
aROOT_DIR
scripts
aSCRIPTS_DIR
aHAS_CPU_AFFINITY
aHAS_ENVIRON
getloadavg
aHAS_GETLOADAVG
ionice
aHAS_IONICE
aHAS_MEMORY_MAPS
net_io_counters
aHAS_NET_IO_COUNTERS
aHAS_PROC_CPU_NUM
io_counters
aHAS_PROC_IO_COUNTERS
rlimit
aHAS_RLIMIT
sensors_battery
aHAS_SENSORS_BATTERY
sensors_fans
aHAS_SENSORS_FANS
sensors_temperatures
aHAS_SENSORS_TEMPERATURES
threads
aHAS_THREADS
getuid
aSKIP_SYSCONS
aHAS_BATTERY
format_exc
cpu_freq
aHAS_CPU_FREQ
a_get_py_exe
devnull
ur+
T aSTATUS_
aVALID_PROC_STATUSES
fake_pytest
ufake_pytest._warn_on_exit
main
ufake_pytest.main
ufake_pytest.raises
warns
ufake_pytest.warns
T u
ufake_pytest.skip
ufake_pytest.fail
ufake_pytest.mark
skipif
ufake_pytest.mark.skipif
ufake_pytest.mark.xdist_group
ufake_pytest.mark.xdist_group.__init__
a__call__
ufake_pytest.mark.xdist_group.__call__
xdist_group
mark
modules
a__prepare__
aThreadTask
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
uThreadTask.__init__
a__repr__
uThreadTask.__repr__
uThreadTask.__enter__
uThreadTask.__exit__
uThreadTask.start
uThreadTask.run
uThreadTask.stop
a__orig_bases__
a_reap_children_on_err
aSIGTERM
kernel_version
get_winver
uretry.__init__
uretry.sleep
uretry.__call__
T aexception
logfun
timeout
interval
T EFileNotFoundError
EAssertionError
T tFasafe_mkdir
create_py_exe
create_c_exe
T u
naPsutilTestCase
a__str__
uPsutilTestCase.__str__
uPsutilTestCase.get_testfn
uPsutilTestCase.spawn_subproc
spawn_psproc
uPsutilTestCase.spawn_psproc
uPsutilTestCase.spawn_children_pair
uPsutilTestCase.spawn_zombie
uPsutilTestCase.pyrun
uPsutilTestCase._check_proc_exc
uPsutilTestCase.assert_pid_gone
assert_proc_gone
uPsutilTestCase.assert_proc_gone
assert_proc_zombie
uPsutilTestCase.assert_proc_zombie
aTestMemoryLeak
D areason
uunreliable on PYPY
T aserial
T aname
l  abool
getenv
T aPSUTIL_DEBUG
classmethod
setUpClass
uTestMemoryLeak.setUpClass
tearDownClass
uTestMemoryLeak.tearDownClass
uTestMemoryLeak._get_mem
uTestMemoryLeak._get_num_fds
uTestMemoryLeak._log
uTestMemoryLeak._check_fds
uTestMemoryLeak._call_ntimes
uTestMemoryLeak._check_mem
uTestMemoryLeak.call
T nnnnuTestMemoryLeak.execute
execute_w_exc
uTestMemoryLeak.execute_w_exc
is_win_secure_system_proc
a_get_eligible_cpu
L T acpu_percent
T
D
T amemory_percent
T
D
utils
L	T aas_dict
T
D
T achildren
T
D arecursive
tT aconnections
T
D
T ais_running
T
D
T aoneshot
T
D
T aparent
T
D
T aparents
T
D
T apid
T
D
T await
T l
D
L T acmdline
T
D
T acpu_times
T
D
T acreate_time
T
D
T acwd
T
D
T aexe
T
D
T amemory_full_info
T
D
T amemory_info
T
D
T aname
T
D
T anet_connections
T
D akind
all
T anice
T
D
T anum_ctx_switches
T
D
T anum_threads
T
D
T aopen_files
T
D
T appid
T
D
T astatus
T
D
T athreads
T
D
T ausername
T
D
getters
L T auids
T
D
L T agids
T
D
L T aterminal
T
D
L T anum_fds
T
D
L T aio_counters
T
D
L T aionice
T
D
aRLIMIT_NOFILE
L T acpu_affinity
T
D
L T acpu_num
T
D
L T aenviron
T
D
L T anum_handles
T
D
L T amemory_maps
T
D agrouped
Fasetters
L T anice
T l
D
nice
aNORMAL_PRIORITY_CLASS
T l  l  aIOPRIO_CLASS_NONE
aIOPRIO_NORMAL
T asuspend
T
D
T aresume
T
D
T aterminate
T
D
T akill
T
D
killers
aCTRL_C_EVENT
aCTRL_BREAK_EVENT
uprocess_namespace.__init__
uprocess_namespace.clear_cache
test_class_coverage
uprocess_namespace.test_class_coverage
test
uprocess_namespace.test
system_namespace
T aboot_time
T
D
T acpu_count
T
D alogical
FT acpu_count
T
D alogical
tT acpu_stats
T
D
T acpu_times
T
D apercpu
FT acpu_times
T
D apercpu
tT adisk_io_counters
T
D aperdisk
tT adisk_partitions
T
D aall
tadisk_usage
T anet_connections
T
D akind
all
T anet_if_addrs
T
D
T anet_if_stats
T
D
T anet_io_counters
T
D apernic
tapid_exists
T apids
T
D
T aswap_memory
T
D
T ausers
T
D
T avirtual_memory
T
D
L T acpu_freq
T
D apercpu
tL T agetloadavg
T
D
L T asensors_temperatures
T
D
L T asensors_fans
T
D
L T asensors_battery
T
D
L T awin_service_iter
T
D
L T awin_service_get
T aalg
D
T aprocess_iter
T
D
T acpu_percent
T
D
T acpu_times_percent
T
D
retry_on_failure
skip_on_access_denied
skip_on_not_implemented
T u127.0.0.1
get_free_port
T T u
l
tcp_socketpair
check_connection_ntuple
filter_proc_net_connections
reload_module
import_module_by_path
is_namedtuple
cleanup_test_procs
upsutil\tests\__init__.py
T a.0
wnT asig
w_T azombie
u<module psutil.tests>
T a__class__
T aself
cls_or_meth
T aself
fun
wrapper
T aself
T aself
args
kwargs
T aself
a__class__
T aself
name
T aself
proc
T aself
exception
timeout
retries
interval
logfun
T aself
stop_at
w_T aself
fqmod
T aself
fun
times
mem1
wxaret
mem2
diff
T aself
fun
before
after
diff
msg
type_
T aself
fun
times
retries
tolerance
messages
prev_mem
increase
idx
mem
msg
success
T aself
proc
exc
T wpT aself
mem
T aattempt
env
base
exe
T aself
msg
T afun
wrapper
T a_warn_on_exit
T aproc
T aself
pid
proc
exc
T aself
proc
ns
fun
name
ret
exc
msg
T	aself
proc
assert_in_pids
clone
ns
fun
name
exc
cm
T aexe
T afamily
type
addr
sock
T aname
type
sock
T aself
fun
T afun
exc
T aexc
fun
T afun
ret
T adirname
curdir
T aconn
addr
T aconn
check_ntuple
check_family
check_type
check_addrs
check_status
T aconn
wsaerr
T aaddr
family
octs
num
T aconn
has_pid
T aconn
valids
T aconn
aSOCK_SEQPACKET
T aexc
match
einfo
err
msg
aExceptionInfo
T aExceptionInfo
T
suffix
aWinError
wintypes
ext
dst
libs
src
cfile
aFreeLibrary
ret
T asuffix
exe
ext
dst
libs
src
T apath
c_code
wfT apath
ast
T asocks
fname1
fname2
s1
s2
s3
wsafname
T aonly_if
T aself
fun
times
warmup_times
retries
tolerance
T aself
exc
fun
kwargs
call
T areason
T acons
new
conn
T ahost
sock
T aret
out
line
bits
name
pid
T aself
suffix
dir
fname
T asuffix
dir
name
path
T awv
sp
T apath
name
spec
mod
T wxwtwbwfT apid
get_procs
T aself
ls
clear_cache
fun_name
args
kwds
fun
T als
fun_name
args
kwds
fun
T wsauname
wcaminor
micro
nums
major
T aexc
T aversion_str
version
T aargs
kw
suite
T aself
args
kwds
sproc
srcfile
T asrc
kwds
srcfile
wfasubp
T aexc
match
aExceptionInfo
context
T arecursive
children
subp
pid
wpw_aalive
T amodule
T afun
stop_at
w_aerr
T aretries
logfun
T apath
retry_fun
ast
fun
T aproc
sig
T acls
T acmd
kwds
flags
wpastdout
stderr
T aonly_if
decorator
T acondition
reason
T aself
child1
child2
T atfile
testfn
wsasubp
child
grandchild_pid
grandchild
T aself
args
kwargs
sproc
T aself
args
kwds
sproc
T acmd
kwds
aCREATE_NO_WINDOW
testfn
pyline
sproc
T aself
parent
zombie
T	aunix_file
src
tfile
sock
parent
conn
w_azpid
zombie
T afamily
addr
all
wcacaddr
waT apid
timeout
proc
term_psutil_proc
T aterm_psutil_proc
T aproc
timeout
sendsig
sig
wait
T asendsig
sig
wait
T aproc
timeout
err
sendsig
sig
wait
T aproc_or_pid
sig
wait_timeout
wait
sendsig
term_subprocess_proc
term_psutil_proc
term_pid
flush_popen
wpapid
T acls
this
ignored
klass
leftout
T acls
test_class
ls
fun_name
w_ameth_name
msg
T aname
server
client
T aproc
timeout
T afname
delete
empty
wfadata
T apid
T amsg
T awarning
match
T aargs
kwargs
fun
T afun
T aargs
kwargs
exc
w_aself
fun
T afun
self
T aargs
kwargs
fun
only_if
T afun
only_if
T aargs
kwargs
msg
fun
only_if
.psutil.tests.test_aix
b
P
sh
T u/usr/bin/svmon -O unit=KB
umemory\s*
T asize
inuse
free
pin
virtual
available
mmode
re_pattern
u(?P<

u>\S+)\s+
re
search
group
T asize
l  T aavailable
T ainuse
T afree
psutil
virtual_memory
T u/usr/sbin/lsps -a
u(?P<space>\S+)\s+(?P<vol>\S+)\s+(?P<vg>\S+)\s+(?P<size>\d+)MB
swap_memory
T u/usr/bin/mpstat -a
uALL\s*
T amin
maj
mpcs
mpcr
dev
soft
dec
ph
cs
ics
bound
rq
push
aS3pull
aS3grd
aS0rd
aS1rd
aS2rd
aS3rd
aS4rd
aS5rd
sysc
cpu_stats
ulcpu=(\d+)
T l acpu_count
T tT alogical
T u/etc/ifconfig -l
split
net_if_addrs
keys
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
l
T aAIX
aAIX
upsutil.tests
T aPsutilTestCase
aPsutilTestCase
T apytest
pytest
T ash
a__prepare__
aAIXSpecificTestCase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
mark
skipif
D areason
uAIX only
