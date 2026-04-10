# Reconstructed from integrated Nuitka blob
# Module: upsutil._psbsd

a__qualname__
L a_cache
a_name
a_ppid
pid
a__slots__
a__init__
uProcess.__init__
uProcess._assert_alive
uProcess.oneshot
oneshot_enter
uProcess.oneshot_enter
oneshot_exit
uProcess.oneshot_exit
uProcess.name
exe
uProcess.exe
uProcess.cmdline
environ
uProcess.environ
terminal
uProcess.terminal
uProcess.ppid
uids
uProcess.uids
gids
uProcess.gids
uProcess.cpu_times
cpu_num
uProcess.cpu_num
memory_info
uProcess.memory_info
memory_full_info
uProcess.create_time
num_threads
uProcess.num_threads
num_ctx_switches
uProcess.num_ctx_switches
uProcess.threads
T ainet
uProcess.net_connections
T nawait
uProcess.wait
nice_get
uProcess.nice_get
nice_set
uProcess.nice_set
uProcess.status
io_counters
uProcess.io_counters
cwd
uProcess.cwd
T ammap
upath rss, private, ref_count, shadow_count
nt_mmap_grouped
T ammap
uaddr, perms path rss, private, ref_count, shadow_count
nt_mmap_ext
open_files
uProcess.open_files
num_fds
uProcess.num_fds
cpu_affinity_get
uProcess.cpu_affinity_get
cpu_affinity_set
uProcess.cpu_affinity_set
memory_maps
uProcess.memory_maps
rlimit
uProcess.rlimit
upsutil\_psbsd.py
u<module psutil._psbsd>
T a__class__
T aself
pid
T aself
T actime
diff
T aself
err
pid
name
ppid
T aself
cpus
allcpus
cpu
msg
err
T aret
wsaindex
root
T acurr
T aret
num_cpus
cpu
current
available_freq
min_freq
max_freq
T	actxsw
intrs
soft_intrs
syscalls
a_traps
a_faults
a_forks
wfaline
T aself
rawtuple
T auser
nice
system
idle
irq
T aself
monotonic
ctime
T	aall
retlist
partitions
partition
device
mountpoint
fstype
opts
ntuple
T aself
shutil
cmdline
T aself
name
T aself
kind
families
types
ret
rawlist
item
fd
fam
type
laddr
raddr
status
nt
T akind
families
types
ret
rawlist
item
fd
fam
type
laddr
raddr
status
pid
nt
T
names
ret
name
mtu
flags
duplex
speed
err
output_flags
isup
T aself
value
T aself
ret
T aself
rawlist
T aret
cpu_t
user
nice
system
idle
irq
item
T apid
exists
T aret
T aself
resource
limits
msg
soft
hard
T apercent
minsleft
power_plugged
secsleft
T aret
num_cpus
cpu
current
high
name
T aself
code
T atotal
used
free
sin
sout
percent
T aself
tty_nr
tmap
T aself
rawlist
retlist
thread_id
utime
stime
ntuple
T	aretlist
rawlist
item
user
tty
hostname
tstamp
pid
nt
T amem
total
free
active
inactive
wired
cached
wfaline
buffers
shared
used
avail
percent
T aself
timeout
T afun
wrapper
T ainst
pid
name
ppid
err
T aself
args
kwargs
pid
ppid
name
err
fun
T afun
.psutil._pslinux
>
~ areadlink
split
T w
l
endswith
T u (deleted)
path_exists_strict
:nq
napath
aO_RDONLY
wraO_WRONLY
wwaO_RDWR
uw+
aO_APPEND
replace
T wwwal T uw+
ur+
T w/w!u/sys/block/

access
aF_OK
open_binary
u/stat
a__enter__
a__exit__
readline
:l nnT nnnL auser
nice
system
idle
iowait
irq
softirq
values
steal
guest
guest_nice
namedtuple
scputimes
cMemFree:
get
T cCached:
l
cActive(file):
cInactive(file):
cSReclaimable:
debug
args
u is missing from /proc/meminfo; using an approximation for calculating available memory
get_procfs_path
u/zoneinfo
strip
startswith
T clow
watermark_low
l aPAGESIZE
min
l f
@u/meminfo
l  amems
cMemTotal:
cBuffers:
buffers
cCached:
cached
cShmem:
cMemShared:
shared
cActive:
active
cInactive:
cInact_dirty:
cInact_clean:
cInact_laundry:
inactive
cSlab:
cMemAvailable:
calculate_avail_vmem
available
usage_percent
D around_
l u{} memory stats couldn't be determined and {} set to 0
u,
was
were
warnings
warn
aRuntimeWarning
D astacklevel
l asvmem
cSwapTotal:
cSwapFree:
cext
linux_sysinfo
utoo many values to unpack (expected 7)
u/vmstat
u'sin' and 'sout' swap memory stats couldn't be determined and were set to 0 (
w)wfT cpswpin
T d l T cpswpout
sin
sout
u'sin' and 'sout' swap memory stats couldn't be determined and were set to 0
a_common
sswap
set_scputimes_ntuple
a_fields
aCLOCK_TICKS
T ccpu
cpus
sysconf
T aSC_NPROCESSORS_ONLN
u/cpuinfo
lower
T cprocessor
num
re
compile
T ucpu\d
open_text
T w asearch
match
glob
T u/sys/devices/system/cpu/cpu[0-9]*/topology/core_cpus_list
T u/sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list
ls
add
read
current_info
ccpu cores
mapping
cphysical id
T T cphysical id
ccpu cores
T c	:
l utoo many values to unpack (expected 2)
T cctxt
T cintr
T csoftirq
ctx_switches
soft_interrupts
interrupts
scpustats
T ccpu mhz
T d:l a_cpu_get_cpuinfo_freq
T u/sys/devices/system/cpu/cpufreq/policy[0-9]*
T u/sys/devices/system/cpu/cpu[0-9]*/cpufreq
sort
u<lambda>
ucpu_freq.<locals>.<lambda>
T akey
join
l  abcat
pjoin
scaling_cur_freq
D afallback
nacpuinfo_cur_freq
u/sys/devices/system/cpu/cpu
u/online
cat
u0
ret
scpufreq
T Z
Z
Z
ucan't find current frequency file
scaling_max_freq
scaling_min_freq
u[0-9]+
group
Z
tcp
socket
aAF_INET
aSOCK_STREAM
tcp6
aAF_INET6
udp
aSOCK_DGRAM
udp6
unix
aAF_UNIX
all
tcp4
udp4
inet
inet4
inet6
tmap
a_procfs_path
defaultdict
T Olist
w/u/fd
self
pid
u/fd/
T EFileNotFoundError
EProcessLookupError
errno
aEINVAL
aENAMETOOLONG
T usocket:[
:l nn:nq naappend
pids
inodes
get_proc_inodes
T EFileNotFoundError
EProcessLookupError
EPermissionError
T w:l aencode
T aascii
aLITTLE_ENDIAN
inet_ntop
base64
b16decode
:nnq astruct
pack
T u>4I
unpack
u<4I
T u<4I
supports_ipv6
a_Ipv6UnsupportedError
addr
file
T w6:nl
nutoo many values to unpack (expected 10)
uerror while parsing
u; malformed line
w T nq afilter_pid
type_
aTCP_STATUSES
aCONN_NONE
aNetConnections
decode_address
family
process_inet
uNetConnections.process_inet
:l
l nq asocktype_to_enum
process_unix
uNetConnections.process_unix
get_all_inodes
utoo many values to unpack (expected 3)
u/net/
T afilter_pid
pconn
sconn
a_net_connections
retrieve
u/net/dev
readlines
lines
:l nnarfind
utoo many values to unpack (expected 16)
retdict
aDUPLEX_FULL
aNIC_DUPLEX_FULL
aDUPLEX_HALF
aNIC_DUPLEX_HALF
aDUPLEX_UNKNOWN
aNIC_DUPLEX_UNKNOWN
net_io_counters
keys
net_if_mtu
net_if_flags
net_if_duplex_speed
aENODEV
w,aflags
running
snicstats
duplex
speed
mtu
read_procfs
udisk_io_counters.<locals>.read_procfs
read_sysfs
udisk_io_counters.<locals>.read_sysfs
u/diskstats
u/sys/block
u/diskstats nor /sys/block are available on this system
is_storage_device
aDISK_SECTOR_SIZE
l :l l n:l l nutoo many values to unpack (expected 11)
:l nnutoo many values to unpack (expected 4)
unot sure how to interpret line
walk
stat
fields
T w/ast_dev
major
minor
u/partitions
isdigit
u/dev/
u/sys/dev/block/
w:u/uevent
T uDEVNAME=
rpartition
iglob
T u/sys/class/block/*/dev
ask_proc_partitions
ask_sys_dev_block
ask_sys_class_block
u/filesystems
T anodev
fstypes
T w	azfs
T azfs
u/proc
u/etc/mtab
realpath
T u/etc/mtab
u/self/mounts
disk_partitions
none
P arootfs
u/dev/root
aRootFsDeviceFinder
find
sdiskpart
retlist
collections
T u/sys/class/hwmon/hwmon*/temp*_*
extend
T u/sys/class/hwmon/hwmon*/device/temp*_*
sorted
T w_T u/sys/devices/platform/coretemp.*/hwmon/hwmon*/temp*_*
T u/sys/devices/platform/coretemp.*/hwmon/
repl
sub
u/sys/class/hwmon/
basenames
a_input
f
@ @aname
T EOSError
EValueError
a_max
a_crit
a_label
D afallback

T u/sys/class/thermal/thermal_zone*
temp
type
u/trip_point*
w_:l
l nabase
a_type
critical
a_temp
high
T u/sys/class/hwmon/hwmon*/fan*_*
T u/sys/class/hwmon/hwmon*/device/fan*_*
sfan
multi_bcat
usensors_battery.<locals>.multi_bcat
aPOWER_SUPPLY_PATH
T aBAT
battery
u/energy_now
u/charge_now
u/power_now
u/current_now
u/energy_full
u/charge_full
u/time_to_empty_now
f
Y@u/capacity
D afallback
q uAC0/online
uAC/online
u/status
discharging
P acharging
full
aPOWER_TIME_UNLIMITED
l  aPOWER_TIME_UNKNOWN
l<asbattery
null
T afallback
users
utoo many values to unpack (expected 5)
suser
T cbtime
uline 'btime' not found in
aENCODING
a_psposix
pid_exists
T cTgid:
u'Tgid' line not found in
aAccessDenied
data
T d)awraps
wrapper
uwrap_exceptions.<locals>.wrapper
a_name
fun
a_raise_if_zombie
aNoSuchProcess
a_ppid
a_ctime
dZa_is_zombie
aZombieProcess
lexists
aUNSET
T d(astatus
ppid
ttynr
l autime
l astime
lachildren_utime
l achildren_stime
l acreate_time
l$acpu_num
l'ablkio_ticks
T ucan't get blkio_ticks, set iowait to 0
u/smaps
a_parse_stat_file
cache_activate
a_read_status_file
a_read_smaps_file
cache_deactivate
decode
a_readlink
u/exe
u/cmdline
w
cmdline
u/environ
parse_environ_block
get_terminal_map
u/io
T c:
u file was empty
pio
csyscr
csyscw
cread_bytes
cwrite_bytes
crchar
cwchar
u field was not found in
u; found fields are
pcputimes
wait_pid
boot_time
u/statm
:nl napmem
rss
vms
text
lib
dirty
u<genexpr>
uProcess.memory_info.<locals>.<genexpr>
u/smaps_rollup
T cPrivate_
uss
T cPss:
T cSwap:
pss
swap
findall
aHAS_PROC_SMAPS_ROLLUP
a_parse_smaps_rollup
T EProcessLookupError
EFileNotFoundError
a_parse_smaps
memory_info
pfullmem
get_blocks
uProcess.memory_maps.<locals>.get_blocks
T d
pop
T l
T nl utoo many values to unpack (expected 6)
u[anon]
T cRss:
l
T cSize:
l
T cPss:
l
T cShared_Clean:
l
T cShared_Dirty:
l
T cPrivate_Clean:
l
T cPrivate_Dirty:
l
T cReferenced:
l
T cAnonymous:
l
T cSwap:
l
T d:acurrent_block
T EValueError
EIndexError
T cVmFlags:
udon't know how to interpret line
u/cwd
u'voluntary_ctxt_switches' and 'nonvoluntary_ctxt_switches'lines were not found in
u/status; the kernel is probably older than 2.6.23
pctxsw
u/task
u/task/
ast
pthread
hit_enoent
a_raise_if_not_alive
proc_priority_get
proc_priority_set
proc_cpu_affinity_get
per_cpu_times
proc_cpu_affinity_set
a_get_eligible_cpus
uinvalid CPU
u; choose between
uCPU number
u is not eligible; choose between
proc_ioprio_get
aIOPriority
pionice
aIOPRIO_CLASS_IDLE
aIOPRIO_CLASS_NONE
u ioclass accepts no value
l uvalue not in 0-7 range
proc_ioprio_set
ucan't use prlimit() against PID 0 process
resource
prlimit
usecond argument must be a (soft, hard) tuple, got
aENOSYS
aPROC_STATUSES
w?aisfile_strict
u/fdinfo/
l afile_flags_to_mode
popenfile
pos
puids
pgids
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
enum
functools
os
sys
T adefaultdict
T anamedtuple
T a_common
T a_psposix
T a_psutil_linux
a_psutil_linux
T aENCODING
T aNIC_DUPLEX_FULL
T aNIC_DUPLEX_HALF
T aNIC_DUPLEX_UNKNOWN
T aAccessDenied
T aNoSuchProcess
T aZombieProcess
T abcat
T acat
T adebug
T adecode
T aget_procfs_path
T aisfile_strict
T amemoize
memoize
T amemoize_when_activated
memoize_when_activated
T aopen_binary
T aopen_text
T aparse_environ_block
T apath_exists_strict
T asupports_ipv6
T ausage_percent
L aPROCFS_PATH
aIOPRIO_CLASS_NONE
aIOPRIO_CLASS_RT
aIOPRIO_CLASS_BE
aIOPRIO_CLASS_IDLE
aCONN_ESTABLISHED
aCONN_SYN_SENT
aCONN_SYN_RECV
aCONN_FIN_WAIT1
aCONN_FIN_WAIT2
aCONN_TIME_WAIT
aCONN_CLOSE
aCONN_CLOSE_WAIT
aCONN_LAST_ACK
aCONN_LISTEN
aCONN_CLOSING
a__extra__all__
u/sys/class/power_supply
u/proc/
getpid
aHAS_PROC_SMAPS
aHAS_PROC_IO_PRIORITY
aHAS_CPU_AFFINITY
T aSC_CLK_TCK
getpagesize
l  aIntEnum
aAddressFamily
aAF_LINK
aAF_PACKET
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
