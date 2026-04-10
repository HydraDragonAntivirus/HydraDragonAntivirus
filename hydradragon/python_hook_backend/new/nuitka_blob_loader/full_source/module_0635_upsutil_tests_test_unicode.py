# Reconstructed from integrated Nuitka blob
# Module: upsutil.tests.test_unicode

a__qualname__
classmethod
uBaseUnicodeTest.setUpClass
uBaseUnicodeTest.setUp
a__orig_bases__
aTestFSAPIs
mark
xdist_group
T aserial
T aname
skipif
D areason
uASCII fs
uTestFSAPIs.expect_exact_path_match
test_proc_exe
uTestFSAPIs.test_proc_exe
test_proc_name
uTestFSAPIs.test_proc_name
test_proc_cmdline
uTestFSAPIs.test_proc_cmdline
test_proc_cwd
uTestFSAPIs.test_proc_cwd
D areason
ufails on PYPY + WINDOWS
D areason
ubroken on NETBSD or OPENBSD
test_proc_open_files
uTestFSAPIs.test_proc_open_files
D areason
uPOSIX only
D areason
ucan't list UNIX sockets
test_proc_net_connections
uTestFSAPIs.test_proc_net_connections
test_net_connections
uTestFSAPIs.test_net_connections
test_disk_usage
uTestFSAPIs.test_disk_usage
D areason
unot supported
test_memory_maps
uTestFSAPIs.test_memory_maps
aTestFSAPIsWithInvalidPath
D areason
uunreliable on CI
uTestFSAPIsWithInvalidPath.expect_exact_path_match
aTestNonFSAPIS
D areason
usegfaults on PYPY + WINDOWS
test_proc_environ
uTestNonFSAPIS.test_proc_environ
upsutil\tests\test_unicode.py
u<module psutil.tests.test_unicode>
T a__class__
T aself
T acons
conn
T wpT aself
a__class__
T acls
a__class__
T aself
dname
T aself
funky_path
normpath
libpaths
path
T aself
find_sock
name
sock
cons
conn
T aself
cmd
subp
wpacmdline
part
T aself
dname
wpacwd
T aself
env
sproc
wpwkwvT aself
cmd
subp
wpaexe
T aself
cmd
subp
name
T aself
name
sock
conn
T aself
wpastart
new
path
T asuffix
sproc
testfn

.psutil.tests.test_windows
'
shutil
which
T upowershell.exe
pytest
skip
T upowershell.exe not available
upowershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -Command "

w"ash
uwmic path
u get
strip
splitlines
:l nnw,aconverter
u<genexpr>
uwmic.<locals>.<genexpr>
environ
aNUMBER_OF_PROCESSORS
win32api
aGetSystemInfo
l apsutil
cpu_count
wmi
aWMI
aWin32_Processor
aNumberOfLogicalProcessors
uTestCpuAPIs.test_cpu_count_logical_vs_wmi.<locals>.<genexpr>
aNumberOfCores
uTestCpuAPIs.test_cpu_count_cores_vs_wmi.<locals>.<genexpr>
l
T uipconfig /all
net_io_counters
T tT apernic
keys
upseudo-interface
replace
T w w-alower
fail
u nic wasn't found in 'ipconfig /all' output
aWin32_ComputerSystem
aWin32_PerfRawData_PerfOS_Memory
swap_memory
total
aWin32_PerfRawData_PerfOS_PagingFile
T a_Total
T aName
aPercentUsage
ldaPercentUsage_Base
aWin32_Process
aProcessId
pids
disk_partitions
T aall
aWin32_LogicalDisk
wmi_parts
ps_part
device
T w\u
aDeviceID
mountpoint
cdrom
opts
startswith
T uA:
disk_usage
aFreeSpace
free
l    upsutil=
u, wmi=
ucan't find partition
aGetDiskFreeSpaceEx
aGetLogicalDriveStrings
split
T v \
w\D u\Device\HarddiskVolume1
uC:
patch
get
T upsutil._pswindows.cext.QueryDosDevice
T aside_effect
a__enter__
a__exit__
T nnnacext
net_if_stats
aWin32_NetworkAdapter
wmi_names
add
aName
aNetConnectionID
aWin32_OperatingSystem
aLastBootUpTime
T w.adatetime
strptime
u%Y%m%d%H%M%S
fromtimestamp
boot_time
total_seconds
windll
kernel32
aGetTickCount64
f
@ @aGetPwrCapabilities
aSystemBatteriesPresent
query
T uselect * from Win32_Battery
sensors_battery
T upsutil._pswindows.cext.sensors_battery
T l
l  l
pT areturn_value
T upsutil._pswindows.cext.sensors_battery
T l l
ppT upsutil._pswindows.cext.sensors_battery
T l
l l
pT upsutil._pswindows.cext.sensors_battery
T l
ppq aspawn_subproc
pid
terminate
aProcess
T l
raises
aAccessDenied
kill
T l ausername
memory_info
:nl nutoo many values to unpack (expected 2)
platform
uname
l P uwin-7
vista
win7
T EValueError
send_signal
signal
aSIGINT
getpid
num_handles
aOpenProcess
win32con
aPROCESS_QUERY_INFORMATION
aFALSE
aCloseHandle
aCTRL_C_EVENT
aCTRL_BREAK_EVENT
wait
aNoSuchProcess
aGetUserNameEx
aNameSamCompatible
endswith
T w$T urunning as service account
re
sub
u[ ]+
w aGetCommandLine
cmdline
T w"u
addCleanup
win32process
aGetPriorityClass
nice
aGetProcessMemoryInfo
aGetExitCodeProcess
from_bitmask
uTestProcess.test_cpu_affinity.<locals>.from_bitmask
aGetProcessAffinityMask
cpu_affinity
;l
l@l wxaGetProcessIoCounters
io_counters
l  aDWORD
aGetProcessHandleCount
byref
value
l  awinerror
T upsutil._psplatform.cext.proc_cwd
T utime.sleep
cwd
q l   a_psplatform
exe
T aProcessId
aGetOwner
utoo many values to unpack (expected 3)
rss
vms
aPageFileUsage
uwmi=
u, psutil=
aCreationDate
time
strftime
localtime
create_time
T upsutil._psplatform.cext.proc_memory_info
EPermissionError
T upsutil._psplatform.cext.proc_times
EPermissionError
cpu_times
T upsutil._psplatform.cext.proc_io_counters
EPermissionError
T upsutil._psplatform.cext.proc_num_handles
EPermissionError
proc_cmdline
D ause_peb
tD ause_peb
Faconvert_oserror
uimport sys; sys.stdout.write(str(sys.maxsize > 2**32))
glob
T uC:\Python*\python.exe
subprocess
aPopen
u-c
code
aPIPE
aSTDOUT
T aargs
stdout
stderr
communicate
aIS_64BIT
a__class__
setUp
find_other_interpreter
T ucould not find interpreter with opposite bitness
executable
python64
python32
copy
aTHINK_OF_A_NUMBER
test_args
T aenv
stdin
proc32
proc64
tearDown
win_service_iter
name
aWaaSMedicSvc
as_dict
win_service_get
aERROR_SERVICE_DOES_NOT_EXIST
aERROR_ACCESS_DENIED
u???
msg
T upsutil._psplatform.cext.winservice_query_status
status
T upsutil._psplatform.cext.winservice_query_config
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
ctypes
os
sys
warnings
mock
T aWINDOWS
aWINDOWS
upsutil.tests
T aGITHUB_ACTIONS
aGITHUB_ACTIONS
T aHAS_BATTERY
aHAS_BATTERY
T aIS_64BIT
T aPYPY
aPYPY
T aTOLERANCE_DISK_USAGE
aTOLERANCE_DISK_USAGE
T aTOLERANCE_SYS_MEM
aTOLERANCE_SYS_MEM
T aPsutilTestCase
aPsutilTestCase
T apytest
T aretry_on_failure
retry_on_failure
T ash
T aspawn_subproc
T aterminate
catch_warnings
simplefilter
T aignore
upsutil._pswindows
T aconvert_oserror
a__prepare__
aWindowsTestCase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
mark
skipif
D areason
uWINDOWS only
D areason
upywin32 not available on PYPY
