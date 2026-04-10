# Reconstructed from integrated Nuitka blob
# Module: unumba.misc.firstlinefinder

a__qualname__
a__init__
uFindDefFirstLine.__init__
uFindDefFirstLine._visit_children
visit_FunctionDef
uFindDefFirstLine.visit_FunctionDef
a__orig_bases__
get_func_body_first_lineno
unumba\misc\firstlinefinder.py
u<module numba.misc.firstlinefinder>
T a__class__
T aself
name
firstlineno
T anode
T aself
node
child
a__class__
T apyfunc
co
fin
source
offset
lines
tree
finder
T aself
node
possible_start_lines
first_decor
first_stmt
.numba.misc.gdb_hook
a_unix_like
errors
aNumbaRuntimeError
T ugdb support is only available on unix-like systems
config
aGDB_BINARY
uIs gdb present? Location specified (%s) does not exist. The gdb binary location can be set using Numba configuration, see: https://numba.readthedocs.io/en/stable/reference/envvars.html
join
T w\aproc
sys
kernel
yama
ptrace_scope
rt
a__enter__
a__exit__
readline
strip
T nnnavalue
T w0w1ugdb can launch but cannot attach to the executing program because ptrace permissions have been restricted at the system level by the Linux security module 'Yama'.
Documentation for this module and the security implications of making changes to its behaviour can be found in the Linux Kernel documentation https://www.kernel.org/doc/Documentation/admin-guide/LSM/Yama.rst
Documentation on how to adjust the behaviour of Yama on Ubuntu Linux with regards to 'ptrace_scope' can be found here https://wiki.ubuntu.com/Security/Features#ptrace.
a_confirm_gdb
gen_gdb_impl
impl
uhook_gdb.<locals>.impl
gdbimpl
uhook_gdb_init.<locals>.impl
ir
aIntType
T l T l autils
aMACHINE_BITS
aPointerType
T l
module
cgutils
alloca_once
D asize
l D asize
l ainsert_const_string
u%d
attach
u-x
a_path
ucmdlang.gdb
u-ex
wcatypes
aStringLiteral
aRequireLiteralValue
literal_value
cgctx
mod
aFunctionType
get_or_insert_function
getpid
D avar_arg
tasnprintf
fork
execl
sleep
aVoidType
numba_gdb_breakpoint
call
store
gep
D ainbounds
taload
T l aicmp_signed
w>aif_then
D alikely
Facall_conv
return_user_exc
T uInternal error: `snprintf` buffer would have overflowed.
u==
T q T uInternal error: `fork` failed.
if_else
utoo many values to unpack (expected 2)
aConstant
printf
uAttaching to PID: %s
T l
intrinsic
gdb_internal
ugen_gdb_impl.<locals>.gdb_internal
void
codegen
ugen_gdb_impl.<locals>.gdb_internal.<locals>.codegen
init_gdb_codegen
const_args
do_break
T ado_break
get_constant
none
ugdb is only available on linux
bp_internal
ugen_bp_impl.<locals>.bp_internal
ugen_bp_impl.<locals>.bp_internal.<locals>.codegen
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
os
sys
llvmlite
T air
l
unumba.core
T atypes
utils
config
cgutils
errors
numba
T agdb
gdb_init
gdb_breakpoint
gdb
gdb_init
gdb_breakpoint
unumba.core.extending
T aoverload
intrinsic
overload
win32
a_platform
linux
darwin
T tahook_gdb
hook_gdb_init
T Fahook_gdb_breakpoint
gen_bp_impl
unumba\misc\gdb_hook.py
u<module numba.misc.gdb_hook>
T aneed_ptrace_attach
msg
gdbloc
ptrace_scope_file
has_ptrace_scope
wfavalue
T atyctx
function_sig
codegen
T acgctx
builder
signature
args
mod
fnty
breakpoint
T acgctx
builder
signature
args
const_args
do_break
T aconst_args
do_break
T abp_internal
T aconst_args
do_break
gdb_internal
T aargs
gdbimpl
impl
T abp_impl
impl
T aargs
gdbimpl
T agdbimpl
T)acgctx
builder
signature
args
const_args
do_break
int8_t
int32_t
intp_t
char_ptr
zero_i32t
mod
pid
pidstr
intfmt
gdb_str
attach_str
new_args
cmdlang
fnty
getpid
snprintf
fork
execl
sleep
breakpoint
parent_pid
pidstr_ptr
pid_val
stat
invalid_write
msg
child_pid
fork_failed
is_child
then
orelse
nullptr
gdb_str_ptr
attach_str_ptr
buf

.numba.misc.init_utils
split
T w.atry_int
ugenerate_version_info.<locals>.try_int
l
l l l aversion_info
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
collections
T anamedtuple
namedtuple
T aversion_info
umajor minor patch short full string tuple git_revision
generate_version_info
unumba\misc\init_utils.py
u<module numba.misc.init_utils>
T aversion
parts
try_int
major
minor
patch
short
full
string
tup
git_revision
T wxu
.numba.misc.inspection
uMust not call numba.misc.inspection.disassemble_elf_to_cfg
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
tempfile
T aNamedTemporaryFile
aTemporaryDirectory
l
aNamedTemporaryFile
aTemporaryDirectory
os
warnings
unumba.core.errors
T aNumbaWarning
aNumbaWarning
disassemble_elf_to_cfg
unumba\misc\inspection.py
u<module numba.misc.inspection>
T aelf
mangled_symbol

.numba.misc.literal
n
'
types
aLiteral
aInitialValue
u<lambda>
u_ov_literally.<locals>.<lambda>
uInvalid use of non-Literal type in literally({})
aTypingError
aPoison
uInvalid use of non-Literal type in literal_unroll(

w)aimpl
uliteral_unroll_impl.<locals>.impl
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unumba.core.extending
T aoverload
l
overload
unumba.core
T atypes
unumba.misc.special
T aliterally
literal_unroll
literally
literal_unroll
unumba.core.errors
T aTypingError
a_ov_literally
literal_unroll_impl
unumba\misc\literal.py
T aobj
u<module numba.misc.literal>
T aobj
wmT acontainer
T acontainer
wmaimpl
.numba.misc.llvm_pass_timings
llvm
set_time_passes
T tareport_and_reset_timings
a_data
T FaProcessedPassTimings
a_pb
start_pass_timing
finish_pass_timing
q amake_adjuster
u_adjust_timings.<locals>.make_adjuster
T auser
system
user_system
wall
u<lambda>
u_adjust_timings.<locals>.<lambda>
chained
u_adjust_timings.<locals>.chained

a_time
a_percent
operator
attrgetter
adjust
u_adjust_timings.<locals>.make_adjuster.<locals>.adjust
time_getter
total_rec
percent_attr
f{  G z ?atime_attr
a_asdict
adj_fns
wdaPassTimingRecord
a_raw_data
list_records
wall_time
a_processed
T awall_time
heapq
nlargest
:nq nw aap
uProcessedPassTimings.summary.<locals>.ap
uTotal
get_total_time
u.4f
wsT uTop timings:
list_top

us (
wall_percent
w5u%)
pass_name
w
buf
append
prefix
a_process
parse
uProcessedPassTimings._process.<locals>.parse
a_adjust_timings
raw_data
splitlines
u(?:\s*-+[a-zA-Z+ ]+-+)+
D uUser Time
uSystem Time
uUser+System
uWall Time
aInstr
aName
user
system
user_system
wall
instruction
pass_name
re
match
multicolheaders
findall
u[a-zA-Z][a-zA-Z+ ]+
strip
u\s*((?:[0-9]+\.)?[0-9]+)
headers
instruction
pat
wnaattrs
u\s+(?:
u\s*\(
u%\)|-+)
a_fields
Z
missing
u\s*(.*)
groups
utoo many values to unpack (expected 2)
update
aTotal
uAnalysis execution timing report
uunexpected text after parser finished:
a_name
a_records
config
aLLVM_PASS_TIMINGS
aRecordLLVMPassTimingsLegacy
a__enter__
a__exit__
T nnnaget
self
a_append
name
record_legacy
uPassTimingsCollection.record_legacy
aRecordLLVMPassTimings
pb
record
uPassTimingsCollection.record
aNamedTimings
timings
u<genexpr>
uPassTimingsCollection.get_total_time.<locals>.<genexpr>
sorted
uPassTimingsCollection.list_longest_first.<locals>.<lambda>
T akey
reverse
is_empty
uNo pass timings were recorded
a__self__
uPrinting pass timings for
uTotal time:
u== #
overall_time
ldu Percent:
u.1f
w%asummary
topn
l T atopn
indent
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
l
collections
T anamedtuple
namedtuple
ucollections.abc
T aSequence
aSequence
contextlib
T acontextmanager
contextmanager
cached_property
unumba.core
T aconfig
ullvmlite.binding
binding
