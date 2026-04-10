# Reconstructed from integrated Nuitka blob
# Module: T l    l ujinja2.bccache

a__qualname__
a__init__
uBucket.__init__
uBucket.reset
uBucket.load_bytecode
uBucket.write_bytecode
uBucket.bytecode_from_string
uBucket.bytecode_to_string
aBytecodeCache
uBytecodeCache.load_bytecode
uBytecodeCache.dump_bytecode
clear
uBytecodeCache.clear
T nuBytecodeCache.get_cache_key
uBytecodeCache.get_source_checksum
get_bucket
uBytecodeCache.get_bucket
set_bucket
uBytecodeCache.set_bucket
a__prepare__
aFileSystemBytecodeCache
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
T nu__jinja2_%s.cache
uFileSystemBytecodeCache.__init__
uFileSystemBytecodeCache._get_default_cache_dir
uFileSystemBytecodeCache._get_cache_filename
uFileSystemBytecodeCache.load_bytecode
uFileSystemBytecodeCache.dump_bytecode
uFileSystemBytecodeCache.clear
a__orig_bases__
aMemcachedBytecodeCache
T ujinja2/bytecode/
ntuMemcachedBytecodeCache.__init__
uMemcachedBytecodeCache.load_bytecode
uMemcachedBytecodeCache.dump_bytecode
ujinja2\bccache.py
u<module jinja2.bccache>
T a__class__
T aself
environment
key
checksum
T aself
directory
pattern
T aself
client
prefix
timeout
ignore_memcache_errors
T aself
bucket
T aself
a_unsafe_dir
tmpdir
dirname
actual_dir
weaactual_dir_stat
T aself
string
T aself
out
T aself
T aself
remove
files
filename
T aself
bucket
name
wfaremove_silent
T aself
bucket
key
value
T aself
environment
name
filename
source
key
checksum
bucket
T aself
name
filename
hash
T aself
source
T aself
wfamagic
checksum
T aself
bucket
filename
wfT aself
bucket
code
T wfT aself
wf.jinja2.compiler
@
a anew_func
uoptimizeconst.<locals>.new_func
update_wrapper
optimizer
eval_ctx
volatile
visit
wfaoptimizeconst
visitor
u_make_binop.<locals>.visitor
environment
sandboxed
op
intercepted_binops
write
uenvironment.call_binop(context,

u,
left
T u,
right
T w(w T w)u_make_unop.<locals>.visitor
intercepted_unops
uenvironment.call_unop(context,
node
w(anodes
aTemplate
uCan't compile non template nodes
code_generator_class
stream
getvalue
aEllipsis
aMarkup
P Otuple
Olist
Oset
Ofrozenset
items
has_safe_repr
u<genexpr>
uhas_safe_repr.<locals>.<genexpr>
utoo many values to unpack (expected 2)
aUndeclaredNameVisitor
aVisitorExit
undeclared
accesses_caller
accesses_kwargs
accesses_varargs
parent
aSymbols
T alevel
symbols
require_output_check
buffer
block
toplevel
rootlevel
loop_frame
block_frame
soft_frame
a__new__
update
copy
aFrame
level
l afilters
tests
generic_visit
add
name
names
ctx
load
discard
aStringIO
filename
created_block_context
defer_init
aOptimizer
import_aliases
blocks
l
extends_so_far
has_known_extends
code_lineno
debug_info
a_write_debug_info
a_new_lines
a_last_line
a_first_write
a_last_identifier
a_indentation
a_assign_stack
a_param_def_block
context
a_context_reference_stack
aTemplateAssertionError
t_
temporary_identifier
writeline
u = []
T uif context.eval_ctx.autoescape:
indent
ureturn Markup(concat(
u))
outdent
T uelse:
ureturn concat(
w)aautoescape
uyield
u.append(
start_write
end_write
T apass
self
frame
aCompilerExit
w
append

newline
max
lineno
chain
kwargs
args
w=adyn_args
T u, *
dyn_kwargs
T u, **dict({
T u, **{
key
u:
value
T u}, **
T w}T u, **
uCodeGenerator.signature.<locals>.<genexpr>
is_python_keyword
cast
aDependencyFinderVisitor
utoo many values to unpack (expected 3)
sorted
id_map
T utry:
u = environment.
w[w]T uexcept KeyError:
T u@internalcode
udef
u(*unused):
uraise TemplateRuntimeError("No
:nq nu named
u found.")
loads
aVAR_LOAD_PARAMETER
aVAR_LOAD_RESOLVE
u =
get_resolve_func
aVAR_LOAD_ALIAS
aVAR_LOAD_UNDEFINED
undefs
uunknown load instruction
u = missing
is_async
choose_async
inner
analyze_node
aMacroRef
caller
T akwargs
varargs
skip_special_params
ref
find_undeclared
body
T acaller
kwargs
varargs
explicit_caller
defaults
fail
uWhen defining macros or call blocks the special "caller" argument must be omitted or be given a default.
declare_parameter
T acaller
T akwargs
varargs
T avarargs
func
T amacro
u):
enter_frame
push_parameter_definitions
uif
u is missing:
u = undefined("parameter
u was not provided", name=
default
mark_parameter_stored
pop_parameter_definitions
blockvisit
return_buffer_contents
D aforce_unescaped
taleave_frame
D awith_python_scope
tw,uMacro(environment, macro,
u, (
u),
u, context.eval_ctx.autoescape)
uCodeGenerator.macro_def.<locals>.<genexpr>
uline
u in
dump_stores
w{w}uCodeGenerator.dump_local_context.<locals>.<genexpr>
T uresolve = context.resolve_or_missing
T uundefined = environment.undefined
T uconcat = environment.concat
T ucond_expr_undefined = Undefined
T uif 0: yield None
dump_param_targets
pop
q aresolve
u.resolve
get_context_ref
u.derived(
dump_local_context
:nl nw_u_loop_vars[
u] =
u_block_vars[
ucontext.vars[
T u_loop_vars.update({
T u_block_vars.update({
T ucontext.vars.update({
T u})
ucontext.exported_vars.add(
repr
ucontext.exported_vars.update((
aEvalContext
runtime
T aasync_exported
async_exported
T aexported
exported
ufrom jinja2.runtime import
u, environment=environment
find
aExtends
find_all
aBlock
ublock
u defined twice
aImportedName
importname
w.arsplit
T w.l ufrom
u import
u as
uimport
uname =
T aroot
u(context, missing=missing
D aextra
l awrite_commons
T aself
u = TemplateReference(context)
T uparent_template = None
pull_dependencies
T uif parent_template is not None:
T uyield from parent_template.root_render_func(context)
T uagen = parent_template.root_render_func(context)
T uasync for event in agen:
T uyield event
T ufinally: await agen.aclose()
block_
T aself
super
super
T asuper
u = context.super(
u, block_
T u_block_vars = {}
ublocks = {
w&udebug_info =
u: block_
uCodeGenerator.visit_Template.<locals>.<genexpr>
T uif parent_template is None:
scoped
derive_context
required
uif len(context.blocks[
u]) <= 1:
uraise TemplateRuntimeError("Required block
u not found")
uyield from context.blocks[
u][0](
ugen = context.blocks[
ufor event in gen:
simple_write
event
ufinally:
T uawait gen.aclose()
ugen.close()
ucannot use extend from a non top-level scope
T uraise TemplateRuntimeError("extended multiple times")
uparent_template = environment.get_template(
template
T ufor name, parent_block in parent_template.blocks.items():
T ucontext.blocks.setdefault(name, []).append(parent_block)
ignore_missing
get_or_select_template
aConst
get_template
T Otuple
Olist
select_template
aTuple
aList
utemplate = environment.
T uexcept TemplateNotFound:
loop_body
uCodeGenerator.visit_Include.<locals>.loop_body
with_context
ugen = template.root_render_func(template.new_context(context.get_all(), True,
T ufor event in (await template._get_default_module_async())._body_stream:
T uyield from template._get_default_module()._body_stream
T uawait
uenvironment.get_template(
u).
make_module
T a_async
u(context.get_all(), True,
a_get_default_module
u(context)
target
a_import_common
startswith
T w_ucontext.exported_vars.discard(
T uincluded_template =
u = getattr(included_template,
u, missing)
position
replace
T w{u{{
T w}u}}
uthe template {included_template.__name__!r} (imported on
u) does not export the requested name
u = undefined(f
u, name=
var_names
discarded_names
ucontext.vars.update({
u})
ucontext.exported_vars.difference_update((
uCodeGenerator.visit_FromImport.<locals>.<genexpr>
recursive
loop
iter_child_nodes
T T abody
T aonly
T aloop
D afor_branch
body
else_
D afor_branch
else
test
D afor_branch
test
u(fiter):
T uasync for
ufor
T u in
T uauto_aiter(fiter)
fiter
T w:T uyield
T l u(reciter, loop_render_func, depth=0):
aName
store
uCan't assign to special loop variable in for-loop target
u = 1
T aAsync
uLoopContext(
loop_filter_func
T areciter
T uauto_aiter(
aiter
T u, undefined, loop_render_func, depth):
u, undefined):
w:T u_loop_vars = {}
iteration_indicator
u = 0
T awith_python_scope
uloop(
T u, loop)
difference_update
stores
uCodeGenerator.visit_For.<locals>.<genexpr>
soft
elif_
uelif
if_frame
macro_body
macro_def
T ucaller =
visit_Call
call
D aforward_caller
tavisit_Filter
filter
targets
values
with_frame
T u =
a_finalize
a_default_finalize
finalize
uenvironment.finalize(
a_PassArg
eval_context
ucontext.eval_ctx
from_obj
uCodeGenerator._make_finalize.<locals>.finalize
a_FinalizeInfo
env_finalize
concat
as_const
escape
aTemplateData
const
T u(escape if context.eval_ctx.autoescape else str)(
T uescape(
T ustr(
src
a_make_finalize
aImpossible
a_output_child_to_const
u.extend((
a_output_const_repr
a_output_child_pre
item
a_output_child_post
T w,apush_assign_tracking
aNSRef
seen_refs
uif not isinstance(
u, Namespace):
T uraise TemplateRuntimeError("cannot assign attribute on non-namespace object")
pop_assign_tracking
T u = (Markup if context.eval_ctx.autoescape else identity)(
uconcat(
find_load
parameter_is_undeclared
u(undefined(name=
u) if
u is missing else
attr
u(Markup if context.eval_ctx.autoescape else identity)(
data
idx
u,)
T w[T w]T w{T u:
u(markup_join if context.eval_ctx.volatile else str_join)
markup_join
str_join
u((
T u))
expr
ops
operators
T u(await auto_await(
T uenvironment.getattr(
arg
aSlice
T uenvironment.getitem(
start
stop
step
is_filter
get
uNo
signature
a_filter_test_common
uCodeGenerator._filter_test_common
a__enter__
a__exit__
u(Markup(concat(
u)) if context.eval_ctx.autoescape else concat(
uMarkup(concat(
T nnnawrite_expr2
uCodeGenerator.visit_CondExpr.<locals>.write_expr2
expr1
T u if
T u else
expr2
ucond_expr_undefined("the inline if-expression on
u evaluated to false and no else section was defined.")
T uenvironment.call(context,
T ucontext.call(
D acaller
caller
D a_loop_vars
a_loop_vars
D a_block_vars
a_block_vars
extra_kwargs
T uMarkup(
T u(Markup if context.eval_ctx.autoescape else identity)(
uenvironment.
uenvironment.extensions[
identifier
u].
T acontext
continue
break
u.vars =
push_context_reference
T tT aisolated
pop_context_reference
options
ucontext.eval_ctx.
val
save
u = context.eval_ctx.save()
visit_EvalContextModifier
revert
ucontext.eval_ctx.revert(
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
wtacontextlib
T acontextmanager
contextmanager
itertools
T achain
keyword
T aiskeyword
iskeyword
markupsafe
T aescape
T aMarkup
T anodes
exceptions
T aTemplateAssertionError
idtracking
T aSymbols
T aVAR_LOAD_ALIAS
T aVAR_LOAD_PARAMETER
T aVAR_LOAD_RESOLVE
T aVAR_LOAD_UNDEFINED
T aEvalContext
T aOptimizer
utils
T a_PassArg
T aconcat
T aNodeVisitor
aNodeVisitor
aTypeVar
aCallable
aAny
T wFT abound
wFD aeq
ne
gt
gteq
lt
lteq
in
notin
u==
u!=
w>u>=
w<u<=
in
unot in
a_make_binop
a_make_unop
T nFtagenerate
