# Reconstructed from integrated Nuitka blob
# Module: uscipy.optimize._hessian_update_strategy

a__qualname__
initialize
uHessianUpdateStrategy.initialize
update
uHessianUpdateStrategy.update
uHessianUpdateStrategy.dot
get_matrix
uHessianUpdateStrategy.get_matrix
a__matmul__
uHessianUpdateStrategy.__matmul__
a__prepare__
aFullHessianUpdateStrategy
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
T asyr
wdT adtype
T asyr2
wdT asymv
wdT aauto
uFullHessianUpdateStrategy.__init__
uFullHessianUpdateStrategy.initialize
uFullHessianUpdateStrategy._auto_scale
uFullHessianUpdateStrategy._update_implementation
uFullHessianUpdateStrategy.update
uFullHessianUpdateStrategy.dot
uFullHessianUpdateStrategy.get_matrix
a__orig_bases__
T askip_update
naauto
uBFGS.__init__
uBFGS._update_inverse_hessian
uBFGS._update_hessian
uBFGS._update_implementation
T f: 0  yE>aauto
uSR1.__init__
uSR1._update_implementation
uscipy\optimize\_hessian_update_strategy.py
u<module scipy.optimize._hessian_update_strategy>
T a__class__
T aself
exception_strategy
min_curvature
init_scale
a__class__
T aself
init_scale
T aself
min_denominator
init_scale
a__class__
T aself
wpT aself
delta_x
delta_grad
s_norm2
y_norm2
ys
T aself
ys
aBs
sBs
wyT
self
delta_x
delta_grad
wwwzawz
aMw
wMw
scale
update_factor
T aself
delta_x
delta_grad
T aself
delta_x
delta_grad
wwwzaMw
z_minus_Mw
denominator
T aself
ys
aHy
yHy
wsT aself
wMali
T aself
T aself
wnaapprox_type
T aself
delta_x
delta_grad
scale
replace
shape
dtype
init_shape
.scipy.optimize._highspy._highs_wrapper
size
np
sum
l
D wxafun
nna_h
aHighsLp
num_col_
num_row_
a_matrix_
aMatrixFormat
kColwise
format_
col_cost_
col_lower_
col_upper_
row_lower_
row_upper_
start_
index_
value_
aHighsVarType
integrality_
a_Highs
aHighsOptions
hopt
aHighsOptionsManager
items
utoo many values to unpack (expected 2)
T asense
hoptmanager
get_option_type
q awarn
uUnrecognized options detected:

aOptimizeWarning
D astacklevel
l T apresolve
parallel
on
off
uOption f"
u" is "
u", but only True or False is allowed. Using default.
aHighsOptionType
check_option
highs
kBool
passOptions
aHighsStatus
kError
status
getModelStatus
message
modelStatusToString
passModel
aHighsModelStatus
kModelError
run
getInfo
kOptimal
kTimeLimit
kIterationLimit
kSolutionLimit
objective_function_value
kHighsInf
umodel_status is
u; primal_status is
solutionStatusToString
primal_solution_status
simplex_nit
simplex_iteration_count
ipm_nit
ipm_iteration_count
crossover_nit
crossover_iteration_count
getSolution
getBasis
zeros
l acol_status
col_dual
aHighsBasisStatus
kLower
marg_bnds
kUpper
l wxaarray
col_value
slack
row_value
lambda
row_dual
fun
mip_node_count
mip_dual_bound
mip_gap
getOptionType
kOk
T q uInvalid option name.
kInt
kDouble
kString
check_string_option
T q uInvalid option value.
check_double_option
check_int_option
T l uUnknown option type.
getOptionValue
T l uFailed to validate option value.
T l
uCheck option succeeded.
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
warnings
T awarn
numpy
uscipy.optimize._highspy._core
optimize
a_highspy
a_core
uscipy.optimize._highspy
T a_highs_options
a_highs_options
uscipy.optimize
T aOptimizeWarning
a_highs_wrapper
uscipy\optimize\_highspy\_highs_wrapper.py
u<module scipy.optimize._highspy._highs_wrapper>
T%wcaindptr
indices
data
lhs
rhs
lb
ub
integrality
options
numcol
numrow
isMip
res
lp
highs
highs_options
hoptmanager
key
val
opt_type
status
msg
opt_status
init_status
err_model_status
run_status
model_status
info
mipFailCondition
lpFailCondition
solution
basis
marg_bnds
basis_col_status
solution_col_dual
ii
T	ahighs_inst
option
value
status
option_type
hoptmanager
valid_types
expected_type
current_value
.scipy.optimize._highspy
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_scipy
u\not_existing
uoptimize\_highspy
T aNUITKA_PACKAGE_scipy_optimize
u\not_existing
a_highspy
T aNUITKA_PACKAGE_scipy_optimize__highspy
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
uscipy\optimize\_highspy\__init__.py
u<module scipy.optimize._highspy>

.scipy.optimize._isotonic
,
np
atleast_1d
:nnn:nnq aarray
wCafloat64
T aorder
dtype
copy
ones_like
T adtype
ndim
l ashape
l
uInput arrays y and w must have one dimension of equal length.
any
uWeights w must be strictly positive.
full
q aintp
T ashape
fill_value
dtype
pava
utoo many values to unpack (expected 4)
aOptimizeResult
T wxaweights
blocks
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
aTYPE_CHECKING
numpy
a_optimize
T aOptimizeResult
a_pava_pybind
T apava
isotonic_regression
a__all__
D aweights
increasing
ntuscipy\optimize\_isotonic.py
u<module scipy.optimize._isotonic>
T wyaweights
increasing
yarr
order
wxawx
warr
wnwrwbu
.scipy.optimize._lbfgsb_py
d
aMemoizeJac
derivative
a_wrap_callback
disp
iprint
maxcor
ftol
np
finfo
T Ofloat
eps
gtol
maxfun
maxiter
callback
maxls
a_minimize_lbfgsb
fun
args
jac
bounds
grad
task
message
funcalls
nfev
nit
warnflag
status
wxa_check_unknown_options
asarray
ravel
shape
utoo many values to unpack (expected 1)
a_NoValue
warnings
warn
uscipy.optimize: The `disp` and `iprint` options of the L-BFGS-B solver are deprecated and will be removed in SciPy 1.18.0.
aDeprecationWarning
D astacklevel
l ulength of x0 != length of bounds
array
old_bound_to_new
l
l aany
uLBFGSB - one of the lower bounds is greater than an upper bound.
clip
a_prepare_scalar_function
x0
T ajac
args
epsilon
bounds
finite_diff_rel_step
workers
fun_and_grad
zeros
int32
float64
inf
T l pl l utoo many values to unpack (expected 2)
isinf
low_bnd
upper_bnd
wLwUanbd
umaxls must be positive.
T adtype
T Z
l l l T l T l T l,T l wgaastype
a_lbfgsb
setulb
wmwfafactr
pgtol
wa
iwa
lsave
isave
dsave
ln_task
func_and_grad
n_iterations
aOptimizeResult
T wxafun
a_call_callback_maybe_halt
l  l  asf
l  l areshape
l amin
aLbfgsInvHessProduct
status_messages
u:
task_messages
ngev
T
fun
jac
nfev
njev
nit
status
message
wxasuccess
hess_inv
ndim
usk and yk must have matching shape, (n_corrs, n)
a__class__
a__init__
T adtype
shape
sk
yk
n_corrs
einsum
uij,ij->i
rho
utoo many values to unpack (expected 4)
dtype
T adtype
copy
T q aempty
q adot
wqaalpha
wrwQ:nnnanewaxis
wRaeye
a_matmat
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
T aarray
asarray
float64
zeros

T a_lbfgsb
a_optimize
T aMemoizeJac
aOptimizeResult
a_call_callback_maybe_halt
a_wrap_callback
a_check_unknown_options
a_prepare_scalar_function
a_constraints
T aold_bound_to_new
uscipy.sparse.linalg
T aLinearOperator
aLinearOperator
uscipy._lib.deprecation
T a_NoValue
fmin_l_bfgs_b
a__all__
D	l
l l l l l l l l aSTART
aNEW_X
aRESTART
aFG
aCONVERGENCE
aSTOP
aWARNING
aERROR
aABNORMAL
D l
l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  u
ppuNORM OF PROJECTED GRADIENT <= PGTOL
uRELATIVE REDUCTION OF F <= FACTR*EPSMCH
uCPU EXCEEDING THE TIME LIMIT
uTOTAL NO. OF F,G EVALUATIONS EXCEEDS LIMIT
uPROJECTED GRADIENT IS SUFFICIENTLY SMALL
uTOTAL NO. OF ITERATIONS REACHED LIMIT
uCALLBACK REQUESTED HALT
uROUNDING ERRORS PREVENT PROGRESS
uSTP = STPMAX
uSTP = STPMIN
uXTOL TEST SATISFIED
uNO FEASIBLE SOLUTION
uFACTR < 0
uFTOL < 0
uGTOL < 0
uXTOL < 0
uSTP < STPMIN
uSTP > STPMAX
uSTPMIN < 0
uSTPMAX < STPMIN
uINITIAL G >= 0
uM <= 0
uN <= 0
uINVALID NBD
l
f
cAf h     >f: 0  yE>l ul f
#>a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
