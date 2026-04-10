# Reconstructed from integrated Nuitka blob
# Module: uscipy._lib.cobyqa.framework

aTrustRegion
a__qualname__
a__init__
uTrustRegion.__init__
uTrustRegion.n
uTrustRegion.m_linear_ub
uTrustRegion.m_linear_eq
uTrustRegion.m_nonlinear_ub
uTrustRegion.m_nonlinear_eq
uTrustRegion.radius
setter
uTrustRegion.resolution
uTrustRegion.penalty
uTrustRegion.models
uTrustRegion.best_index
uTrustRegion.x_best
uTrustRegion.fun_best
uTrustRegion.cub_best
uTrustRegion.ceq_best
lag_model
uTrustRegion.lag_model
lag_model_grad
uTrustRegion.lag_model_grad
lag_model_hess
uTrustRegion.lag_model_hess
uTrustRegion.lag_model_hess_prod
lag_model_curv
uTrustRegion.lag_model_curv
uTrustRegion.sqp_fun
uTrustRegion.sqp_cub
uTrustRegion.sqp_ceq
T nnnuTrustRegion.merit
uTrustRegion.get_constraint_linearizations
get_trust_region_step
uTrustRegion.get_trust_region_step
get_geometry_step
uTrustRegion.get_geometry_step
get_second_order_correction_step
uTrustRegion.get_second_order_correction_step
get_reduction_ratio
uTrustRegion.get_reduction_ratio
increase_penalty
uTrustRegion.increase_penalty
decrease_penalty
uTrustRegion.decrease_penalty
uTrustRegion.set_best_index
T naget_index_to_remove
uTrustRegion.get_index_to_remove
update_radius
uTrustRegion.update_radius
enhance_resolution
uTrustRegion.enhance_resolution
uTrustRegion.shift_x_base
uTrustRegion.set_multipliers
uTrustRegion._get_low_penalty
uscipy\_lib\cobyqa\framework.py
T a.0
array
T wvalag
self
T alag
self
u<module scipy._lib.cobyqa.framework>
T a__class__
T aself
pb
options
constants
T aself
r_val_ub
r_val_eq
r_val
c_min
c_max
indices
f_min
f_max
c_min_neg
c_diff
penalty
T aself
T aself
options
T aself
wxaaub
bub
aeq
beq
T aself
k_new
options
coord_vec
lag
g_lag
xl
xu
step
sigma
xpt
step_alt
sigma_alt
aub
bub
aeq
beq
tol_bd
tol_ub
free_xl
free_xu
free_ub
n_act
wqag_lag_proj
norm_g_lag_proj
cbd
cub
ceq
maxcv_val
tol
T aself
x_new
dist_sq
sigma
weights
k_max
T	aself
step
fun_val
cub_val
ceq_val
merit_old
merit_new
merit_model_old
merit_model_new
T aself
step
options
aub
bub
aeq
beq
xl
xu
radius
soc_step
tol
Taself
options
aub
bub
aeq
beq
xl
xu
radius
normal_step
tol
g_best
tangential_step
T
self
step
aub
bub
aeq
beq
viol_diff
sqp_val
threshold
best_index_save
T aself
wxT aself
wvT aself
hess
T aself
wxafun_val
cub_val
ceq_val
m_val
c_val
T aself
radius
T aself
resolution
T	aself
best_index
m_best
r_best
tol
wkax_val
m_val
r_val
T aself
wxaincl_linear_ub
incl_nonlinear_ub
incl_xl
incl_xu
m_linear_ub
m_nonlinear_ub
m_xl
m_xu
identity
c_jac
g_best
xl_lm
res
T aself
step
T aself
step
ratio
s_norm

.scipy._lib.cobyqa.main
aOptions
aVERBOSE
aDEFAULT_OPTIONS
aFEASIBILITY_TOL
aSCALE
aSTORE_HISTORY
aHISTORY_SIZE
l
uThe size of the history must be positive.
aFILTER_SIZE
uThe size of the filter must be positive.
aDEBUG
aObjectiveFunction
a__len__
aBoundConstraints
a_get_bounds
a_get_constraints
utoo many values to unpack (expected 2)
aLinearConstraints
aNonlinearConstraints
aProblem
a_set_default_options
wna_set_default_constants
bounds
is_feasible
a_build_result
Z
aExitStatus
aINFEASIBLE_ERROR
aFIXED_SUCCESS
print
T uStarting the optimization procedure.
uInitial trust-region radius:
aRHOBEG

w.uFinal trust-region radius:
aRHOEND
uMaximum number of function evaluations:
aMAX_EVAL
uMaximum number of iterations:
aMAX_ITER
aTrustRegion
aTargetSuccess
aTARGET_SUCCESS
aCallbackSuccess
aCALLBACK_SUCCESS
aFeasibleSuccess
aFEASIBLE_SUCCESS
aMaxEvalError
aMAX_ITER_WARNING
np
linalg
aLinAlgError
aLINALG_ERROR
n_iter
options
norm
framework
x_best
models
interpolation
x_base
aConstants
aLARGE_SHIFT_FACTOR
radius
shift_x_base
get_trust_region_step
aSHORT_STEP_THRESHOLD
resolution
aDECREASE_RESOLUTION_FACTOR
n_short_steps
l an_very_short_steps
f       ?l l aget_index_to_remove
max
aRESOLUTION_FACTOR
increase_penalty
a_eval
pb
utoo many values to unpack (expected 3)
aMAX_EVAL_WARNING
merit
fun_best
cub_best
ceq_best
type
unonlinearly constrained
aBYRD_OMOJOKUN_FACTOR
f
@aget_second_order_correction_step
get_reduction_ratio
step
fun_val
cub_val
ceq_val
update_interpolation
set_best_index
update_radius
aVERY_LOW_RATIO
n_alt_models
fun_grad
fun_alt_grad
aLARGE_GRADIENT_FACTOR
reset_models
set_multipliers
aLOW_RATIO
aRADIUS_SUCCESS
enhance_resolution
decrease_penalty
maxcv
a_print_step
uNew trust-region radius:
build_x
n_eval
get_geometry_step
k_new
penalty
aBounds
full
inf
lb
shape
ub
uThe bounds must have
u elements.
asarray
l uThe shape of the bounds is not compatible with the number of variables.
T :nnnl
T :nnnl uThe bounds must be an instance of scipy.optimize.Bounds or an array-like object.
aLinearConstraint
exact_1d_array
uThe lower bound of the linear constraints must be a vector.
uThe upper bound of the linear constraints must be a vector.
linear_constraints
wAabroadcast_arrays
aNonlinearConstraint
uThe lower bound of the nonlinear constraints must be a vector.
uThe upper bound of the nonlinear constraints must be a vector.
nonlinear_constraints
fun
T aeq
ineq
uThe constraint type must be "eq" or "ineq".
callable
uThe constraint function must be callable.
args
get
T aargs
T
uThe constraints must be instances of scipy.optimize.LinearConstraint, scipy.optimize.NonlinearConstraint, or dict.
uThe initial trust-region radius must be positive.
uThe final trust-region radius must be nonnegative.
uThe initial trust-region radius must be greater than or equal to the final trust-region radius.
min
value
aNPT
uThe number of interpolation points must be positive.
uThe number of interpolation points must be at most
setdefault
uThe maximum number of function evaluations must be positive.
uThe maximum number of iterations must be positive.
aTARGET
a__members__
values
warnings
warn
uUnknown option:
aRuntimeWarning
aDECREASE_RADIUS_FACTOR
aDEFAULT_CONSTANTS
f
?uThe constant decrease_radius_factor must be in the interval (0, 1).
aINCREASE_RADIUS_THRESHOLD
uThe constant increase_radius_threshold must be greater than 1.
aINCREASE_RADIUS_FACTOR
uThe constant increase_radius_factor must be greater than 1.
aDECREASE_RADIUS_THRESHOLD
uThe constant decrease_radius_threshold must be greater than 1.
uThe constant decrease_radius_threshold must be less than increase_radius_factor.
f
?uThe constant decrease_resolution_factor must be in the interval (0, 1).
aLARGE_RESOLUTION_THRESHOLD
uThe constant large_resolution_threshold must be greater than 1.
aMODERATE_RESOLUTION_THRESHOLD
uThe constant moderate_resolution_threshold must be greater than 1.
uThe constant moderate_resolution_threshold must be at most large_resolution_threshold.
uThe constant low_ratio must be in the interval (0, 1).
aHIGH_RATIO
uThe constant high_ratio must be in the interval (0, 1).
uThe constant low_ratio must be at most high_ratio.
uThe constant very_low_ratio must be in the interval (0, 1).
aPENALTY_INCREASE_THRESHOLD
uThe constant penalty_increase_threshold must be greater than or equal to 1.
aPENALTY_INCREASE_FACTOR
uThe constant penalty_increase_factor must be greater than 1.
uThe constant penalty_increase_factor must be greater than or equal to penalty_increase_threshold.
uThe constant short_step_threshold must be in the interval (0, 1).
aLOW_RADIUS_FACTOR
uThe constant low_radius_factor must be in the interval (0, 1).
uThe constant byrd_omojokun_factor must be in the interval (0, 1).
aTHRESHOLD_RATIO_CONSTRAINTS
uThe constant threshold_ratio_constraints must be greater than 1.
uThe constant large_shift_factor must be nonnegative.
uThe constant large_gradient_factor must be greater than 1.
uThe constant resolution_factor must be greater than 1.
aIMPROVE_TCG
uUnknown constant:
is_feasibility
best_eval
isfinite
aOptimizeResult
uThe lower bound for the trust-region radius has been reached
uThe target objective function value has been reached
uAll variables are fixed by the bound constraints
uThe callback requested to stop the optimization procedure
uThe feasibility problem received has been solved successfully
uThe maximum number of function evaluations has been exceeded
uThe maximum number of iterations has been exceeded
uThe bound constraints are infeasible
uA linear algebra error occurred
uUnknown exit status
message
success
status
wxanfev
nit
fun_history
maxcv_history
uNumber of function evaluations:
uNumber of iterations:
uLeast value of
fun_name
u:
uMaximum constraint violation:
printoptions
aPRINT_OPTIONS
a__enter__
a__exit__
uCorresponding point:
T nnna__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.optimize
T aBounds
aLinearConstraint
aNonlinearConstraint
aOptimizeResult
T aTrustRegion
problem
T aObjectiveFunction
aBoundConstraints
aLinearConstraints
aNonlinearConstraints
aProblem
utils
T aMaxEvalError
aTargetSuccess
aCallbackSuccess
aFeasibleSuccess
exact_1d_array
settings
T aExitStatus
aOptions
aConstants
aDEFAULT_OPTIONS
aDEFAULT_CONSTANTS
aPRINT_OPTIONS
T T
nT
nnaminimize
uscipy\_lib\cobyqa\main.py
u<module scipy._lib.cobyqa.main>
T
pb
penalty
success
status
n_iter
options
wxafun
maxcv
result
T	apb
framework
step
options
x_eval
fun_val
cub_val
ceq_val
r_val
T abounds
wnT aconstraints
linear_constraints
nonlinear_constraints
constraint
lb
ub
T amessage
pb
wxafun_val
r_val
n_eval
n_iter
T akwargs
constants
key
T aoptions
wnakey
T3afun
x0
args
bounds
constraints
callback
options
kwargs
verbose
feasibility_tol
scale
store_history
history_size
filter_size
debug
obj
n_orig
linear_constraints
nonlinear_constraints
linear
nonlinear
pb
constants
framework
success
n_iter
k_new
n_short_steps
n_very_short_steps
n_alt_models
status
radius_save
normal_step
tangential_step
step
s_norm
enhance_resolution
improve_geometry
dist_new
same_best_point
fun_val
cub_val
ceq_val
merit_old
merit_new
soc_step
ratio
ill_conditioned
grad
grad_alt
maxcv_val
.scipy._lib.cobyqa.models
aOptions
aDEBUG
a_debug
f
?anp
min
bounds
xu
xl
aRHOBEG
value
aRHOEND
copy
x0
a_x_base
x_base
minimum
maximum
zeros
wnaNPT
a_xpt
l apb
self
xpt
l f
@f
a_lhs_cache
shape
l
:nnnaarray_equal
waaright_scaling
eigh
max
linalg
norm
D aaxis
l
aEPS
T ainitial
utoo many values to unpack (expected 2)
wTf
?aempty
D acheck_finite
Fanpt
uThe number of interpolation points must be at least

w.a_get_model
utoo many values to unpack (expected 4)
a_const
a_grad
a_i_hess
a_e_hess
size
hess_prod
newaxis
outer
Z
grad
build_system
utoo many values to unpack (expected 3)
all
isfinite
aLinAlgError
T uThe interpolation system is ill-defined.
abs
aQuadratic
solve_systems
block
aInterpolation
a_interpolation
interpolation
point
T l
full
nan
a_fun_val
a_cub_val
a_ceq_val
aMAX_EVAL
aMaxEvalError
fun_init
fun_val
cub_init
cub_val
ceq_init
ceq_val
penalty
is_feasibility
maxcv
wkaFEASIBILITY_TOL
aFeasibleSuccess
aTARGET
aTargetSuccess
a_fun
m_nonlinear_ub
T adtype
a_cub
m_nonlinear_eq
a_ceq
a_check_interpolation_conditions
hess
curv
array
a_get_cub
wxareshape
q wva_get_ceq
fun
cub
ceq
update
ill_conditioned
k_new
dir_old
T :nnnl
eye
diag
shift_x_base
new_x_base
error_fun
error_cub
error_ceq
f
$@asqrt
D ainitial
f
?awarnings
warn
uThe interpolation conditions for the objective function are not satisfied.
aRuntimeWarning
uThe interpolation conditions for the inequality constraint function are not satisfied.
uThe interpolation conditions for the equality constraint function are not satisfied.
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.linalg
T aeigh
settings
T aOptions
utils
T aMaxEvalError
aTargetSuccess
aFeasibleSuccess
finfo
T Ofloat
eps
