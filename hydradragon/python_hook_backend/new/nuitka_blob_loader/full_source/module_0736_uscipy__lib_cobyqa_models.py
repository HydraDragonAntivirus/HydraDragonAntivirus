# Reconstructed from integrated Nuitka blob
# Module: uscipy._lib.cobyqa.models

a__qualname__
a__init__
uInterpolation.__init__
uInterpolation.n
uInterpolation.npt
uInterpolation.xpt
setter
uInterpolation.x_base
uInterpolation.point
uQuadratic.__init__
a__call__
uQuadratic.__call__
uQuadratic.n
uQuadratic.npt
uQuadratic.grad
uQuadratic.hess
uQuadratic.hess_prod
uQuadratic.curv
uQuadratic.update
uQuadratic.shift_x_base
uQuadratic.solve_systems
uQuadratic._get_model
aModels
uModels.__init__
uModels.n
uModels.npt
uModels.m_nonlinear_ub
uModels.m_nonlinear_eq
uModels.interpolation
uModels.fun_val
uModels.cub_val
uModels.ceq_val
uModels.fun
fun_grad
uModels.fun_grad
fun_hess
uModels.fun_hess
fun_hess_prod
uModels.fun_hess_prod
fun_curv
uModels.fun_curv
fun_alt_grad
uModels.fun_alt_grad
T nuModels.cub
cub_grad
uModels.cub_grad
cub_hess
uModels.cub_hess
cub_hess_prod
uModels.cub_hess_prod
cub_curv
uModels.cub_curv
uModels.ceq
ceq_grad
uModels.ceq_grad
ceq_hess
uModels.ceq_hess
ceq_hess_prod
uModels.ceq_hess_prod
ceq_curv
uModels.ceq_curv
reset_models
uModels.reset_models
update_interpolation
uModels.update_interpolation
determinants
uModels.determinants
uModels.shift_x_base
uModels._get_cub
uModels._get_ceq
uModels._check_interpolation_conditions
uscipy\_lib\cobyqa\models.py
u<module scipy._lib.cobyqa.models>
T a__class__
T aself
wxainterpolation
x_diff
T aself
pb
options
max_radius
very_close_xl_idx
close_xl_idx
very_close_xu_idx
close_xu_idx
wkaspread
k1
k2
T
self
pb
options
penalty
x_eval
fun_init
cub_init
ceq_init
wkwiT aself
interpolation
values
debug
w_T aself
error_fun
error_cub
error_ceq
wkatol
T aself
mask
T ainterpolation
values
wnanpt
wxaill_conditioned
T ainterpolation
a_cache
scale
xpt_scale
wnanpt
waaright_scaling
eig_values
eig_vectors
new_cache
T aself
wxamask
T aself
wvamask
T aself
T aself
wvainterpolation
T
self
x_new
k_new
shift
new_col
inv_new_col
beta
coord_vec
alpha
tau
T aself
wxT aself
wxamodel
T aself
wvT aself
interpolation
T aself
wkT aself
wiT aself
new_x_base
options
model
shift
T aself
interpolation
new_x_base
shift
update
T ainterpolation
rhs
wnanpt
waaright_scaling
eig
rhs_scaled
eig_values
eig_vectors
large_eig_values
inv_eig_values
ill_conditioned
left_scaled_solutions
T	aself
interpolation
k_new
dir_old
values_diff
const
grad
i_hess
ill_conditioned
T aself
k_new
x_new
fun_val
cub_val
ceq_val
fun_diff
cub_diff
ceq_diff
dir_old
ill_conditioned
wiT aself
x_base
T aself
xpt
.scipy._lib.cobyqa.problem
a_fun
a_verbose
a_args
l
a_n_eval
np
array
D adtype
Ofloat
Z
squeeze
l aprintoptions
aPRINT_OPTIONS
a__enter__
a__exit__
print
name

w(u) =
T nnna__name__
fun
lb
a_xl
ub
a_xu
inf
xl
isnan
xu
all
is_feasible
count_nonzero
wmaPreparedConstraint
ones
size
pcs
asarray
violation
clip
empty
a_a_ub
T l
a_b_ub
a_a_eq
a_b_eq
abs
get_arrays_tol
any
vstack
self
a_eq
wAaconcatenate
b_eq
f
?aa_ub
b_ub
isinf
:nnnwnamax
D ainitial
Z
wxa_constraints
a_map_ub
a_map_eq
a_m_ub
a_m_eq
callable
jac
copy
u<lambda>
uNonlinearConstraints.__call__.<locals>.<lambda>
hess
f_updated
append
arange
bounds
utoo many values to unpack (expected 2)
suppress
T EAttributeError
c_ub
c_eq
uThe number of nonlinear inequality constraints is unknown.
uThe number of nonlinear equality constraints is unknown.
nfev
T acub_val
ceq_val
a_obj
a_linear
a_nonlinear
uThe callback must be a callable function.
a_callback
exact_1d_array
uThe initial guess must be a vector.
uThe bounds must have
u elements.
shape
uThe left-hand side matrices of the linear constraints must have
u columns.
a_fixed_idx
a_fixed_val
a_orig_bounds
aBoundConstraints
aBounds
a_bounds
project
a_x0
aLinearConstraints
aLinearConstraint
isfinite
a_scaling_factor
a_scaling_shift
diag
zeros
a_feasibility_tol
a_filter_size
a_fun_filter
a_maxcv_filter
a_x_filter
a_store_history
a_history_size
a_fun_history
a_maxcv_history
a_x_history
build_x
maxcv
pop
q afun_val
maxcv_val
signature
best_eval
utoo many values to unpack (expected 3)
parameters
S aintermediate_result
aOptimizeResult
T wxafun
T aintermediate_result
aCallbackSuccess
aBARRIER
min
maximum
minimum
u<genexpr>
uProblem.__call__.<locals>.<genexpr>
x0
n_eval
linear
m_ub
m_eq
m_nonlinear_ub
m_nonlinear_eq
unonlinearly constrained
m_linear_ub
m_linear_eq
ulinearly constrained
m_bounds
ubound-constrained
unconstrained
fun_name
n_orig
nanmin
flatnonzero
fun_min_idx
full_like
nan
merit_min_idx
fun_filter
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
contextlib
T asuppress
inspect
T asignature
numpy
uscipy.optimize
T aBounds
aLinearConstraint
aNonlinearConstraint
aOptimizeResult
aNonlinearConstraint
uscipy.optimize._constraints
T aPreparedConstraint
settings
T aPRINT_OPTIONS
aBARRIER
utils
T aCallbackSuccess
get_arrays_tol
T aexact_1d_array
