# Reconstructed from integrated Nuitka blob
# Module: uscipy.optimize._lsq.least_squares

a__qualname__
T T
na__init__
u_WrapArgsKwargs.__init__
a__call__
u_WrapArgsKwargs.__call__
u2-point
f: 0  yE>aleast_squares
uscipy\optimize\_lsq\least_squares.py
T a.0
wbu<module scipy.optimize._lsq.least_squares>
T aself
wxT aself
wfaargs
kwargs
T wxaargs
T wzarho
cost_only
wtT afun
x0
jac
ftol
xtol
gtol
max_nfev
x_scale
jac_method
wnadiag
full_output
col_deriv
factor
xp
wxainfo
status
wfwJacost
wgag_norm
nfev
njev
active_mask
T atol
name
T ajac_sparsity
wmwnT aftol
xtol
gtol
method
check
T ax_scale
x0
method
valid
T wmaloss
f_scale
rho
loss_function
T wzarho
cost_only
mask
T&afun
x0
jac
bounds
method
ftol
xtol
gtol
x_scale
loss
f_scale
diff_step
tr_solver
tr_options
jac_sparsity
max_nfev
verbose
args
kwargs
callback
workers
lb
ub
fun_wrapped
jac_wrapped
a_dummy_hess
vector_fun
f0
aJ0
wnwmaloss_function
rho
initial_cost
w_ajac_scale
callback_wrapped
result
T wfacost_only
wzaf_scale
loss
rho
T af_scale
loss
rho
T wfacost_only
wzarho
f_scale
loss
T af_scale
loss
T abounds
wnalb
ub
.scipy.optimize._lsq.lsq_linear
v
u`bounds` must contain 2 elements.
utoo many values to unpack (expected 2)
ndim
l
np
resize
lb
ub
asarray
D adtype
Ofloat
u<genexpr>
uprepare_bounds.<locals>.<genexpr>
T atrf
bvls
u`method` must be 'trf' or 'bvls'
T naexact
lsmr
u`solver` must be None, 'exact' or 'lsmr'.
T l
l l u`verbose` must be in [0, 1, 2].
issparse
csr_array
aLinearOperator
atleast_2d
bvls
lsmr
umethod='bvls' can't be used with lsq_solver='lsmr'
wAandarray
umethod='bvls' can't be used with `A` being sparse or LinearOperator.
exact
u`exact` solver can't be used when `A` is sparse or LinearOperator.
shape
u`A` must have at most 2 dimensions.
u`max_iter` must be None or positive integer.
atleast_1d
l u`b` must have at most 1 dimension.
size
uInconsistent shapes between `A` and `b`.
aBounds
prepare_bounds
uBounds have wrong shape.
any
uEach lower bound must be strictly less than each upper bound.
u`lsmr_maxiter` must be None or positive integer.
T aauto
nu`lsmr_tol` must be None, 'auto', or positive float.
linalg
lstsq
D arcond
q aauto
f{  G z ?T amaxiter
atol
btol
unbd_lsq
in_bounds
f
?adot
aTERMINATION_MESSAGES
l acompute_grad
norm
inf
T aord
print
uFinal cost
u.4e
u, first-order optimality
u.2e

aOptimizeResult
zeros
T
wxafun
cost
optimality
active_mask
unbounded_sol
nit
status
message
success
trf
trf_linear
T alsmr_maxiter
res
unbounded_sol
status
message
success
verbose
uNumber of iterations
nit
u, initial cost
initial_cost
u, final cost
cost
optimality
w.a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
unumpy.linalg
T anorm
uscipy.sparse
T aissparse
csr_array
uscipy.sparse.linalg
T aLinearOperator
lsmr
uscipy.optimize
T aOptimizeResult
uscipy.optimize._minimize
T aBounds
common
T ain_bounds
compute_grad
T atrf_linear
T abvls
D q l
l l l uThe algorithm was not able to make progress on the last iteration.
uThe maximum number of iterations is exceeded.
uThe first-order optimality measure is less than `tol`.
uThe relative change of the cost function is less than `tol`.
uThe unconstrained solution is optimal.
f     | =D alsmr_maxiter
nalsq_linear
uscipy\optimize\_lsq\lsq_linear.py
T a.0
wbu<module scipy.optimize._lsq.lsq_linear>
T wAwbabounds
method
tol
lsq_solver
lsmr_tol
max_iter
verbose
lsmr_maxiter
wmwnalb
ub
unbd_lsq
first_lsmr_tol
x_lsq
wracost
termination_status
termination_message
wgag_norm
res
T abounds
wnalb
ub
.scipy.optimize._lsq.trf
np
all
inf
trf_no_bounds
T acallback
trf_bounds
in_bounds
evaluate_quadratic
T adiag
step_size_to_bound
utoo many values to unpack (expected 2)
copy
astype
T Obool
q aintersect_trust_region
min
l
l abuild_quadratic_1d
T as0
diag
utoo many values to unpack (expected 3)
minimize_quadratic_1d
T wcanorm
wrar_h
shape
f
?asum
scale_for_robust_loss_function
dot
compute_grad
wJwfajac
compute_jac_scale
aCL_scaling_vector
f
?T aord
zeros
exact
empty
lsmr
Z
pop
T aregularize
tasize
ldl aprint_header_nonlinear
wxwgalb
ub
print_iteration_nonlinear
iteration
nfev
cost
actual_reduction
step_norm
termination_status
scale_inv
scale
f_augmented
wmaJ_augmented
diag
svd
D afull_matrices
FwTaright_multiplied_operator
regularize
aDelta
regularized_lsq_operator
reg_term
vstack
qr
D amode
economic
max
f  p=
?asolve_lsq_trust_region
wnauf
wswVaalpha
T ainitial_alpha
solve_trust_region_2d
aB_S
g_S
wSwdap_h
select_step
aJ_h
diag_h
g_h
theta
make_strictly_feasible
D arstep
l
fun
isfinite
f
?aloss_function
D acost_only
taupdate_tr_radius
fffffff ?acheck_termination
ftol
xtol
x_new
f_new
cost_new
njev
callback
aOptimizeResult
f_true
T wxafun
nit
nfev
a_call_callback_maybe_halt
q afind_active_constraints
T artol
T
wxacost
fun
jac
grad
optimality
active_mask
nfev
njev
status
T adamp
Z
damp
step_h
zeros_like
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
unumpy.linalg
T anorm
uscipy.linalg
T asvd
qr
uscipy.sparse.linalg
T alsmr
uscipy.optimize
T aOptimizeResult
common
T astep_size_to_bound
find_active_constraints
in_bounds
make_strictly_feasible
intersect_trust_region
solve_lsq_trust_region
solve_trust_region_2d
minimize_quadratic_1d
build_quadratic_1d
evaluate_quadratic
right_multiplied_operator
regularized_lsq_operator
aCL_scaling_vector
compute_grad
compute_jac_scale
check_termination
update_tr_radius
scale_for_robust_loss_function
print_header_nonlinear
print_iteration_nonlinear
uscipy._lib._util
T a_call_callback_maybe_halt
T natrf
uscipy\optimize\_lsq\trf.py
u<module scipy.optimize._lsq.trf>
T wxaJ_h
diag_h
g_h
wpap_h
wdaDelta
lb
ub
theta
p_value
p_stride
hits
r_h
wrax_on_bound
w_ato_tr
to_bound
r_stride
r_stride_l
r_stride_u
wawbwcar_value
ag_h
ag
ag_stride
ag_value
T afun
jac
x0
f0
aJ0
lb
ub
ftol
xtol
gtol
max_nfev
x_scale
loss_function
tr_solver
tr_options
verbose
callback
TOafun
jac
x0
f0
aJ0
lb
ub
ftol
xtol
gtol
max_nfev
x_scale
loss_function
tr_solver
tr_options
verbose
callback
wxwfaf_true
nfev
wJanjev
wmwnarho
cost
wgajac_scale
scale
scale_inv
wvadv
aDelta
g_norm
f_augmented
aJ_augmented
reg_term
regularize
alpha
termination_status
iteration
step_norm
actual_reduction
wdadiag_h
g_h
aJ_h
wUwswVauf
wawbato_tr
ag_value
lsmr_op
gn_h
wSw_aJS
aB_S
g_S
theta
p_h
n_iter
p_S
wpastep
step_h
predicted_reduction
x_new
f_new
step_h_norm
cost_new
aDelta_new
ratio
intermediate_result
active_mask
TFafun
jac
x0
f0
aJ0
ftol
xtol
gtol
max_nfev
x_scale
loss_function
tr_solver
tr_options
verbose
callback
wxwfaf_true
nfev
wJanjev
wmwnarho
cost
wgajac_scale
scale
scale_inv
aDelta
reg_term
damp
regularize
alpha
termination_status
iteration
step_norm
actual_reduction
g_norm
wdag_h
aJ_h
wUwswVauf
wawbato_tr
ag_value
damp_full
gn_h
wSw_aJS
aB_S
g_S
step_h
n_iter
p_S
predicted_reduction
step
x_new
f_new
step_h_norm
cost_new
aDelta_new
ratio
intermediate_result
active_mask

.scipy.optimize._lsq.trf_linear
Z
}
copy
givens_elimination
np
abs
diag
aEPS
max
nonzero
utoo many values to unpack (expected 1)
ix_
zeros
solve_triangular
l areflective_transformation
wxaalpha
wpalb
ub
utoo many values to unpack (expected 2)
evaluate_quadratic
wAwgf        ap_dot_g
f
?afind_active_constraints
any
l
make_strictly_feasible
D arstep
l
step
in_bounds
step_size_to_bound
astype
T Obool
q abuild_quadratic_1d
T as0
diag
utoo many values to unpack (expected 3)
minimize_quadratic_1d
T wcainf
T adiag
wrashape
D arstep
f       ?aexact
qr
D amode
pivoting
economic
twTavstack
min
lsmr
f{  G z ?aauto
dot
compute_grad
ldl aprint_header_linear
aCL_scaling_vector
norm
T aord
tol
print_iteration_linear
cost
cost_change
step_norm
termination_status
right_multiplied_operator
aQT
aQTr
wkaregularized_lsq_with_qr
wmwnwRaperm
D acopy_R
Faregularized_lsq_operator
r_aug
auto_lsmr_tol
f       ?alsmr_maxiter
lsmr_tol
T amaxiter
atol
btol
p_h
f{  G zt?aselect_step
backtracking
wbT artol
aOptimizeResult
g_norm
iteration
T wxafun
cost
optimality
active_mask
nit
status
initial_cost
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
unumpy.linalg
T anorm
uscipy.linalg
T aqr
solve_triangular
uscipy.sparse.linalg
T alsmr
uscipy.optimize
T aOptimizeResult
T agivens_elimination
common
T aEPS
step_size_to_bound
find_active_constraints
in_bounds
make_strictly_feasible
build_quadratic_1d
evaluate_quadratic
minimize_quadratic_1d
aCL_scaling_vector
reflective_transformation
print_header_linear
print_iteration_linear
compute_grad
regularized_lsq_operator
right_multiplied_operator
T tD alsmr_maxiter
natrf_linear
uscipy\optimize\_lsq\trf_linear.py
u<module scipy.optimize._lsq.trf_linear>
T wAwgwxwpatheta
p_dot_g
lb
ub
alpha
x_new
w_astep
cost_change
active
T wmwnwRaQTb
perm
diag
copy_R
wvaabs_diag_R
threshold
nns
wxT wxaA_h
g_h
c_h
wpap_h
wdalb
ub
theta
p_stride
hits
r_h
wrax_on_bound
r_stride_u
w_ar_stride_l
wawbwcar_stride
r_value
p_value
ag_h
ag
ag_stride_u
ag_stride
ag_value
T/wAwbax_lsq
lb
ub
tol
lsq_solver
lsmr_tol
max_iter
verbose
lsmr_maxiter
wmwnwxw_aQT
wRaperm
aQTr
wkar_aug
auto_lsmr_tol
wrwgacost
initial_cost
termination_status
step_norm
cost_change
iteration
wvadv
g_scaled
g_norm
diag_h
diag_root_h
wdag_h
aA_h
p_h
lsmr_op
eta
wpap_dot_g
theta
step
active_mask

.scipy.optimize._milp
;
p
aLinearConstraint
u`constraints` (or each element within `constraints`) must be convertible into an instance of `scipy.optimize.LinearConstraint`.
aVisibleDeprecationWarning
constraints
aAs
csc_array
wAab_ls
np
atleast_1d
lb
astype
float64
b_us
ub
vstack
D aformat
csc
concatenate
l
issparse
u`c` must be a dense array.
ndim
l asize
all
isfinite
u`c` must be a one-dimensional array of finite numbers with at least one element.
u`integrality` must be a dense array.
broadcast_to
integrality
shape
uint8
u`integrality` must contain integers 0-3 and be broadcastable to `c.shape`.
min
max
l aBounds
inf
u`bounds` must be convertible into an instance of `scipy.optimize.Bounds`.
T EValueError
ETypeError
u`bounds.lb` and `bounds.ub` must contain reals and be broadcastable to `c.shape`.
empty
T T l
a_constraints_to_components
utoo many values to unpack (expected 3)
uThe shape of `A` must be (len(b_l), len(c)).
indptr
indices
data
S apresolve
node_limit
mip_rel_gap
time_limit
disp
difference
uUnrecognized options detected:

u. These will be passed to HiGHS verbatim.
warnings
warn
aRuntimeWarning
D astacklevel
l alog_to_console
pop
T adisp
Famip_max_nodes
T anode_limit
na_milp_iv
utoo many values to unpack (expected 10)
a_highs_wrapper
get
T astatus
nT amessage
na_highs_to_scipy_status_message
utoo many values to unpack (expected 2)
status
message
success
T wxnaarray
wxT afun
nafun
T amip_node_count
namip_node_count
T amip_dual_bound
namip_dual_bound
T amip_gap
namip_gap
aOptimizeResult
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
unumpy.exceptions
T aVisibleDeprecationWarning
uscipy.sparse
T acsc_array
vstack
issparse
u_highspy._highs_wrapper
T a_highs_wrapper
a_constraints
T aLinearConstraint
aBounds
a_optimize
T aOptimizeResult
a_linprog_highs
T a_highs_to_scipy_status_message
D aintegrality
bounds
constraints
options
nnnnamilp
uscipy\optimize\_milp.py
u<module scipy.optimize._milp>
T
constraints
message
aAs
b_ls
b_us
exc
constraint
wAab_l
b_u
T wcaintegrality
bounds
constraints
options
message
exc
lb
ub
wAab_l
b_u
indptr
indices
data
supported_options
unsupported_options
options_iv
T wcaintegrality
bounds
constraints
options
args_iv
lb
ub
indptr
indices
data
b_l
b_u
highs_res
res
highs_status
highs_message
status
message
wx.scipy.optimize._minimize
np
atleast_1d
asarray
ndim
l u'x0' must only have one dimension.
dtype
kind
typecodes
aAllInteger
D adtype
Ofloat
aSLSQP
uL-BFGS-B
aBFGS
callable
a_custom
lower
T unelder-mead
powell
cobyla
cobyqa
warn
uMethod

u does not use gradient information (jac).
aRuntimeWarning
D astacklevel
l T unewton-cg
dogleg
utrust-ncg
utrust-constr
utrust-krylov
utrust-exact
a_custom
u does not use Hessian information (hess).
T unewton-cg
utrust-ncg
utrust-constr
utrust-krylov
a_custom
u does not use Hessian-vector product information (hessp).
T acobyla
cobyqa
slsqp
utrust-constr
a_custom
any
u cannot handle constraints.
T	unelder-mead
powell
ul-bfgs-b
cobyla
cobyqa
slsqp
tnc
utrust-constr
a_custom
u cannot handle bounds.
T ul-bfgs-b
tnc
cobyla
cobyqa
slsqp
get
T areturn_all
Fu does not support the return_all option.
aMemoizeJac
derivative
aFD_METHODS
T utrust-constr
bfgs
cg
ul-bfgs-b
tnc
slsqp
T utrust-constr
u2-point
unelder-mead
xatol
fatol
T unewton-cg
powell
tnc
xtol
T apowell
ul-bfgs-b
tnc
slsqp
ftol
T abfgs
cg
ul-bfgs-b
tnc
dogleg
utrust-ncg
utrust-exact
utrust-krylov
gtol
T acobyla
a_custom
tol
cobyqa
final_tr_radius
utrust-constr
barrier_tol
fun
x0
args
jac
hess
hessp
bounds
constraints
callback
options
standardize_constraints
standardize_bounds
new
a_validate_bounds
P atnc
slsqp
ul-bfgs-b
lb
ub
all
a_optimize_result_for_equal_bounds
T aargs
constraints
T ajac
nafd_needed
tnc
a_remove_from_bounds
a_Remove_From_Func
wrapped_inspect_signature
parameters
S aintermediate_result
print
a_Patch_Callback_Equal_Variables
D aremove
l acopy
i_fixed
x_fixed
D amin_dim
remove
l l
D amin_dim
remove
l l a_wrap_callback
a_minimize_neldermead
powell
a_minimize_powell
cg
a_minimize_cg
bfgs
a_minimize_bfgs
unewton-cg
a_minimize_newtoncg
ul-bfgs-b
a_minimize_lbfgsb
a_minimize_tnc
cobyla
a_minimize_cobyla
a_minimize_cobyqa
slsqp
a_minimize_slsqp
a_minimize_trustregion_constr
dogleg
a_minimize_dogleg
utrust-ncg
a_minimize_trust_ncg
utrust-krylov
a_minimize_trust_krylov
utrust-exact
a_minimize_trustregion_exact
uUnknown solver
a_add_to_array
wxanan
hess_inv
stop_iteration
success
lcastatus
u`callback` raised `StopIteration`.
message
brent
bounded
P abrent
golden
uUse of `bounds` is incompatible with 'method=
u'.
uMethod 'bounded' does not support relative tolerance in x; defaulting to absolute tolerance.
T adisp
l adisp
bracket
a_recover_from_bracket_error
a_minimize_scalar_brent
uThe `bounds` parameter is mandatory for method `bounded`.
a_minimize_scalar_bounded
golden
a_minimize_scalar_golden
reshape
shape
aBounds
zeros_like
T adtype
fun_in
min_dim
remove
array
atleast_2d
T :nnnnT n:nnnaravel
uAn upper bound is less than the corresponding lower bound.
broadcast_to
uThe number of bounds is not compatible with the length of `x0`.
P acobyla
unelder-mead
new
powell
cobyqa
utrust-constr
old_bound_to_new
utoo many values to unpack (expected 2)
T ul-bfgs-b
tnc
slsqp
old
new_bounds_to_old
l
aNonlinearConstraint
aLinearConstraint
:nq nT utrust-constr
cobyqa
new
cobyla
old_constraint_to_new
new_constraint_to_old
extend
:l nnuAll independent variables were fixed by bounds.
uAll independent variables were fixed by bounds at values that satisfy the constraints.
aPreparedConstraint
violation
sum
max
maxcv
uAll independent variables were fixed by bounds, but the independent variables do not satisfy the constraints exactly. (Maximum violation:
u).
aOptimizeResult
T wxafun
success
message
nfev
njev
nhev
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
minimize
minimize_scalar
a__all__
warnings
T awarn
numpy
uscipy._lib._util
T awrapped_inspect_signature
a_optimize
T a_minimize_neldermead
a_minimize_powell
a_minimize_cg
a_minimize_bfgs
a_minimize_newtoncg
a_minimize_scalar_brent
a_minimize_scalar_bounded
a_minimize_scalar_golden
aMemoizeJac
aOptimizeResult
a_wrap_callback
a_recover_from_bracket_error
a_trustregion_dogleg
T a_minimize_dogleg
a_trustregion_ncg
T a_minimize_trust_ncg
a_trustregion_krylov
T a_minimize_trust_krylov
a_trustregion_exact
T a_minimize_trustregion_exact
a_trustregion_constr
T a_minimize_trustregion_constr
a_lbfgsb_py
T a_minimize_lbfgsb
a_tnc
T a_minimize_tnc
a_cobyla_py
T a_minimize_cobyla
a_cobyqa_py
T a_minimize_cobyqa
a_slsqp_py
T a_minimize_slsqp
a_constraints
T aold_bound_to_new
new_bounds_to_old
old_constraint_to_new
new_constraint_to_old
aNonlinearConstraint
aLinearConstraint
aBounds
aPreparedConstraint
a_differentiable_functions
T aFD_METHODS
L unelder-mead
powell
cg
bfgs
unewton-cg
ul-bfgs-b
tnc
cobyla
cobyqa
slsqp
utrust-constr
dogleg
utrust-ncg
utrust-exact
utrust-krylov
aMINIMIZE_METHODS
L unelder-mead
powell
cg
bfgs
unewton-cg
ul-bfgs-b
utrust-constr
dogleg
utrust-ncg
utrust-exact
utrust-krylov
cobyqa
cobyla
slsqp
aMINIMIZE_METHODS_NEW_CB
aMINIMIZE_SCALAR_METHODS
T
T
nnnnnT
nnnT nnT
