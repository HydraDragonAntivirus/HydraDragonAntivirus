# Reconstructed from integrated Nuitka blob
# Module: uscipy.optimize._trustregion_constr.canonical_constraint

aCanonicalConstraint
a__qualname__
a__init__
uCanonicalConstraint.__init__
from_PreparedConstraint
uCanonicalConstraint.from_PreparedConstraint
uCanonicalConstraint.empty
concatenate
uCanonicalConstraint.concatenate
uCanonicalConstraint._equal_to_canonical
uCanonicalConstraint._less_to_canonical
uCanonicalConstraint._greater_to_canonical
uCanonicalConstraint._interval_to_canonical
initial_constraints_as_canonical
uscipy\optimize\_trustregion_constr\canonical_constraint.py
T a.0
wcu<module scipy.optimize._trustregion_constr.canonical_constraint>
T aself
n_eq
n_ineq
fun
jac
hess
keep_feasible
T acls
cfun
value
empty_fun
wnan_eq
n_ineq
keep_feasible
empty_jac
fun
jac
hess
Tacls
cfun
lb
keep_feasible
empty_fun
wnaempty_jac
finite_lb
n_eq
n_ineq
fun
jac
hess
T acls
cfun
lb
ub
keep_feasible
lb_inf
ub_inf
equal
less
greater
interval
n_less
n_greater
n_interval
n_ineq
n_eq
fun
jac
hess
Tacls
cfun
ub
keep_feasible
empty_fun
wnaempty_jac
finite_ub
n_eq
n_ineq
fun
jac
hess
T
cls
canonical_constraints
sparse_jacobian
fun
vstack
jac
hess
n_eq
n_ineq
keep_feasible
T acls
wnaempty_fun
empty_jac
empty_hess
fun
jac
hess
T acls
constraint
lb
ub
cfun
keep_feasible
T wxacfun
value
empty_fun
T acfun
empty_fun
value
T wxaempty_fun
lb
cfun
T acfun
empty_fun
lb
T wxaempty_fun
lb
cfun
finite_lb
T acfun
empty_fun
finite_lb
lb
T wxwfaeq
le
ge
il
ig
cfun
equal
lb
less
ub
greater
interval
T acfun
equal
greater
interval
lb
less
ub
T wxaempty_fun
cfun
finite_ub
ub
T acfun
empty_fun
finite_ub
ub
T wxaempty_fun
cfun
ub
T acfun
empty_fun
ub
T wxaeq_all
ineq_all
canonical_constraints
T acanonical_constraints
T wxaempty_fun
T aempty_fun
T wxav_eq
v_ineq
cfun
T acfun
T wxav_eq
v_ineq
wvacfun
finite_lb
T acfun
finite_lb
T wxav_eq
v_ineq
n_start
v_l
v_g
v_il
v_ig
wvan_less
n_greater
n_interval
lb
equal
less
greater
interval
cfun
T	acfun
equal
greater
interval
lb
less
n_greater
n_interval
n_less
T wxav_eq
v_ineq
wvacfun
finite_ub
T acfun
finite_ub
T wxav_eq
v_ineq
hess_all
index_eq
index_ineq
wcavc_eq
vc_ineq
matvec
wnacanonical_constraints
T wxav_eq
v_ineq
empty_hess
T aempty_hess
T wnaprepared_constraints
sparse_jacobian
c_eq
c_ineq
aJ_eq
aJ_ineq
wcwfwJalb
ub
finite_ub
finite_lb
lb_inf
ub_inf
equal
less
greater
interval
vstack
empty
T wxacfun
empty_jac
T acfun
empty_jac
T wxaempty_jac
cfun
T wxaempty_jac
cfun
finite_lb
T acfun
empty_jac
finite_lb
TwxwJaeq
le
ge
il
ig
ineq
cfun
equal
less
greater
interval
T acfun
equal
greater
interval
less
T wxaempty_jac
cfun
finite_ub
T acfun
empty_jac
finite_ub
T wxaeq_all
ineq_all
canonical_constraints
vstack
T acanonical_constraints
vstack
T wxaempty_jac
T aempty_jac
T wparesult
whahess_all
T ahess_all

.scipy.optimize._trustregion_constr
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_scipy
u\not_existing
uoptimize\_trustregion_constr
T aNUITKA_PACKAGE_scipy_optimize
u\not_existing
a_trustregion_constr
T aNUITKA_PACKAGE_scipy_optimize__trustregion_constr
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
minimize_trustregion_constr
T a_minimize_trustregion_constr
l a_minimize_trustregion_constr
l
a__all__
uscipy\optimize\_trustregion_constr\__init__.py
u<module scipy.optimize._trustregion_constr>

.scipy.optimize._trustregion_constr.equality_constrained_sqp
^
np
shape
utoo many values to unpack (expected 1)
speye
f
@f
@f
?f       ?f       ?afull
inf
copy
projections
utoo many values to unpack (expected 3)
uexpected square matrix
uThe 'expected square matrix' error can occur if there are more equality constraints than independent variables. Consider how your constraints are set up, or use factorization_method='SVDFactorization'.
dot
norm
wTl
D aniter
stop_cond
hits_boundary
l
pFastop_criteria
state
wxalast_iteration_failed
optimality
constr_violation
trust_radius
penalty
cg_info
modified_dogleg
wAwYwbaTR_FACTOR
aBOX_FACTOR
trust_lb
trust_ub
wHwcazeros_like
sqrt
l alinalg
projected_cg
wZutoo many values to unpack (expected 2)
max
f       <fffffff ?wfwSafun_and_constr
f: 0  yE>aSOC_THRESHOLD
box_intersections
f       ?aTRUST_ENLARGEMENT_FACTOR_L
f333333 ?aTRUST_ENLARGEMENT_FACTOR_S
fG      ?l aMAX_TRUST_REDUCTION
aMIN_TRUST_REDUCTION
x_next
f_next
b_next
grad_and_jac
scaling
factorization_method
lagr_hess
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uscipy.sparse
T aeye_array
eye_array
T aprojections
qp_subproblem
T amodified_dogleg
projected_cg
box_intersections
numpy
unumpy.linalg
T anorm
equality_constrained_sqp
a__all__
default_scaling
uscipy\optimize\_trustregion_constr\equality_constrained_sqp.py
u<module scipy.optimize._trustregion_constr.equality_constrained_sqp>
T wxwnTOafun_and_constr
grad_and_jac
lagr_hess
x0
fun0
grad0
constr0
jac0
stop_criteria
state
initial_penalty
initial_trust_radius
factorization_method
trust_lb
trust_ub
scaling
aPENALTY_FACTOR
aLARGE_REDUCTION_RATIO
aINTERMEDIARY_REDUCTION_RATIO
aSUFFICIENT_REDUCTION_RATIO
aTRUST_ENLARGEMENT_FACTOR_L
aTRUST_ENLARGEMENT_FACTOR_S
aMAX_TRUST_REDUCTION
aMIN_TRUST_REDUCTION
aSOC_THRESHOLD
aTR_FACTOR
aBOX_FACTOR
wnwxatrust_radius
penalty
wfwcwbwAwSwZaLS
wYwewvwHaoptimality
constr_violation
cg_info
last_iteration_failed
dn
c_t
b_t
trust_radius_t
lb_t
ub_t
dt
wdaquadratic_model
linearized_constr
vpred
previous_penalty
new_penalty
predicted_reduction
merit_function
x_next
f_next
b_next
merit_function_next
actual_reduction
reduction_ratio
wyw_wtaintersect
x_soc
f_soc
b_soc
merit_function_soc
actual_reduction_soc
reduction_ratio_soc
trust_reduction
new_trust_radius

.scipy.optimize._trustregion_constr.minimize_trustregion_constr
D
hessp
wnamatvec
uHessianLinearOperator.__call__.<locals>.matvec
aLinearOperator
T amatvec
self
wxaargs
objective_hess
constraints_hess
np
empty
T l
uLagrangianHessian.__call__.<locals>.matvec
aH_objective
dot
aH_constraints
nit
l anfev
ngev
njev
nhev
fun
aVectorFunction
l
constr_nfev
constr_njev
constr_nhev
wfwgagrad
wvaconstr
wJajac
copy
lagrangian_grad
state
wTalinalg
norm
inf
optimality
constr_violation
bounds
utoo many values to unpack (expected 2)
max
time
execution_time
tr_radius
constr_penalty
cg_niter
niter
stop_cond
cg_stop_cond
update_state_sqp
barrier_parameter
barrier_tolerance
atleast_1d
astype
T Ofloat
size
callable
aHessianLinearOperator
aBFGS
nextafter
lb
T awhere
out
ub
where
isfinite
aBounds
keep_feasible
T akeep_feasible
strict_bounds
aScalarFunction
T aworkers
aNonlinearConstraint
aLinearConstraint
aPreparedConstraint
x0
sparse_jacobian
finite_diff_bounds
uAll constraints must have the same kind of the Jacobian --- either all sparse or all dense. You can set the sparsity globally by setting `sparse_jacobian` to either True of False.
append
initial_constraints_as_canonical
utoo many values to unpack (expected 4)
aCanonicalConstraint
from_PreparedConstraint
concatenate
aLagrangianHessian
hess
n_ineq
equality_constrained_sqp
tr_interior_point
aOptimizeResult
T anit
nfev
njev
nhev
cg_niter
cg_stop_cond
fun
grad
lagrangian_grad
constr
jac
constr_nfev
constr_njev
constr_nhev
wvamethod
stop_criteria
u_minimize_trustregion_constr.<locals>.stop_criteria
verbose
l aBasicReport
print_header
aSQPReport
aIPReport
fun_and_constr
u_minimize_trustregion_constr.<locals>.fun_and_constr
grad_and_jac
u_minimize_trustregion_constr.<locals>.grad_and_jac
n_eq
result
status
T l l l asuccess
aTERMINATION_MESSAGES
message
print_footer
print
uNumber of iterations:

u, function evaluations:
u, CG iterations:
u, optimality:
u.2e
u, constraint violation:
u, execution time:
u4.2
u s.
u<genexpr>
u_minimize_trustregion_constr.<locals>.<genexpr>
objective
prepared_constraints
start_time
print_iteration
callback
l agtol
xtol
maxiter
T l
l l l aupdate_state_ip
barrier_tol
canonical
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.sparse.linalg
T aLinearOperator
a_differentiable_functions
T aVectorFunction
a_constraints
T aNonlinearConstraint
aLinearConstraint
aPreparedConstraint
aBounds
strict_bounds
a_hessian_update_strategy
T aBFGS
a_optimize
T aOptimizeResult
T aScalarFunction
T aequality_constrained_sqp
canonical_constraint
T aCanonicalConstraint
initial_constraints_as_canonical
T atr_interior_point
report
T aBasicReport
aSQPReport
aIPReport
D l
l l l l uThe maximum number of function evaluations is exceeded.
u`gtol` termination condition is satisfied.
u`xtol` termination condition is satisfied.
u`callback` raised `StopIteration`.
uConstraint violation exceeds 'gtol'
