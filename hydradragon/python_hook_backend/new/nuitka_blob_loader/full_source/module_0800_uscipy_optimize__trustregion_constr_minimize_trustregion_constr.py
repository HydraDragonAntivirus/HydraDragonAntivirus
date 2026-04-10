# Reconstructed from integrated Nuitka blob
# Module: uscipy.optimize._trustregion_constr.minimize_trustregion_constr

a__qualname__
a__init__
uHessianLinearOperator.__init__
a__call__
uHessianLinearOperator.__call__
uLagrangianHessian.__init__
T nuLagrangianHessian.__call__
T f: 0  yE>f: 0  yE>f: 0  yE>nnl  l
nf
?f
?f       ?f       ?nFna_minimize_trustregion_constr
uscipy\optimize\_trustregion_constr\minimize_trustregion_constr.py
T a.0
wcu<module scipy.optimize._trustregion_constr.minimize_trustregion_constr>
T aself
wxaargs
matvec
T aself
wxav_eq
v_ineq
aH_objective
aH_constraints
matvec
T aself
hessp
wnT aself
wnaobjective_hess
constraints_hess
T-afun
x0
args
grad
hess
hessp
bounds
constraints
xtol
gtol
barrier_tol
sparse_jacobian
callback
maxiter
verbose
finite_diff_rel_step
initial_constr_penalty
initial_tr_radius
initial_barrier_parameter
initial_barrier_tolerance
factorization_method
disp
workers
n_vars
modified_lb
modified_ub
finite_diff_bounds
objective
prepared_constraints
n_sparse
c_eq0
c_ineq0
aJ_eq0
aJ_ineq0
canonical_all
canonical
lagrangian_hess
method
state
start_time
stop_criteria
fun_and_constr
grad_and_jac
w_aresult
T wxwfac_eq
w_aobjective
canonical
T acanonical
objective
T wxwgaJ_eq
w_aobjective
canonical
T wpaself
wxaargs
T aargs
self
wxT wpaH_objective
aH_constraints
T aH_constraints
aH_objective
T astate
wxalast_iteration_failed
optimality
constr_violation
tr_radius
constr_penalty
cg_info
callback_stop
objective
prepared_constraints
start_time
verbose
callback
gtol
xtol
maxiter
T acallback
gtol
maxiter
objective
prepared_constraints
start_time
verbose
xtol
T astate
wxalast_iteration_failed
tr_radius
constr_penalty
cg_info
barrier_parameter
barrier_tolerance
callback_stop
objective
prepared_constraints
start_time
verbose
callback
gtol
xtol
barrier_tol
maxiter
T	abarrier_tol
callback
gtol
maxiter
objective
prepared_constraints
start_time
verbose
xtol
T astate
wxalast_iteration_failed
objective
prepared_constraints
start_time
tr_radius
constr_penalty
cg_info
barrier_parameter
barrier_tolerance
Tastate
wxalast_iteration_failed
objective
prepared_constraints
start_time
tr_radius
constr_penalty
cg_info
wcwialb
ub
.scipy.optimize._trustregion_constr.projections
H
np
linalg
norm
issparse
scipy
sparse
D aord
fro
l
dot
catch_warnings
ignore
aCholmodTypeConversionWarning
T aaction
category
a__enter__
a__exit__
cholesky_AAt
T nnnanull_space
unormal_equation_projections.<locals>.null_space
least_squares
unormal_equation_projections.<locals>.least_squares
row_space
unormal_equation_projections.<locals>.row_space
factor
wAwTaorthogonality
wzaorth_tol
wkamax_refin
block_array
eye_array
D aformat
csc
factorized
warn
T uSingular Jacobian matrix. Using dense SVD decomposition to perform the factorizations.
l T astacklevel
svd_factorization_projections
toarray
uaugmented_system_projections.<locals>.null_space
uaugmented_system_projections.<locals>.least_squares
uaugmented_system_projections.<locals>.row_space
hstack
zeros
wmasolve
wnwvwKalu_sol
qr
D apivoting
mode
taeconomic
utoo many values to unpack (expected 3)
T q :nnnainf
T uSingular Jacobian matrix. Using SVD decomposition to perform the factorizations.
l uqr_factorization_projections.<locals>.null_space
uqr_factorization_projections.<locals>.least_squares
uqr_factorization_projections.<locals>.row_space
wQasolve_triangular
wRD alower
FwPD alower
trans
FwTasvd
D afull_matrices
F:nnnusvd_factorization_projections.<locals>.null_space
usvd_factorization_projections.<locals>.least_squares
usvd_factorization_projections.<locals>.row_space
aVt
l wswUashape
utoo many values to unpack (expected 2)
csc_array
aAugmentedSystem
T aNormalEquation
aAugmentedSystem
uMethod not allowed for sparse array.
aNormalEquation
sksparse_available
warnings
uOnly accepts 'NormalEquation' option when scikit-sparse is available. Using 'AugmentedSystem' option instead.
aImportWarning
D astacklevel
l aQRFactorization
T aQRFactorization
aSVDFactorization
uMethod not allowed for dense array.
normal_equation_projections
augmented_system_projections
qr_factorization_projections
aSVDFactorization
aLinearOperator
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uscipy.sparse
T ablock_array
csc_array
eye_array
issparse
uscipy.sparse.linalg
T aLinearOperator
uscipy.linalg
usksparse.cholmod
T acholesky_AAt
aCholmodTypeConversionWarning
numpy
T awarn
catch_warnings
projections
a__all__
T nf  -   q=l f V     <uscipy\optimize\_trustregion_constr\projections.py
u<module scipy.optimize._trustregion_constr.projections>
T wAwmwnaorth_tol
max_refin
tol
wKasolve
null_space
least_squares
row_space
T wxwvalu_sol
wmasolve
wnT wmwnasolve
T wxafactor
wAT wAafactor
T wxaaux1
aux2
wzwQwRwmwPT wPwQwRwmT wxaaux1
aux2
wzaVt
wswUT wUaVt
wsT
wAwmwnaorth_tol
max_refin
tol
factor
null_space
least_squares
row_space
T wxwvalu_sol
wzwkanew_v
lu_update
wmasolve
wnwAaorth_tol
max_refin
wKT wAwKwmamax_refin
wnaorth_tol
solve
T wxwvwzwkafactor
wAaorth_tol
max_refin
T wAafactor
max_refin
orth_tol
Twxaaux1
aux2
wvwzwkwQwRwmwPwAaorth_tol
max_refin
T wAwPwQwRwmamax_refin
orth_tol
T wxaaux1
aux2
wvwzwkaVt
wswUwAaorth_tol
max_refin
T wAwUaVt
max_refin
orth_tol
wsT wAwganorm_g
norm_A
norm_A_g
orth
TwAamethod
orth_tol
max_refin
tol
wmwnanull_space
least_squares
row_space
wZaLS
wYT wAwmwnaorth_tol
max_refin
tol
wQwRwPanull_space
least_squares
row_space
T wxwvalu_sol
wnasolve
T wnasolve
T wxwAafactor
T wxaaux1
aux2
wzwPwRwQT wPwQwRT wxaaux1
aux2
wzwUwsaVt
T wAwmwnaorth_tol
max_refin
tol
wUwsaVt
null_space
least_squares
row_space

.scipy.optimize._trustregion_constr.qp_subproblem
c
np
shape
utoo many values to unpack (expected 1)
block_array
wTD aformat
csc
hstack
linalg
splu
solve
norm
l
T l
pFaisinf
inf
l adot
l l asqrt
copysign
q asorted
utoo many values to unpack (expected 2)
max
min
asarray
any
logical_not
minimum
maximum
box_intersections
utoo many values to unpack (expected 3)
sphere_intersections
ta
tb
intersect
all
inside_box_boundaries
zeros_like
box_sphere_intersections
uTrust region problem does not have a solution.
f }     :D aniter
stop_cond
hits_boundary
l
l taallvecs
append
f{  G z ?f       ?afull
rt_g
wkaH_p
wpatrust_radius
uNegative curvature not allowed for unrestricted problems.
wxalb
ub
D aentire_line
tareinforce_box_boundaries
l acounter
wrwZwHalast_feasible_x
niter
stop_cond
hits_boundary
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uscipy.sparse
T alinalg
block_array
math
T acopysign
numpy
unumpy.linalg
T anorm
L aeqp_kktfact
sphere_intersections
box_intersections
box_sphere_intersections
inside_box_boundaries
modified_dogleg
projected_cg
a__all__
eqp_kktfact
T FT Fpamodified_dogleg
projected_cg
uscipy\optimize\_trustregion_constr\qp_subproblem.py
u<module scipy.optimize._trustregion_constr.qp_subproblem>
T wzwdalb
ub
entire_line
zero_d
intersect
not_zero_d
t_lb
t_ub
ta
tb
T wzwdalb
ub
trust_radius
entire_line
extra_info
ta_b
tb_b
intersect_b
ta_s
tb_s
intersect_s
ta
tb
intersect
sphere_info
box_info
T wHwcwAwbwnwmakkt_matrix
kkt_vec
lu
kkt_sol
wxalagrange_multipliers
T wxalb
ub
T wAwYwbatrust_radius
lb
ub
newton_point
wxwgaA_g
cauchy_point
origin_point
wzwpw_aalpha
intersect
x1
x2
T(wHwcwZwYwbatrust_radius
lb
ub
tol
max_iter
max_infeasible_iter
return_all
aCLOSE_TO_ZERO
wnwmwxwrwgwpaallvecs
aH_p
rt_g
tr_distance
info
hits_boundary
stop_cond
counter
last_feasible_x
wkwiapt_H_p
w_aalpha
intersect
x_next
theta
r_next
g_next
rt_g_next
beta
Twzwdatrust_radius
entire_line
ta
tb
intersect
wawbwcadiscriminant
sqrt_discriminant
aux

.scipy.optimize._trustregion_constr.report
h
4
w|aCOLUMN_WIDTHS
u{:^

w}w-aprint
format
aCOLUMN_NAMES
aITERATION_FORMATS
u{:
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
