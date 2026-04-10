# Reconstructed from integrated Nuitka blob
# Module: uscipy.optimize._numdiff

a__qualname__
a__init__
u_Fun_Wrapper.__init__
a__call__
u_Fun_Wrapper.__call__
check_derivative
uscipy\optimize\_numdiff.py
T a.0
wbu<module scipy.optimize._numdiff>
T aself
wxaxp
wfT aself
fun
x0
args
kwargs
T ax0
whanum_steps
scheme
lb
ub
use_one_sided
h_total
h_adjusted
lower_dist
upper_dist
wxaviolated
fitting
forward
backward
central
min_dist
adjusted_central
T arel_step
x0
f0
method
sign_x0
rstep
abs_step
dx
T afun
x0
f0
whause_one_sided
method
workers
wmwnaJ_transposed
nfev
x_generator2
f_evals
dx
df
df_dx
x_generator3
gen
wiaone_sided
wlwuaf1
f2
x_generator_cs
wvT ax0_dtype
f0_dtype
method
aEPS
x0_is_fp
x0_itemsize
f0_itemsize
T afun
x0
f0
whamethod
wmwnamatvec
T abounds
x0
lb
ub
T%afun
x0
f0
whause_one_sided
structure
groups
method
workers
wmwnarow_indices
col_indices
fractions
n_groups
nfev
e_generator
x_generator2
x_generator3
x_generator_cs
f_evals
xs
weacols
wiwjw_adx
df
x1
x2
mask_1
mask_2
f1
f2
mask
rows
T afun
x0
method
rel_step
abs_step
f0
bounds
sparsity
as_linear_operator
args
kwargs
full_output
workers
info_dict
xp
a_x
a_dtype
lb
ub
fun_wrapped
nfev
a_nfev
wJw_whasign_x0
dx
use_one_sided
mf
structure
groups
Tafun
jac
x0
bounds
args
kwargs
aJ_to_test
aJ_diff
abs_err
wiwjaabs_err_data
aJ_diff_data
T agroup
n_groups
groups
T agroups
n_groups
T wAaorder
wmwnarng
groups
T	wpadx
wxadf
wmwhax0
fun
f0
T af0
fun
whwmax0
T	wpadx
wxaf1
df
wmwhax0
fun
T afun
whwmax0
T wpadx
x1
x2
f1
f2
df
wmwhax0
fun
T ax0
whwiax1
wnT wnT ae_gen
weah_vec
wxae_generator
whax0
T ae_generator
whax0
T ax0
whause_one_sided
wiaone_sided
x1
x2
T ae_gen
weah_vec
x1
x2
mask_1
mask_2
e_generator
whax0
use_one_sided
T ae_generator
whause_one_sided
x0
T ax0
whwiaxc
wnT ae_gen
weah_vec
e_generator
whax0
.scipy.optimize._optimize
H
fun
jac
a_value
wxanp
all
asarray
copy
l l
a_compute_if_needed
P acobyla
tnc
cobyqa
wrapped_inspect_signature
parameters
S aintermediate_result
wrapped_callback
u_wrap_callback.<locals>.wrapped_callback
utrust-constr
differential_evolution
stop_iteration
callback
T aintermediate_result
convergence
is_pos_def
u_check_positive_definite.<locals>.is_pos_def
u'hess_inv0' matrix isn't positive definite.
issymmetric
cholesky
aLinAlgError
u,
keys
warnings
warn
uUnknown solver options:

aOptimizeWarning
D astacklevel
l asize
isfinite
inf
amax
abs
amin
sum
D aaxis
l
f
?acallable
aFD_METHODS
u2-point
hess
u_prepare_scalar_function.<locals>.hess
aScalarFunction
T aepsilon
workers
eval
u_clip_x_for_func.<locals>.eval
a_check_clip_x
bounds
func
any
uValues in x were outside bounds during a minimize step, clipping to bounds
aRuntimeWarning
D astacklevel
l aclip
array_namespace
xp_promote
T aforce_floating
xp
f
Y@:l nn:nq nf
@adtype
T aaxis
dtype
:l q n:nq n:l nnazeros_like
l  l l  q  q q axpx
create_diagonal
T aoffset
xp
zeros
shape
T adtype
at
set
l 	T l  l  T axp
atleast_nd
T andim
xp
function_wrapper
u_wrap_scalar_function.<locals>.function_wrapper
ncalls
function
args
isscalar
item
T ETypeError
EValueError
uThe user-provided objective function must return a scalar value.
fx
u_wrap_scalar_function_maxfun_validation.<locals>.function_wrapper
maxfun
a_MaxFuncCallError
T uToo many function calls
xatol
fatol
maxiter
maxfev
disp
return_all
initial_simplex
a_wrap_callback
a_minimize_neldermead
nit
nfev
status
allvecs
a_check_unknown_options
atleast_1d
flatten
issubdtype
inexact
float64
f
?f
?f    Mb0?alb
ub
utoo many values to unpack (expected 2)
uNelder Mead - one of the lower bounds is greater than an upper bound.
uInitial guess is not within the specified bounds
lower_bound
upper_bound
x0
empty
array
D acopy
tf       ?azdelt
wyasim
atleast_2d
ndim
u`initial_simplex` should be an array of shape (N+1,N)
uSize of `initial_simplex` is not consistent with `x0`
wNawhere
full
D adtype
Ofloat
a_wrap_scalar_function_maxfun_validation
fsim
argsort
take
iterations
max
ravel
add
reduce
rho
chi
psi
one2np1
sigma
append
aOptimizeResult
T wxafun
a_call_callback_maybe_halt
min
a_status_message
success
print
u         Current function value:
wfu         Iterations:
wdu         Function evaluations:
msg
T afun
nit
nfev
status
success
message
wxafinal_simplex
approx_derivative
T amethod
abs_step
args
f0
wgucheck_grad.<locals>.g
random
asanyarray
u'random' can only be used with scalar valued func
check_random_state
standard_normal
T asize
T T l adot
u is not a valid string for ``direction`` argument
sqrt
approx_fprime
extra_condition
line_search_wolfe1
l l T nacatch_warnings
a__enter__
a__exit__
simplefilter
ignore
aLineSearchWarning
T ac1
c2
amax
kwargs2
line_search_wolfe2
T nnna_LineSearchError
gtol
norm
eps
xrtol
c1
c2
hess_inv0
a_minimize_bfgs
hess_inv
njev
a_check_positive_definite
reshape
a_prepare_scalar_function
T aargs
epsilon
finite_diff_rel_step
workers
grad
eye
D adtype
Oint
linalg
vecnorm
T aord
gnorm
wkaHk
gfk
a_line_search_wolfe12
myfprime
xk
old_fval
old_old_fval
f0   . ++f}  % I TT aamin
amax
c1
c2
utoo many values to unpack (expected 6)
Z
f
@ @uDivide-by-zero encountered: rhok assumed large
a_print_success_message_or_warn
wI:nnnanewaxis
pr_loss
isnan
nan
u         Gradient evaluations:
ngev
T
fun
jac
hess_inv
nfev
njev
status
success
message
wxanit
a_minimize_cg
T ajac
args
epsilon
finite_diff_rel_step
workers
f{  G z ?apolak_ribiere_powell_step
u_minimize_cg.<locals>.polak_ribiere_powell_step
descent_condition
u_minimize_cg.<locals>.descent_condition
pk
T ac1
c2
amin
amax
extra_condition
utoo many values to unpack (expected 5)
T	afun
jac
nfev
njev
status
success
message
wxanit
deltak
cached_step
sigma_3
xtol
a_minimize_newtoncg
nhev
uJacobian is required for Newton-CG method
T aargs
epsilon
hess
workers
aLinearOperator
a_hessp
u_minimize_newtoncg.<locals>._hessp
terminate
u_minimize_newtoncg.<locals>.terminate
l afinfo
T Ofloat
update_l1norm
uWarning:
fprime
D aord
l amath
sf
hcalls
ri
approx_fhess_p
psupi
epsilon
wAasqueeze
float64eps
wiadri0
xsupi
T l uWarning: CG iterations didn't converge. The Hessian is not positive definite.
T ac1
c2
retall
T l u
u         Hessian evaluations:
T
fun
jac
nfev
njev
nhev
status
success
message
wxanit
a_minimize_scalar_bounded
ubounds must have two elements.
is_finite_scalar
uOptimization bounds must be finite scalars.
uThe lower bound exceeds the upper bound.
u       initial
T fOd @   <f
@T f
@T w T u Func-count     x          f(x)          Procedure
u%5.0f   %12.6g %12.6g %s
xf
xm
tol2
wbwaweatol1
nfc
ffulc
fulc
fnfc
rat
u       parabolic
sign
golden_mean
u       golden
maximum
num
step
sqrt_eps
fu
a_endprint
uSolution found.
uMaximum number of function calls reached.
T afun
status
success
message
wxanfev
nit
tol
f dy    =a_mintol
f    !r ?a_cg
xmin
fval
aiter
funcalls
brack
bracket
T aargs
utoo many values to unpack (expected 7)
T axa
xb
args
utoo many values to unpack (expected 3)
uBracketing values (xa, xb, xc) do not fulfill this requirement: (xa < xb) and (xb < xc)
uBracketing values (xa, xb, xc) do not fulfill this requirement: (f(xb) < f(xa)) and (f(xb) < f(xc))
uBracketing interval must be length 2 or 3 sequence.
get_bracket_info
uFunc-count
u^12
w uf(x)
u ^12
u^12g
u^12.6g
self
deltax
wwafv
wvafw
wua_minimize_scalar_brent
utolerance should be >= 0, got
aBrent
T afunc
args
tol
full_output
maxiter
disp
set_bracket
optimize
get_result
T tT afull_output
utoo many values to unpack (expected 4)

Optimization terminated successfully;
The returned value satisfies the termination criteria
(using xtol =
u )

Maximum number of iterations exceeded
message
T afun
wxanit
nfev
success
message
a_minimize_scalar_golden
fz  7   ?ax3
x1
x2
f2
f1
a_gR
a_gC
T afun
nfev
wxanit
success
message
f    w  ?afc
fb
xb
xa
xc
fa
fO
;fO
;agrow_limit
uNo valid bracket was found before the iteration limit was reached. Consider trying different initial points or increasing `maxiter`.
a_gold
aBracketError
T uThe algorithm terminated without finding a valid bracket. Consider trying different initial points.
data
argmin
nonzero
utoo many values to unpack (expected 1)
T l
pamyfunc
u_linesearch_powell.<locals>.myfunc
a_recover_from_bracket_error
T axtol
a_line_for_search
isneginf
isposinf
a_linesearch_powell
T afval
tol
ldT axatol
arctan
u<lambda>
u_linesearch_powell.<locals>.<lambda>
tan
wpaxi
ftol
direc
a_minimize_powell
l  amatrix_rank
udirec input is not full rank, some parameters may not be optimized
T nnT atol
lower_bound
upper_bound
fval
delta
f#B     ;abigind
l aout_of_bounds
T afun
direc
nit
nfev
status
success
message
wxw)u
Maximum number of function evaluations exceeded --- increase maxfun argument.
w
uBrute Force not possible with more than 40 variables.
lrange
mgrid
prod
wTaiterable
a_Brute_Wrapper
aMapWrapper
T apool
grid
aJout
D aaxis
q aindx
aNindx
a_getfullargspec
full_output
options
uEither final optimization did not succeed or `finish` does not return `statuscode` as its last argument.
D astacklevel
l atextwrap
D aminimize
root
root_scalar
linprog
quadratic_assignment
minimize_scalar
T T abfgs
uscipy.optimize._optimize._minimize_bfgs
T acg
uscipy.optimize._optimize._minimize_cg
T acobyla
uscipy.optimize._cobyla_py._minimize_cobyla
T acobyqa
uscipy.optimize._cobyqa_py._minimize_cobyqa
T adogleg
uscipy.optimize._trustregion_dogleg._minimize_dogleg
T ul-bfgs-b
uscipy.optimize._lbfgsb_py._minimize_lbfgsb
T unelder-mead
uscipy.optimize._optimize._minimize_neldermead
T unewton-cg
uscipy.optimize._optimize._minimize_newtoncg
T apowell
uscipy.optimize._optimize._minimize_powell
T aslsqp
uscipy.optimize._slsqp_py._minimize_slsqp
T atnc
uscipy.optimize._tnc._minimize_tnc
T utrust-ncg
uscipy.optimize._trustregion_ncg._minimize_trust_ncg
T utrust-constr
uscipy.optimize._trustregion_constr._minimize_trustregion_constr
T utrust-exact
uscipy.optimize._trustregion_exact._minimize_trustregion_exact
T utrust-krylov
uscipy.optimize._trustregion_krylov._minimize_trust_krylov
T
T ahybr
uscipy.optimize._minpack_py._root_hybr
T alm
uscipy.optimize._root._root_leastsq
T abroyden1
uscipy.optimize._root._root_broyden1_doc
T abroyden2
uscipy.optimize._root._root_broyden2_doc
T aanderson
uscipy.optimize._root._root_anderson_doc
T adiagbroyden
uscipy.optimize._root._root_diagbroyden_doc
T aexcitingmixing
uscipy.optimize._root._root_excitingmixing_doc
T alinearmixing
uscipy.optimize._root._root_linearmixing_doc
T akrylov
uscipy.optimize._root._root_krylov_doc
T udf-sane
uscipy.optimize._spectral._root_df_sane
T T abisect
uscipy.optimize._root_scalar._root_scalar_bisect_doc
T abrentq
uscipy.optimize._root_scalar._root_scalar_brentq_doc
T abrenth
uscipy.optimize._root_scalar._root_scalar_brenth_doc
T aridder
uscipy.optimize._root_scalar._root_scalar_ridder_doc
T atoms748
uscipy.optimize._root_scalar._root_scalar_toms748_doc
T asecant
uscipy.optimize._root_scalar._root_scalar_secant_doc
T anewton
uscipy.optimize._root_scalar._root_scalar_newton_doc
T ahalley
uscipy.optimize._root_scalar._root_scalar_halley_doc
T T asimplex
uscipy.optimize._linprog._linprog_simplex_doc
T uinterior-point
uscipy.optimize._linprog._linprog_ip_doc
T urevised simplex
uscipy.optimize._linprog._linprog_rs_doc
T uhighs-ipm
uscipy.optimize._linprog._linprog_highs_ipm_doc
T uhighs-ds
uscipy.optimize._linprog._linprog_highs_ds_doc
T ahighs
uscipy.optimize._linprog._linprog_highs_doc
T T afaq
uscipy.optimize._qap._quadratic_assignment_faq
T u2opt
uscipy.optimize._qap._quadratic_assignment_2opt
T T abrent
uscipy.optimize._optimize._minimize_scalar_brent
T abounded
uscipy.optimize._optimize._minimize_scalar_bounded
T agolden
uscipy.optimize._optimize._minimize_scalar_golden

========
minimize
u========
show_options
T aminimize
FT adisp

===============
minimize_scalar
u===============
T aminimize_scalar
Fu
====
root
u====
T aroot
Fu
=======
linprog
u=======
T alinprog
Falower
uUnknown solver
text

w=asolver
D adisp
FuUnknown method
split
T w.w.amodules
a__doc__
dedent
strip
a__file__
a__spec__
origin
has_location
a__cached__
L afmin
fmin_powell
fmin_bfgs
fmin_ncg
fmin_cg
fminbound
brent
golden
bracket
rosen
rosen_der
rosen_hess
rosen_hess_prod
brute
approx_fprime
line_search
check_grad
aOptimizeResult
show_options
aOptimizeWarning
a__all__
urestructuredtext en
a__docformat__
sys
numpy
T aeye
argmin
zeros
shape
asarray
sqrt
uscipy.linalg
T acholesky
issymmetric
aLinAlgError
uscipy.sparse.linalg
T aLinearOperator
a_linesearch
T aline_search_wolfe1
line_search_wolfe2
paLineSearchWarning
line_search
a_numdiff
T aapprox_derivative
uscipy._lib._util
T agetfullargspec_no_self
getfullargspec_no_self
T aMapWrapper
check_random_state
a_RichResult
a_call_callback_maybe_halt
a_transition_to_rng
wrapped_inspect_signature
a_RichResult
a_transition_to_rng
uscipy.optimize._differentiable_functions
T aScalarFunction
aFD_METHODS
uscipy._lib._array_api
T aarray_namespace
xp_capabilities
xp_promote
xp_capabilities
uscipy._lib
T aarray_api_extra
array_api_extra
D asuccess
maxfev
maxiter
pr_loss
nan
out_of_bounds
uOptimization terminated successfully.
uMaximum number of function evaluations has been exceeded.
uMaximum number of iterations has been exceeded.
uDesired error not necessarily achieved due to precision loss.
uNaN result encountered.
uThe result is outside of the provided bounds.
