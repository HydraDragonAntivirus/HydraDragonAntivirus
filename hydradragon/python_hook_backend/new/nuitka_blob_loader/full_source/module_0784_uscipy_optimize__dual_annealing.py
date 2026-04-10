# Reconstructed from integrated Nuitka blob
# Module: uscipy.optimize._dual_annealing

a__qualname__
f
Aa__init__
uVisitingDistribution.__init__
uVisitingDistribution.visiting
uVisitingDistribution.visit_fn
T nuEnergyState.__init__
uEnergyState.reset
uEnergyState.update_best
uEnergyState.update_current
uStrategyChain.__init__
uStrategyChain.accept_reject
uStrategyChain.run
uStrategyChain.local_search
T f
cAuObjectiveFunWrapper.__init__
uObjectiveFunWrapper.fun
l uLocalSearchWrapper.__init__
uLocalSearchWrapper.local_search
T aseed
l
T aposition_num
T T
l  nf
n @f h     >f (\    @f
f
cAnFnnuscipy\optimize\_dual_annealing.py
u<module scipy.optimize._dual_annealing>
T aself
lower
upper
callback
T aself
search_bounds
func_wrapper
args
kwargs
bounds_list
wnals_max_iter
wrapped_jac
wrapped_hess
wrapped_hessp
T aself
func
maxfun
args
T aself
acceptance_param
visit_dist
func_wrapper
minimizer_wrapper
rand_gen
energy_state
T aself
lb
ub
visiting_param
rng_gen
T aself
wjweax_visit
wrapqv_temp
pqv
T"afunc
bounds
args
maxiter
minimizer_kwargs
initial_temp
restart_temp_ratio
visit
accept
maxfun
rng
no_local_search
callback
x0
lu
lower
upper
func_wrapper
minimizer_wrapper
rng_gen
energy_state
temperature_restart
visit_dist
strategy_chain
need_to_stop
iteration
message
optimize_res
t1
wiwsat2
temperature
val
T aself
wxT aself
wxweax_tmp
mres
is_finite
in_bounds
is_valid
T aself
wewxaval
do_ls
pls
T aself
func_wrapper
rng_gen
x0
init_error
reinit_counter
message
T aself
step
temperature
wjax_visit
weaval
T aself
wewxacontext
val
T aself
wewxT aself
temperature
dim
wxwyafactor1
factor4
den
Taself
wxastep
temperature
dim
visits
upper_sample
lower_sample
x_visit
wawbavisit
index
T wxaself
args
T aargs
self
T wxwpaself
args

.scipy.optimize._elementwise
2
L
reformat_result
ufind_root.<locals>.reformat_result
utoo many values to unpack (expected 2)
D axatol
xrtol
fatol
frtol
nnnl
callable
a_callback
ufind_root.<locals>._callback
a_chandrupatla
args
maxiter
callback
a_RichResult
status
success
wxafun
f_x
nfev
nit
xl
xr
bracket
fl
fr
f_bracket
L asuccess
status
wxaf_x
nfev
nit
bracket
f_bracket
a_order_keys
ufind_minimum.<locals>.reformat_result
utoo many values to unpack (expected 3)
D axatol
xrtol
fatol
frtol
nnnnufind_minimum.<locals>._callback
a_chandrupatla_minimize
xm
fm
a_bracket_root
T axr0
xmin
xmax
factor
args
maxiter
a_bracket_minimum
T axl0
xr0
xmin
xmax
factor
args
maxiter
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uscipy.optimize._bracket
T a_bracket_root
a_bracket_minimum
l
uscipy.optimize._chandrupatla
T a_chandrupatla
a_chandrupatla_minimize
uscipy._lib._util
T a_RichResult
uscipy._lib._array_api
T axp_capabilities
xp_capabilities
T L T udask.array
uboolean indexing assignment
T aarray_api_strict
uCurrently uses fancy indexing assignment.
T ujax.numpy
uJAX arrays do not support item assignment.
T askip_backends
D aargs
tolerances
maxiter
callback
T
nnnafind_root
D aargs
tolerances
maxiter
callback
T
nldnafind_minimum
T nD axmin
xmax
factor
args
maxiter
nnnT
l  abracket_root
T L T udask.array
uboolean indexing assignment
T aarray_api_strict
uCurrently uses fancy indexing assignment.
T ujax.numpy
uJAX arrays do not support item assignment.
T atorch
udata-apis/array-api-compat#271
D axl0
xr0
xmin
xmax
factor
args
maxiter
nnnnnT
l  abracket_minimum
uscipy\optimize\_elementwise.py
u<module scipy.optimize._elementwise>
T ares
callback
reformat_result
T acallback
reformat_result
T
wfaxm0
xl0
xr0
xmin
xmax
factor
args
maxiter
res
T	wfaxl0
xr0
xmin
xmax
factor
args
maxiter
res
Twfainit
args
tolerances
maxiter
callback
reformat_result
xl
xm
xr
default_tolerances
a_callback
res
T wfainit
args
tolerances
maxiter
callback
reformat_result
xl
xr
default_tolerances
a_callback
res
T ares_in
res_out

.scipy.optimize._hessian_update_strategy
H
uThe method ``initialize(n, approx_type)`` is not implemented.
uThe method ``update(delta_x, delta_grad)`` is not implemented.
uThe method ``dot(p)`` is not implemented.
uThe method ``get_matrix(p)`` is not implemented.
dot
init_scale
first_iteration
approx_type
wBwHwnT ahess
inv_hess
u`approx_type` must be 'hess' or 'inv_hess'.
hess
np
eye
D adtype
Ofloat
abs
Z
l
l uThe method ``_update_implementation`` is not implemented.
all
warn
udelta_grad == 0.0. Check if the approximated function is linear. If the function is linear better results can be obtained by defining the Hessian as zero instead of using quasi-Newton approximations.
aUserWarning
D astacklevel
l aauto
a_auto_scale
size
iscomplexobj
uinit_scale contains complex elements, must be real.
shape
dtype
array
T adtype
copy
uIf init_scale is an array, it must have the dimensions of the hess/inv_hess:

u. Got
w.aissymmetric
uIf init_scale is an array, it must be symmetric (passing scipy.linalg.issymmetric) to be an approximation of a hess/inv_hess.
scale
a_update_implementation
a_symv
copy
tril_indices_from
D wkq wTaskip_update
min_curvature
f: 0  yE>adamp_update
f       ?u`exception_strategy` must be 'skip_update' or 'damp_update'.
a__class__
self
a__init__
exception_strategy
a_syr2
f
T waa_syr
l f
?adelta_x
delta_grad
aMw
a_update_hessian
wza_update_inverse_hessian
min_denominator
norm
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
T aget_blas_funcs
issymmetric
get_blas_funcs
warnings
T awarn
aHessianUpdateStrategy
aBFGS
aSR1
a__all__
