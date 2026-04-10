# Reconstructed from integrated Nuitka blob
# Module: uscipy.optimize._differentiable_functions

a__qualname__
T nnnu_ScalarGradWrapper.__init__
T na__call__
u_ScalarGradWrapper.__call__
T nnnnu_ScalarHessWrapper.__init__
u_ScalarHessWrapper.__call__
u_ScalarHessWrapper._fd_hess
u_ScalarHessWrapper._sparse_callable
u_ScalarHessWrapper._dense_callable
u_ScalarHessWrapper._linearoperator_callable
aScalarFunction
uScalarFunction.__init__
uScalarFunction.nfev
uScalarFunction.ngev
uScalarFunction.nhev
uScalarFunction._update_x
uScalarFunction._update_fun
uScalarFunction._update_grad
uScalarFunction._update_hess
uScalarFunction.fun
uScalarFunction.grad
uScalarFunction.hess
fun_and_grad
uScalarFunction.fun_and_grad
u_VectorFunWrapper.__init__
u_VectorFunWrapper.__call__
u_VectorJacWrapper.__init__
u_VectorJacWrapper.__call__
T nnu_VectorHessWrapper.__init__
u_VectorHessWrapper.__call__
u_VectorHessWrapper._fd_hess
u_VectorHessWrapper.jac_dot_v
u_VectorHessWrapper._callable_hess
aVectorFunction
uVectorFunction.__init__
uVectorFunction.nfev
uVectorFunction.njev
uVectorFunction.nhev
uVectorFunction._update_v
uVectorFunction._update_x
uVectorFunction._update_fun
uVectorFunction._update_jac
uVectorFunction._update_hess
uVectorFunction.fun
uVectorFunction.jac
uVectorFunction.hess
aLinearVectorFunction
uLinearVectorFunction.__init__
uLinearVectorFunction._update_x
uLinearVectorFunction.fun
uLinearVectorFunction.jac
uLinearVectorFunction.hess
a__prepare__
aIdentityVectorFunction
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uIdentityVectorFunction.__init__
a__orig_bases__
uscipy\optimize\_differentiable_functions.py
u<module scipy.optimize._differentiable_functions>
T a__class__
T aself
wxaf0
kwds
wgadct
T aself
wxaf0
kwds
a_h
T aself
wxT aself
wxwvaJ0
kwds
T aself
wxaf0
kwds
wJadct
T aself
x0
sparse_jacobian
wnwAa__class__
T aself
wAax0
sparse_jacobian
xp
a_x
a_dtype
T aself
fun
x0
args
grad
hess
finite_diff_rel_step
finite_diff_bounds
epsilon
workers
xp
a_x
a_dtype
finite_diff_options
a_FakeCounter
T aself
fun
x0
jac
hess
finite_diff_rel_step
finite_diff_jac_sparsity
finite_diff_bounds
sparse_jacobian
workers
xp
a_x
a_dtype
finite_diff_options
sparsity_groups
dct
T aself
grad
fun
args
finite_diff_options
T aself
hess
x0
grad
args
finite_diff_options
T aself
fun
T aself
hess
jac
finite_diff_options
T aself
jac
fun
finite_diff_options
sparse_jacobian
T aself
wxwvwHT aself
wxakwds
T aself
wxaf0
kwds
dct
T aself
wxwvaJ0
wHT aself
fx
T aself
T aself
delta_x
delta_g
T aself
wvT aself
wxa_x
T aself
wxwv.scipy.optimize._differentialevolution
'
aDifferentialEvolutionSolver
T aargs
strategy
maxiter
popsize
tol
mutation
recombination
rng
polish
callback
disp
init
atol
updating
workers
constraints
x0
integrality
vectorized
a__enter__
a__exit__
solve
T nnnaret
callable
a_DifferentialEvolutionSolver__combined
uPlease select a valid mutation strategy
strategy
a_wrap_callback
differential_evolution
callback
polish
T aimmediate
deferred
a_updating
vectorized
l aimmediate
warnings
warn
udifferential_evolution: the 'workers' keyword has overridden updating='immediate' to updating='deferred'
aUserWarning
D astacklevel
l adeferred
T udifferential_evolution: the 'workers' keyword overrides the 'vectorized' keyword
l T astacklevel
udifferential_evolution: the 'vectorized' keyword has overridden updating='immediate' to updating='deferred'
maplike_for_vectorized_func
uDifferentialEvolutionSolver.__init__.<locals>.maplike_for_vectorized_func
aMapWrapper
a_mapwrapper
utoo many values to unpack (expected 2)
tol
atol
scale
np
all
isfinite
any
array
l l
uThe mutation constant must be a float in U[0, 2), or specified as a tuple(min, max) where min < max and min, max are in U[0, 2).
dither
a__iter__
sort
cross_over_probability
original_func
a_FunctionWrapper
func
args
aBounds
new_bounds_to_old
lb
ub
D adtype
Ofloat
wTalimits
D adtype
float
size
ubounds should be a sequence containing finite real valued (min, max) pairs for each value in x
l  amaxiter
inf
maxfun
f
?a_DifferentialEvolutionSolver__scale_arg1
fabs
a_DifferentialEvolutionSolver__scale_arg2
errstate
T aignore
T adivide
a_DifferentialEvolutionSolver__recip_scale_arg2
parameter_count
check_random_state
random_number_generator
broadcast_to
asarray
copy
ceil
floor
uOne of the integrality constraints does not have any possible integer values between the lower/upper bounds.
nextafter
integrality
count_nonzero
max
l anum_population_members
population_shape
a_nfev
latinhypercube
init_population_lhs
sobol
log2
init_population_qmc
T asobol
T aqmc_engine
halton
T ahalton
random
init_population_random
a_DifferentialEvolutionSolver__init_error_msg
init_population_array
a_unscale_parameters
f
?Z
uSome entries in x0 lay outside the specified bounds
population
constraints
a_wrapped_constraints
a__len__
self
append
a_ConstraintWrapper
wxasum
num_constr
total_constraints
zeros
constraint_violation
ones
feasible
arange
a_random_population_index
disp
atleast_1d
uniform
T asize
linspace
D aendpoint
F:nnnanewaxis
zeros_like
rng
permutation
full
population_energies
uscipy.stats
T aqmc
qmc
aLatinHypercube
T wdaseed
aSobol
aHalton
T wnafloat64
T adtype
shape
uThe population supplied needs to have shape (S, len(x)), where S > 4.
clip
a_scale_parameters
isinf
std
abs
mean
a_MACHEPS
T l
Fa_status_message
success
a_calculate_population_feasibilities
a_calculate_population_energies
a_promote_lowest_energy
maxfev
uMaximum number of function evaluations has been reached.
print
udifferential_evolution step

u: f(x)=
convergence
a_result
uin progress
T anit
message
ucallback function requested stop early
warning_flag
converged
nit
status_message
T anit
message
warning_flag
uL-BFGS-B
utrust-constr
a_constraint_violation_fn
udifferential evolution didn't find a solution satisfying the constraints, attempting to polish from the least infeasible solution
partial
minimize
T amethod
a_f
uDifferentialEvolutionSolver.solve.<locals>._f
uPolishing solution with '
w'T alb
ub
T abounds
constraints
aOptimizeResult
uThe result from a user defined polishing function should return an OptimizeResult.
get
T anfev
l
nfev
fun
T ajac
najac
violation
aDE_result
constr
concatenate
constr_violation
maxcv
uThe solution does not satisfy the constraints, MAXCV =
message
atleast_2d
T wxafun
nfev
nit
message
success
population
population_energies
result
min
squeeze
T ETypeError
EValueError
uThe map-like callable must be of the form f(func, iterable), returning a sequence of numbers the same length as 'iterable'
uThe vectorized function must return an array of shape (S,) when given an array of shape (len(x), S)
ufunc(x, *args) must return a scalar value
argmin
D aaxis
l q wSuAn array returned from a Constraint has the wrong shape. If `vectorized is False` the Constraint should return an array of shape (M,). If `vectorized is True` then the Constraint must return an array of shape (M, S), where S is the number of solution vectors and M is the number of constraint components in a given Constraint object.
reshape
a_out
offset
T :nnnl
a_mutate
a_ensure_constraint
a_accept_trial
cv
a_mutate_many
where
round
bitwise_or
T arng
ustrategy must have signature f(candidate: int, population: np.ndarray, rng=None) returning an array of shape (N,)
a_population
trial
a_mutate_custom
a_select_samples
T acurrenttobest1exp
currenttobest1bin
mutation_func
rng_integers
a_binomial
a_exponential
T Q
l
wiainit_fill
fill_point
T Q
:nl nT Q
:nl nutoo many values to unpack (expected 3)
T Q
:nl nutoo many values to unpack (expected 4)
T Q
:nl nutoo many values to unpack (expected 5)
shuffle
constraint
aNonlinearConstraint
u_ConstraintWrapper.__init__.<locals>.fun
aLinearConstraint
u`constraint` of an unknown type is passed.
ndim
resize
bounds
issparse
wAadot
res
maximum
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.optimize
T aOptimizeResult
minimize
uscipy.optimize._constraints
T aBounds
new_bounds_to_old
aNonlinearConstraint
aLinearConstraint
uscipy.optimize._optimize
T a_status_message
a_wrap_callback
uscipy._lib._util
T acheck_random_state
aMapWrapper
a_FunctionWrapper
rng_integers
a_transition_to_rng
a_transition_to_rng
uscipy._lib._sparse
T aissparse
a__all__
finfo
eps
T aseed
l	T aposition_num
T T
best1bin
l  l f{  G z ?T f
?l fffffff ?nnFtalatinhypercube
l
immediate
l T
nD aintegrality
vectorized
