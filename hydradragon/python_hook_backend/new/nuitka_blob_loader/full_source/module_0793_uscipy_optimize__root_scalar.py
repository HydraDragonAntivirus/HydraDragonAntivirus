# Reconstructed from integrated Nuitka blob
# Module: uscipy.optimize._root_scalar

a__qualname__
a__init__
uMemoizeDer.__init__
a__call__
uMemoizeDer.__call__
uMemoizeDer.fprime
uMemoizeDer.fprime2
ncalls
uMemoizeDer.ncalls
T T
nnnnnnnnnna_root_scalar_brentq_doc
a_root_scalar_brenth_doc
a_root_scalar_toms748_doc
a_root_scalar_secant_doc
a_root_scalar_newton_doc
a_root_scalar_halley_doc
a_root_scalar_ridder_doc
a_root_scalar_bisect_doc
uscipy\optimize\_root_scalar.py
u<module scipy.optimize._root_scalar>
T aself
wxaargs
fg
T aself
fun
T wxaargs
wfT wfT aself
wxaargs
T wxaargs
f_wrapped
T aself
T wfaargs
method
bracket
fprime
fprime2
x0
x1
xtol
rtol
maxiter
options
is_memoized
kwargs
wkwvameth
map2underlying
methodc
wewawbwrasol
n_calls
.scipy.optimize._shgo
v
aBounds
new_bounds_to_old
lb
ub
aSHGO
T	aargs
constraints
wnaiters
callback
minimizer_kwargs
options
sampling_method
workers
a__enter__
a__exit__
iterate_all
T nnnabreak_routine
disp
logging
info
T uSuccessfully completed construction of complex.
aLMC
xl_maps
find_lowest_vertex
fail_routine
uFailed to find a feasible minimizer point. Lowest sampling point =
f_lowest

T ames
res
fun
x_lowest
wxafn
nfev
n_sampled
tnev
uOptimization terminated successfully.
message
success
uscipy.stats
T aqmc
l
qmc
halton
sobol
simplicial
uUnknown sampling_method specified. Valid methods: {}
u,
copy
get
T ajac
najac
pop
T ajac
minimizer_kwargs
callable
aMemoizeJac
func
derivative
T ETypeError
EKeyError
a_FunctionWrapper
bounds
args
callback
np
array
shape
dim
isfinite
f d~   Q T :nnnl
f d~   QJT :nnnl l aany
uError: lb > ub in bounds
w.aconstraints
min_cons
g_cons
g_args
standardize_constraints
empty
old
type
ineq
self
append
T T
method
aSLSQP
options
update
D aftol
f  -   q=alower
T aslsqp
cobyla
cobyqa
utrust-constr
init_options
f_min_true
minimize_every_iter
maxiter
maxfev
maxev
maxtime
minhgrd
symmetry
infty_cons_sampl
local_iter
T ahess
nahess
T aargs
nL afun
x0
args
callback
options
method
min_solver_args
D a_custom
unelder-mead
powell
cg
bfgs
unewton-cg
ul-bfgs-b
tnc
cobyla
cobyqa
slsqp
dogleg
utrust-ncg
utrust-krylov
utrust-exact
utrust-constr
L ajac
hess
hessp
bounds
constraints
L
pL ajac
L ajac
L ajac
hess
hessp
L ajac
bounds
L ajac
bounds
L aconstraints
catol
L abounds
constraints
feasibility_tol
L ajac
bounds
constraints
L ajac
hess
L ajac
hess
hessp
L ajac
hess
hessp
L ajac
hess
L ajac
hess
hessp
constraints
a_restrict_to_keys
uSHGO.__init__.<locals>._restrict_to_keys
ftol
stop_global
iters
iters_done
wnanc
n_prc
hgr
qhull_incremental
l ldaComplex
T adim
domain
sfield
sfield_args
symmetry
constraints
workers
aHC
iterate_hypercube
iterate_complex
sampling_method
T ahalton
sobol
iterate_delaunay
ceil
log2
aSobol
T wdascramble
seed
qmc_engine
aHalton
uSHGO.__init__.<locals>.sampling_method
custom
sampling_custom
sampling
sampling_function
stop_l_iter
stop_complex_iter
minimizer_pool
aLMapCache
aOptimizeResult
nlfev
nljev
nlhev
u<genexpr>
uSHGO.__init__.<locals>.<genexpr>
dictionary
random
T ajac
hess
hessp
T aminimize_every_iter
tT amaxiter
nT amaxfev
nT amaxev
natime
init
T amaxtime
naf_min
T af_tol
f-C   6 ?af_tol
T aminhgrd
nT asymmetry
FT alocal_iter
FT ainfty_constraints
tT adisp
FwVa_mapwrapper
T uSplitting first generation
iterate
stopping_criteria
find_minima
nit
T uSearching for minimizer pool...
minimizers
aX_min
minimise_pool
sort_result
uMinimiser pool = SHGO.X_min =
inf
cache
wfuself.HC.V[x].f =
x_a
x_l
min
uIterations done =
u /
uSHGO.finite_iterations.<locals>.<genexpr>
uFunction evaluations done =
uSampling evaluations done =
uTime elapsed =
uLowest function evaluation =
uSpecified minimum =
Z
warnings
warn
uA much lower value than expected f* =
u was found f_lowest =
D astacklevel
l asize
hgrd
uCurrent homology growth =
u  (minimum growth =
w)afinite_iterations
finite_fev
finite_ev
finite_time
finite_precision
finite_homology_growth
T uConstructing and refining simplicial complex graph structure
refine_all
refine
T uTriangulation completed, evaluating all constraints and objective function values.
star
nn
v_near
union
process_pools
T uEvaluations completed.
sampled_surface
T ainfty_cons_sampl
uself.n =
uself.nc =
T uConstructing and refining simplicial complex graph structure from sampling points.
argsort
wCD aaxis
l
aInd_sorted
flatten
utoo many values to unpack (expected 2)
tris
namedtuple
aTri
points
simplices
delaunay_triangulation
T an_prc
vf_to_vv
all
in_LMC
minimiser
T u============================================================
uv.x =
u is minimizer
uv.f =
T u==============================
T uNeighbors:
ux =
u || f =
minimizer_pool_F
aX_min_cache
sort_min_pool
minimize
T aind
trim_min_pool
T l
force_iter
g_topograph
lres_f_min
wZT :nnnq aSs
T q :nnnq aind_f_min
delete
spatial
distance
cdist
euclidean
wYD aaxis
q av_min
ucbounds found for v_min.x_a =
ucbounds =
uVertex minimiser maps =
v_maps
lres
uFound self.LMC[x_min].lres =
uCallback for minimizer starting at
w:uStarting minimization at
u...
construct_lcb_simplicial
construct_lcb_delaunay
T ubounds in kwarg:
x_min
ulres =
njev
nhev
T EIndexError
ETypeError
add_res
g_bounds
T abounds
sort_cache_result
xl
funl
T uGenerating sampling points
vstack
sampling_subspace
sorted_samples
:nnnD adtype
Obool
uNo sampling point found within the feasible set. Increasing sampling size.
aXs
add_points
aDelaunay
T aincremental
aQhullError
exc_info
:nl naQH6239
warning
T uQH6239 Qhull precision error detected, this usually occurs when no bounds are specified, Qhull can only run with handling cocircular/cospherical points and in this case incremental mode is switched off. The performance of shgo will be reduced in this mode.
wvalbounds
xl_maps_set
f_maps
lbound_maps
ndarray
tolist
aLMap
add
wTa__doc__
a__file__
a__spec__
origin
has_location
a__cached__
collections
T anamedtuple
sys
numpy
scipy
T aspatial
uscipy.optimize
T aOptimizeResult
minimize
aBounds
uscipy.optimize._optimize
T aMemoizeJac
uscipy.optimize._constraints
T anew_bounds_to_old
uscipy.optimize._minimize
T astandardize_constraints
uscipy._lib._util
T a_FunctionWrapper
uscipy.optimize._shgo_lib._complex
T aComplex
shgo
a__all__
T T
nldl nnnasimplicial
D aworkers
