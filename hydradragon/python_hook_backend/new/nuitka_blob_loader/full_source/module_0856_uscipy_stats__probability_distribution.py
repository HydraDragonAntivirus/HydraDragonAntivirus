# Reconstructed from integrated Nuitka blob
# Module: uscipy.stats._probability_distribution

a__qualname__
classmethod
a__class_getitem__
support
u_ProbabilityDistribution.support
sample
u_ProbabilityDistribution.sample
moment
u_ProbabilityDistribution.moment
mean
u_ProbabilityDistribution.mean
median
u_ProbabilityDistribution.median
mode
u_ProbabilityDistribution.mode
variance
u_ProbabilityDistribution.variance
standard_deviation
u_ProbabilityDistribution.standard_deviation
skewness
u_ProbabilityDistribution.skewness
kurtosis
u_ProbabilityDistribution.kurtosis
pdf
u_ProbabilityDistribution.pdf
logpdf
u_ProbabilityDistribution.logpdf
D amethod
napmf
u_ProbabilityDistribution.pmf
logpmf
u_ProbabilityDistribution.logpmf
cdf
u_ProbabilityDistribution.cdf
icdf
u_ProbabilityDistribution.icdf
ccdf
u_ProbabilityDistribution.ccdf
iccdf
u_ProbabilityDistribution.iccdf
logcdf
u_ProbabilityDistribution.logcdf
ilogcdf
u_ProbabilityDistribution.ilogcdf
logccdf
u_ProbabilityDistribution.logccdf
ilogccdf
u_ProbabilityDistribution.ilogccdf
logentropy
u_ProbabilityDistribution.logentropy
entropy
u_ProbabilityDistribution.entropy
a__orig_bases__
uscipy\stats\_probability_distribution.py
u<module scipy.stats._probability_distribution>
T a__class__
T aself
wxwyamethod
T aself
method
T aself
wpamethod
T aself
logp
method
T aself
wxamethod
T aself
order
kind
method
T aself
shape
method
rng
T aself

.scipy.stats._qmc
,
numbers
aIntegral
np
integer
random
default_rng
aRandomState
aGenerator

u cannot be used to seed a numpy.random.Generator instance
asarray
ndim
l uSample is not a 2D array
a_validate_bounds
shape
l T al_bounds
u_bounds
wdutoo many values to unpack (expected 2)
max
f
?amin
Z
uSample is not in unit hypercube
all
uSample is out of bounds
float64
wCT adtype
order
a_ensure_in_unit_hypercube
a_validate_workers
aCD
a_cy_wrapper_centered_discrepancy
aWD
a_cy_wrapper_wrap_around_discrepancy
aMD
a_cy_wrapper_mixture_discrepancy
uL2-star
a_cy_wrapper_l2_star_discrepancy
T aworkers
u is not a valid method. It must be one of
l
uSample must contain at least two points
distance
pdist
T ametric
any
warnings
warn
T uSample contains duplicate points.
l T astacklevel
mindist
nonzero
mst
squareform
minimum_spanning_tree
mean
u is not a valid method. It must be one of {'mindist', 'mst'}
ux_new is not a 1D array
ux_new is not in unit hypercube
ux_new and sample must be broadcastable
a_cy_wrapper_update_discrepancy
f
?f
@aprod
:nnnD aaxis
l aones
D adtype
Obool
l l asieve
l ar_
:l nnL  l l l l l ll l l l l l%l)l+l/l5l;l=lClGlIlOlSlYlalelglklmlql l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  aprimes_from_2_to
big_number
primes
check_random_state
math
ceil
l6alog2
repeat
arange
D aaxis
l
rng
shuffle
u'base' must be at least 2
a_van_der_corput_permutations
T abase
rng
astype
int64
a_cy_van_der_corput_scrambled
a_cy_van_der_corput
a_initialize
T aoptimization
rng
issubdtype
ud must be a non-negative integer value
wda_rng_spawn
copy
deepcopy
rng_seed
num_generated
n_nochange
ldan_iters
l Natol
f h     >amaxiter
l
qhull_options
a_optimization
a_select_optimizer
optimization_method
a_random
atleast_1d
dtype
u'u_bounds' and 'l_bounds' must be integers or array-like of integers
aHalton
T wnaworkers
T wnascale
T al_bounds
u_bounds
floor
scramble
optimization
a_init_quad
a__class__
T wdaoptimization
rng
n_primes
base
a_initialize_permutations
a_permutations
self
van_der_corput
wnaworkers
T astart_index
scramble
permutations
workers
array
wTareshape
strength
T wdarng
optimization
a_random_lhs
a_random_oa_lhs
lhs_method
u is not a valid strength. It must be one of
uniform
T asize
tile
sqrt
T Oint
un is not the square of a prime number. Close values are
:q nnun is too small for d. Must be n > (d-1)**2
zeros
T ashape
dtype
T l l astack
meshgrid
D aaxis
q T q l T :nnn:nl namod
oa_sample
T :nnnl
T :nnnl wpaempty
permutation
oa_sample_
T ashape
aLatinHypercube
T wdascramble
strength
rng
lhs_engine
flatten
bits
aMAXDIM
uMaximum supported dimensionality is
w.l l auint32
dtype_i
l@auint64
uMaximum supported 'bits' is 64
maxn
T adtype
a_sv
a_initialize_v
T adim
bits
a_shift
a_scramble
a_quasi
a_scale
T l q a_first_point
dot
rng_integers
T asize
dtype
tril
a_cscramble
T adim
bits
ltm
sv
uAt most 2**
w=u distinct points can be generated.
u points have been previously generated, then: n=
w+u.
uConsider increasing `bits`.
T uThe balance properties of Sobol' points require n to be a power of 2.
l a_draw
T wnanum_gen
dim
scale
sv
quasi
sample
concatenate
sample
uThe balance properties of Sobol' points require n to be a power of 2.
u+2**
u. If you still want to do this, the function 'Sobol.random()' can be used.
reset
a_fast_forward
T wnanum_gen
dim
sv
quasi
radius
hypersphere
ncandidates
volume
a_hypersphere_volume_sample
surface
a_hypersphere_surface_sample
hypersphere_method
u is not a valid hypersphere sampling method. It must be one of
fj t    ?aradius_factor
radius_squared
l_bounds
u_bounds
errstate
T aignore
T adivide
a__enter__
a__exit__
cell_size
grid_size
T nnna_initialize_grid_pool
sample_pool
append
float32
sample_grid
fill
nan
in_limits
uPoissonDisk._random.<locals>.in_limits
T l ain_neighborhood
uPoissonDisk._random.<locals>.in_neighborhood
add_sample
uPoissonDisk._random.<locals>.add_sample
num_drawn
maximum
minimum
isnan
T ainvalid
sum
square
T aaxis
curr_sample
inf
standard_normal
gammainc
T q l amultiply
linalg
norm
T :nnnnaatleast_2d
uDimension mismatch between mean and covariance.
allclose
transpose
uCovariance matrix is not symmetric.
cholesky
aLinAlgError
eigh
f: 0  yE uCovariance matrix not PSD.
clip
a_inv_transform
seed
aSobol
engine
aQMCEngine
uDimension of `engine` must be consistent with dimensions of mean and covariance. If `inv_transform` is False, it must be an even number.
u`engine` must be an instance of `scipy.stats.qmc.QMCEngine` or `None`.
a_mean
cov_root
a_corr_matrix
a_d
a_standard_normal_samples
a_correlate
stats
ppf
f A     ?q q alog
pi
cos
sin
pvals
uElements of pvals must be non-negative.
isclose
uElements of pvals must sum to 1.
n_trials
D wdascramble
bits
l tl uDimension of `engine` must be 1.
ravel
empty_like
D adtype
Ofloat
a_fill_p_cumulative
zeros_like
intp
a_categorize
urandom-cd
a_random_cd
lloyd
a_lloyd_centroidal_voronoi_tessellation
lower
u is not a valid optimization method. It must be one of
partial
discrepancy
n_nochange_
n_iters_
D aendpoint
ta_perturb_discrepancy
best_sample
best_disc
cityblock
aVoronoi
T aqhull_options
point_region
voronoi
regions
vertices
decay
new_sample
logical_and
u`sample` is not a 2D array
u`sample` dimension is not >= 2
u`sample` is not in unit hypercube
uQbb Qc Qz QJ
l u Qx
T f       ?aexp
root
f       ?a_l1_norm
T asample
a_lloyd_iteration
T asample
decay
qhull_options
l1_old
cpu_count
uCannot determine the number of cpus using os.cpu_count(), cannot use -1 for the number of workers
uInvalid number of workers:
u, must be -1 or > 0
broadcast_to
u'l_bounds' and 'u_bounds' must be broadcastable and respect the sample dimension
uBounds are not consistent 'l_bounds' < 'u_bounds'
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
os
abc
T aABC
abstractmethod
aABC
abstractmethod
aClassVar
aLiteral
overload
aTYPE_CHECKING
ucollections.abc
T aCallable
aCallable
numpy
uscipy._lib._util
T aDecimalNumber
aGeneratorType
aIntNumber
aSeedType
aDecimalNumber
aGeneratorType
aIntNumber
aSeedType
uscipy.stats
T arng_integers
a_rng_spawn
a_transition_to_rng
a_transition_to_rng
uscipy.sparse.csgraph
T aminimum_spanning_tree
uscipy.spatial
T adistance
aVoronoi
uscipy.special
T agammainc
a_sobol
T a_initialize_v
a_cscramble
a_fill_p_cumulative
a_draw
a_fast_forward
a_categorize
a_MAXDIM
a_MAXDIM
a_qmc_cy
T a_cy_wrapper_centered_discrepancy
a_cy_wrapper_wrap_around_discrepancy
a_cy_wrapper_mixture_discrepancy
a_cy_wrapper_l2_star_discrepancy
a_cy_wrapper_update_discrepancy
a_cy_van_der_corput_scrambled
a_cy_van_der_corput
L ascale
discrepancy
geometric_discrepancy
update_discrepancy
aQMCEngine
aSobol
aHalton
aLatinHypercube
aPoissonDisk
aMultinomialQMC
aMultivariateNormalQMC
a__all__
T Q
T nD areverse
FD aiterative
method
workers
FaCD
l T amindist
euclidean
geometric_discrepancy
update_discrepancy
D arng
nD astart_index
scramble
permutations
rng
workers
l
Fnnl a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
