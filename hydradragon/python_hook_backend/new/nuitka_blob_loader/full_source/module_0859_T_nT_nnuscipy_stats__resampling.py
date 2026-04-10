# Reconstructed from integrated Nuitka blob
# Module: T nT nnuscipy.stats._resampling

a__qualname__
T L T ujax.numpy
uIncompatible with `quantile`.
T udask.array
uDask doesn't have take_along_axis.
T askip_backends
T arandom_state
D
n_resamples
batch
vectorized
paired
axis
confidence_level
alternative
method
bootstrap_result
rng
l NnnFl
fffffff ?utwo-sided
aBCa
nnT asample
data
D avectorized
n_resamples
batch
alternative
axis
nl Nnutwo-sided
l
T tFT aallow_dask_compute
jax_jit
D asignificance
vectorized
n_resamples
batch
kwargs
f{  G z ?nl Nnnapower
T L T udask.array
ulacks required indexing capabilities
D apermutation_type
vectorized
n_resamples
batch
alternative
axis
rng
independent
nl Nnutwo-sided
l
naResamplingMethod
l Na__prepare__
aMonteCarloMethod
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
T l NnnnuMonteCarloMethod.__init__
a_asdict
uMonteCarloMethod._asdict
a__orig_bases__
uUse of attribute `random_state` is deprecated and replaced by `rng`. Support for `random_state` will be removed in SciPy 1.19.0. To silence this warning and ensure consistent behavior in SciPy 1.19.0, control the RNG using attribute `rng`. Values set using attribute `rng` will be validated by `np.random.default_rng`, so the behavior corresponding with a given value may change compared to use of `random_state`. For example, 1) `None` will result in unpredictable random numbers, 2) an integer will result in a different stream of random numbers, (with the same distribution), and 3) `np.random` or `RandomState` instances will result in an error. See the documentation of `default_rng` for more information.
a_rs_deprecation
aPermutationMethod
T FpnT ainit
repr
default
property
uPermutationMethod.random_state
setter
uPermutationMethod.rng
T l NnnD arng
nuPermutationMethod.__init__
uPermutationMethod._asdict
aBootstrapMethod
aBCa
uBootstrapMethod.random_state
uBootstrapMethod.rng
T l NnnaBCa
uBootstrapMethod.__init__
uBootstrapMethod._asdict
uscipy\stats\_resampling.py
T a.0
wiarng
n_obs
T a.0
wian_obs_sample
u<module scipy.stats._resampling>
T a__class__
rng
a_rng
method
T a__class__
rvs
rng
T a__class__
rng
a_rng
T aself
n_resamples
batch
random_state
method
rng
a__class__
T a__class__
T aself
n_resamples
batch
rvs
rng
message
T aself
n_resamples
batch
random_state
rng
a__class__
T ans
all_partitions
all_partitions_n
wzapartitioning
wxT aself
wdT aself
T aiterable
batch
iterator
wzT adata
statistic
axis
alpha
theta_hat_b
batch
xp
theta_hat
percentile
z0_hat
theta_hat_ji
wjasample
samples
theta_hat_i
jackknife_sample
broadcasted
n_j
theta_hat_j_dot
aU_ji
nums
dens
a_hat
z_alpha
z_1alpha
num1
alpha_1
num2
alpha_2
T adata
statistic
vectorized
paired
axis
confidence_level
alternative
n_resamples
batch
method
bootstrap_result
rng
xp
message
axis_int
n_samples
data_iv
sample
wnaconfidence_level_float
alternatives
n_resamples_int
batch_iv
methods
T asample
n_resamples
rng
xp
wnwiT adata
statistic
n_permutations
batch
rng
xp
n_obs_i
n_obs_ic
n_obs
n_max
exact_test
perm_generator
null_distribution
indices
data_batch
T adata
statistic
n_permutations
batch
rng
xp
n_samples
n_obs_sample
n_max
exact_test
perm_generator
batched_perm_generator
args
null_distribution
indices
data_batch
wiT adata
statistic
n_permutations
batch
rng
xp
n_samples
statistic_wrapped
T asample
wiaxp
T	asample
batch
xp
wnabatch_nominal
wkabatch_actual
wjwiT adata
rvs
statistic
vectorized
n_resamples
batch
alternative
axis
axis_int
rvs_i
message
weasignature
xp
dtype
statistic_vectorized
data_iv
sample
n_resamples_int
batch_iv
alternatives
T an_permutations
n_samples
n_obs_sample
batch
rng
batched_perm_generator
T waascore
axis
xp
wBanonzeros
T adata
statistic
permutation_type
vectorized
n_resamples
batch
alternative
axis
rng
axis_int
permutation_types
message
xp
data_iv
sample
n_resamples_int
batch_iv
alternatives
float_dtype
T arvs
test
n_observations
significance
vectorized
n_resamples
batch
kwargs
rvs_i
message
vals
keys
xp
wrapped_rvs
tmp
shape
nobs
integer_dtype
test_vectorized
n_resamples_int
batch_iv
T astatistic
stat_nd
T afun
keys
wrapped_rvs_i
T wzwnwcax0
x1
T wzans
wcwdaall_partitions
all_partitions_n
T aall_partitions
all_partitions_n
T	aindices
wkabatch_actual
permuted_indices
n_obs_sample
batch
n_samples
n_permutations
rng
T abatch
n_obs_sample
n_permutations
n_samples
rng
T	wkabatch_actual
size
wxan_permutations
batch
n_samples
n_obs_sample
rng
T adata
statistic
n_resamples
batch
vectorized
paired
axis
confidence_level
alternative
method
bootstrap_result
rng
args
xp
theta_hat_b
batch_nominal
wkabatch_actual
resampled_data
sample
resample
alpha
interval
ci
msg
ci_l
ci_u
theta_hat
standard_error
T anull_distribution
observed
cmps
pvalues
gamma
xp
dtype
n_resamples
T adtype
gamma
n_resamples
xp
T
null_distribution
observed
cmps
count
pvalues
gamma
xp
adjustment
float_dtype
n_resamples
T aadjustment
float_dtype
gamma
n_resamples
xp
T adata
rvs
statistic
vectorized
n_resamples
batch
alternative
axis
args
dtype
xp
observed
n_observations
batch_nominal
null_distribution
wkabatch_actual
resamples
eps
gamma
less
greater
two_sided
compare
pvalues
T adata
statistic
permutation_type
vectorized
n_resamples
batch
alternative
axis
rng
args
float_dtype
xp
observed
null_calculators
null_calculator_args
calculate_null
null_distribution
exact_test
adjustment
eps
gamma
less
greater
two_sided
compare
pvalues
T atest
rvs
n_observations
significance
vectorized
n_resamples
batch
kwargs
tmp
nobs
args
kwds
shape
xp
batch_nominal
pvalues
wianobs_i
args_i
kwargs_i
pvalues_i
wkabatch_actual
resamples
res
wpanewdims
float_dtype
powers
T aself
val
T wzadata
split_indices
statistic
T asplit_indices
statistic
T aaxis
data
lengths
split_indices
wzastat_1d
T astatistic
T wiaaxis
data
unpaired_statistic
xp
T aaxis
data
xp
n_samples
statistic
T an_samples
statistic
xp
T anull_distribution
observed
pvalues_less
pvalues_greater
pvalues
less
greater
xp
T agreater
less
xp
T akeys
fun
args
all_kwargs
kwargs
.scipy.stats._sensitivity_analysis
$
np
atleast_2d
sin
l
l l l f       ?l aqmc
aSobol
l@T wdaseed
bits
random
wTareshape
q utoo many values to unpack (expected 2)
ppf
aA_B
:nnnuEach distribution in `dists` must have method `ppf`.
shape
tile
arange
var
D aaxis
T l
q amean
D aaxis
q f
?astatistic
uSobolResult.bootstrap.<locals>.statistic
a_f_A
bootstrap
aBCa
a_bootstrap_result
T astatistic
method
n_resamples
confidence_level
bootstrap_result
aBootstrapResult
aConfidenceInterval
confidence_interval
low
high
bootstrap_distribution
standard_error
T aconfidence_interval
bootstrap_distribution
standard_error
aBootstrapSobolResult
T afirst_order
total_order
self
a_f_B
a_f_AB
a_indices_method
check_random_state
uThe balance properties of Sobol' points require 'n' to be a power of 2.
callable
saltelli_2010
lower
method

u is not a valid 'method'. It must be one of
u or a callable.
inspect
signature
parameters
S af_A
f_AB
f_B
uIf 'method' is a callable, it must have the following signature:
indices_method
usobol_indices.<locals>.indices_method
u'dists' must be defined when 'func' is a callable.
wrapped_func
usobol_indices.<locals>.wrapped_func
sample_A_B
T wnadists
rng
sample_AB
T wAwBu'func' output should have a shape ``(s, -1)`` with ``s`` the number of output.
funcAB
usobol_indices.<locals>.funcAB
u<lambda>
usobol_indices.<locals>.<lambda>
f_A
f_B
f_AB
utoo many values to unpack (expected 3)
uWhen 'func' is a dictionary, it must contain the following keys: 'f_A', 'f_B' and 'f_AB'.'f_A' and 'f_B' should have a shape ``(s, n)`` and 'f_AB' should have a shape ``(d, s, n)``.
T q l aerrstate
T aignore
ignore
T adivide
invalid
a__enter__
a__exit__
T af_A
f_B
f_AB
T nnnafirst_order
isfinite
total_order
a_A
wAa_B
wBa_AB
aAB
aSobolResult
squeeze
indices_method_
func
moveaxis
copy
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
dataclasses
T adataclass
dataclass
aTYPE_CHECKING
aAny
ucollections.abc
T aCallable
aCallable
numpy
uscipy.stats._common
T aConfidenceInterval
uscipy.stats._qmc
T acheck_random_state
uscipy.stats._resampling
T aBootstrapResult
uscipy.stats
T aqmc
bootstrap
uscipy._lib._array_api
T axp_capabilities
xp_capabilities
uscipy._lib._util
T a_transition_to_rng
a_transition_to_rng
sobol_indices
a__all__
f_ishigami
