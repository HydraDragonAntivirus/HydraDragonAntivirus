# Reconstructed from integrated Nuitka blob
# Module: uscipy.stats._relative_risk

a__qualname__
T fffffff ?aconfidence_interval
uRelativeRiskResult.confidence_interval
uscipy\stats\_relative_risk.py
u<module scipy.stats._relative_risk>
T wnabound
name
msg
T	aself
confidence_level
alpha
wzarr
se
delta
katz_lo
katz_hi
T aexposed_cases
exposed_total
control_cases
control_total
rr
p1
p2
.scipy.stats._resampling
/
D aaxis
l
stat_nd
u_vectorize_statistic.<locals>.stat_nd
shape
np
cumsum
:nq na_broadcast_concatenate
moveaxis
l
stat_1d
u_vectorize_statistic.<locals>.stat_nd.<locals>.stat_1d
apply_along_axis
split
split_indices
statistic
sample
q abatch
min
wnaones
D adtype
Obool
fill_diagonal
:nnnaarange
broadcast_to
reshape
l axp
asarray
xp_device
T adevice
a_get_from_last_axis
T axp
a_jackknife_resample
rng_integers
is_array_api_strict
ndim
l aexpand_dims
D aaxis
q a_broadcast_arrays
T aaxis
xp
utoo many values to unpack (expected 2)
take_along_axis
D aaxis
q acount_nonzero
T aaxis
astype
dtype
axis
a_percentile_of_score
T adtype
device
ndtri
data
samples
theta_hat_i
theta_hat_ji
concat
mean
D aaxis
keepdims
q tutoo many values to unpack (expected 3)
sum
l fUUUUUU ?f
?andtr
array_namespace
P Ftnu`vectorized` must be `True`, `False`, or `None`.
inspect
signature
parameters
is_numpy
uWhen using array library
a__name__

u, `func` must be vectorized and accept argument `axis`.
a_vectorize_statistic
u`axis` must be an integer.
u`data` must be a sequence of samples.
u`data` must contain at least one sample.
axis_int
ueach sample in `data` must contain two or more observations along `axis`.
data_iv
P Ftu`paired` must be `True` or `False`.
:l nnuWhen `paired is True`, all samples must have the same length along `axis`
u_bootstrap_iv.<locals>.statistic
lower
S utwo-sided
greater
less
u`alternative` must be one of
u`n_resamples` must be a non-negative integer.
u`batch` must be a positive integer or None.
S abca
percentile
basic
u`method` must be in
bootstrap_distribution
u`bootstrap_result` must have attribute `bootstrap_distribution'
xp_size
uEither `bootstrap_result.bootstrap_distribution.size` or `n_resamples` must be positive.
check_random_state
wia_bootstrap_iv
utoo many values to unpack (expected 13)
n_resamples
a_bootstrap_resample
batch_actual
rng
T an_resamples
rng
xp
resampled_data
theta_hat_b
utwo-sided
bca
a_bca_interval
T aaxis
alpha
theta_hat_b
batch
xp
:nl nastack
stats
quantile
any
isnan
warnings
warn
aDegenerateDataWarning
T uThe BCa confidence interval cannot be calculated. This problem is known to occur when the distribution is degenerate or the statistic is np.min.
D astacklevel
l T Q
l
T Q
l abasic
less
full_like
inf
greater
std
D acorrection
axis
l q aBootstrapResult
aConfidenceInterval
T aconfidence_interval
bootstrap_distribution
standard_error
aSequence
callable
u`rvs` must be callable or sequence of callables.
uIf `rvs` is a sequence, `len(rvs)` must equal `len(data)`.
u`statistic` must be callable.
uSignature inspection of statistic=
u failed; pass `vectorize` explicitly.
xp_result_type
force_floating
u`statistic` must be vectorized (i.e. support an `axis` argument) when `data` contains
u arrays.
T l u`n_resamples` must be a positive integer.
u`alternative` must be in
a_monte_carlo_test_iv
utoo many values to unpack (expected 10)
rvs
n_observations
T asize
null_distribution
T q aisdtype
ureal floating
finfo
eps
ldaabs
umonte_carlo_test.<locals>.less
umonte_carlo_test.<locals>.greater
two_sided
umonte_carlo_test.<locals>.two_sided
clip
Z
f
?aMonteCarloTestResult
gamma
T adtype
T aaxis
dtype
minimum
keys
S asize
fun
wrapped_rvs_i
u_wrap_kwargs.<locals>.wrapped_rvs_i
uIf `rvs` is a sequence, `len(rvs)` must equal `len(n_observations)`.
u`kwargs` must be a dictionary that maps keywords to arrays.
values
max
u`significance` must contain floats between 0 and 1.
a_wrap_kwargs
broadcast_arrays
wTu`test` must be callable.
u, `test` must be be vectorized and accept argument `axis`.
a_power_iv
utoo many values to unpack (expected 11)
nobs_i
size
test
pvalue
pvalues_i
pvalues
xpx
significance
aPowerResult
T apower
pvalues
all_partitions
u_all_partitions_concatenated.<locals>.all_partitions
all_partitions_n
u_all_partitions_concatenated.<locals>.all_partitions_n
ns
concatenate
T Oint
a_all_partitions_concatenated
combinations
wz:l
l naiterable
u`batch` must be positive.
iterator
a_batch_generator
permuted
batched_perm_generator
u_pairings_permutations_gen.<locals>.batched_perm_generator
n_obs_sample
tile
n_samples
n_permutations
indices
random
argsort
accumulate
D ainitial
l
math
prod
comb
T abatch
q apermutation
n_obs
u<genexpr>
u_calculate_null_both.<locals>.<genexpr>
factorial
product
a_pairings_permutations_gen
xp_swapaxes
data_batch
permutations
u_calculate_null_pairings.<locals>.<genexpr>
statistic_wrapped
u_calculate_null_samples.<locals>.statistic_wrapped
a_calculate_null_pairings
T :l
l nQ
S apairings
samples
independent
u`permutation_type` must be in
w.aindependent
u`data` must be a tuple containing at least two samples
atleast_nd
D andim
l aisinf
a_permutation_test_iv
pairings
a_calculate_null_samples
a_calculate_null_both
upermutation_test.<locals>.less
upermutation_test.<locals>.greater
upermutation_test.<locals>.two_sided
aPermutationTestResult
adjustment
float_dtype
uUse of `rvs` and `rng` are mutually exclusive.
a_random_state
a_rng
a__class__
a__init__
T an_resamples
batch
random_state
method
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
itertools
T acombinations
permutations
product
accumulate
ucollections.abc
T aSequence
dataclasses
T adataclass
field
dataclass
field
uscipy._lib._util
T acheck_random_state
a_rename_parameter
rng_integers
a_transition_to_rng
a_rename_parameter
a_transition_to_rng
uscipy._lib._array_api
T aarray_namespace
is_numpy
is_array_api_strict
xp_capabilities
xp_result_type
xp_size
xp_device
xp_swapaxes
xp_capabilities
uscipy._lib
T aarray_api_extra
array_api_extra
uscipy.special
T andtr
ndtri
scipy
T astats
a_common
T aConfidenceInterval
a_axis_nan_policy
T a_broadcast_concatenate
a_broadcast_arrays
a_warnings_errors
T aDegenerateDataWarning
bootstrap
monte_carlo_test
permutation_test
a__all__
