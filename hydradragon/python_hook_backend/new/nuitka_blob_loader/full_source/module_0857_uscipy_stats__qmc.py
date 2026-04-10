# Reconstructed from integrated Nuitka blob
# Module: uscipy.stats._qmc

a__qualname__
T aseed
FT areplace_doc
D aoptimization
rng
nna__init__
uQMCEngine.__init__
uQMCEngine._initialize
T l D aworkers
l uQMCEngine._random
uQMCEngine.random
D au_bounds
wnaendpoint
workers
nl Fl aintegers
uQMCEngine.integers
uQMCEngine.reset
fast_forward
uQMCEngine.fast_forward
a__orig_bases__
D ascramble
optimization
rng
tnnuHalton.__init__
uHalton._initialize_permutations
uHalton._random
D ascramble
strength
optimization
rng
tl nnuLatinHypercube.__init__
uLatinHypercube._random
uLatinHypercube._random_lhs
T l uLatinHypercube._random_oa_lhs
D ascramble
bits
rng
optimization
tnnnuSobol.__init__
uSobol._scramble
uSobol._random
random_base2
uSobol.random_base2
uSobol.reset
uSobol.fast_forward
aPoissonDisk
D aradius
hypersphere
ncandidates
optimization
rng
l_bounds
u_bounds
f       ?avolume
l nnnnuPoissonDisk.__init__
uPoissonDisk._initialize_grid_pool
uPoissonDisk._random
fill_space
uPoissonDisk.fill_space
uPoissonDisk.reset
uPoissonDisk._hypersphere_volume_sample
uPoissonDisk._hypersphere_surface_sample
aMultivariateNormalQMC
D acov_root
inv_transform
engine
rng
ntnnuMultivariateNormalQMC.__init__
uMultivariateNormalQMC.random
uMultivariateNormalQMC._correlate
uMultivariateNormalQMC._standard_normal_samples
aMultinomialQMC
D aengine
rng
nnuMultinomialQMC.__init__
uMultinomialQMC.random
D atol
maxiter
qhull_options
f h     >l
nuscipy\stats\_qmc.py
u<module scipy.stats._qmc>
T a__class__
T a__class__
aMAXDIM
T aself
wdascramble
optimization
rng
a__class__
T
self
wdascramble
strength
optimization
rng
lhs_method_strength
exc
message
a__class__
T aself
pvals
n_trials
engine
rng
kwarg
kwargs
Taself
mean
cov
cov_root
inv_transform
engine
rng
wdaeigval
eigvec
engine_dim
kwarg
kwargs
Taself
wdaradius
hypersphere
ncandidates
optimization
rng
l_bounds
u_bounds
hypersphere_sample
exc
message
a__class__
T aself
wdaoptimization
rng
T aself
wdascramble
bits
rng
optimization
a__class__
T aself
base_samples
T aself
center
radius
candidates
vec
wpT	aself
center
radius
candidates
wxassq
fr
fr_tiled
wpT aself
wdaoptimization
rng
config
T aself
T aself
wiabdim
permutations
T
sample
tol
maxiter
qhull_options
kwargs
root
decay
l1_old
wial1_new
T asample
decay
qhull_options
new_sample
voronoi
ii
idx
region
verts
centroid
is_valid
T asample
i1
i2
wkadisc
wnaz_ij
c_i1j
c_i2j
c_i1i1
c_i2i2
num
denum
gamma
c_p_i1j
c_p_i2j
alpha
beta
g_i1
g_i2
h_i1
h_i2
c_p_i1i1
c_p_i2i2
sum_
mask
disc_ep
T aself
wnaworkers
sample
T aself
wnaworkers
lhs
T aself
wnaworkers
curr_sample
in_limits
in_neighborhood
add_sample
num_drawn
idx_center
center
candidates
candidate
T aself
wnaworkers
T aself
wnaworkers
sample
total_n
msg
T abest_sample
n_iters
n_nochange
rng
kwargs
wnwdabest_disc
bounds
n_nochange_
n_iters_
col
row_1
row_2
disc
T aself
wnasamples
perms
wiT aself
wnwpan_row
n_col
primes
oa_sample
arrays
p_
oa_sample_
wjaperms
oa_lhs_sample
lhs_engine
wkaidx
lhs
T aself
ltm
T aoptimization
config
optimization_method
optimizer
optimizer_
exc
message
T	aself
wnasamples
even
aRs
thetas
cos
sin
transf_samples
T al_bounds
u_bounds
wdalower
upper
exc
msg
T abase
rng
count
permutations
perm
T acandidate
indices
self
curr_sample
T acurr_sample
self
T aseed
T asample
iterative
method
workers
methods
T aself
wnT asample
method
metric
distances
fully_connected_graph
mst
T asample
wiaself
T acandidate
wnaindices
ind_min
ind_max
waaself
T aself
l_bounds
u_bounds
wnaendpoint
workers
message
sample
T wnaprimes
big_number
T wnasieve
wiwkT aself
wnasample
wiabase_draws
p_cumulative
sample_
T aself
wnabase_samples
T aself
wmwnatotal_n
T aself
a__class__
T aself
rng
T asample
l_bounds
u_bounds
reverse
lower
upper
T ax_new
sample
initial_disc
T wnabase
start_index
scramble
permutations
rng
workers
.scipy.stats._qmvnt
primes_from_2_to
np
sqrt
l wnwpafactors
add
sorted
a_factorize_int
l l
wkapm
pow
wrq aones
hstack
f
?f       ?aarange
a_primitive_root
D adtype
Oint
wgaperm
n_qmc_samples
minimum
fUUUUUU ?afft
ww:nnq wqaifft
fc
real
argmin
wzaphi
f
?f V     <a_bvn
min
l  Z
est_error
n_samples
round
T l ami
rng
utoo many values to unpack (expected 3)
prob
a_permuted_cholesky
flags
c_contiguous
copy
cho
shape
a_cbc_lattice
max
utoo many values to unpack (expected 2)
random
T asize
a_qmvn_inner
T l
paintegrand
u_mvn_qmc_integrand.<locals>.integrand
atleast_1d
zeros
full
ci
dci
use_tent
phinv
wcadc
wywi:nnnalo
hi
pv
asarray
float64
T adtype
a_qmvt_inner
array
uexpected a square symmetric array
uexpected integration boundaries the same dimensions as the covariance matrix
maximum
diag
newaxis
pi
tol
new_lo
wsanew_hi
dem
im
a_swap_slices
s_
ck
exp
lo_m
hi_m
sqtp
q
l
math
T l pT l
l a_bvnu
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.fft
T afft
ifft
uscipy.special
T andtr
ndtri
ndtr
ndtri
uscipy.stats._qmc
T aprimes_from_2_to
uscipy.stats._stats_pythran
T a_bvnu
a_qmvnt_cy
T a_qmvn_inner
a_qmvt_inner
T f    MbP?l Na_qauto
T acbc
l
a_qmvn
T Fa_mvn_qmc_integrand
a_qmvt
T f     | =uscipy\stats\_qmvnt.py
u<module scipy.stats._qmvnt>
T wawbwAas1
s2
s12
wraxl
xu
yl
yu
wpT an_dim
n_qmc_samples
primes
bt
gm
wqwwwzwmwgaperm
wjapn
wcafc
wsareordered
T wnafactors
wpT acovar
low
high
use_tent
cho
lo
hi
wnandim_integrand
ct
wcwdaci
dci
integrand
T acovar
low
high
tol
cho
new_lo
new_hi
wnadc
wyasqtp
wkaepk
im
ck
dem
wsalo_m
hi_m
wiaci
lo_i
hi_i
de
T wpapm
factors
wnwrwkwdard
T afunc
covar
low
high
rng
error
limit
kwds
wnan_samples
prob
est_error
mi
ei
pi
ni
wt
T wmacovar
low
high
rng
lattice
n_batches
cho
lo
hi
wnwqan_qmc_samples
rndm
prob
est_error
n_samples
T wmanu
covar
low
high
rng
lattice
n_batches
sn
cho
lo
hi
wnwqan_qmc_samples
rndm
prob
est_error
n_samples
T wxaslc1
slc2
wtT azs
ndim_qmc
n_qmc_samples
wywcadc
pv
wiwxwsact
wdaci
dci
wnause_tent
cho
lo
hi
T acho
ci
dci
hi
lo
wnause_tent

.scipy.stats._quantile
array_namespace
isdtype
asarray
dtype
T aintegral
ureal floating
u`x` must have real dtype.
ureal floating
u`p` must have real floating dtype.
u`weights` must have real dtype.
xp_promote
T aforce_floating
xp
utoo many values to unpack (expected 3)
xp_device
T adevice
max
ndim
xp_ravel
l
np
iterable
u`axis` must be an integer or None.
u`axis` is not compatible with the shapes of the inputs.
axis
S aweibull
a_midpoint
averaged_inverted_cdf
linear
inverted_cdf
median_unbiased
a_nearest
interpolated_inverted_cdf
normal_unbiased
uharrell-davis
round_inward
round_nearest
a_lower
a_higher
hazen
closest_observation
round_outward
u`method` must be one of

S a_midpoint
a_nearest
uharrell-davis
round_inward
round_nearest
a_lower
a_higher
round_outward
u`method='
u'` does not support `weights`.
a_contains_nan
wxT axp_omit_okay
xp
P ntFuIf specified, `keepdims` must be True or False.
shape
l afull
nan
T adtype
device
sort
T aaxis
stable
a_broadcast_arrays
wpT aaxis
utoo many values to unpack (expected 2)
broadcast_arrays
count_nonzero
T aaxis
keepdims
xpx
at
set
inf
D acopy
taargsort
take_along_axis
utoo many values to unpack (expected 5)
u`keepdims` may be False only if the length of `p` along `axis` is 1.
moveaxis
q a_length_nonmasked
T axp
keepdims
isnan
propagate
any
D aaxis
q D aaxis
keepdims
q taastype
nan_out
nans
uharrell-davis
T l
wyT f
?a_quantile_iv
utoo many values to unpack (expected 12)
P	aweibull
averaged_inverted_cdf
linear
median_unbiased
inverted_cdf
interpolated_inverted_cdf
normal_unbiased
hazen
closest_observation
a_quantile_hf
P uharrell-davis
a_quantile_hd
P a_lower
a_higher
a_midpoint
a_nearest
a_quantile_bc
a_quantile_winsor
xp
T l areshape
squeeze
inverted_cdf
averaged_inverted_cdf
closest_observation
f
interpolated_inverted_cdf
hazen
f
?aweibull
linear
median_unbiased
l fUUUUUU ?anormal_unbiased
l f
?acumulative_sum
int64
T adtype
broadcast_to
:nq na_xp_searchsorted
D aside
right
jg
l P ainverted_cdf
closest_observation
averaged_inverted_cdf
clip
Z
wnajp1
newaxis
arange
betainc
T Q
:l nnT Q
:nq navecdot
round_outward
floor
ceil
round_inward
round_nearest
round
where
a_midpoint
a_lower
a_higher
a_nearest
wkT aaxis
xp
is_torch
searchsorted
T aside
D acopy
Faleft
less_equal
less
math
log2
wawbacompare
min
right
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.special
T abetainc
uscipy._lib._array_api
T axp_capabilities
xp_ravel
array_namespace
xp_promote
xp_device
a_length_nonmasked
is_torch
xp_capabilities
uscipy._lib.array_api_extra
a_lib
array_api_extra
uscipy.stats._axis_nan_policy
T a_broadcast_arrays
a_contains_nan
T L T udask.array
uNo take_along_axis yet.
FT askip_backends
jax_jit
D amethod
axis
nan_policy
keepdims
weights
linear
l
propagate
nnaquantile
T L T udask.array
uNo take_along_axis yet.
T askip_backends
D aside
xp
left
nuscipy\stats\_quantile.py
u<module scipy.stats._quantile>
T wywpwnamethod
xp
ij
wkT	wywpwnaxp
wawbwiwwares
T wywpwnamethod
weights
xp
ms
wmajg
jp1
wjacumulative_weights
n_int
total_weight
wgT wxwpamethod
axis
nan_policy
keepdims
weights
xp
dtype
axis_none
ndim
message
methods
no_weights
contains_nans
shape
wyan_zero_weight
i_zero_weight
i_y
wnanans
nan_out
n_int
p_mask
T	wywpwnamethod
xp
ops
op_left
op_right
wjT wxwyaside
xp
xp_default_int
y_0d
x_1d
out
wawnwbacompare
wiwcax0
wjT wxwpamethod
axis
nan_policy
keepdims
weights
temp
wywnaaxis_none
ndim
p_mask
xp
res
shape
.scipy.stats._rcont
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_scipy
u\not_existing
ustats\_rcont
T aNUITKA_PACKAGE_scipy_stats
u\not_existing
a_rcont
T aNUITKA_PACKAGE_scipy_stats__rcont
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
rcont
T arvs_rcont1
rvs_rcont2
l arvs_rcont1
l
rvs_rcont2
a__all__
uscipy\stats\_rcont\__init__.py
u<module scipy.stats._rcont>

.scipy.stats._relative_risk
5

u must be an integer not less than
u, but got
operator
index
l
l uconfidence_level must be in the interval [0, 1].
exposed_cases
control_cases
aConfidenceInterval
np
nan
T alow
high
Z
inf
ndtri
l arelative_risk
sqrt
exposed_total
control_total
exp
a_validate_int
uexposed_cases must not exceed exposed_total.
ucontrol_cases must not exceed control_total.
aRelativeRiskResult
T arelative_risk
exposed_cases
exposed_total
control_cases
control_total
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
dataclasses
T adataclass
dataclass
numpy
uscipy.special
T andtri
a_common
T aConfidenceInterval
