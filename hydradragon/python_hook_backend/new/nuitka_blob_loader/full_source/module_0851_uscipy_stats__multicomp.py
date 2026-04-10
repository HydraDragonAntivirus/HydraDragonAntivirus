# Reconstructed from integrated Nuitka blob
# Module: uscipy.stats._multicomp

a__qualname__
T FT arepr
T nFT adefault
repr
a__str__
uDunnettResult.__str__
T fffffff ?f    MbP?uDunnettResult._allowance
uDunnettResult.confidence_interval
T tT anp_only
T arandom_state
FT areplace_doc
D aalternative
rng
utwo-sided
nT nuscipy\stats\_multicomp.py
u<module scipy.stats._multicomp>
T a__class__
statistic
pvalue
a_alternative
a_rho
a_df
a_std
a_mean_samples
a_mean_control
a_n_samples
a_n_control
a_rng
a_ci
a_ci_cl
T aself
wswiT aself
confidence_level
tol
alpha
pvalue_from_stat
res
critical_value
allowance
T	asamples
control
alternative
rng
samples_control
ndim_msg
n_obs_msg
samples_
sample
T	asamples
control
n_samples
n_sample
n_control
wnan_groups
df
rho
T arho
df
statistic
alternative
rng
mvt
pvalue
T asamples
control
df
n_samples
n_control
mean_control
mean_samples
all_samples
all_means
s2
std
wzT aself
confidence_level
allowance
diff_means
low
high
T acontrol
alternative
rng
samples
samples_
control_
rho
df
n_group
n_samples
n_control
statistic
std
mean_control
mean_samples
pvalue
T astatistic
sf
self
alpha
T aalpha
self
.scipy.stats._multivariate
squeeze
ndim
l
out
T nq adtype
char
lower
D wfwdf
@ @f
.Aanp
finfo
eps
max
array
l D adtype
Ofloat
copy
atleast_1d
uCannot marginalize all dimensions.
issubdtype
integer
uElements of `dimensions` must be integers - the indices of the marginal variables being retained.
unique
uAll elements of `dimensions` must be unique.
any
uDimensions

u are invalid for a distribution in
u dimensions.
asarray
a_M
scipy
linalg
eigh
T alower
check_finite
utoo many values to unpack (expected 2)
a_eigvalsh_to_eps
min
uThe input matrix must be symmetric positive semidefinite.
aLinAlgError
T uWhen `allow_singular is False`, the input matrix must be symmetric positive definite.
a_pinv_1d
multiply
sqrt
f
@ @:nnnwVarank
wUasum
log
log_pdet
a_pinv
norm
D aaxis
q adot
wTa__class__
a__init__
check_random_state
a_random_state
a_dist
doccer
docformat
a__doc__
mvn_docdict_params
multivariate_normal_frozen
allow_singular
seed
a_covariance
aCovariance
a_process_parameters_Covariance
a_process_parameters_psd
utoo many values to unpack (expected 3)
a_PSD
T aallow_singular
aCovViaPSD
shape
q Z
u`cov` represents a covariance matrix in
u dimensions,and so `mean` must be broadcastable to shape
broadcast_to
l asize
isscalar
uDimension of random variable must be a scalar.
mean
zeros
dim
cov
f
?areshape
T l T l puArray 'mean' must be a vector of length
w.aeye
diag
uArray 'cov' must be square if it is two dimensional, but cov.shape =
uDimension mismatch: array 'cov' is of shape
u, but 'mean' is a vector of length
uArray 'cov' must be at most two-dimensional, but cov.ndim =
newaxis
wxasquare
whiten
f
a_LOG_2PI
a_process_parameters
a_process_quantiles
a_logpdf
a_support_mask
inf
a_squeeze_output
exp
full
broadcast_arrays
T q T aaxis
concatenate
func1d
umultivariate_normal_gen._cdf.<locals>.func1d
apply_along_axis
a_qauto
a_qmvn
wnarng
abseps
maxpts
l
T aerror
limit
n_batches
covariance
l  =a_get_random_state
a_cdf
JZ
Z
multivariate_normal
iterable
normal
T asize
colorize
f
?u`x` must be two-dimensional.
u`fix_mean` must be a one-dimensional array the same length as the dimensionality of the vectors `x`.
T l
atleast_2d
u`fix_cov` must be a two-dimensional square array of same side length as the dimensionality of the vectors `x`.
D alower
check_finite
tpu`fix_cov` must be symmetric positive semidefinite.
a_validate_marginal_input
ix_
multivariate_normal_gen
cov_object
a_allow_singular
releps
logpdf
cdf
T alower_limit
rng
rvs
marginal
matnorm_docdict_params
matrix_normal_frozen
T aseed
uArray `mean` must be two dimensional.
uArray `mean` has invalid shape.
identity
meanshape
rowcov
u`rowcov` must be a scalar or a 2D array.
uArray `rowcov` must be square.
uArray `rowcov` has invalid shape.
colcov
u`colcov` must be a scalar or a 2D array.
uArray `colcov` must be square.
uArray `colcov` has invalid shape.
uArrays `mean` and `rowcov` must have the same number of rows.
uArrays `mean` and `colcov` must have the same number of columns.
wX:q nnuThe shape of array `X` is not compatible with the distribution parameters.
moveaxis
tensordot
D aaxis
l
utoo many values to unpack (expected 4)
D aallow_singular
Facholesky
D alower
tastandard_normal
transpose
T l l l
einsum
ujp,ipq,kq->ijk
D aoptimize
ta_entropy
matrix_normal_gen
dims
rowpsd
colpsd
a_lib
matrix_t_docdict_params
matrix_t_frozen
uArray `mean` must be 2D.
row_spread
uArray `row_spread` has invalid shape.
uArray `row_spread` must be a scalar or a 2D array.
uArray `row_spread` must be square.
col_spread
uArray `col_spread` has invalid shape.
uArray `col_spread` must be a scalar or a 2D array.
uArray `col_spread` must be square.
uArrays `mean` and `row_spread` must have the same number of rows.
uArrays `mean` and `col_spread` must have the same number of columns.
uDegrees of freedom must be a scalar.
uDegrees of freedom must be positive.
df
uThe shape of array `X` is not conformal with the distribution parameters.
l unij,njk,nkl,nlp->nip
T l
l l aslogdet
special
multigammaln
a_LOG_PI
:nq nutoo many values to unpack (expected 5)
pinv
a_cholesky_invwishart_rvs
uijp,ipq,ikq->ijk
matrix_t_gen
random
aRandomState
stats
invwishart
empty_like
iw_samples
D alower
check_finite
tF:l nnachol_samples
uAll parameters must be greater than 0
uParameter vector 'a' must be one dimensional, but a.shape =
uVector 'x' must have either the same number of entries as, or one entry fewer than, parameter vector 'a', but alpha.shape =
u and x.shape =
append
vstack
uThe input must be one dimensional or a two dimensional matrix containing the entries.
uEach entry in 'x' must be greater than or equal to zero.
uEach entry in 'x' must be smaller or equal one.
repeat
logical_and
uEach entry in 'x' must be greater than zero if its alpha is less than one.
abs
f  &  . >uThe input vector 'x' must lie within the normal simplex. but np.sum(x, 0) =
gammaln
dirichlet_docdict_params
dirichlet_frozen
a_lnB
xlogy
a_dirichlet_check_parameters
a_dirichlet_check_input
outer
psi
dirichlet
alpha
dirichlet_gen
pdf
var
entropy
wishart_docdict_params
wishart_frozen
uArray 'scale' must be square if it is two dimensional, but scale.scale =
uArray 'scale' must be at most two-dimensional, but scale.ndim =
scale
uDegrees of freedom must be greater than the dimension of scale matrix minus 1.
uQuantiles must be square if they are two dimensional, but x.shape =
uQuantiles must be square in the first two dimensions if they are three dimensional, but x.shape =
uQuantiles must be at most two-dimensional with an additional dimension for multiple components, but x.ndim =
:l
l nuQuantiles have incompatible dimensions: should be
u, got
uSize must be an integer or tuple of integers; thus must have dimension <= 1. Got size.ndim =
prod
empty
self
a_cholesky_logdet
log_det_x
cho_solve
wCascale_inv_x
trace
tr_scale_inv_x
a_LOG_2
a_mean
a_mode
diagonal
a_var
r_
random_state
chisquare
:nnq atril_indices
D wkq adiag_indices
a_standard_rvs
ndindex
wAa_process_size
a_rvs
wishart_gen
log_det_scale
invwishart_frozen
get_blas_funcs
trsm
D aside
lower
l
tatr_scale_x_inv
T l
paarange
T adf
size
a_inv_standard_rvs
trmm
D aside
lower
l tD aside
lower
trans_a
l tpT aout
invwishart_gen
multinomial_docdict_params
multinomial_frozen
result_type
float32
float64
T adtype
copy
T Q
:nq nuSome rows of `p` do not sum to 1.0 within tolerance of eps=
u. Currently, the last element of these rows is adjusted to compensate, but this condition will produce NaNs beginning in SciPy 1.18.0. Please ensure that rows of `p` sum to 1.0 to avoid futher disruption.
warnings
warn
aFutureWarning
D astacklevel
l D adtype
copy
Oint
tD adtype
Oint
ux must be an array.
uSize of each quantile should be size of p: received
u, but expected
result
a_logpmf
bool_
T adtype
a_checkresult
nan
logpmf
u...j,...k->...jk
entr
binom
pmf
multinomial
multinomial_gen
wpanpcond
umultinomial_frozen.__init__.<locals>._process_parameters
special_ortho_group_frozen
uDimension of rotation must be specified,
nd must be a scalar nonnegative integer.
ortho_group
det
T Q
l
:nnnaspecial_ortho_group_gen
ortho_group_frozen
uDimension of rotation must be specified,and must be a scalar nonnegative integer.
qr
T l
q q T aoffset
axis1
axis2
ortho_group_gen
random_correlation_frozen
T aseed
tol
diag_tol
uArray 'eigs' must be a vector of length greater than 1.
fabs
uSum of eigenvalues must equal dimensionality.
uAll eigenvalues must be non-negative.
T Z
f
?amath
copysign
flags
c_contiguous
wmwda_givens_to_1
wiwjaravel
drot
T wnaoffx
incx
offy
incy
overwrite_x
overwrite_y
T atol
T arandom_state
a_to_corr
uFailed to generate a valid correlation matrix
random_correlation_gen
tol
diag_tol
eigs
T arandom_state
tol
diag_tol
unitary_group_frozen
T l JZ
f
?aunitary_group_gen
mvt_docdict_params
T amean
cov
allow_singular
seed
multivariate_t_frozen
T aloc
shape
df
allow_singular
seed
f
@api
l  umultivariate_t_gen._cdf.<locals>.func1d
a_qmvt
T nT acov
regular
umultivariate_t_gen._entropy.<locals>.regular
asymptotic
umultivariate_t_gen._entropy.<locals>.asymptotic
ldl axpx
apply_where
shape_term
f
f
l q l f
l l f
l aisinf
ones
T Q
nT l
Ofloat
T l Ofloat
loc
uArray 'loc' must be a vector of length
uDimension mismatch: array 'cov' is of shape %s, but 'loc' is a vector of length %d.
u'df' must be greater than zero.
isnan
u'df' is 'nan' but must be greater than zero or 'np.inf'.
multivariate_t_gen
shape_info
T aloc
shape
df
size
random_state
mhg_docdict_params
multivariate_hypergeom_frozen
astype
T Oint
u'm' must an array of integers.
u'n' must an array of integers.
u'm' must be an array with at least one dimension.
T Q
l
u'x' must an array of integers.
u'x' must be an array with at least one dimension.
uSize of each quantile must be size of 'm': received
zeros_like
betaln
utoo many values to unpack (expected 6)
ma
masked_array
T amask
u...i,...j->...ij
T Q
l
pwMaoutput
rem
hypergeometric
multivariate_hypergeom_gen
mcond
ncond
mncond
umultivariate_hypergeom_frozen.__init__.<locals>._process_parameters
T asize
random_state
random_table_frozen
u`x` must be at least two-dimensional
errstate
T aignore
T ainvalid
a__enter__
a__exit__
all
u`x` must contain only integral values
T nnnu`x` must contain only non-negative values
D aaxis
q ushape of `x` must agree with `row`
ushape of `x` must agree with `col`
lnfac
urandom_table_gen.logpmf.<locals>.lnfac
D aaxis
T q q a_process_size_shape
a_process_rvs_method
int64
u`row` must be one-dimensional
u`col` must be one-dimensional
ueach element of `row` must be non-negative
ueach element of `col` must be non-negative
usums over `row` and `col` must be equal
ueach element of `row` must be an integer
ueach element of `col` must be an integer
u`size` must be a non-negative integer or `None`
a_rvs_select
boyett
a_rvs_boyett
patefield
a_rvs_patefield
w'u' not recognized, must be one of
a_rcont
rvs_rcont1
rvs_rcont2
random_table_gen
a_params
urandom_table_frozen.__init__.<locals>._process_parameters
T nnT asize
method
random_state
uniform_direction_frozen
uDimension of vector must be specified, and must be an integer greater than 0.
T L
Oint
a_sample_uniform_direction
uniform_direction_gen
D aaxis
keepdims
q tu`x` and `alpha` must be broadcastable.
floor
u`x` must contain only non-negative integers.
u`alpha` must contain only positive values.
u`n` must be a non-negative integer.
dirichlet_mn_docdict_params
dirichlet_multinomial_frozen
a_dirichlet_multinomial_check_parameters
loggamma
place
dirichlet_multinomial
dirichlet_multinomial_gen
vonmises_fisher_frozen
u'mu' must have one-dimensional shape.
allclose
u'mu' must be a unit vector of norm 1.
u'mu' must have at least two entries.
u'kappa' must be a positive scalar.
uFor 'kappa=0' the von Mises-Fisher distribution becomes the uniform distribution on the sphere surface. Consider using 'scipy.stats.uniform_direction' instead.
uThe dimensionality of the last axis of 'x' must match the dimensionality of the von Mises Fisher distribution.
u'x' must be unit vectors of norm 1 along last dimension.
ive
a_check_data_vs_dist
ui,...i->...
a_log_norm_factor
arctan2
vonmises
stack
cos
sin
q T Q
l f
l@T l alog1p
n_accepted
n_samples
beta
halfdim
envelop_param
kappa
dim_minus_one
correction
u...,...i->...i
D aaxis
l T n:nnnamatmul
T :nnnnT :nnnl
uij,...j->...i
a_rvs_2d
a_rvs_3d
a_rejection_sampling
a_rotate_samples
u'x' must be two dimensional.
directional_stats
mean_direction
mean_resultant_length
solve_for_kappa
uvonmises_fisher_gen.fit.<locals>.solve_for_kappa
root_scalar
D amethod
bracket
brentq
T f: 0  yE>f
e  Aaroot
wravonmises_fisher_gen
mu
invgamma
T ascale
T aloc
scale
a_process_parameters_pdf
T aall
gamma
a_pdf
a_process_shapes
T f
?D acopy
Fu<genexpr>
unormal_inverse_gamma_gen._process_parameters_pdf.<locals>.<genexpr>
unormal_inverse_gamma_gen._process_shapes.<locals>.<genexpr>
normal_inverse_gamma_frozen
normal_inverse_gamma_gen
a_shapes
a__file__
a__spec__
origin
has_location
a__cached__
threading
types
numpy
uscipy.linalg
uscipy._lib
T adoccer
uscipy.special
T agammaln
psi
multigammaln
xlogy
entr
betaln
ive
loggamma
T aspecial
uscipy._lib.array_api_extra
array_api_extra
uscipy._lib._util
T acheck_random_state
uscipy.linalg.blas
T adrot
get_blas_funcs
a_continuous_distns
T anorm
invgamma
a_discrete_distns
T abinom
T a_covariance
a_rcont
a_qmvnt
T a_qmvt
a_qmvn
a_qauto
a_morestats
T adirectional_stats
uscipy.optimize
T aroot_scalar
L amultivariate_normal
matrix_normal
dirichlet
dirichlet_multinomial
wishart
invwishart
multinomial
special_ortho_group
ortho_group
random_correlation
unitary_group
multivariate_t
multivariate_hypergeom
random_table
uniform_direction
vonmises_fisher
normal_inverse_gamma
matrix_t
a__all__
aLock
aMVN_LOCK
useed : {None, int, np.random.RandomState, np.random.Generator}, optional
Used for drawing random variates.
If `seed` is `None`, the `~np.random.RandomState` singleton is used.
If `seed` is an int, a new ``RandomState`` instance is used, seeded
with seed.
If `seed` is already a ``RandomState`` or ``Generator`` instance,
then that object is used.
Default is `None`.
a_doc_random_state
