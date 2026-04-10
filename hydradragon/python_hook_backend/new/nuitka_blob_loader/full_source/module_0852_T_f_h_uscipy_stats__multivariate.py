# Reconstructed from integrated Nuitka blob
# Module: T f h     >uscipy.stats._multivariate

a__qualname__
T nntppu_PSD.__init__
u_PSD._support_mask
u_PSD.pinv
multi_rv_generic
umulti_rv_generic.__init__
umulti_rv_generic.random_state
setter
umulti_rv_generic._get_random_state
multi_rv_frozen
aGenericAlias
a__class_getitem__
umulti_rv_frozen.random_state
umean : array_like, default: ``[0]``
Mean of the distribution.
cov : array_like or `Covariance`, default: ``[1]``
Symmetric positive (semi)definite covariance matrix of the distribution.
llow_singular : bool, default: ``False``
Whether to allow a singular covariance matrix. This is ignored if `cov` is
a `Covariance` object.
a_mvn_doc_default_callparams
uSetting the parameter `mean` to `None` is equivalent to having `mean`
be the zero-vector. The parameter `cov` can be a scalar, in which case
the covariance matrix is the identity times that value, a vector of
diagonal entries for the covariance matrix, a two-dimensional array_like,
or a `Covariance` object.
a_mvn_doc_callparams_note
a_mvn_doc_frozen_callparams
uSee class definition for a detailed description of parameters.
a_mvn_doc_frozen_callparams_note
mvn_docdict_noparams
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
umultivariate_normal_gen.__init__
T nl Fna__call__
umultivariate_normal_gen.__call__
T tumultivariate_normal_gen._process_parameters
umultivariate_normal_gen._process_parameters_Covariance
umultivariate_normal_gen._process_parameters_psd
umultivariate_normal_gen._process_quantiles
umultivariate_normal_gen._logpdf
T nl Fumultivariate_normal_gen.logpdf
umultivariate_normal_gen.pdf
umultivariate_normal_gen._cdf
T nl Fnf h     >f h     >D alower_limit
rng
nnalogcdf
umultivariate_normal_gen.logcdf
umultivariate_normal_gen.cdf
T nl pnumultivariate_normal_gen.rvs
T nl umultivariate_normal_gen.entropy
fit
umultivariate_normal_gen.fit
umultivariate_normal_gen.marginal
a__orig_bases__
T nl Fnnf h     >f h     >umultivariate_normal_frozen.__init__
property
umultivariate_normal_frozen.cov
umultivariate_normal_frozen.logpdf
umultivariate_normal_frozen.pdf
umultivariate_normal_frozen.logcdf
umultivariate_normal_frozen.cdf
T l numultivariate_normal_frozen.rvs
umultivariate_normal_frozen.entropy
umultivariate_normal_frozen.marginal
T alogpdf
pdf
logcdf
cdf
rvs
name
method
method_frozen
umean : array_like, optional
Mean of the distribution (default: `None`)
rowcov : array_like, optional
Among-row covariance matrix of the distribution (default: ``1``)
colcov : array_like, optional
Among-column covariance matrix of the distribution (default: ``1``)
a_matnorm_doc_default_callparams
uIf `mean` is set to `None` then a matrix of zeros is used for the mean.
The dimensions of this matrix are inferred from the shape of `rowcov` and
`colcov`, if these are provided, or set to ``1`` if ambiguous.
`rowcov` and `colcov` can be two-dimensional array_likes specifying the
covariance matrices directly. Alternatively, a one-dimensional array will
be be interpreted as the entries of a diagonal matrix, and a scalar or
zero-dimensional array will be interpreted as this value times the
identity matrix.
a_matnorm_doc_callparams_note
a_matnorm_doc_frozen_callparams
a_matnorm_doc_frozen_callparams_note
matnorm_docdict_noparams
umatrix_normal_gen.__init__
umatrix_normal_gen.__call__
umatrix_normal_gen._process_parameters
umatrix_normal_gen._process_quantiles
umatrix_normal_gen._logpdf
T nl pumatrix_normal_gen.logpdf
umatrix_normal_gen.pdf
T nl ppnumatrix_normal_gen.rvs
umatrix_normal_gen.entropy
umatrix_normal_gen._entropy
matrix_normal
umatrix_normal_frozen.__init__
umatrix_normal_frozen.logpdf
umatrix_normal_frozen.pdf
umatrix_normal_frozen.rvs
umatrix_normal_frozen.entropy
T alogpdf
pdf
rvs
entropy
umean : array_like, optional
Mean of the distribution (default: `None`)
row_spread : array_like, optional
Row-wise 2nd order raw central moment matrix (default: ``1``)
col_spread : array_like, optional
Column-wise 2nd order raw central moment matrix (default: ``1``)
df : scalar, optional
Degrees of freedom (default: ``1``)
a_matt_doc_default_callparams
uIf `mean` is set to `None` then a matrix of zeros is used for the mean.
The dimensions of this matrix are inferred from the shape of `row_spread` and
`col_spread`, if these are provided, or set to ``1`` if ambiguous.
`row_spread` and `col_spread` can be two-dimensional array_likes specifying the
spread matrices directly. Alternatively, a one-dimensional array will
be be interpreted as the entries of a diagonal matrix, and a scalar or
zero-dimensional array will be interpreted as this value times the
identity matrix.
a_matt_doc_callparams_note
a_matt_doc_frozen_callparams
a_matt_doc_frozen_callparams_note
matrix_t_docdict_noparams
umatrix_t_gen.__init__
T nl pnnumatrix_t_gen.__call__
umatrix_t_gen._process_parameters
umatrix_t_gen._process_quantiles
umatrix_t_gen._logpdf
T nl ppumatrix_t_gen.logpdf
umatrix_t_gen.pdf
T nl pppnumatrix_t_gen.rvs
matrix_t
umatrix_t_frozen.__init__
umatrix_t_frozen.logpdf
umatrix_t_frozen.pdf
umatrix_t_frozen.rvs
T alogpdf
pdf
rvs
ualpha : array_like
The concentration parameters. The number of entries determines the
dimensionality of the distribution.
a_dirichlet_doc_default_callparams
a_dirichlet_doc_frozen_callparams
a_dirichlet_doc_frozen_callparams_note
dirichlet_docdict_noparams
udirichlet_gen.__init__
udirichlet_gen.__call__
udirichlet_gen._logpdf
udirichlet_gen.logpdf
udirichlet_gen.pdf
udirichlet_gen.mean
udirichlet_gen.var
udirichlet_gen.cov
udirichlet_gen.entropy
udirichlet_gen.rvs
udirichlet_frozen.__init__
udirichlet_frozen.logpdf
udirichlet_frozen.pdf
udirichlet_frozen.mean
udirichlet_frozen.var
udirichlet_frozen.cov
udirichlet_frozen.entropy
udirichlet_frozen.rvs
T alogpdf
pdf
rvs
mean
var
cov
entropy
udf : int
Degrees of freedom, must be greater than or equal to dimension of the
scale matrix
scale : array_like
Symmetric positive definite scale matrix of the distribution
a_wishart_doc_default_callparams
a_wishart_doc_callparams_note
a_wishart_doc_frozen_callparams
a_wishart_doc_frozen_callparams_note
a_doc_default_callparams
a_doc_callparams_note
wishart_docdict_noparams
uwishart_gen.__init__
uwishart_gen.__call__
uwishart_gen._process_parameters
uwishart_gen._process_quantiles
uwishart_gen._process_size
uwishart_gen._logpdf
uwishart_gen.logpdf
uwishart_gen.pdf
uwishart_gen._mean
uwishart_gen.mean
uwishart_gen._mode
mode
uwishart_gen.mode
uwishart_gen._var
uwishart_gen.var
uwishart_gen._standard_rvs
uwishart_gen._rvs
uwishart_gen.rvs
uwishart_gen._entropy
uwishart_gen.entropy
uwishart_gen._cholesky_logdet
wishart
uwishart_frozen.__init__
uwishart_frozen.logpdf
uwishart_frozen.pdf
uwishart_frozen.mean
uwishart_frozen.mode
uwishart_frozen.var
uwishart_frozen.rvs
uwishart_frozen.entropy
T alogpdf
pdf
mean
mode
var
rvs
entropy
uinvwishart_gen.__init__
uinvwishart_gen.__call__
uinvwishart_gen._logpdf
uinvwishart_gen.logpdf
uinvwishart_gen.pdf
uinvwishart_gen._mean
uinvwishart_gen.mean
uinvwishart_gen._mode
uinvwishart_gen.mode
uinvwishart_gen._var
uinvwishart_gen.var
uinvwishart_gen._inv_standard_rvs
uinvwishart_gen._rvs
uinvwishart_gen.rvs
uinvwishart_gen._entropy
uinvwishart_gen.entropy
uinvwishart_frozen.__init__
uinvwishart_frozen.logpdf
uinvwishart_frozen.pdf
uinvwishart_frozen.mean
uinvwishart_frozen.mode
uinvwishart_frozen.var
uinvwishart_frozen.rvs
uinvwishart_frozen.entropy
T alogpdf
pdf
mean
mode
var
rvs
un : int
Number of trials
p : array_like
Probability of a trial falling into each category; should sum to 1
a_multinomial_doc_default_callparams
u`n` should be a nonnegative integer. Each element of `p` should be in the
interval :math:`[0,1]` and the elements should sum to 1. If they do not sum to
1, the last element of the `p` array is not used and is replaced with the
remaining probability left over from the earlier elements.
a_multinomial_doc_callparams_note
a_multinomial_doc_frozen_callparams
a_multinomial_doc_frozen_callparams_note
multinomial_docdict_noparams
umultinomial_gen.__init__
umultinomial_gen.__call__
umultinomial_gen._process_parameters
umultinomial_gen._process_quantiles
umultinomial_gen._checkresult
umultinomial_gen._logpmf
umultinomial_gen.logpmf
umultinomial_gen.pmf
umultinomial_gen.mean
umultinomial_gen.cov
umultinomial_gen.entropy
umultinomial_gen.rvs
umultinomial_frozen.__init__
umultinomial_frozen.logpmf
umultinomial_frozen.pmf
umultinomial_frozen.mean
umultinomial_frozen.cov
umultinomial_frozen.entropy
umultinomial_frozen.rvs
T alogpmf
pmf
mean
cov
rvs
uspecial_ortho_group_gen.__init__
uspecial_ortho_group_gen.__call__
uspecial_ortho_group_gen._process_parameters
uspecial_ortho_group_gen.rvs
special_ortho_group
uspecial_ortho_group_frozen.__init__
uspecial_ortho_group_frozen.rvs
uortho_group_gen.__init__
uortho_group_gen.__call__
uortho_group_gen._process_parameters
uortho_group_gen.rvs
uortho_group_frozen.__init__
uortho_group_frozen.rvs
urandom_correlation_gen.__init__
T nf vIh %<=fH     z>urandom_correlation_gen.__call__
urandom_correlation_gen._process_parameters
urandom_correlation_gen._givens_to_1
urandom_correlation_gen._to_corr
urandom_correlation_gen.rvs
random_correlation
urandom_correlation_frozen.__init__
urandom_correlation_frozen.rvs
uunitary_group_gen.__init__
uunitary_group_gen.__call__
uunitary_group_gen._process_parameters
uunitary_group_gen.rvs
unitary_group
uunitary_group_frozen.__init__
uunitary_group_frozen.rvs
uloc : array_like, optional
Location of the distribution. (default ``0``)
shape : array_like, optional
Positive semidefinite matrix of the distribution. (default ``1``)
df : float, optional
Degrees of freedom of the distribution; must be greater than zero.
If ``np.inf`` then results are multivariate normal. The default is ``1``.
llow_singular : bool, optional
Whether to allow a singular matrix. (default ``False``)
a_mvt_doc_default_callparams
uSetting the parameter `loc` to ``None`` is equivalent to having `loc`
be the zero-vector. The parameter `shape` can be a scalar, in which case
the shape matrix is the identity times that value, a vector of
diagonal entries for the shape matrix, or a two-dimensional array_like.
a_mvt_doc_callparams_note
a_mvt_doc_frozen_callparams_note
mvt_docdict_noparams
umultivariate_t_gen.__init__
T nl pFnumultivariate_t_gen.__call__
T nl pFumultivariate_t_gen.pdf
umultivariate_t_gen.logpdf
umultivariate_t_gen._logpdf
umultivariate_t_gen._cdf
D amaxpts
lower_limit
random_state
nnnumultivariate_t_gen.cdf
umultivariate_t_gen._entropy
umultivariate_t_gen.entropy
umultivariate_t_gen.rvs
umultivariate_t_gen._process_quantiles
umultivariate_t_gen._process_parameters
umultivariate_t_gen.marginal
umultivariate_t_frozen.__init__
umultivariate_t_frozen.logpdf
umultivariate_t_frozen.cdf
umultivariate_t_frozen.pdf
umultivariate_t_frozen.rvs
umultivariate_t_frozen.entropy
umultivariate_t_frozen.marginal
multivariate_t
T alogpdf
pdf
rvs
cdf
entropy
um : array_like
The number of each type of object in the population.
That is, :math:`m[i]` is the number of objects of
type :math:`i`.
n : array_like
The number of samples taken from the population.
a_mhg_doc_default_callparams
u`m` must be an array of positive integers. If the quantile
:math:`i` contains values out of the range :math:`[0, m_i]`
where :math:`m_i` is the number of objects of type :math:`i`
in the population or if the parameters are inconsistent with one
nother (e.g. ``x.sum() != n``), methods return the appropriate
value (e.g. ``0`` for ``pmf``). If `m` or `n` contain negative
values, the result will contain ``nan`` there.
a_mhg_doc_callparams_note
a_mhg_doc_frozen_callparams
a_mhg_doc_frozen_callparams_note
mhg_docdict_noparams
umultivariate_hypergeom_gen.__init__
umultivariate_hypergeom_gen.__call__
umultivariate_hypergeom_gen._process_parameters
umultivariate_hypergeom_gen._process_quantiles
umultivariate_hypergeom_gen._checkresult
umultivariate_hypergeom_gen._logpmf
umultivariate_hypergeom_gen.logpmf
umultivariate_hypergeom_gen.pmf
umultivariate_hypergeom_gen.mean
umultivariate_hypergeom_gen.var
umultivariate_hypergeom_gen.cov
umultivariate_hypergeom_gen.rvs
multivariate_hypergeom
umultivariate_hypergeom_frozen.__init__
umultivariate_hypergeom_frozen.logpmf
umultivariate_hypergeom_frozen.pmf
umultivariate_hypergeom_frozen.mean
umultivariate_hypergeom_frozen.var
umultivariate_hypergeom_frozen.cov
umultivariate_hypergeom_frozen.rvs
T alogpmf
pmf
mean
var
cov
rvs
urandom_table_gen.__init__
D aseed
nurandom_table_gen.__call__
urandom_table_gen.logpmf
urandom_table_gen.pmf
urandom_table_gen.mean
D asize
method
random_state
nnnurandom_table_gen.rvs
staticmethod
urandom_table_gen._process_parameters
urandom_table_gen._process_size_shape
classmethod
urandom_table_gen._process_rvs_method
urandom_table_gen._rvs_select
urandom_table_gen._rvs_boyett
urandom_table_gen._rvs_patefield
random_table
urandom_table_frozen.__init__
urandom_table_frozen.logpmf
urandom_table_frozen.pmf
urandom_table_frozen.mean
urandom_table_frozen.rvs
urow : array_like
Sum of table entries in each row.
col : array_like
Sum of table entries in each column.
a_ctab_doc_row_col
ux : array-like
Two-dimensional table of non-negative integers, or a
multi-dimensional array with the last two dimensions
corresponding with the tables.
a_ctab_doc_x
uThe row and column vectors must be one-dimensional, not empty,
nd each sum up to the same value. They cannot contain negative
or noninteger entries.
a_ctab_doc_row_col_note

Parameters
----------
a_ctab_doc_mean_params
a_ctab_doc_row_col_note_frozen
a_doc_row_col
a_doc_x
a_doc_mean_params
a_doc_row_col_note
a_ctab_docdict
a_ctab_docdict_frozen
a_docfill
T alogpmf
pmf
mean
rvs
uuniform_direction_gen.__init__
uuniform_direction_gen.__call__
uuniform_direction_gen._process_parameters
uuniform_direction_gen.rvs
uniform_direction
uuniform_direction_frozen.__init__
uuniform_direction_frozen.rvs
ualpha : array_like
The concentration parameters. The number of entries along the last axis
determines the dimensionality of the distribution. Each entry must be
strictly positive.
n : int or array_like
The number of trials. Each element must be a non-negative integer.
a_dirichlet_mn_doc_default_callparams
a_dirichlet_mn_doc_frozen_callparams
a_dirichlet_mn_doc_frozen_callparams_note
dirichlet_mn_docdict_noparams
udirichlet_multinomial_gen.__init__
udirichlet_multinomial_gen.__call__
udirichlet_multinomial_gen.logpmf
udirichlet_multinomial_gen.pmf
udirichlet_multinomial_gen.mean
udirichlet_multinomial_gen.var
udirichlet_multinomial_gen.cov
udirichlet_multinomial_frozen.__init__
udirichlet_multinomial_frozen.logpmf
udirichlet_multinomial_frozen.pmf
udirichlet_multinomial_frozen.mean
udirichlet_multinomial_frozen.var
udirichlet_multinomial_frozen.cov
T alogpmf
pmf
mean
var
cov
uvonmises_fisher_gen.__init__
T nl nuvonmises_fisher_gen.__call__
uvonmises_fisher_gen._process_parameters
uvonmises_fisher_gen._check_data_vs_dist
uvonmises_fisher_gen._log_norm_factor
uvonmises_fisher_gen._logpdf
uvonmises_fisher_gen.logpdf
uvonmises_fisher_gen.pdf
uvonmises_fisher_gen._rvs_2d
uvonmises_fisher_gen._rvs_3d
uvonmises_fisher_gen._rejection_sampling
uvonmises_fisher_gen._rotate_samples
uvonmises_fisher_gen._rvs
uvonmises_fisher_gen.rvs
uvonmises_fisher_gen._entropy
uvonmises_fisher_gen.entropy
uvonmises_fisher_gen.fit
vonmises_fisher
uvonmises_fisher_frozen.__init__
uvonmises_fisher_frozen.logpdf
uvonmises_fisher_frozen.pdf
uvonmises_fisher_frozen.rvs
uvonmises_fisher_frozen.entropy
T l
l ppnnunormal_inverse_gamma_gen.rvs
unormal_inverse_gamma_gen._logpdf
T l
l ppunormal_inverse_gamma_gen.logpdf
unormal_inverse_gamma_gen._pdf
unormal_inverse_gamma_gen.pdf
unormal_inverse_gamma_gen.mean
unormal_inverse_gamma_gen.var
unormal_inverse_gamma_gen._process_parameters_pdf
unormal_inverse_gamma_gen._process_shapes
T l
l ppnunormal_inverse_gamma_gen.__call__
normal_inverse_gamma
unormal_inverse_gamma_frozen.__init__
unormal_inverse_gamma_frozen.logpdf
unormal_inverse_gamma_frozen.pdf
unormal_inverse_gamma_frozen.mean
unormal_inverse_gamma_frozen.var
unormal_inverse_gamma_frozen.rvs
T alogpdf
pdf
mean
var
rvs
uscipy\stats\_multivariate.py
T a.0
arg
u<module scipy.stats._multivariate>
T a__class__
T aself
alpha
seed
T aself
alpha
wnaseed
T aself
df
scale
seed
T aself
mean
rowcov
colcov
seed
T aself
mean
row_spread
col_spread
df
seed
T aself
wnwpaseed
T aself
wmwnaseed
T aself
mean
cov
allow_singular
seed
kwds
T aself
loc
shape
df
allow_singular
seed
T aself
mu
lmbda
wawbaseed
T aself
dim
seed
T aself
eigs
seed
tol
diag_tol
T aself
row
col
seed
T aself
mu
kappa
seed
T aself
wMacond
rcond
lower
check_finite
allow_singular
wswuaeps
msg
wdas_pinv
wUT aself
seed
a__class__
T aself
alpha
wnaseed
aSa
T aself
wnwpaseed
a_process_parameters
T aself
wmwnaseed
a_process_parameters
T aself
mean
cov
allow_singular
seed
maxpts
abseps
releps
T aself
loc
shape
df
allow_singular
seed
dim
T aself
eigs
seed
tol
diag_tol
w_T aself
row
col
seed
a_process_parameters
T aself
wxamean
cov
maxpts
abseps
releps
lower_limit
rng
lower
wbwaai_swap
signs
wnalimits
func1d
out
T aself
wxaloc
shape
df
dim
maxpts
lower_limit
random_state
rng
wbwaai_swap
signs
wnalimits
func1d
res
T aself
wxadim
msg
T aself
result
cond
bad_value
T adf
scale
size
random_state
df_iw
iw_samples
chol_samples
idx
T aself
scale
c_decomp
logdet
T aalpha
wxaxk
xeq0
alphalt1
chk
T aalpha
T aalpha
wnwxweamsg
x_int
n_int
sum_alpha
T aobj
docdict
template
T aspectrum
cond
rcond
wtafactor
eps
T aself
dim
df
log_det_scale
psi_eval_points
T aself
dims
row_cov_logdet
col_cov_logdet
wnwpT	aself
dim
df
shape
shape_info
shape_term
regular
asymptotic
threshold
T aself
dim
kappa
halfdim
T aself
dim
df
log_det_scale
T aself
random_state
T
self
aii
ajj
aij
aiid
ajjd
dd
wtwcwsT aself
wnashape
dim
df
random_state
wAatri_rows
tri_cols
n_tril
rows
chi_dfs
T aself
wxaalpha
lnB
Taself
wxadim
df
log_det_scale
wCalog_det_x
tr_scale_x_inv
trsm
wiaCx
wAaout
Taself
dims
wXamean
row_prec_rt
log_det_rowcov
col_prec_rt
log_det_colcov
numrows
numcols
roll_dev
scale_dev
maha
T aself
dims
wXamean
df
invrow_spread
invcol_spread
logdetrow_spread
logdetcol_spread
wmwnaX_shape
aX_centered
det_arg
w_alogdet
log_d_mn
log_f_mn
retval
T aself
wxamean
cov_object
log_det_cov
rank
dev
maha
T aself
wxaloc
prec_U
log_pdet
df
dim
rank
cov_object
dev
maha
wtwAwBwCwDwET aself
wxas2
mu
lmbda
wawbat1
t2
t3
t4
T aself
wxadim
mu
kappa
dotproducts
Taself
wxadim
df
scale
log_det_scale
wCalog_det_x
scale_inv_x
tr_scale_inv_x
wiw_aout
T aself
wxwnwpT	aself
wxwMwmwnamxcond
ncond
num
den
T aself
dim
df
scale
out
T aself
dim
df
scale
T wvaeps
T
self
mean
rowcov
colcov
meanshape
rowshape
numrows
colshape
numcols
dims
T aself
mean
row_spread
col_spread
df
meanshape
rowshape
numrows
colshape
numcols
dims
T wnwpaself
T aself
T	aself
wnwpaeps
p_adjusted
i_adjusted
message
pcond
ncond
T wmwnaself
T aself
wmwnamcond
wMancond
T aself
mean
cov
allow_singular
dim
psd
cov_object
T aself
loc
shape
df
dim
rows
cols
msg
T aself
dim
T aself
eigs
tol
dim
wxT wrwcaself
T arow
col
wrwcwnT aself
mu
kappa
kappa_error_msg
dim
T aself
df
scale
dim
T aself
mean
cov
dim
message
weT
self
wxas2
mu
lmbda
wawbaargs
dtype
invalid
T aself
dim
mean
cov
rows
cols
msg
T aself
wXadims
T aself
wxwnwpaxx
cond
T aself
wxwMwmwnaxcond
T aself
wxadim
T acls
method
wrwcwnaknown_methods
T aself
mu
lmbda
wawbaargs
dtype
invalid
T aself
size
wnashape
T asize
wrwcashape
T aself
dim
kappa
size
random_state
dim_minus_one
n_samples
sqrt
envelop_param
node
correction
n_accepted
wxahalfdim
sym_beta
coord_x
accept_tol
criterion
accepted_iter
coord_rest
samples
T	aself
samples
mu
dim
base_point
embedded
rotmatrix
w_arotsign
T aself
wnashape
dim
df
wCarandom_state
wAatrsm
trmm
index
aCA
T aself
dim
mu
kappa
size
random_state
samples
T
self
wnashape
dim
df
wCarandom_state
wAaindex
aCA
T aself
mu
kappa
size
random_state
mean_angle
angle_samples
samples
T	aself
kappa
size
random_state
sample_size
wxatemp
uniformcircle
samples
T arow
col
ntot
size
random_state
T acls
wrwcwnafac
wkT adim
size
random_state
samples_shape
samples
Taself
wnashape
dim
df
random_state
n_tril
covariances
variances
wAasize_idx
tril_idx
diag_idx
T aself
wxaresidual
in_support
T aself
wmwdwiwjwcwsamv
T adimensions
multivariate_dims
dims
msg
original_dims
i_invalid
T aself
dim
df
scale
var
diag
T adim
df
shape_term
T ashape_term
T aself
wxalower_limit
rng
out
T aself
wxamean
cov
allow_singular
maxpts
abseps
releps
lower_limit
rng
params
dim
cov_object
out
T aself
wxamaxpts
lower_limit
random_state
T
self
wxaloc
shape
df
allow_singular
maxpts
lower_limit
random_state
dim
T aself
alpha
alpha0
waacov
T	aself
alpha
wnwaaSa
var
aiaj
cov
ii
T aself
wnwpanpcond
nn
result
wiT
self
wmwnwMw_amncond
cond
output
dim
wiT aself
alpha
alpha0
lnB
wKaout
T aself
df
scale
dim
w_alog_det_scale
T aself
rowcov
colcov
dummy_mean
dims
w_arowpsd
colpsd
T	aself
wnwpanpcond
wxaterm1
new_axes_needed
new_shape
term2
T aself
log_pdet
rank
T aself
mean
cov
dim
cov_object
T aself
loc
shape
df
dim
T aself
mu
kappa
dim
w_Taself
wxafix_mean
fix_cov
n_vectors
dim
msg
mean
wswuaeps
cov
centered_data
T aself
wxamsg
dim
dirstats
mu
wrahalfdim
solve_for_kappa
root_res
kappa
T alimits
res
cov
wnarng
abseps
maxpts
T aabseps
cov
maxpts
wnarng
T alimits
wawbwnamaxpts
df
shape
rng
T adf
maxpts
wnarng
shape
T wxT aself
wxalower_limit
rng
cdf
out
T aself
wxamean
cov
allow_singular
maxpts
abseps
releps
lower_limit
rng
params
dim
cov_object
cdf
out
T aself
wxT aself
wxaalpha
out
T aself
wxaout
T aself
wxadf
scale
dim
wCalog_det_scale
out
T aself
wXaout
T	aself
wXamean
rowcov
colcov
dims
rowpsd
colpsd
out
T	aself
wXarowpsd
colpsd
invrow_spread
invcol_spread
logdetrow_spread
logdetcol_spread
out
T aself
wXamean
row_spread
col_spread
df
dims
rowpsd
colpsd
invrow_spread
invcol_spread
logdetrow_spread
logdetcol_spread
out
T aself
wxaout
out_of_bounds
T
self
wxamean
cov
allow_singular
params
dim
cov_object
out
out_of_bounds
T aself
wxwUalog_pdet
T aself
wxaloc
shape
df
dim
shape_info
cov_object
T aself
wxas2
T
self
wxas2
mu
lmbda
wawbainvalid
args
logpdf
T aself
wxamu
kappa
dim
T aself
wxaalpha
wnwaaSa
out
T	aself
wxwnwpanpcond
xcond
result
xcond_
npcond_
T aself
wxwmwnwMamcond
ncond
mncond
xcond
xcond_reduced
mxcond
result
xcond_
mncond_
Taself
wxarow
col
wrwcwnadtype_is_int
r2
c2
res
mask
lnfac
T aself
dimensions
T	aself
dimensions
mean
cov
allow_singular
params
wnacov_object
dims
T	aself
dimensions
loc
shape
df
allow_singular
params
wnadims
T aself
alpha
out
T aself
alpha
wnwaaSa
T aself
out
T aself
df
scale
dim
out
T aself
wnwpanpcond
result
T aself
wmwnwMw_amncond
cond
mu
T	aself
mu
lmbda
wawbainvalid
args
mean_x
mean_s2
T aself
row
col
wrwcwnT aself
wxadf
scale
T aself
wXT aself
wXamean
rowcov
colcov
T aself
wXamean
row_spread
col_spread
df
T	aself
wxaloc
shape
df
allow_singular
dim
shape_info
logpdf
T
self
wxas2
mu
lmbda
wawbainvalid
args
pdf
T aself
wxaalpha
wnT aself
wxwmwnaout
T aself
wxarow
col
T aself
seed
T adim
df
halfsum
half_df
shape_term
T aself
size
random_state
T aself
alpha
size
random_state
T aself
size
random_state
wnashape
out
T
self
df
scale
size
random_state
wnashape
dim
wCaout
T aself
mean
rowcov
colcov
size
random_state
dims
rowchol
colchol
std_norm
out
Taself
mean
row_spread
col_spread
df
size
random_state
dims
std_norm
rowchol
colchol
t_raw
t_centered
T aself
wnwpasize
random_state
npcond
T aself
wmwnasize
random_state
wMw_arvs
rem
wcan0mask
T
self
mean
cov
size
random_state
dim
cov_object
out
shape
wxT aself
loc
shape
df
size
random_state
dim
rng
wxwzasamples
T aself
mu
lmbda
wawbasize
random_state
s2
scale
wxadtype
T aself
dim
size
random_state
wzwqwrwdT aself
eigs
random_state
tol
diag_tol
dim
wmT aself
size
method
random_state
T aself
row
col
size
method
random_state
wrwcwnashape
meth
T aself
dim
size
random_state
wqadets
T aself
dim
size
random_state
samples
T aself
mu
kappa
size
random_state
dim
samples
T akappa
bessel_vals
halfdim
wrT ahalfdim
wrT aself
alpha
alpha0
out
T aself
wmwnwMw_amncond
cond
output
T aself
mu
lmbda
wawbainvalid
args
invalid_x
invalid_s2
var_x
var_s2
.scipy.stats._new_distributions
i
c a__class__
a__new__
aStandardNormal
a__init__
mu
sigma
a_logpdf_formula
np
log
a_pdf_formula
a_logcdf_formula
a_cdf_formula
a_logccdf_formula
a_ccdf_formula
a_icdf_formula
a_ilogcdf_formula
a_iccdf_formula
a_ilogccdf_formula
a_entropy_formula
a_logentropy_formula
errstate
T aignore
T adivide
a__enter__
a__exit__
JZ
Z
T nnnaspecial
logsumexp
broadcast_arrays
lls
D aaxis
l
l
ones_like
l l azeros_like
factorial2
D aexact
tanormal
T aloc
scale
size
pi
JZ
f
?aContinuousDistribution
a_log_normalization
a_normalization
exp
log_ndtr
ndtr
ndtri
ndtri_exp
log1p
T l D l
l l l l l l l
l l
l l
a_moment_raw_formula
T asize
abs
f
?acosh
log_expit
expit
logit
Z
bernoulli
q a_scale
logistic
wawbalog_a
log_b
a_one
real
a_log_diff
ab
where
isnan
nan
l auniform
T l
l agamma
wnwpascu
a_binom_pmf
gammaln
xlogy
xlog1py
a_binom_cdf
T f
?T wnwpaxpx
apply_where
u<lambda>
uBinomial._logcdf_formula.<locals>.<lambda>
a_binom_sf
uBinomial._logccdf_formula.<locals>.<lambda>
a_binom_ppf
a_binom_isf
floor
l l l a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
sys
numpy
T ainf
inf
uscipy._lib
T aarray_api_extra
array_api_extra
scipy
T aspecial
uscipy.special
T a_ufuncs
a_ufuncs
uscipy.stats._distribution_infrastructure
T aContinuousDistribution
aDiscreteDistribution
a_RealInterval
a_IntegerInterval
a_RealParameter
a_Parameterization
a_combine_docs
aDiscreteDistribution
a_RealInterval
a_IntegerInterval
a_RealParameter
a_Parameterization
a_combine_docs
L aNormal
aLogistic
aUniform
aBinomial
a__all__
a__prepare__
aNormal
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
