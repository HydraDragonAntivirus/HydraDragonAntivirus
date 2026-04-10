# Reconstructed from integrated Nuitka blob
# Module: uscipy.stats._axis_nan_policy

a__qualname__
a__orig_bases__
T nnT nT Fna_name
L uIf an int, the axis of the input along which to compute the statistic.
uThe statistic of each axis-slice (e.g. row) of the input will appear in a
ucorresponding element of the output.
uIf ``None``, the input will be raveled before computing the statistic.
a_desc
u{'propagate', 'omit', 'raise'}
a_type
L
uDefines how to handle input NaNs.

u- ``propagate``: if a NaN is present in the axis slice (e.g. row) along
u  which the  statistic is computed, the corresponding entry of the output
u  will be NaN.
u- ``omit``: NaNs will be omitted when performing the calculation.
u  If insufficient data remains in the axis slice along which the
u  statistic is computed, the corresponding entry of the output will be
u  NaN.
u- ``raise``: if a NaN is present, a ``ValueError`` will be raised.
D adefault
propagate
ubool, default: False
uIf this is set to True, the axes which are reduced are left
uin the result as dimensions with size one. With this option,
uthe result will broadcast correctly against the input array.
D adefault
FL u
uBeginning in SciPy 1.9, ``np.matrix`` inputs (not recommended for new
ucode) are converted to ``np.ndarray`` before the calculation is performed. In
uthis case, the output will be a scalar or ``np.ndarray`` of appropriate shape
urather than a 2D ``np.matrix``. Similarly, while masked elements of masked
uarrays are ignored, the output will be a scalar or ``np.ndarray`` rather than a
umasked array with ``mask=False``.
T l
l Fnl
l T
na_axis_nan_policy_factory
uscipy\stats\_axis_nan_policy.py
T a.0
sample
T wxw_u<module scipy.stats._axis_nan_policy>
T ares
reduced_axes
keepdims
xp
T atuple_to_result
default_axis
n_samples
paired
result_to_tuple
too_small
n_outputs
kwd_samples
override
temp
is_too_small
axis_nan_policy_decorator
T aarrays
axis
shapes
T aarrays
axis
xp
shapes
new_shapes
T aarrays
axis
paired
xp
res
T ashapes
axis
message
axis_int
wean_dims
new_shapes
row
shape
removed_shapes
new_shape
new_axis
T ashapes
axis
shape
T asamples
axis
xp
output_shape
aNaN
output
T adefault_axis
a_name
a_desc
a_type
a_axis_parameter_doc
a_axis_parameter
T asamples
has_mask
sample
mask
dtype
wiainexact
info
max_possible
min_possible
nextafter
sentinel
message
out_samples
T asamples
paired
xp
nans
sample
not_nans
T asamples
paired
sentinel
sentinels
sample
not_sentinels
T
hypotest_fun_in
axis_nan_policy_wrapper
a_axis_parameter_doc
a_axis_parameter
doc
parameter_names
sig
parameters
parameter_list
default_axis
T	adefault_axis
is_too_small
kwd_samples
n_outputs
n_samples
override
paired
result_to_tuple
tuple_to_result
T/a_no_deco
args
kwds
used_kwd_samples
temp
msg
params
maxarg
d_args
intersection
n_samp
n_out
kwd_samp
n_kwd_samp
hypotest_fun_out
samples
xp
vectorized
axis
nan_policy
keepdims
sentinel
reduced_axes
n_dims
n_axes
shapes
new_shapes
aNaN
ndims
contains_nan
res
too_small_msg
empty_output
lengths
split_indices
wxahypotest_fun
hypotest_fun_in
kwd_samples
n_samples
n_outputs
override
default_axis
paired
tuple_to_result
is_too_small
result_to_tuple
T
default_axis
hypotest_fun_in
is_too_small
kwd_samples
n_outputs
n_samples
override
paired
result_to_tuple
tuple_to_result
Twxasamples
n_out
aNaN
split_indices
n_samp
n_kwd_samp
sentinel
paired
is_too_small
kwds
result_to_tuple
hypotest_fun_out
T aNaN
hypotest_fun_out
is_too_small
kwds
n_kwd_samp
n_out
n_samp
paired
result_to_tuple
sentinel
split_indices
Twxasamples
split_indices
n_samp
n_kwd_samp
paired
sentinel
is_too_small
kwds
n_out
aNaN
result_to_tuple
hypotest_fun_out
Twxasamples
split_indices
n_samp
n_kwd_samp
sentinel
paired
is_too_small
kwds
n_out
aNaN
result_to_tuple
hypotest_fun_out
T asamples
kwds
new_kwds
kwd_samp
n_samp
hypotest_fun_in
T ahypotest_fun_in
kwd_samp
n_samp
T asamples
axis
ts_args
ts_kwargs
sample
too_small
T atoo_small
T ares
w_.scipy.stats._binned_statistic
l anp
asarray
binned_statistic_dd
bins
range
utoo many values to unpack (expected 3)
aBinnedStatisticResult
l
T aexpand_binnumbers
aBinnedStatistic2dResult
iscomplexobj
bincount
real
imag
JZ
f
?L amean
median
count
sum
std
min
max
callable
uinvalid statistic

index
isfinite
all
u contains non-finite values.
shape
utoo many values to unpack (expected 2)
T EAttributeError
EValueError
atleast_2d
wTacount
uThe number of `values` elements must match the length of each `sample` dimension.
uThe dimension of bins must be equal to the dimension of the sample x.
a_bin_edges
sample
a_bin_numbers
bin_edges
array
diff
binnumber
result_type
float64
empty
nbin
prod
T adtype
mean
fill
nan
a_bincount
nonzero
binnumbers
result
std
sqrt
conj
T l
arange
newaxis
:nnnasum
median
lexsort
unique
D areturn_index
return_counts
tpl afloor
astype
T Oint
ceil
min
argsort
:nnq amax
errstate
T aignore
T ainvalid
a__enter__
a__exit__
catch_warnings
simplefilter
ignore
aRuntimeWarning
T nnnanull
complex128
a_calc_binned_statistic
reshape
append
:l q naunravel_index
any
:l nnuInternal Shape Error
:nq naBinnedStatisticddResult
edges
a_create_binned_data
bin_numbers
unique_bin_numbers
values
stat_func
uThe statistic function returns complex
bin_map
atleast_1d
T aaxis
urange given for
u dimensions;
u required
uIn
udimension
u of
urange, start must be <= stop
smin
smax
f
?aissubdtype
dtype
floating
isscalar
linspace
edges_dtype
dedges
digitize
uThe smallest edge difference is numerically 0.
log10
l awhere
q aaround
ravel_multi_index
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
builtins
warnings
T acatch_warnings
simplefilter
numpy
operator
T aindex
collections
T anamedtuple
namedtuple
uscipy._lib._array_api
T axp_capabilities
xp_capabilities
binned_statistic
binned_statistic_2d
a__all__
T aBinnedStatisticResult
T astatistic
bin_edges
binnumber
T tT anp_only
T amean
l
nT aBinnedStatistic2dResult
T astatistic
x_edge
y_edge
binnumber
T amean
l
nFT aBinnedStatisticddResult
T astatistic
bin_edges
binnumber
T amean
l
nFnT nnuscipy\stats\_binned_statistic.py
u<module scipy.stats._binned_statistic>
T asample
bins
range
aDlen
aNdim
nbin
edges
dedges
smin
smax
wiaedges_dtype
T asample
nbin
edges
dedges
aDlen
aNdim
sampBin
wiadedges_min
decimal
on_edge
binnumbers
T wxaweights
wawbwzT
aVdim
bin_numbers
result
values
stat_func
unique_bin_numbers
vv
bin_map
wiastat
T abin_numbers
unique_bin_numbers
values
vv
bin_map
wiT	wxavalues
statistic
bins
range
wNamedians
edges
binnumbers
Twxwyavalues
statistic
bins
range
expand_binnumbers
wNaxedges
yedges
medians
edges
binnumbers
T$asample
values
statistic
bins
range
expand_binnumbers
binned_statistic_result
known_stats
aDlen
aNdim
input_shape
aVdim
aVlen
wManbin
edges
dedges
binnumbers
result_type
result
flatcount
waavv
flatsum
delta
std
wiw_wjacounts
mid
mid_a
mid_b
medians
null
core
.scipy.stats._binomtest
"
}
wkwnaalternative
statistic
pvalue
proportion_estimate
uBinomTestResult(k=

u, n=
u, alternative=
u, statistic=
u, pvalue=
w)T aexact
wilson
wilsoncc
umethod ('
u') must be one of 'exact', 'wilson' or 'wilsoncc'.
l
l uconfidence_level (
u) must be in the interval [0, 1].
exact
a_binom_exact_conf_int
utoo many values to unpack (expected 2)
a_binom_wilson_conf_int
wilsoncc
T acorrection
aConfidenceInterval
T alow
high
brentq
unumerical solver failed to converge when computing the confidence limits
ubrentq raised a ValueError; report this to the SciPy developers
utwo-sided
l Z
a_findp
u<lambda>
u_binom_exact_conf_int.<locals>.<lambda>
f
?aless
greater
plow
phigh
binom
sf
alpha
cdf
ndtri
f
?asqrt
l a_validate_int
D aminimum
l
D aminimum
l uk (
u) must not be greater than n (
u).
up (
u) must be in range [0,1]
T utwo-sided
less
greater
ualternative ('
u') not recognized;
must be 'two-sided', 'less' or 'greater'
pmf
a_binary_search_for_binom_tst
ubinomtest.<locals>.<lambda>
f
?anp
ceil
floor
min
aBinomTestResult
T wkwnaalternative
statistic
pvalue
wpalo
hi
waa__doc__
a__file__
a__spec__
origin
has_location
a__cached__
math
T asqrt
numpy
uscipy._lib._array_api
T axp_capabilities
xp_capabilities
uscipy._lib._util
T a_validate_int
uscipy.optimize
T abrentq
uscipy.special
T andtri
a_discrete_distns
T abinom
a_common
T aConfidenceInterval
