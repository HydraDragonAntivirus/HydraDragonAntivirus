# Reconstructed from integrated Nuitka blob
# Module: uscipy.spatial.transform._rotation_spline

aRotationSpline
a__qualname__
l
f  &  . >uRotationSpline._solve_for_angular_rates
a__init__
uRotationSpline.__init__
T l
a__call__
uRotationSpline.__call__
uscipy\spatial\transform\_rotation_spline.py
u<module scipy.spatial.transform._rotation_spline>
T
self
times
order
singe_time
rotvecs
index
n_segments
result
rotvecs_dot
rotvecs_dot_dot
T	aself
times
rotations
aPPoly
dt
rotvecs
angular_rates
rotvecs_dot
coeff
T arotvecs
rotvecs_dot
norm
dp
cp
ccp
dccp
k1
k2
k3
mask
nm
T arotvecs
norm
wkamask
nm
skew
result
T arotvecs
rotvecs_dot
rotvecs_dot_dot
T arotvecs
rotvecs_dot
T wAwBwdaind
ind_blocks
aA_i
aA_j
aB_i
aB_j
diag_i
diag_j
wiwjavalues
wuwlaresult
T wxaresult
T wAwbT arotvecs
norm
k1
k2
mask
nm
skew
result
T aself
dt
angular_rates
rotvecs
angular_rate_first
wAaA_inv
wMab0
iteration
rotvecs_dot
delta_beta
wbaangular_rates_new
delta
.scipy.spatial.transform._rotation_xp
V aarray_namespace
roll
q D aaxis
q aasarray
quat
D acopy
ta_normalize_quaternion
xp_device
linalg
det
l
is_lazy_array
any
nonzero
xpx
atleast_nd
l T andim
xp
uNon-positive determinant (left-handed or null coordinate frame) in rotation matrix

u:
w.awhere
T Q
nnanan
matrix
matrix_transpose
eye
dtype
T l T adtype
device
all
isclose
f  -   q=T aatol
xp
D aaxis
T q q asvd
D afull_matrices
Futoo many values to unpack (expected 3)
at
set
a_from_matrix_orthogonal
T Q
l
pT Q
l pT Q
l pastack
argmax
D aaxis
keepdims
q taempty
shape
:nq nT l l T Q
l l
T Q
l
l T Q
l l
T Q
l
l T Q
l l T Q
l l l uExpected `rot_vec` to have shape (..., 3), got
a_deg2rad
xp_vector_norm
T aaxis
keepdims
xp
f    MbP?f
?l0l  T adtype
sin
concat
cos
uExpected `mrp` to have shape (..., 3), got
vecdot
T Q
nT Q
:nl nuExpected axis specification to be a non-empty string of up to 3 characters, got
re
match
u^[XYZ]{1,3}$
u^[xyz]{1,3}$
uExpected axes from `seq` to be from ['x', 'y', 'z'] or ['X', 'Y', 'Z'], got
uExpected consecutive axes to be different, got
angles
uExpected last dimension of `angles` to match number of sequence axes specified, got
lower
a_elementary_basis_index
a_elementary_quat_compose
seq
u<genexpr>
ufrom_euler.<locals>.<genexpr>
T weaextrinsic
T wiaintrinsic
uorder should be 'e'/'extrinsic' for extrinsic sequences or 'i'/'intrinsic' for intrinsic sequences, got
uAxes must be vectors of length 3.
q uExpected up to 3 axes, got
zeros
bool
abs
T Q
l
:nnnT Q
l :nnnfH     z>T Q
l :nnnuConsecutive axes must be orthogonal.
broadcastable
:nq nuExpected `angles` to match number of axes, got
u angles and
u axes.
T Q
l T l afrom_rotvec
:nnnacompose_quat
wqa_quat_canonical
T Q
l
T Q
l T Q
l areshape
atan2
l l l  f
@a_rad2deg
T f
?T adevice
dtype
T Q
l nf
?uExpected 3 axes, got
;l
l l :nnq T adevice
a_get_angles
pi
uas_euler.<locals>.<genexpr>
uExpected `axes` to match number of rotations, got
u axes and
u rotations.
a_compute_davenport_from_quat
multiply
T q tT acopy
T aaxis
xp
warnings
warn
T uatol must be set to use the degrees flag, defaulting to 1e-8 radians.
l T astacklevel
f: 0  yE>uExpected broadcastable shapes in both rotations, got
u rotations in first and
u rotations in second object.
inv
magnitude
xp_result_type
T aforce_floating
xp
uMean of an empty rotation set is undefined.
ndim
axis
u`axis` must be None, int, or tuple of ints.
min
max
uaxis
u is out of bounds for rotation with shape
sorted
T Q
n:nnnu`weights` must be non-negative.
uExpected `weights` to be broadcastable to rotation shape, got shape
u for
moveaxis
T q l pamean
D aaxis
q aeigh
utoo many values to unpack (expected 2)
T Q
q umean.<locals>.<genexpr>
ones_like
a_split_rotation
T Q
:nnnnnT Q
n:nnnnT Q
nn:nnnasum
T Q
:nnnn:nnnT Q
n:nnn:nnnT Q
:nnn:nnnnacross
T Q
:nnn:nnnn:nnnT Q
nn:nnn:nnnD aaxis
l aarange
T l q T q l aleft_best
right_best
as_matrix
uCannot broadcast
u rotations to
u vectors.
uExpected input `a` to have shape (3,) or (N, 3), got
uExpected input `b` to have shape (3,) or (N, 3), got
uExpected inputs `a` and `b` to have same shapes, got
u and
u respectively.
uExpected inputs `a` and `b` to have shape (3,) or (N, 3), got
ones
uExpected `weights` to be 1 dimensional, got shape
uExpected `weights` to have number of values equal to number of input vectors, got
u values and
u`weights` may not contain negative values
inf
astype
uOnly one infinite weight is allowed
uCannot return sensitivity matrix with an infinite weight or one vector pair
a_align_vectors
a_align_vectors_fixed
T :nnnnamT
T Q
:nnnq asqrt
maximum
T L taxp
uint8
is_jax
T ashift
axis
T l
Q
T nQ
uCannot align zero length primary vectors
T L Z
Z
Z
f
?aargmin
T l
l T l
l T l
pT axp
l l  T :l nnQ
:l nnaapply
T l
T acopy
xp
isnan
is_array_api_obj
uArray exponent must be a scalar
xp_promote
wnaas_rotvec
uFound zero norm quaternions in `quat`.
wxwywzuExpected axis to be from ['x', 'y', 'z'], got
a_make_elementary_quat
T adevice
xp
device
hypot
T uGimbal lock detected. Setting third angle to zero since it is not possible to uniquely determine all angles.
l T Q
:nq nanp
f
f@a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
aEllipsisType
numpy
uscipy._lib._array_api
T aarray_namespace
aArray
aArrayLike
is_lazy_array
xp_vector_norm
xp_result_type
xp_promote
is_jax
aArray
aArrayLike
uscipy._lib._util
T abroadcastable
uscipy._lib.array_api_compat
T ais_array_api_obj
uscipy._lib.array_api_extra
a_lib
array_api_extra
T tpD ascalar_first
Fafrom_quat
T Fafrom_matrix
from_mrp
from_euler
from_davenport
as_quat
as_mrp
D asuppress_warnings
Faas_euler
as_davenport
T nFaapprox_equal
T nnareduce
setitem
align_vectors
pow
uscipy\spatial\transform\_rotation_xp.py
T a.0
wiaseq
T a.0
wiaaxis
T a.0
wxaquat
u<module scipy.spatial.transform._rotation_xp>
T wawbaweights
xp
device
wBwuwsavh
neg_det
wCassd
rssd
zeta
kappa
eye
sensitivity
q_opt
T*wawbaweights
xp
device
wNaweight_is_inf
inf_idx
a_sorted
b_sorted
weights_sorted
a_pri
b_pri
a_pri_norm
b_pri_norm
cross
cross_norm
theta
tolerance
q_flip
flip
wiar_components
wratheta2
small_scale
r_small_scale
r_large_scale
q_pri
a_sec
b_sec
weights_sec
c_sec
sin_term
cos_term
phi
q_sec
q_opt
mask
weights_inf_zero
a_est
rssd
T aquat
n1
n2
n3
extrinsic
suppress_warnings
xp
n_cross
lamb
mask
correct_set
quat_lamb
q_trans
wawbwcwdaangles
T aangles
T aaxis
T aaxes
angles
intrinsic
xp
device
quat
wiaax_quat
T amatrix
xp
device
matrix_trace
decision
choice
quat
quat_0
quat_1
quat_2
quat_3
T aextrinsic
symmetric
sign
lamb
wawbwcwdasuppress_warnings
xp
device
eps
half_sum
half_diff
angles
angle_first
angle_third
case1
case2
case0
a0
a1
a3
T aaxis
angle
device
xp
quat
T aquat
xp
quat_norm
zero_norm
T aquat
xp
mask
zero_w
zero_wx
zero_wxy
T wqaxp
T wawbaweights
return_sensitivity
xp
dtype
a_original
b_original
wNanegative_weights
weight_is_inf
n_inf
inf_branch
q_opt
rssd
sensitivity
q_opt_inf
rssd_inf
sensitivity_inf
T aquat
points
inverse
xp
mat
T aquat
other
atol
degrees
quat_result
angles
T aquat
axes
order
degrees
suppress_warnings
xp
extrinsic
vdot_ax0_ax1
vdot_ax1_ax2
is_invalid
angles
T aquat
seq
degrees
suppress_warnings
xp
intrinsic
extrinsic
device
axes
wiwjwkasymmetric
mask
sign
wawbwcwdaangles
T aquat
xp
wxwywzwwax2
y2
z2
w2
xy
zw
xz
yw
yz
xw
matrix_elements
matrix
T aquat
xp
one
sign
denominator
T aquat
canonical
scalar_first
xp
T aquat
degrees
xp
ax_norm
angle
small_angle
angle2
small_scale
div_sin
large_scale
scale
rotvec
T	wpwqaxp
cross
qx
qy
qz
qw
quat
Taaxes
order
angles
degrees
xp
device
extrinsic
num_axes
axes_not_orthogonal
q_shape
wqwiaqi
T	aseq
angles
degrees
xp
num_axes
intrinsic
extrinsic
axes
wqT amatrix
assume_valid
xp
device
mask
lazy
ind
gramians
eye
is_orthogonal
wUw_aVt
is_not_orthogonal
T amrp
xp
mrp2_plus_1
q_no_norm
quat
T aquat
normalize
copy
scalar_first
xp
T arotvec
degrees
xp
angle
small_angle
angle2
small_scale
div_angle
large_scale
scale
quat
T aquat
T aquat
xp
sin_q
cos_q
angles
T aquat
weights
axis
xp
device
dtype
all_axes
lazy
quat_expand
wKaneg_weights
weighted_quat
keep_axes
axes_order
aK_reordered
new_shape
w_wvT aquat
wnaxp
device
result
identity
T aquat
left
right
xp
wpaps
pv
ls
lv
rs
rv
term1
prv
term2
lrv
term3
lpv
term4
lv_expanded
pv_expanded
cross_lp
term5
qs
max_ind
left_best
right_best
all_idx
left_idx
right_idx
reduced
T aquat
value
indexer
.scipy.spatial.transform
*
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_scipy
u\not_existing
uspatial\transform
T aNUITKA_PACKAGE_scipy_spatial
u\not_existing
transform
T aNUITKA_PACKAGE_scipy_spatial_transform
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
a_rotation
T aRotation
aSlerp
l aRotation
l
aSlerp
a_rigid_transform
T aRigidTransform
aRigidTransform
a_rotation_spline
T aRotationSpline
aRotationSpline

T arotation
rotation
L aRotation
aSlerp
aRotationSpline
aRigidTransform
a__all__
uscipy._lib._testutils
T aPytestTester
aPytestTester
T uscipy.spatial.transform
test
uscipy\spatial\transform\__init__.py
u<module scipy.spatial.transform>
.scipy.spatial.transform.rotation
z
a__all__
a_sub_module_deprecation
uspatial.transform
rotation
a_rotation
T asub_package
module
private_modules
all
attribute
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uscipy._lib.deprecation
T a_sub_module_deprecation
l
aRotation
aSlerp
a__dir__
a__getattr__
uscipy\spatial\transform\rotation.py
u<module scipy.spatial.transform.rotation>
T aname

.scipy.special._basic
s aasarray
utoo many values to unpack (expected 2)
issubdtype
dtype
inexact
zeros
shape
np
finfo
eps
f C  ]r2<f dy    =f V     <fH     z>f    MbP?l
floor
place
nan
l asin
l aextract
pi
pow
q around
isscalar
l 	uNumber must be integer <= 1200.
a_specfun
jdzo
utoo many values to unpack (expected 4)
uArguments must be scalars.
uArguments must be integers.
unt > 0
jyzo
jnyn_zeros
l uArguments must be scalar positive integer.
cyzo
f
?aphase
wpwnwswLwvwzf
@a_nonneg_int_or_fail
jv
a_bessel_diff_formula
yv
kv
iv
hankel1
hankel2
uarguments must be scalars.
D astrict
Faempty
float64
T adtype
empty_like
a_rctj
T aout
a_rcty
uArgument must be positive scalar integer.
cerzo
fcszo
a_ufuncs
eval_genlaguerre
f
gamma
zeta
where
psi
um and q must be scalars.
uq >=0
um must be an integer >=0.
f
@f      L@asqrt
ffffff `@f      V@f
1@f       @fT      ?f   _vOn?f
?l  awarnings
warn
uToo many predicted coefficients.
aRuntimeWarning
D astacklevel
l amathieu_a
fcoef
um must be an integer > 0
l amathieu_b
um must be a non-negative integer.
un must be a non-negative integer.
max
astype
iscomplexobj
complex128
ndim
a_lqmn
moveaxis
T l
l T q q aqd
bernob
eulerb
T Ofloat
a_lqn
unt must be a positive integer scalar.
airyzo
uargument must be > 0.
lamv
utoo many values to unpack (expected 3)
lamn
pbdv
pbvv
un must be an integer.
cpbdn
unt must be positive integer scalar.
klvnzo
l l l l uModes must be integers.
l  uDifference between n and m is too large.
segv
binom
ndarray
T f
?avals
comb
T aexact
a_comb_int
uNon-integer `N` and `k` with `exact=True` is not supported.
T l
squeeze
u`N` and `k` must be scalar integers with `exact=True`.
val
poch
math
factorial
a_range_prod
unique
a_FACTORIALK_LIMITS_64BITS
keys
a_FACTORIALK_LIMITS_32BITS
int64
T along
wkaun
size
T wkaout
complex
a_factorialx_approx_core
T wkaextend
isnan
a_is_subdtype
wcaisinf
T anan
res
a_gamma1p
array
catch_warnings
a__enter__
a__exit__
simplefilter
ignore
power
rgamma
T nnnaresult
corr
u_factorialx_approx_core.<locals>.corr
wiainteger
wfafloating
complexfloating
number
u<genexpr>
u_is_subdtype.<locals>.<genexpr>
T azero
complex
uargument `extend` must be either 'zero' or 'complex', received:

uIncompatible options: `exact=True` and `extend='complex'`
uUnsupported data type for {vname} in {fname}: {dtype}
Permitted data types are integers and floating point numbers, as well as complex numbers if `extend='complex' is passed.
uUnsupported data type for {vname} in {fname}: {dtype}
Permitted data types are integers, as well as floating point numbers and complex numbers if `extend='complex' is passed.
uIn order to use non-integer arguments, you must opt into this by passing `extend='complex'`. Note that this changes the result for all negative arguments (which by default return 0).
factorial2
u Additionally, it will rescale the values of the double factorial at even integers by a factor of sqrt(2/pi).
factorialk
u Additionally, it will perturb the values of the multifactorial at most positive integers `n`.
format
u`k`
T avname
fname
dtype
zero
uFor `extend='zero'`, k must be a positive integer, received:
uParameter k cannot be zero!
L wiwfwcM
u`n`
T unan+nanj
P l
l T l u`exact=True` only supports integers, cannot use data type {dtype}
a_factorialx_array_exact
a_factorialx_array_approx
a_factorialx_wrapper
T wkaexact
extend
uArgument `N` must contain only integers
uArgument `K` must contain only integers
a_stirling2_inexact
nditer
refs_ok
take
heapify
defaultdict
T Oint
T T l
pT l pT l l T l pasnsk_vals
T l L l
l pank_pairs
heappop
n_old
num_iters
n_row
append
buffered
L L areadonly
L areadonly
L awriteonly
allocate
T aop_dtypes
it
finished
iternext
operands
output
a_riemann_zeta
a_zeta
logaddexp
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
collections
T adefaultdict
heapq
T aheapify
heappop
T api
asarray
floor
isscalar
sqrt
where
sin
place
issubdtype
extract
inexact
nan
zeros
sinc
sinc
T a_ufuncs
T amathieu_a
mathieu_b
iv
jv
gamma
rgamma
psi
hankel1
hankel2
yv
kv
poch
binom
a_stirling2_inexact
a_gufuncs
T a_lqn
a_lqmn
a_rctj
a_rcty
a_input_validation
T a_nonneg_int_or_fail
T a_specfun
a_comb
T a_comb_int
L9aai_zeros
assoc_laguerre
bei_zeros
beip_zeros
ber_zeros
bernoulli
berp_zeros
bi_zeros
comb
digamma
diric
erf_zeros
euler
factorial
factorial2
factorialk
fresnel_zeros
fresnelc_zeros
fresnels_zeros
h1vp
h2vp
ivp
jn_zeros
jnjnp_zeros
jnp_zeros
jnyn_zeros
jvp
kei_zeros
keip_zeros
kelvin_zeros
ker_zeros
kerp_zeros
kvp
lmbda
lqmn
lqn
mathieu_even_coef
mathieu_odd_coef
obl_cv_seq
pbdn_seq
pbdv_seq
pbvv_seq
perm
polygamma
pro_cv_seq
riccati_jn
riccati_yn
sinc
softplus
stirling2
y0_zeros
y1_zeros
y1p_zeros
yn_zeros
ynp_zeros
yvp
zeta
a__all__
D	l l l l l l l l l	l l!l,l6lAlJlTl]leD	l l l l l l l l l	l l l l l%l+l/l3l8adiric
jnjnp_zeros
jn_zeros
jnp_zeros
yn_zeros
ynp_zeros
T Fay0_zeros
y1_zeros
y1p_zeros
jvp
yvp
kvp
ivp
h1vp
h2vp
riccati_jn
riccati_yn
erf_zeros
fresnelc_zeros
fresnels_zeros
fresnel_zeros
T Z
assoc_laguerre
digamma
polygamma
mathieu_even_coef
mathieu_odd_coef
lqmn
bernoulli
euler
lqn
ai_zeros
bi_zeros
lmbda
pbdv_seq
pbvv_seq
pbdn_seq
ber_zeros
bei_zeros
ker_zeros
kei_zeros
berp_zeros
beip_zeros
kerp_zeros
keip_zeros
kelvin_zeros
pro_cv_seq
obl_cv_seq
D aexact
repetition
Fpaperm
T Fazero
D aexact
Fastirling2
T nnasoftplus
uscipy\special\_basic.py
T a.0
dt
dtype
u<module scipy.special._basic>
T wvwzwnwLaphase
wpwswiT wnwkaextend
result
p_dtype
n_mod_k
corr
wrT wnwkaextend
result
cond
n_to_compute
T wnwkaun
dt
out
lane
ul
val
wiaprev
current
T afname
wnwkaexact
extend
msg_unsup
msg_exact_not_possible
msg_needs_complex
msg
types_requiring_complex
complexify
T avals
res
T adtype
dtypes
mapping
T alo
hi
wkamid
T ant
kf
T wxwnwkT ant
T wnan1
T wNwkaexact
repetition
cond
vals
T wkwrTwxwnaytype
wyaminval
mask1
denom
mask2
xsub
nsub
zsub
mask
dsub
T wnaexact
extend
T wnwkaexact
extend
T wvwzwnT wnant
T ant
wnwmwtazo
T	wvwxwnav0
n1
v1
vm
vl
dl
T wmwnwzamm
nn
wqaqd
T wnwzan1
qn
qd
T wmwqaqm
km
kd
waafc
T wmwqaqm
km
kd
wbafc
T wmwnwcamaxL
T wnwzan1
cpb
cpd
T
wvwxwnav0
n1
v1
dv
dp
pdf
pdd
T
wNwkaexact
floor_N
floor_k
non_integral
val
wiacond
vals
T wnwxafac2
T wnwxan1
jn
jnp
T wnwxan1
yn
ynp
T wxakwargs
T wNwKaexact
output_is_scalar
nk_pairs
snsk_vals
pair
n_old
n_row
wnwkanum_iters
wjaout_types
it
output
T ant
complex
kf
kc
T wxwqaout
.scipy.special._ellip_harm
%
a_ellip_harm
np
errstate
T aignore
T aall
a__enter__
a__exit__
a_ellip_harm_2_vec
T nnna_ellipsoid_norm
a_ellip_normal_vec
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
l
a_ufuncs
T a_ellip_harm
l a_ellip_harm_2
T a_ellipsoid
a_ellipsoid_norm
a_ellipsoid
T l paellip_harm
vectorize
D aotypes
wdaellip_harm_2
ellip_normal
uscipy\special\_ellip_harm.py
u<module scipy.special._ellip_harm>
T ah2
k2
wnwpT ah2
k2
wnwpwsasignm
signn
T ah2
k2
wnwpwsu
.scipy.special._input_validation
operator
index
math
floor
l
T EValueError
ETypeError

u must be a non-negative integer
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
T ta_nonneg_int_or_fail
uscipy\special\_input_validation.py
u<module scipy.special._input_validation>
T wnavar_name
strict
err
.scipy.special._lambertw
np
asarray
dtype
T along
T adtype
a_lambertw
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a_ufuncs
T a_lambertw
l l
numpy
T l
f: 0  yE>alambertw
uscipy\special\_lambertw.py
u<module scipy.special._lambertw>
T wzwkatol

.scipy.special._logsumexp
m
array_namespace
xp_promote
T abroadcast
force_floating
xp
utoo many values to unpack (expected 2)
xpx
atleast_nd
l T andim
xp
ndim
xp_size
l
np
errstate
T aignore
ignore
ignore
T adivide
invalid
over
a__enter__
a__exit__
exp
sum
T aaxis
keepdims
sign
abs
log
T nnnT aignore
ignore
T adivide
invalid
a_logsumexp
T aaxis
return_sign
xp
isfinite
out
where
out_inf
sgn
sgn_inf
asarray
shape
full
inf
dtype
xp_device
T adtype
device
isdtype
ucomplex floating
real
xp_float_to_complex
a_wrap_radians
imag
T axp
JZ
f
?asqueeze
T aaxis
pi
l amax
reshape
arange
T adevice
at
set
T q Z
T aaxis
dtype
keepdims
mask
D acopy
ta_elements_and_indices_with_max_real
T aaxis
xp
T acopy
astype
T aaxis
keepdims
dtype
ureal floating
q aa_max
log1p
wswmanan
T l
x_max
T aignore
T adivide
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy._lib._array_api
T aarray_namespace
xp_capabilities
xp_device
xp_size
xp_promote
xp_float_to_complex
xp_capabilities
uscipy._lib
T aarray_api_extra
array_api_extra
logsumexp
softmax
log_softmax
a__all__
T nnFpD aaxis
q T nuscipy\special\_logsumexp.py
u<module scipy.special._logsumexp>
T waaaxis
xp
real_a
max_
mask
wiamax_i
T wawbaaxis
return_sign
xp
a_max
i_max
i_max_dt
b_i_max
wmaexp
wsasgn
out
T wxaxp
wrapped
no_wrap
T wxaaxis
xp
x_max
tmp
exp_tmp
wsaout
T waaaxis
wbakeepdims
return_sign
xp
b_exp_a
sum_
sgn_inf
out_inf
out
sgn
out_finite
shape
real
imag
T wxaaxis
xp
x_max
exp_x_shifted

.scipy.special._multiufuncs
(
np
ufunc
collections
abc
aMapping
values
aIterable
uufunc_or_ufuncs should be a ufunc or a ufunc collection
uAll ufuncs must have type `numpy.ufunc`. Received
ufunc_or_ufuncs

seen_input_types
add
types
uAll ufuncs must take the same input types.
a__name__
a_ufunc_or_ufuncs
a_MultiUFunc__doc
a_MultiUFunc__force_complex_output
a_default_kwargs
a_resolve_out_shapes
a_finalize_out
a_key
u<lambda>
uMultiUFunc.__init__.<locals>.<lambda>
a_ufunc_default_args
a_ufunc_default_kwargs
split
T u->
l
u<genexpr>
uMultiUFunc.__init__.<locals>.<genexpr>
a__doc__
uResolve to output shapes based on relevant inputs.
resolve_out_shapes
a_resolve_ufunc
nin
asarray
nout
resolve_dtypes
T naresult_type
issubdtype
inexact
float64
ufunc_out_dtype
out
shape
uMultiUFunc.__call__.<locals>.<genexpr>
dtype
JZ
f
?utoo many values to unpack (expected 2)
empty
T adtype
a_nonneg_int_or_fail
diff_n
D astrict
Fl udiff_n is currently only implemented for orders 0, 1, and 2, received:
w.amoveaxis
q D aaxes
L T
T l
l q anumbers
aIntegral
un must be a non-negative integer.
l udiff_n must be a non-negative integer, received:
D aaxes
L T
pT l
l q um must be a non-negative integer.
broadcast_shapes
D aaxes
L T
T l
q wnT Q
l
pT Q
L l l
L l
l l T Q
L L l l L l l
L L l
l L l l udiff_n is currently only implemented for orders 2, received:
D aaxes
L T
pT l
l q q a__file__
a__spec__
origin
has_location
a__cached__
numpy
a_input_validation
T a_nonneg_int_or_fail
a_special_ufuncs
T alegendre_p
assoc_legendre_p
sph_legendre_p
sph_harm_y
legendre_p
assoc_legendre_p
sph_legendre_p
sph_harm_y
a_gufuncs
T alegendre_p_all
assoc_legendre_p_all
sph_legendre_p_all
sph_harm_y_all
legendre_p_all
assoc_legendre_p_all
sph_legendre_p_all
sph_harm_y_all
L aassoc_legendre_p
assoc_legendre_p_all
legendre_p
legendre_p_all
sph_harm_y
sph_harm_y_all
sph_legendre_p
sph_legendre_p_all
a__all__
