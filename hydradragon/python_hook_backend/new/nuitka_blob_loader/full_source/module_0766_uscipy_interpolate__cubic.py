# Reconstructed from integrated Nuitka blob
# Module: uscipy.interpolate._cubic

a__qualname__
T l
nuCubicHermiteSpline.__init__
a__orig_bases__
a__class_getitem__
uPchipInterpolator.__init__
staticmethod
uPchipInterpolator._edge_case
uPchipInterpolator._find_derivatives
pchip_interpolate
aAkima1DInterpolator
T tL T udask.array
ulacks nd fancy indexing
T ujax.numpy
uimmutable arrays
T aarray_api_strict
ufancy indexing __setitem__
T acpu_only
xfail_backends
D amethod
extrapolate
akima
nuAkima1DInterpolator.__init__
T taextend
uAkima1DInterpolator.extend
classmethod
from_spline
uAkima1DInterpolator.from_spline
from_bernstein_basis
uAkima1DInterpolator.from_bernstein_basis
aCubicSpline
T l
unot-a-knot
nuCubicSpline.__init__
uCubicSpline._validate_bc
uscipy\interpolate\_cubic.py
u<module scipy.interpolate._cubic>
T a__class__
T aself
wxwyaaxis
method
extrapolate
xp
dx
w_amsg
xv
hk
mk
wtwmadm
pm
f1
f2
break_mult
f12
mmax
ind
x_ind
y_ind
a__class__
Taself
wxwyadydx
axis
extrapolate
xp
dx
dxr
slope
wtwca__class__
T!aself
wxwyaaxis
bc_type
extrapolate
xp
dx
w_wnabc
wsadxr
slope
wAwbwmwtabc_start
bc_end
a_m1_0
a_m1_m2
a_m1_m1
a_m2_m1
a_0_m1
aAc
b1
b2
s1
s2
s_m1
wda__class__
T aself
wxwyaaxis
extrapolate
xp
w_amsg
xv
dk
a__class__
T	ah0
h1
m0
m1
xp
wdamask
mask2
mmm
T wxwyaxp
y_shape
hk
mk
dk
smk
condition
w1
w2
whmean
T	abc_type
wyaexpected_deriv_shape
axis
validated_bc
abc
deriv_order
deriv_value
weT aself
wcwxaright
T acls
bp
extrapolate
T acls
tck
extrapolate
T axi
yi
wxader
axis
wPT wxwyaaxis
dydx
xp
dtype
dx
.scipy.interpolate._fitpack2
a5
q avalidate_input
utoo many values to unpack (expected 5)
ext
aFITPACK_LOCK
a__enter__
a__exit__
dfitpack
fpcurf0
l
l T wwaxb
xe
wsT nnnadata
q a_reset_nest
a_data
a_reset_class
np
asarray
utoo many values to unpack (expected 3)
isfinite
all
ux and y array must not contain NaNs or infs.
diff
Z
ux must be increasing if s > 0
ux must be strictly increasing if s = 0
size
ux and y should have a same length
ux, y, and w should have a same length
shape
T l ubbox shape should be (2,)
l uk should be 1 <= k <= 5
us should be s >= 0.0
a_extrap_modes
uUnknown extrapolation mode

w.a__new__
a_eval_args
l l l	a_set_class
aInterpolatedUnivariateSpline
q aLSQUnivariateSpline
a_curfit_messages
get
uier=
warnings
warn
D astacklevel
l a_spline_class
aUnivariateSpline
l
utoo many values to unpack (expected 2)
u`nest` can only be increased
T l l	l l utoo many values to unpack (expected 4)
:nl nlafpcurf1
resize
nest
u<genexpr>
uUnivariateSpline._reset_nest.<locals>.<genexpr>
l T usmoothing factor unchanged forLSQ spline with fixed knots
l T astacklevel
:nl n:l nnaarray
a_fitpack_impl
splev
T ader
ext
splint
spalde
l asproot
T amest
ufinding roots unsupported for non-cubic splines
splder
a_from_tck
tck
T aext
splantider
ux must be strictly increasing
ux must be increasing
concatenate
D aaxis
l
uInterior knots t must satisfy Schoenberg-Whitney conditions
fpchec
a_fpchec_error_string
fpcurfm1
T wwaxb
xe
:nq nutck should be a 5 element tuple of tx, ty, c, kx, ky
:nl n:l nnadegrees
fp
:nl nl azeros
dtype
T adtype
ux must be strictly increasing when `grid` is True
uy must be strictly increasing when `grid` is True
parder
ier
uError code returned by parder:
bispev
uError code returned by bispev:
broadcast_arrays
wxaravel
wyapardeu
uError code returned by pardeu:
bispeu
uError code returned by bispeu:
wzareshape
uorder of derivative must be positive or zero
uorder of derivative must be less than degree of spline
pardtc
uUnexpected error code returned by pardtc:
a_DerivedBivariateSpline
newc
a__call__
T adx
dy
grid
dblint
ux, y, and z should have a same length
ux, y, z, and w should have a same length
uw should be positive
f
?ueps should be between (0, 1)
uThe length of x, y and z should be at least (kx+1) * (ky+1)
wwuattribute "fp"
a_invalid_why
umethod "get_residual"
a_validate_input
T l ubbox shape should be (4,)
surfit_smth
T wsaeps
lwrk2
utoo many values to unpack (expected 8)
T l
q q a_surfit_messages
D astacklevel
l atx
nx
ty
any
wcamax
surfit_lsq
D alwrk2
l T alwrk2
T q atx1
ty1
uy must be strictly increasing
ux dimension of z must have same number of elements as x
uy dimension of z must have same number of elements as y
regrid_smth
utoo many values to unpack (expected 7)
min
pi
urequested theta out of bounds.
a_BivariateSplineBase
T adtheta
dphi
grid
utheta should be between [0, pi]
f
@uphi should be between [0, 2pi]
us should be positive
spherfit_smth
T wwwsaeps
a_spherefit_messages
tt_
nt_
tp_
np_
l T l purequested phi out of bounds.
aSphereBivariateSpline
utt should be between (0, pi)
utp should be between (0, 2pi)
:l q n:q nnaspherfit_lsq
T wwaeps
dfitpack_int
T L l
ppT L q l
q l
T nnafloat32
float64
:l nnaider
uu should be between (0, pi)
uv[0] should be between [-pi, pi)
uv[-1] should be v[0] + 2pi or less
uu must be strictly increasing
uv must be strictly increasing
uu dimension of r must have same number of elements as u
uv dimension of r must have same number of elements as v
uif pole_continuity is False, so must be pole_flat
regrid_smth_spher
copy
a_spfit_messages
tu
nu
tv
nv
v0
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
L
aUnivariateSpline
aInterpolatedUnivariateSpline
aLSQUnivariateSpline
aBivariateSpline
aLSQBivariateSpline
aSmoothBivariateSpline
aLSQSphereBivariateSpline
aSmoothSphereBivariateSpline
aRectBivariateSpline
aRectSphereBivariateSpline
a__all__
threading
T aLock
aLock
numpy
T azeros
concatenate
ravel
diff
array
T a_fitpack_impl
T a_dfitpack
a_dfitpack
uscipy._lib._array_api
T axp_capabilities
xp_capabilities
types
intvar
D l l l l

The required storage space exceeds the available storage space, as
specified by the parameter nest: nest too small. If nest is already
large (say nest > m/2), it may also indicate that s is too small.
The approximation returned is the weighted least-squares spline
ccording to the knots t[0],t[1],...,t[n-1]. (n=nest) the parameter fp
gives the corresponding weighted sum of squared residuals (fp>s).

A theoretically impossible result was found during the iteration
process for finding a smoothing spline with fp = s: s too small.
There is an approximation returned but the corresponding weighted sum
of squared residuals does not satisfy the condition abs(fp-s)/s < tol.

The maximal number of iterations maxit (set to 20 by the program)
llowed for finding a smoothing spline with fp=s has been reached: s
too small.
There is an approximation returned but the corresponding weighted sum
of squared residuals does not satisfy the condition abs(fp-s)/s < tol.

Error on entry, no approximation returned. The following conditions
must hold:
xb<=x[0]<x[1]<...<x[m-1]<=xe, w[i]>0, i=0..m-1
if iopt=-1:
xb<t[k+1]<t[k+2]<...<t[n-k-2]<xe
D l
extrapolate
l azeros
l araise
l aconst
l
pl pl pl pT tT aout_of_scope
