# Reconstructed from integrated Nuitka blob
# Module: uscipy.interpolate._fitpack2

a__qualname__
a__init__
uUnivariateSpline.__init__
uUnivariateSpline.validate_input
T l
uUnivariateSpline._from_tck
uUnivariateSpline._reset_class
uUnivariateSpline._set_class
T nuUnivariateSpline._reset_nest
set_smoothing_factor
uUnivariateSpline.set_smoothing_factor
T l
nuUnivariateSpline.__call__
get_knots
uUnivariateSpline.get_knots
get_coeffs
uUnivariateSpline.get_coeffs
get_residual
uUnivariateSpline.get_residual
integral
uUnivariateSpline.integral
derivatives
uUnivariateSpline.derivatives
roots
uUnivariateSpline.roots
T l aderivative
uUnivariateSpline.derivative
antiderivative
uUnivariateSpline.antiderivative
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uInterpolatedUnivariateSpline.__init__
a__orig_bases__
uThe input parameters have been rejected by fpchec. This means that at least one of the following conditions is violated:
1) k+1 <= n-k-1 <= m
2) t(1) <= t(2) <= ... <= t(k+1)
t(n-k) <= t(n-k+1) <= ... <= t(n)
3) t(k+1) < t(k+2) < ... < t(n-k)
4) t(k+1) <= x(i) <= t(n-k)
5) The conditions specified by Schoenberg and Whitney must hold
for at least one subset of data points, i.e., there must be a
subset of data points y(j) such that
t(j) < y(j) < t(j+k+1), j=1,2,...,n-k-1
uLSQUnivariateSpline.__init__
u_BivariateSplineBase._from_tck
u_BivariateSplineBase.get_residual
u_BivariateSplineBase.get_knots
u_BivariateSplineBase.get_coeffs
T l
ptu_BivariateSplineBase.__call__
partial_derivative
u_BivariateSplineBase.partial_derivative
D l l l l l l
q u
The required storage space exceeds the available storage space: nxest
or nyest too small, or s too small.
The weighted least-squares spline corresponds to the current set of
knots.

A theoretically impossible result was found during the iteration
process for finding a smoothing spline with fp = s: s too small or
badly chosen eps.
Weighted sum of squared residuals does not satisfy abs(fp-s)/s < tol.

the maximal number of iterations maxit (set to 20 by the program)
llowed for finding a smoothing spline with fp=s has been reached:
s too small.
Weighted sum of squared residuals does not satisfy abs(fp-s)/s < tol.
Try increasing maxit by passing it as a keyword argument.

No more knots can be added because the number of b-spline coefficients
(nx-kx-1)*(ny-ky-1) already exceeds the number of data points m:
either s or m too small.
The weighted least-squares spline corresponds to the current set of
knots.

No more knots can be added because the additional knot would (quasi)
coincide with an old one: s too small or too large a weight to an
inaccurate data point.
The weighted least-squares spline corresponds to the current set of
knots.

Error on entry, no approximation returned. The following conditions
must hold:
xb<=x[i]<=xe, yb<=y[i]<=ye, w[i]>0, i=0..m-1
If iopt==-1, then
xb<tx[kx+1]<tx[kx+2]<...<tx[nx-kx-2]<xe
yb<ty[ky+1]<ty[ky+2]<...<ty[ny-ky-2]<ye

The coefficients of the spline returned have been computed as the
minimal norm least-squares solution of a (numerically) rank deficient
system (deficiency=%i). If deficiency is large, the results may be
inaccurate. Deficiency may strongly depend on the value of eps.
aBivariateSpline
T l
paev
uBivariateSpline.ev
uBivariateSpline.integral
staticmethod
uBivariateSpline._validate_input
uis unavailable, because _DerivedBivariateSpline instance is not constructed from data that are to be interpolated or smoothed, but derived from the underlying knots and coefficients of another spline object
property
u_DerivedBivariateSpline.fp
u_DerivedBivariateSpline.get_residual
aSmoothBivariateSpline
f       <uSmoothBivariateSpline.__init__
aLSQBivariateSpline
uLSQBivariateSpline.__init__
aRectBivariateSpline
l uRectBivariateSpline.__init__

ERROR. On entry, the input data are controlled on validity. The following
restrictions must be satisfied:
-1<=iopt<=1,  m>=2, ntest>=8 ,npest >=8, 0<eps<1,
0<=teta(i)<=pi, 0<=phi(i)<=2*pi, w(i)>0, i=1,...,m
lwrk1 >= 185+52*v+10*u+14*u*v+8*(u-1)*v**2+8*m
kwrk >= m+(ntest-7)*(npest-7)
if iopt=-1: 8<=nt<=ntest , 9<=np<=npest
0<tt(5)<tt(6)<...<tt(nt-4)<pi
0<tp(5)<tp(6)<...<tp(np-4)<2*pi
if iopt>=0: s>=0
if one of these conditions is found to be violated,control
is immediately repassed to the calling program. in that
case there is no approximation returned.

WARNING. The coefficients of the spline returned have been computed as the
minimal norm least-squares solution of a (numerically) rank
deficient system (deficiency=%i, rank=%i). Especially if the rank
deficiency, which is computed by 6+(nt-8)*(np-7)+ier, is large,
the results may be inaccurate. They could also seriously depend on
the value of eps.
q uSphereBivariateSpline.__call__
uSphereBivariateSpline.ev
aSmoothSphereBivariateSpline
T nZ
f       <uSmoothSphereBivariateSpline.__init__
uSmoothSphereBivariateSpline.__call__
aLSQSphereBivariateSpline
T nf       <uLSQSphereBivariateSpline.__init__
uLSQSphereBivariateSpline.__call__

ERROR: on entry, the input data are controlled on validity
the following restrictions must be satisfied.
-1<=iopt(1)<=1, 0<=iopt(2)<=1, 0<=iopt(3)<=1,
-1<=ider(1)<=1, 0<=ider(2)<=1, ider(2)=0 if iopt(2)=0.
-1<=ider(3)<=1, 0<=ider(4)<=1, ider(4)=0 if iopt(3)=0.
mu >= mumin (see above), mv >= 4, nuest >=8, nvest >= 8,
kwrk>=5+mu+mv+nuest+nvest,
lwrk >= 12+nuest*(mv+nvest+3)+nvest*24+4*mu+8*mv+max(nuest,mv+nvest)
0< u(i-1)<u(i)< pi,i=2,..,mu,
-pi<=v(1)< pi, v(1)<v(i-1)<v(i)<v(1)+2*pi, i=3,...,mv
if iopt(1)=-1: 8<=nu<=min(nuest,mu+6+iopt(2)+iopt(3))
0<tu(5)<tu(6)<...<tu(nu-4)< pi
8<=nv<=min(nvest,mv+7)
v(1)<tv(5)<tv(6)<...<tv(nv-4)<v(1)+2*pi
the schoenberg-whitney conditions, i.e. there must be
subset of grid coordinates uu(p) and vv(q) such that
tu(p) < uu(p) < tu(p+4) ,p=1,...,nu-4
(iopt(2)=1 and iopt(3)=1 also count for a uu-value
tv(q) < vv(q) < tv(q+4) ,q=1,...,nv-4
(vv(q) is either a value v(j) or v(j)+2*pi)
if iopt(1)>=0: s>=0
if s=0: nuest>=mu+6+iopt(2)+iopt(3), nvest>=mv+7
if one of these conditions is found to be violated,control is
immediately repassed to the calling program. in that case there is no
pproximation returned.
aRectSphereBivariateSpline
T Z
FnFpuRectSphereBivariateSpline.__init__
uRectSphereBivariateSpline.__call__
uscipy\interpolate\_fitpack2.py
T a.0
wjadata
nest
u<module scipy.interpolate._fitpack2>
T a__class__
T aself
theta
phi
dtheta
dphi
grid
T aself
wxanu
ext
weT aself
wxwyadx
dy
grid
tx
ty
wcakx
ky
wzaier
shape
T aself
wxwywwabbox
wkaext
check_finite
T aself
wxwywzatx
ty
wwabbox
kx
ky
eps
nx
any
nmax
tx1
ty1
xb
xe
yb
ye
wcafp
ier
deficiency
message
T aself
theta
phi
wratt
tp
wwaeps
nt_
np_
tt_
tp_
wcafp
ier
message
Taself
wxwywtwwabbox
wkaext
check_finite
xb
xe
wnadata
T aself
wxwywzabbox
kx
ky
wsamaxit
xb
xe
yb
ye
nx
tx
any
ty
wcafp
ier
msg
T aself
wuwvwrwsapole_continuity
pole_values
pole_exact
pole_flat
iopt
ider
r0
r1
nu
tu
nv
tv
wcafp
ier
msg
T aself
wxwywzwwabbox
kx
ky
wsaeps
xb
xe
yb
ye
nx
tx
any
ty
wcafp
wrk1
ier
message
T aself
theta
phi
wrwwwsaeps
nt_
tt_
np_
tp_
wcafp
ier
message
T
self
wxwywwabbox
wkwsaext
check_finite
data
T acls
tck
ext
self
wtwcwkT acls
tck
self
T aself
data
wnwtwcwkaier
message
T aself
data
nest
wnwkwmwtwcafpint
nrdata
args
T aself
cls
T wxwywzwwakx
ky
eps
T aself
wnatck
T aself
wnatck
ext
T aself
wxT aself
xi
yi
dx
dy
T aself
theta
phi
dtheta
dphi
T aself
T aself
data
wkwnT
self
xa
xb
ya
yb
tx
ty
wcakx
ky
T aself
wawbT aself
dx
dy
kx
ky
tx
ty
wcanewc
ier
nx
any
newtx
newty
newkx
newky
newclen
T aself
wkwtamest
T aself
wsadata
args
T
wxwywwabbox
wkwsaext
check_finite
w_finite
we.scipy.interpolate._fitpack_impl
iinfo
dfitpack_int
max

u cannot fit into an
type
l
wtaarray
wrk
iwrk
wuaub
ue
l aatleast_1d
shape
utoo many values to unpack (expected 2)
q awarnings
warn
aRuntimeWarning
uSetting x[
u][
u]=x[
u][0]
D astacklevel
l l u0 < idim < 11 must hold
ones
a_parcur_cache
zeros
l u1 <= k=
u <=5 must hold
utask must be -1, 0 or 1
uMismatch of input dimensions
sqrt
l uKnots must be given for task=-1
uThere must be at least 2*k+2 knots for task=-1
um > k must hold
l a_fitpack
a_parcur
ravel
transpose
utoo many values to unpack (expected 3)
ier
fp
reshape
a_iermess
u	k=
u n=
u m=
u fp=
u s=
T l l l aunknown
Z
wmulen(w)=
u is not equal to m=
uLengths of the first three arguments (x,y,w) must be equal
uGiven degree of the spline (k=
u) is not supported. (1<=k<=5)
task
empty
a_curfit_cache
nest
l l umust call with task=1 only after call with task=0,-1
dfitpack
curfit
utoo many values to unpack (expected 4)
percur
wsu<lambda>
usplev.<locals>.<lambda>
u0<=der=
u<=k=
u must hold
T l
l l l uext =
u not in (0, 1, 2, 3)
asarray
splev
splder
l
uInvalid input data
uFound x value not in the domain
uAn error occurred
ext
usplint.<locals>.<lambda>
splint
usproot works only for cubic (k=3) splines
usproot.<locals>.<lambda>
uThe number of knots
u>=8
sproot
uInvalid input data. t1<=..<=t4<t5<..<tn-3<=..<=tn must hold.
T uThe number of zeros exceeds mest
uUnknown error
uspalde.<locals>.<lambda>
spalde
uInvalid input data. t(k)<=x<=t(n-k+1) must hold.
ulen(x)==len(y)==len(z) must hold.
min
uKnots_x must be given for task=-1
a_surfit_cache
tx
uKnots_y must be given for task=-1
ty
uThere must be at least 2*kx+2 knots_x for task=-1
uThere must be at least 2*ky+2 knots_x for task=-1
uGiven degree of the spline (kx,ky=
w,um >= (kx+1)(ky+1) must hold
a_int_overflow
D amsg
uToo many data points to interpolate
a_surfit
q a_iermess2
u	kx,ky=
u nx,ny=
T l l l l l u
kx,ky=
utoo many values to unpack (expected 5)
u0 <= dx =
u < kx =
u0 <= dy =
u < ky =
uFirst two entries should be rank-1 arrays.
size
D amsg
uToo many data points to interpolate.
parder
bispev
dblint
insert
wxwkacc
tt
kk
a_insert
splantider
array_namespace
uOrder of derivative (n =
u) must be <= order of spline (k =
w)T :nnnT n:l nnanp
errstate
T araise
raise
T ainvalid
divide
a__enter__
a__exit__
wcq aconcat_1d
xp
:l q nuThe spline has internal repeated knots and is not differentiable
u times
T nnnacumulative_sum
D aaxis
l
T l astack
T q Q
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
L asplrep
splprep
splev
splint
sproot
spalde
bisplrep
bisplev
insert
splder
splantider
a__all__
numpy
T a_fitpack
T
atleast_1d
array
ones
zeros
sqrt
ravel
transpose
empty
iinfo
asarray
T a_dfitpack
a_dfitpack
uscipy._lib._array_api
T aarray_namespace
concat_1d
xp_capabilities
xp_capabilities
types
intvar
dtype
D l
q q l l l l
unknown
L uThe spline has a residual sum of squares fp such that abs(fp-s)/s<=0.001
nL uThe spline is an interpolating spline (fp=0)
nL uThe spline is weighted least-squares polynomial of degree k.
fp gives the upper bound fp0 for the smoothing factor s
nL uThe required storage space exceeds the available storage space.
Probable causes: data (x,y) size is too small or smoothing parameter
s is too small (fp>s).
EValueError
L uA theoretically impossible result when finding a smoothing spline
with fp = s. Probable cause: s too small. (abs(fp-s)/s>0.001)
EValueError
L uThe maximal number of iterations (20) allowed for finding smoothing
spline with fp=s has been reached. Probable cause: s too small.
(abs(fp-s)/s>0.001)
EValueError
L uError on input data
EValueError
L uAn error occurred
ETypeError
D l
q q q l l l l l l
l aunknown
L uThe spline has a residual sum of squares fp such that abs(fp-s)/s<=0.001
nL uThe spline is an interpolating spline (fp=0)
nL uThe spline is weighted least-squares polynomial of degree kx and ky.
fp gives the upper bound fp0 for the smoothing factor s
nL uWarning. The coefficients of the spline have been computed as the
minimal norm least-squares solution of a rank deficient system.
nL uThe required storage space exceeds the available storage space.
Probable causes: nxest or nyest too small or s is too small. (fp>s)
EValueError
L uA theoretically impossible result when finding a smoothing spline
with fp = s. Probable causes: s too small or badly chosen eps.
(abs(fp-s)/s>0.001)
EValueError
L uThe maximal number of iterations (20) allowed for finding smoothing
spline with fp=s has been reached. Probable cause: s too small.
(abs(fp-s)/s>0.001)
EValueError
L uNo more knots can be added because the number of B-spline
coefficients already exceeds the number of data points m.
Probable causes: either s or m too small. (fp>s)
EValueError
L uNo more knots can be added because the additional knot would
coincide with an old one. Probable cause: s too small or too large
a weight to an inaccurate data point. (fp>s)
EValueError
L uError on input data
EValueError
L urwrk2 too small, i.e., there is not enough workspace for computing
the minimal least-squares solution of a rank deficient system of
linear equations.
EValueError
L uAn error occurred
ETypeError
T nnnnl l
nnl
nl
l asplprep
T
nnnl l
nnl
pl asplrep
T l
pT l
T l
T tT aout_of_scope
T nnnnnl pl
nf       <nnl
nnl abisplrep
bisplev
T l l
T l nD axp
nuscipy\interpolate\_fitpack_impl.py
T wcwxwtwkT wxatck
T wcwxwtwkader
ext
T aext
T wcwawbwtwkT wcwtwkamest
u<module scipy.interpolate._fitpack_impl>
T wxaexception
msg
Twxwyatck
dx
dy
tx
ty
wcakx
ky
msg
wzaier
T*wxwywzwwaxb
xe
yb
ye
kx
ky
task
wsaeps
tx
ty
full_output
nxest
nyest
quiet
wmanx
any
wrk
wuwvakm
ne
bx
by
b1
b2
msg
lwrk1
lwrk2
wcwoaier
fp
tck
ierm
a_mess
weT
xa
xb
ya
yb
tck
tx
ty
wcakx
ky
T wxatck
wmaper
wtwcwkaparametric
cc
c_vals
tt
cc_val
kk
ier
T wxatck
wtwcwkaparametric
wdaier
T	atck
wnaxp
wtwcwkash
wjadt
T
tck
wnaxp
wtwcwkash
wjadt
weT wxatck
der
ext
wtwcwkaparametric
shape
wyaier
T
wawbatck
full_output
wtwcwkaparametric
aint
wrk
T wxwwwuaub
ue
wkatask
wswtafull_output
nest
per
quiet
a_parcur_cache
idim
wmwiaipar
wnawrk
iwrk
wcwoaier
fp
tcku
weT wxwywwaxb
xe
wkatask
wswtafull_output
per
quiet
a_curfit_cache
wmanumknots
nest
wrk
iwrk
wewnwcafp
ier
tck
a_mess
T	atck
mest
wtwcwkaparametric
wzwmaier
.scipy.interpolate._fitpack_py
M
a_impl
splprep
splrep
aBSpline
wcandim
l uCalling splev() with BSpline objects with c.ndim > 1 is not allowed. Use BSpline.__call__(x) instead.
D l
tuExtrapolation mode

u is not supported by BSpline.
T aextrapolate
splev
uCalling splint() with BSpline objects with c.ndim > 1 is not allowed. Use BSpline.integrate() instead.
l
ufull_output =
u is not supported. Proceeding as if full_output = 0
integrate
D aextrapolate
Fasplint
uCalling sproot() with BSpline objects with c.ndim > 1 is not allowed.
tck
utoo many values to unpack (expected 3)
transpose
:l nnT l
sproot
uspalde does not accept BSpline instances.
spalde
insert
np
asarray
q :nq naderivative
splder
antiderivative
splantider
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
L asplrep
splprep
splev
splint
sproot
spalde
bisplrep
bisplev
insert
splder
splantider
a__all__
numpy
a_fitpack_impl
T abisplrep
bisplev
dblint
bisplrep
bisplev
dblint
T a_fitpack_impl
a_bsplines
T aBSpline
uscipy._lib._array_api
T axp_capabilities
xp_capabilities
T tT aout_of_scope
T nnnnl l
nnl
nl
l T
nnnl l
nnl
pl T l
pT l
T l l
T l uscipy\interpolate\_fitpack_py.py
u<module scipy.interpolate._fitpack_py>
T wxatck
wmaper
wtwcwkash
t_
c_
k_
T wxatck
T atck
wnT wxatck
der
ext
mesg
extrapolate
weT wawbatck
full_output
mesg
T wxwwwuaub
ue
wkatask
wswtafull_output
nest
per
quiet
res
Twxwywwaxb
xe
wkatask
wswtafull_output
per
quiet
res
T atck
mest
mesg
wtwcwkash
.scipy.interpolate._fitpack_repro
a_lsq_solve_qr
T aperiodic
utoo many values to unpack (expected 5)
np
isnan
sum
a_iermesg
l unot-a-knot
T unot-a-knot
periodic
uOnly 'not-a-knot' and 'periodic' boundary conditions are recognised, found

a_dierckx
fpknot
searchsorted
r_
asarray
D adtype
Ofloat
flags
c_contiguous
copy
ones_like
wxwwandim
uw.ndim =
u not implemented yet.
l
any
uWeights must be non-negative
uAll weights are zero.
wyl uy.ndim =
u not supported (must be 1 or 2.)
u != 2 not supported with parametric =
w.u != 1 not supported with parametric =
T :nnnnashape
uWeights is incompatible: w.shape =
u !=
uData is incompatible: x.shape =
u and y.shape =
:l nn:nq nuExpect `x` to be an ordered 1D sequence.
operator
index
u`s` must be non-negative. Got s =
min
max
allclose
q D aatol
f V     <uFirst and last points does not match which is required for `bc_type='periodic'`.
array_namespace
a_validate_bc_type
bc_type
periodic
wsanest
us == 0 is interpolation only
wka_periodic_knots
a_not_a_knot
a_validate_inputs
xb
xe
T aparametric
periodic
utoo many values to unpack (expected 7)
a_generate_knots_impl
T axp
generate_knots
aTOL
size
l u`nest` too small: nest =
u < 2*(k+1) =
wmazeros
per
wta_get_residuals
utoo many values to unpack (expected 2)
Z
wnaxp
fp
T wwaperiodic
nplus
add_knot
residuals
f
?wiares
empty
jj
prodd
wjamatr
array
int64
T adtype
u != 1.
uF: expected y.ndim == 2, got y.ndim =
u instead.
disc
utoo many values to unpack (expected 3)
uInternal error: R.shape[1] =
u != k+1 =
aYY
:nnnaAA
arange
offset
nc
wbaqr_reduce
T astartrow
fpback
aBSpline
spl
a_lsq_solve_qr_for_root_rati_periodic
utoo many values to unpack (expected 8)
init_augmented_matrices
aG1_
aG2_
aH1_
aH2_
aZ_
offset_
dtype
qr_reduce_augmented_matrices
fpbacp
T :nq n:nnnainf
update
f       ?f       ?f{  G z ?T l
paMAXIT
wpwfT l
taich3
f3
con4
p1
con9
con1
ich1
f1
p3
T l Fafprati
T l Faier
warnings
warn
aRuntimeWarning
D astacklevel
l aBunch
converged
it
T aconverged
root
iterations
ier
uEither supply `t` or `nest`.
fpcheck
T :nnnl
tc
wFT wkwswwwRwYaFperiodic
aA1
aA2
wZT wkwswwwRwYaA1
aA2
wZaroot_rati
tck
axis
extrapolate
construct_fast
T aaxis
extrapolate
us==0 is for interpolation only
make_interp_spline
T wkabc_type
a_make_splrep_impl
wcastack
D aaxis
l T :l nn:nnnacumulative_sum
sqrt
concat_1d
wuwTT wkaaxis
T aperiodic
xp
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy._lib._array_api
T aarray_namespace
concat_1d
xp_capabilities
xp_capabilities
a_bsplines
T a_not_a_knot
make_interp_spline
aBSpline
fpcheck
a_lsq_solve_qr
a_lsq_solve_qr_for_root_rati_periodic
a_periodic_knots
T a_dierckx
f    MbP?l T FT tFtT acpu_only
jax_jit
allow_dask_compute
D wwaxb
xe
wkwsanest
bc_type
nnnl l
