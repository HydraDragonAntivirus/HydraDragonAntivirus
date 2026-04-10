# Reconstructed from integrated Nuitka blob
# Module: uscipy.integrate._quad_vec

a__qualname__
a__init__
uLRUDict.__init__
uLRUDict.__setitem__
uLRUDict.update
a__orig_bases__
uSemiInfiniteFunc.__init__
uSemiInfiniteFunc.get_t
a__call__
uSemiInfiniteFunc.__call__
uDoubleInfiniteFunc.__init__
uDoubleInfiniteFunc.get_t
uDoubleInfiniteFunc.__call__
u_Bunch.__init__
a__repr__
u_Bunch.__repr__
T tT anp_only
T	f  N  ~h f: 0  yE>w2f
Al Nl nnFD aargs
T
l	l l uscipy\integrate\_quad_vec.py
T a.0
wkaself
T a.0
xp
f2
u<module scipy.integrate._quad_vec>
T a__class__
T aself
wtwxwfT aself
func
T aself
max_size
T aself
func
start
infty
T aself
kwargs
T aself
key_value_pairs
T aself
key
value
existing_key
a__class__
T aobj
T wxT wawbwfanorm_func
wxwwwvafv
wcwhas_k
s_k_abs
wiaff
vv
s_g
s_k_dabs
y0
err
dabs
eps
round_err
T wawbwfanorm_func
wxwwwvT ax1
x2
wfanorm_func
x3
f1
f2
f3
s2
round_err
s1
err
T aargs
interval
wfanorm_func
a_quadrature
old_err
wawbaold_int
wcas1
err1
round1
dneval
s2
err2
round2
w_adint
derr
dround_err
subintervals
T aself
wxwsT aself
wxwzT@wfwawbaepsabs
epsrel
norm
cache_size
limit
workers
points
quadrature
full_output
args
kwargs
f2
res
sgn
norm_funcs
norm_func
parallel_count
min_intervals
a_quadrature
weainitial_intervals
prev
wpaglobal_integral
global_error
rounding_error
interval_cache
intervals
neval
x1
x2
ig
err
rnd
cache_count
aCONVERGED
aNOT_CONVERGED
aROUNDING_ERROR
aNOT_A_NUMBER
status_msg
mapwrapper
ier
tol
to_process
err_sum
wjainterval
neg_old_err
old_int
parts
dint
derr
dround_err
subint
dneval
wxares_arr
dummy
integrals
errors
info
T aself
other
.scipy.integrate._quadpack_py
l
T Z
Z
neval
last
alist
np
full
nan
float64
T adtype
blist
rlist
zeros
elist
iord
int32
JZ
Z
real
imag
Z
min
max
utoo many values to unpack (expected 3)
imfunc
uquad.<locals>.imfunc
refunc
uquad.<locals>.refunc
quad
D acomplex_func
FJZ
f
?l :l nna_quad
warnings
warn
uBreak points cannot be specified when using weighted integrand.
Continuing, ignoring specified points.
aIntegrationWarning
D astacklevel
l a_quad_weight
:l nnq :nq nlPuA Python error occurred possibly while calling the function.
uThe maximum number of subdivisions (
limit

u) has been achieved.
If increasing the limit yields no improvement it is advised to analyze
the integrand in order to determine the difficulties.  If the position of a
local difficulty can be determined (singularity, discontinuity) one will
probably gain from splitting up the interval and calling the integrator
on the subranges.  Perhaps a special-purpose integrator should be used.
l uThe occurrence of roundoff error is detected, which prevents
the requested tolerance from being achieved.  The error may be
underestimated.
l uExtremely bad integrand behavior occurs at some points of the
integration interval.
l uThe algorithm does not converge.  Roundoff error is detected
in the extrapolation table.  It is assumed that the requested tolerance
cannot be achieved, and that the returned result (if full_output = 1) is
the best which can be obtained.
l uThe integral is probably divergent, or slowly convergent.
l uThe input is invalid.
l uAbnormal termination of the routine.  The estimates for result
nd error are less reliable.  It is assumed that the requested accuracy
has not been achieved.
unknown
uUnknown error.
T acos
sin
wbainf
wauThe maximum number of cycles allowed has been achieved., e.e.
of subintervals (a+(k-1)c, a+kc) where c = (2*int(abs(omega)+1))
*pi/abs(omega), for k = 1, 2, ..., lst.  One can allow more cycles by increasing the value of limlst.  Look at info['ierlst'] with full_output=1.
uThe extrapolation table constructed for convergence acceleration
of the series formed by the integral contributions over the cycles,
does not converge to within the requested accuracy.  Look at
info['ierlst'] with full_output=1.
uBad integrand behavior occurs within one or more of the cycles.
Location and type of the difficulty involved can be determined from
the vector info['ierlist'] obtained with full_output=1.
D l l l l l uThe maximum number of subdivisions (= limit) has been
chieved on this cycle.
uThe occurrence of roundoff error is detected and prevents
the tolerance imposed on this cycle from being achieved.
uExtremely bad integrand behavior occurs at some points of
this cycle.
uThe integral over this cycle does not converge (to within the required accuracy) due to roundoff in the extrapolation procedure invoked on this cycle.  It is assumed that the result on this interval is the best which can be obtained.
uThe integral over this cycle is probably divergent or slowly convergent.
T l l l l l l afull_output
explain
epsabs
epsrel
l2afloat_info
epsilon
f `P    :uIf 'epsabs'<=0, 'epsrel' must be greater than both 5e-29 and 50*(machine epsilon).
T asin
cos
uSine or cosine weighted integrals with infinite domain must have 'epsabs'>0.
uInvalid 'limit' argument. There must be at least one subinterval
uAll break points in 'points' must lie within the integration limits.
uNumber of break points (
wdu) must be less than subinterval limit (
w)uChebyshev moment limit maxp1 must be >=1.
uCycle limit limlst must be >=3.
startswith
T aalg
uwvar parameters (alpha, beta) must both be >= -1.
uIntegration limits a, b must satistfy a<b.
cauchy
uParameter 'wvar' must not equal integration limits 'a' or 'b'.
func
uInfinity comparisons don't work for you.
a_quadpack
a_qagse
a_qagie
bound
uInfinity inputs cannot be used with break points.
unique
concatenate
a_qagpe
T acos
sin
alg
ualg-loga
ualg-logb
ualg-log
cauchy
u not a recognized weighting function.
D acos
sin
alg
ualg-loga
ualg-logb
ualg-log
l l l l l l a_qawoe
a_qawfe
cos
thefunc
u_quad_weight.<locals>.thefunc
uCannot integrate with this weight from -Inf to +Inf.
uCannot integrate with this weight over an infinite interval.
a_qawse
a_qawce
temp_ranges
udblquad.<locals>.temp_ranges
nquad
T aargs
opts
callable
gfun
hfun
ranges0
utplquad.<locals>.ranges0
ranges1
utplquad.<locals>.ranges1
qfun
rfun
a_RangeFunc
L D
a_OptFunc
a_NQuad
integrate
range_
opt
abserr
ranges
opts
maxdepth
D aneval
l
out_dict
depth
uunexpected kwargs
utoo many values to unpack (expected 2)
points
partial
T adepth
args
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
sys
T a_quadpack
numpy
uscipy._lib._array_api
T axp_capabilities
xp_capabilities
L aquad
dblquad
tplquad
nquad
aIntegrationWarning
a__all__
aUserWarning
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
