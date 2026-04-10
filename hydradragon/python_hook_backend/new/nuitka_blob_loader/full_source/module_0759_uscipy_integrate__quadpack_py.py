# Reconstructed from integrated Nuitka blob
# Module: uscipy.integrate._quadpack_py

a__qualname__
a__orig_bases__
T tT anp_only
T T
l
f "  \ O>f "  \ O>l2nnnnl2pFT T
f "  \ O>f "  \ O>adblquad
tplquad
T nnFa__init__
u_RangeFunc.__init__
a__call__
u_RangeFunc.__call__
u_OptFunc.__init__
u_OptFunc.__call__
u_NQuad.__init__
u_NQuad.integrate
uscipy\integrate\_quadpack_py.py
u<module scipy.integrate._quadpack_py>
T aself
args
T aself
func
ranges
opts
full_output
T aself
opt
T aself
range_
T afunc
wawbaargs
full_output
epsabs
epsrel
limit
points
infbounds
bound
the_points
T afunc
wawbaargs
full_output
epsabs
epsrel
limlst
limit
maxp1
weight
wvar
wopts
strdict
integr
momcom
chebcom
thefunc
message
T	afunc
wawbagfun
hfun
args
epsabs
epsrel
temp_ranges
T wxaargs
func
T afunc
T aself
args
kwargs
depth
ind
fn_range
low
high
fn_opt
opt
wfaquad_r
value
abserr
infodict
T afunc
ranges
args
opts
full_output
depth
T afunc
wawbaargs
full_output
epsabs
epsrel
limit
points
weight
wvar
wopts
maxp1
limlst
complex_func
infodict
flip
imfunc
refunc
re_retval
im_retval
integral
error_estimate
retval
msgexp
msg
ier
msgs
explain
T aargs
qfun
rfun
T aqfun
rfun
T aargs
gfun
hfun
T agfun
hfun
T wxamyargs
wyafunc
Tafunc
wawbagfun
hfun
qfun
rfun
args
epsabs
epsrel
ranges0
ranges1
ranges
.scipy.integrate._quadrature
2 aarray_namespace
a_asarray
T axp
subok
xp_result_type
T aforce_floating
xp
ndim
:nnn:l nn:nq nl abroadcast_to
shape
sum
f
@T aaxis
dtype
asarray
a_cached_roots_legendre
cache
roots_legendre
utoo many values to unpack (expected 2)
np
real
isinf
uGaussian quadrature is only available for finite limits.
D aaxis
q l
uAt least one point is required along `axis`.
diff
q areshape
uIf given, shape of x must be 1-D or the same as y.
T aaxis
uIf given, length of x along axis must be the same as y.
tupleset
T :nnnacumulative_sum
wdu`initial` must be `None` or `0`.
isscalar
u`initial` parameter should be a scalar.
concat
full
dtype
T adtype
l f
@f
@aastype
T Ofloat
FT acopy
true_divide
zeros_like
T aout
where
f
@f
?wxZ
q f
?a_basic_simpson
l q afloat64
:q q l :q nl asqueeze
l asaveshape
flip
empty
result_type
T Q
:nnl T Q
:nq l T Q
:l nl T Q
q T Q
:nq nT Q
:nq nT Q
:l q nT Q
:l nnl l T Q
:l nnaxp_promote
xp_swapaxes
u`axis=

u` is not valid for `y` with `y.ndim=
u`.
cumulative_trapezoid
T adx
axis
initial
uIf given, shape of `x` must be the same as `y` or 1-D with the same length as `y` along `axis`.
any
uInput x must be strictly increasing.
a_cumulatively_sum_simpson_integrals
a_cumulative_simpson_unequal_intervals
uIf provided, `dx` must either be a scalar or have the same shape as `y` but with only 1 point along `axis`.
a_cumulative_simpson_equal_intervals
uIf provided, `initial` must either be a scalar or have the same shape as `y` but with only 1 point along `axis`.
wnwkuNumber of samples must be one plus a non-negative power of 2.
T l
pastart
slice_R
axis
step
wRwhaxp
wiaprint
T u*** Printing table only supported for integrals of a single data set.
T ETypeError
EIndexError
l w%w.wfT uRichardson Extrapolation Table for Romberg Integration
u======================================================
w
pT asep
end
formstr
D aend
w T u======================================================
arange
all
wNa_builtincoeffs
utoo many values to unpack (expected 5)
array
D adtype
Ofloat
rn
uThe sample positions must start at 0 and end at N
newaxis
linalg
inv
;l
l l aCinv
dot
wC:nnl T :nnn:nnl amath
log
gammaln
exp
qmc_quad
qmc
scipy
T astats
stats
callable
u`func` must be callable.
T abroadcast
force_floating
xp
xpx
atleast_nd
T andim
xp
broadcast_arrays
xp_copy
u`func` must evaluate the integrand at points within the integration range; e.g. `func( (a + b) / 2)` must return the integrand at the centroid of the integration volume.
stack
wTais_numpy
uException encountered when attempting vectorized call to `func`:
u. When using array library
u, `func` must accept two-dimensional array `x` with shape `(a.shape[0], n_points)` and return an array of the integrand value at each of the `n_points`.
u. For better performance, `func` should accept two-dimensional array `x` with shape `(len(a), n_points)` and return an array of the integrand value at each of the `n_points`.
warnings
warn
D astacklevel
l avfunc
u_qmc_quad_iv.<locals>.vfunc
u`n_points` must be an integer.
u`n_estimates` must be an integer.
aHalton
aQMCEngine
u`qrng` must be an instance of scipy.stats.qmc.QMCEngine.
u`qrng` must be initialized with dimensionality equal to the number of variables in `a`, i.e., `qrng.random().shape[-1]` must equal `a.shape[0]`.
rng_seed
a_qmc
check_random_state
P Ftu`log` must be boolean (`True` or `False`).
apply_along_axis
func
T aaxis
arr
a_qmc_quad_iv
utoo many values to unpack (expected 9)
T Fasum_product
uqmc_quad.<locals>.sum_product
mean
uqmc_quad.<locals>.mean
T nl
Fastd
uqmc_quad.<locals>.std
T nnFasem
uqmc_quad.<locals>.sem
T uA lower limit was equal to an upper limit, so the value of the integral is zero by definition.
l T astacklevel
inf
aQMCQuadResult
T Z
count_nonzero
at
set
prod
zeros
a_rng_spawn
rng
qrng
random
n_points
wawbaestimates
dA
seed
a_init_quad
T wmalog
pi
JZ
f
?alogsumexp
n_estimates
D aaxis
l
T acorrection
T addof
log
sqrt
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
collections
T anamedtuple
namedtuple
ucollections.abc
T aCallable
aCallable
uscipy.special
T aroots_legendre
T agammaln
logsumexp
uscipy._lib._util
T a_rng_spawn
uscipy._lib._array_api
T a_asarray
array_namespace
xp_result_type
xp_copy
xp_capabilities
xp_promote
xp_swapaxes
is_numpy
xp_capabilities
uscipy._lib.array_api_extra
a_lib
array_api_extra
L afixed_quad
romb
trapezoid
simpson
cumulative_trapezoid
newton_cotes
qmc_quad
cumulative_simpson
a__all__
T L T ujax.numpy
uJAX arrays do not support item assignment
T askip_backends
T nf
?q atrapezoid
T tT anp_only
T T
l afixed_quad
T nf
?q nT nD adx
axis
f
?q asimpson
T l L T ujax.numpy
uitem assignment
T aallow_dask_compute
skip_backends
D wxadx
axis
initial
nf
?q nacumulative_simpson
T f
?q Faromb
D l l l l l l l l l	l
l l ll T l l L l pq l T l l L l l l q lZT l l L l l pl q lPT l l-L l l l l l q l  T l l  L l lKl2plKl q  l ^T l l  L l)l  l l  l l  l)q	l
T l l   L l  l  l
l  l  l
l  l  q ?l   T l l nL	l  l .q  l Rq #l Rq  l .l  q  l   T l	l   L
l  l zl  l   l -l -l   l  l zl  q $l   T l l   L l }l   q   l   q   l   q   l   q   l   l }q  )l   MT l l   )L l    l    q    l    q    l    l    q    l    q    l    l    G     $g n     T l l    Ll  Sl    q    l    q    l   )q   )l   )q    l    q    l    l  Sq  l  5T lg        L g       g       G       g H     G F     g `     G     MG     Mg `     G F     g H     G       g       g       G       g        T l g       L l   +l     q     g       G     Wg       G       g 	   bG       g       G     Wg       q     l     l   +G       g        T l
newton_cotes
integral
standard_error
T L T udask.array
uDask arrays are confused about their shape
FT askip_backends
jax_jit
D an_estimates
n_points
qrng
log
l l  nFuscipy\integrate\_quadrature.py
u<module scipy.integrate._quadrature>
T wyastart
stop
wxadx
axis
nd
step
slice_all
slice0
slice1
slice2
result
whasl0
sl1
h0
h1
hsum
hprod
h0divh1
tmp
T wnT wyadx
wdaf1
f2
f3
T wyadx
x21
x32
f1
f2
f3
x31
x21_x31
x21_x32
x21x21_x31x32
coeff1
coeff2
coeff3
T	wyadx
integration_func
xp
sub_integrals_h1
sub_integrals_h2
shape
sub_integrals
res
T afunc
wawban_points
n_estimates
qrng
log
xp
stats
message
dim
weavfunc
n_points_int
n_estimates_int
rng_seed
rng
T wywxadx
axis
initial
xp
original_y
original_shape
weamessage
res
final_dx_shape
alt_input_dx_shape
alt_initial_input_shape
T wywxadx
axis
initial
xp
wdashape
nd
slice1
slice2
res
T afunc
wawbaargs
wnwxwwwyT aestimates
log
n_estimates
xp
T an_estimates
xp
T arn
equal
wNana
da
vi
nb
db
an
yi
ti
nvec
wCaCinv
wiavec
ai
aBN
power
p1
fac
T afunc
wawban_estimates
n_points
qrng
log
xp
args
rng
stats
sum_product
mean
std
sem
message
zero
i_swap
sign
a_iswap
b_iswap
wAadA
estimates
rngs
wiasample
wxaintegrands
integral
standard_error
T wyadx
axis
show
xp
nd
aNsamps
aNinterv
wnwkwRaslice_all
slice0
slicem1
whaslice_R
start
stop
step
wiwjaprev
precis
width
formstr
title
T aestimates
wmwsalog
mean
std
n_estimates
T amean
n_estimates
std
T wywxadx
axis
nd
wNalast_dx
returnshape
shapex
saveshape
val
result
slice_all
slice1
slice2
slice3
whahm2
hm1
diffs
num
den
alpha
beta
eta
T	aestimates
wmaddof
log
temp
diff
mean
xp
n_estimates
T amean
n_estimates
xp
T aintegrands
dA
log
xp
T axp
T wywxadx
axis
xp
result_dtype
nd
slice1
slice2
wdaslice3
ret
T wtwiavalue
wlT wxafunc
T afunc
.scipy.integrate._rules._base
f
estimate
l
a_split_subregion
utoo many values to unpack (expected 2)
refined_est
self
wfaargs
xp
abs
nodes_and_weights
array_namespace
a_apply_fixed_rule
higher
lower
lower_nodes_and_weights
concat
D aaxis
l
aNestedFixedRule
ubase rules for product need to be instance ofNestedFixedRule
base_rules
a_cartesian_product
prod
l D aaxis
q ameshgrid
D aindexing
ij
reshape
stack
q wawbasplit_at
l ashape
dtype
astype
ndim
T :nnnnaorig_nodes
xp_size
urule and function are of incompatible dimension, nodes havendim

u, while limit of integration has ndima_ndim=
u, b_ndim=
f
?T adtype
T q asum
T aaxis
dtype
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uscipy._lib._array_api
T aarray_namespace
xp_size
cached_property
