# Reconstructed from integrated Nuitka blob
# Module: nnuscipy.interpolate._fitpack_repro

a__qualname__
T nD wRwYnna__init__
uF.__init__
a__call__
uF.__call__
D wRwYaA1
aA2
wZnnnnnuFperiodic.__init__
uFperiodic.__call__
uBunch.__init__
uerror. a theoretically impossible result was found during
the iteration process for finding a smoothing spline with
fp = s. probably causes : s too small.
a_iermesg1
uthe weighted sum of squared residuals is becoming NaN
uthere is an approximation returned but the corresponding
weighted sum of squared residuals does not satisfy the
condition abs(fp-s)/s < tol.
uerror. the maximal number of iterations maxit (set to 20
by the program) allowed for finding a smoothing spline
with fp=s has been reached. probably causes : s too small
there is an approximation returned but the corresponding
weighted sum of squared residuals does not satisfy the
condition abs(fp-s)/s < tol.
D wwaxb
xe
wkwswtanest
bc_type
nnnl l
nnnamake_splrep
D	wwwuaub
ue
wkwswtanest
bc_type
nnnnl l
nnnamake_splprep
uscipy\interpolate\_fitpack_repro.py
u<module scipy.interpolate._fitpack_repro>
T
self
wpaAB
offset
nc
aQY
wcw_afp
spl
T aself
wpaG1
aG2
aH1
aH2
wZapinv
wcw_afp
spl
T aself
kwargs
T aself
wxwywtwkwswwwRwYwbab_offset
b_nc
w_anc
nz
wzaAA
T aself
wxwywtwkwswwwRwYaA1
aA2
wZwbab_offset
b_nc
w_aG1
aG2
aH1
aH2
offset
T wxwywwaxb
xe
wkwsanest
periodic
xp
acc
wmanmin
nmax
per
wtwiw_afp
fpold
nplus
wnaiter
wjaresiduals
fpms
delta
npl1
T	wxwywtwkwwaperiodic
w_afp
residuals
T"wxwywwaxb
xe
wkwswtanest
periodic
xp
acc
wmagen
w_wcwRaA1
aA2
wZwYwpanc
fp
fpinf
fp0
per
tc
wiabracket
wfaaxis
extrap
spl
T abc_type
T	wxwywwwkwsaxb
xe
parametric
periodic
T wxwtwkaresiduals
new_knot
idx_t
t_new
T wtwkwnadelta
nrint
matr
jj
wjaii
wiaoffset
nc
T	ap1
f1
p2
f2
p3
f3
h1
h2
h3
T wxwywwaxb
xe
wkwsanest
bc_type
xp
periodic
wtT wxwwwuaub
ue
wkwswtanest
bc_type
periodic
xp
dp
spl
cc
spl1
Twxwywwaxb
xe
wkwswtanest
bc_type
xp
periodic
spl
T wtwiwjwkares
wsT wfap0
bracket
acc
con1
con9
con4
ich1
ich3
p1
f1
p3
f3
wpait
p2
f2
ier
converged
.scipy.interpolate._interpolate
"
poly1d
T Z
pt
f
?wpaerr_mesg
shape
:nnq utoo many values to unpack (expected 2)
l asize
np
ones
dtype
arr_from
ravel

u argument must be able to broadcast up to shape
u but had shape
extrapolate
a_Interpolator1D
a__init__
T aaxis
bounds_error
copy
copy_if_needed
T azero
slinear
quadratic
cubic
D azero
slinear
quadratic
cubic
l
l l l aspline
T alinear
nearest
unearest-up
previous
anext
u is unsupported: Use fitpack routines for other types.
array
T acopy
argsort
D akind
mergesort
take
ndim
uthe x array must have exactly one dimension.
l
uthe y array must have at least one dimension.
type
inexact
astype
float64
wyaaxis
a_reshape_yi
a_y
wxa_kind
nearest
left
a_side
f
@ax_bds
:l nn:nq na_call_nearest
a_call
unearest-up
right
previous
a_ind
nextafter
inf
a_x_shift
a_call_previousnext
a_do_extrapolate
a_check_and_update_bounds_error_for_extrapolation
nan
q anext
T Oint
a_call_linear_np
a_call_linear
order
isnan
any
u`x` array is all-nan
linspace
nanmin
nanmax
ones_like
make_interp_spline
T wkacheck_finite
a_spline
a_call_nan_spline
a_call_spline
ux and y arrays must have at least
u entries
fill_value
a_fill_value_orig
a_extrapolate
T l aasarray
;l
l l a_check_broadcast_up_to
below_above
broadcast_shape
T ufill_value (below)
ufill_value (above)
l a_fill_value_below
a_fill_value_above
self
uCannot extrapolate and raise at the same time.
interp
searchsorted
clip
T :nnnnT aside
intp
a_check_bounds
argmax
uA value (
u) in x_new is below the interpolation range's minimum value (
u).
u) in x_new is above the interpolation range's maximum value (
array_namespace
a_asarray
a_c
ascontiguousarray
T adtype
a_x
periodic
uCoefficients array must be at least 2-dimensional.
uaxis=
u must be between 0 and
moveaxis
ux must be 1-dimensional
uat least 2 breakpoints are needed
uc must have at least 2 dimensions
upolynomial must be at least of order 0
unumber of coefficients != len(x)-1
diff
all
u`x` must be strictly increasing or decreasing.
a_get_dtype
issubdtype
complexfloating
complex128
a__new__
flags
c_contiguous
uinvalid dimensions for c
uinvalid dimensions for x
uShapes of x
u and c
u are incompatible
:l nnuShapes of c
u and self._c
u`x` is not sorted.
u`x` is in the different order than `self.x`.
append
prepend
u`x` is neither on the left or on the right from `self.x`.
max
zeros
r_
c2
empty
prod
a_ensure_c_contiguous
a_evaluate
reshape
transpose
a_ppoly
evaluate
antiderivative
:nnnaspec
poch
arange
T :nnnT naconstruct_fast
derivative
fix_continuity
integrate
T aout
fill
T l
empty_like
range_int
uRoot finding is only for real-valued polynomials
real_roots
D adtype
Oobject
r2
solve
aBSpline
a_t
wkutoo many values to unpack (expected 3)
a_fitpack_py
splev
wtwcT ader
gamma
cvals
aBPoly
u.from_bernstein_basis only accepts BPoly instances. Got
u instead.
zeros_like
comb
bp
waafactor
rest
evaluate_bernstein
T n:nnnD aaxis
l
cumsum
T :l nnQ
T :nnn:l nna_raise_degree
a_PPolyBase
extend
aPPoly
u.from_power_basis only accepts PPoly instances. Got
pp
uxi and yi need to have the same length
:nl nux coordinates are not in increasing order
uUsing a 1-D array for y? Please .reshape(-1, 1).
integer
uOrders must be positive.
yi
orders
min
uPoint
u has
u derivatives, point
u derivatives, but order
u requested
u`order` input incompatible with length y1 or y2.
a_construct_from_derivatives
y1
n1
y2
n2
wbaswapaxes
T l
l u<genexpr>
uBPoly.from_derivatives.<locals>.<genexpr>
uShapes of ya
u and yb
wnaxb
xa
wqwdaout
wfux arrays must all be 1-dimensional
ux arrays must all contain at least 2 points
uc must have at least 2*len(x) dimensions
ux-coordinates are not in increasing order
ux and c do not agree on the number of intervals
uNdPPoly.__init__.<locals>.<genexpr>
a_ndim_coords_from_arrays
intc
uinvalid number of derivative orders nu
evaluate_nd
nu
a_antiderivative_inplace
a_derivative_inplace
T aextrapolate
a__len__
uRange not a sequence of correct length
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
L ainterp1d
interp2d
lagrange
aPPoly
aBPoly
aNdPPoly
a__all__
math
T aprod
aGenericAlias
numpy
T aarray
asarray
intp
poly1d
searchsorted
uscipy.special
special
uscipy._lib._util
T acopy_if_needed
T acomb
uscipy._lib._array_api
T aarray_namespace
xp_capabilities
xp_capabilities
T a_fitpack_py
a_polyint
T a_Interpolator1D
T a_ppoly
a_interpnd
T a_ndim_coords_from_arrays
a_bsplines
T amake_interp_spline
aBSpline
lagrange
u`interp2d` has been removed in SciPy 1.14.0.
For legacy code, nearly bug-for-bug compatible replacements are
`RectBivariateSpline` on regular grids, and `bisplrep`/`bisplev` for
scattered 2D data.
In new code, for regular grids use `RegularGridInterpolator` instead.
For scattered data, prefer `LinearNDInterpolator` or
`CloughTocher2DInterpolator`.
For more details see
https://scipy.github.io/devdocs/tutorial/interpolate/interp_transition_guide.html
