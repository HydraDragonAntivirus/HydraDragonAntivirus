# Reconstructed from integrated Nuitka blob
# Module: uscipy.interpolate._bsplines

a__qualname__
a__class_getitem__
T tl
uBSpline.__init__
uBSpline.construct_fast
tck
uBSpline.tck
uBSpline.t
setter
uBSpline.c
T tabasis_element
uBSpline.basis_element
uBSpline.design_matrix
T l
na__call__
uBSpline.__call__
uBSpline._ensure_c_contiguous
T l aderivative
uBSpline.derivative
antiderivative
uBSpline.antiderivative
T naintegrate
uBSpline.integrate
T unot-a-knot
from_power_basis
uBSpline.from_power_basis
insert_knot
uBSpline.insert_knot
T l
T tFtT acpu_only
jax_jit
allow_dask_compute
T l nnl
tamake_interp_spline
T l nl
tD amethod
qr
make_lsq_spline
a_lsq_solve_qr_for_root_rati_periodic
D aaxis
l
make_smoothing_spline
fpcheck
uscipy\interpolate\_bsplines.py
T a.0
w_T a.0
wiwku<module scipy.interpolate._bsplines>
T a__class__
T aself
wxanu
extrapolate
x_shape
x_ndim
wnais_complex
cc
out
wlT	aself
wtwcwkaextrapolate
axis
wnadt
a__class__
T wxacheck_finite
dtyp
T wxwkT wxwnares
wiapp
wkTwXawE
wywwacompute_banded_symmetric_XT_W_Y
compute_b_inv
a_gcv
wnaXtWX
aXtE
gcv_est
wiaest
T aderiv
target_shape
T wjwkwywdwtacomb
res
wiT wjwkwtwyT aself
T alam
wXaXtWX
wE
aXtE
wywnwcares
tmp
wiwjanumer
lhs
b_banded
tr
denom
compute_b_inv
T acompute_b_inv
T wtwkaxval
ab
kl
ku
deriv_ords
offset
left
row
nu
wrk
waaclmn
T axval
wtwcwkaperiodic
interval
tt
newshape
cc
wiafac
wnank
n2k
wTT wxwywtwkwwaperiodic
y_w
wAaoffset
nc
wcaresiduals
fp
wRaH1
aH2
aA1
aA2
wZw_T wxwywtwkwway_w
wRaH1
aH2
offset
nc
aA1
aA2
wZwpw_wcaresiduals
T wxwywtwkwnamatr
wiabb
xval
left
wbwcT wxwywtwkaaxis
xp
wnaextradim
y_new
wcwiant
kul
ab
ur
all
wAacc
T wxwkak2
wtT wxwkaxc
wnadx
wtwiT aderiv
ords
vals
weamsg
T wAaur
all
wbwkak_mod
abs
wnwUaVT
wZwHwywcT aself
nu
wcwtaxp
ct
tck
extrapolate
T acls
wtaextrapolate
xp
wkwcT aself
wcT wAafind_b_inv_elem
wUwiwDwnwBwjT wXwwwYaW_Y
wiwnares
wjT acls
wtwcwkaextrapolate
axis
self
T aself
nu
wcwtaxp
ct
tck
Tacls
wxwtwkaextrapolate
wnannz
int_dtype
data
offsets
w_aindices
indptr
T wiwjwUwDwBarng
rng_sum
wkadiag
ind
wnT wnT wxwtwkaperiodic
wmwnank1
mesg
per
m1
shift
wjatj
tl
found
wiaidx
xi
wlank3
T acls
pp
bc_type
aCubicSpline
wxacoef
wkwnwtanod
wcwmwiwjT aself
wxwmatt
cc
w_T aself
wawbaextrapolate
sign
wnaintegral
wcact
ta
ca
ka
ts
te
period
interval
n_periods
left
wxaout
T wxwywkwtabc_type
axis
check_finite
deriv_l
deriv_r
weaxp
wcaderiv_l_ords
deriv_l_vals
nleft
deriv_r_ords
deriv_r_vals
nright
wnant
kl
ku
ab
extradim
rhs
gbsv
lu
piv
info
T wxwywtwkwwaaxis
check_finite
method
xp
wnawas_complex
yy
extradim
lower
ab
rhs
cho_decomp
wmwcw_T wxwywwalam
axis
xp
wtwnay_shape1
aX_bspl
wXwiawE
wjwcac0
c1
cm0
cm1
c_
T aself
wt.scipy.interpolate._cubic
|
asarray
utoo many values to unpack (expected 2)
isdtype
dtype
ucomplex floating
u`x` must contain real values.
astype
float64
complex128
shape
uThe shapes of `y` and `dydx` must be identical.
D acopy
Fandim
l u`x` must be 1-dimensional.
l
l u`x` must contain at least 2 elements.
uThe length of `y` along `axis`=

u doesn't match the length of `x`
all
isfinite
u`x` must contain only finite values.
u`y` must contain only finite values.
u`dydx` must contain only finite values.
diff
any
u`x` must be strictly increasing sequence.
moveaxis
dydx
array_namespace
prepare_input
T axp
utoo many values to unpack (expected 5)
reshape
T l D aaxis
l
T :nq nQ
T :l nnQ
stack
a__class__
a__init__
T aextrapolate
axis
u`PchipInterpolator` only works with real values for `y`. If you are trying to use the real components of the passed array, use `np.real` on the array before passing to `PchipInterpolator`.
a_find_derivatives
T aaxis
extrapolate
sign
abs
f
@Z
T :nnnn:l nn:nq nwyazeros_like
np
errstate
T aignore
ignore
T adivide
invalid
a__enter__
a__exit__
T nnn:l q nf
?awhmean
aPchipInterpolator
a_edge_case
q q T aaxis
a_isscalar
derivative
wPwxP amakima
akima
u`method`=
u is unsupported.
u`Akima1DInterpolator` only works with real values for `y`. If you are trying to use the real components of the passed array, use `np.real` on the array before passing to `Akima1DInterpolator`.
empty
l T :nnnT nT :l q nQ
f
@T l Q
T l Q
T l Q
T l
Q
T q Q
T q Q
T q Q
T q Q
f
?T :l nnQ
T :nq nQ
makima
T :l nnQ
T :nq nQ
xp_size
max
inf
nonzero
f  &  . >wtuExtending a 1-D Akima interpolator is not yet implemented
uThis method does not make sense for an Akima interpolator.
np_compat
a_validate_bc
periodic
size
T unot-a-knot
periodic
unot-a-knot
zeros
T T l pT l T adtype
T l
pT l
l T l l
T l pT l l T l l T l pasolve
D aoverwrite_a
overwrite_b
check_finite
tpFasum
T l
broadcast_to
T l :l q nT l
:l nnT q :nq nT :nnn:l
q nq T :nnn:nq nasolve_banded
D aoverwrite_ab
overwrite_b
check_finite
Fpp:nq nf
T l q T q q D aoverwrite_ab
overwrite_b
check_finite
tpFwsutoo many values to unpack (expected 3)
allclose
D artol
atol
f V     <f V     <uThe first and last `y` point along axis
u must be identical (within machine precision) when bc_type='periodic'.
u`bc_type` must contain 2 elements to specify start and end conditions.
u'periodic' `bc_type` is defined for both curve ends and cannot be used with other boundary conditions.
bc_type
clamped
validated_bc
expected_deriv_shape
natural
ubc_type=
u is not allowed.
uA specified derivative value must be given in the form (order, value).
uThe specified derivative order must be 1 or 2.
u`deriv_value` shape
u is not the expected one
w.aissubdtype
complexfloating
T Ocomplex
FT acopy
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
aLiteral
numpy
uscipy.linalg
T asolve
solve_banded
uscipy._lib._array_api
T aarray_namespace
xp_size
xp_capabilities
xp_capabilities
uscipy._lib.array_api_compat
T anumpy
T aPPoly
aPPoly
a_polyint
T a_isscalar
L aCubicHermiteSpline
aPchipInterpolator
pchip_interpolate
aAkima1DInterpolator
aCubicSpline
a__all__
T nna__prepare__
aCubicHermiteSpline
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
T tFL T udask.array
uhttps://github.com/data-apis/array-api-extra/issues/488
T acpu_only
jax_jit
skip_backends
