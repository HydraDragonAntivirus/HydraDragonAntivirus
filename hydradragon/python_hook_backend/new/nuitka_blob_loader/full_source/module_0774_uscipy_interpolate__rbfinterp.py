# Reconstructed from integrated Nuitka blob
# Module: uscipy.interpolate._rbfinterp

a__qualname__
a__class_getitem__
T nZ
thin_plate_spline
nna__init__
uRBFInterpolator.__init__
a__setstate__
uRBFInterpolator.__setstate__
a__getstate__
uRBFInterpolator.__getstate__
T l  =uRBFInterpolator._chunk_evaluator
a__call__
uRBFInterpolator.__call__
uscipy\interpolate\_rbfinterp.py
u<module scipy.interpolate._rbfinterp>
T a__class__
T aself
wxanx
ndim
memory_budget
out
a_build_and_solve_system
w_ayindices
inv
xindices
wiwjaxidx
yidx
xnbr
ynbr
dnbr
snbr
shift
scale
coeffs
T aself
tpl
tpl2
T aself
wywdaneighbors
smoothing
kernel
epsilon
degree
xp
a_backend
any
ndim
d_dtype
d_shape
min_degree
nobs
powers
shift
scale
coeffs
T aself
state
tpl1
tpl2
T aself
wxwyashift
scale
coeffs
memory_budget
a_backend
nx
ndim
nnei
chunksize
out
wiachunk
T axp
.scipy.interpolate._rbfinterp_common
U
comb
l
ndim
l acombinations_with_replacement
count
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
itertools
T acombinations_with_replacement
math
T acomb
a_monomial_powers_impl
uscipy\interpolate\_rbfinterp_common.py
u<module scipy.interpolate._rbfinterp_common>
T andim
degree
nmonos
out
count
deg
mono
var

.scipy.interpolate._rbfinterp_np
8
a_pythran_build_evaluation_coefficients
a_pythran_polynomial_matrix
a_monomial_powers_impl
np
asarray
int64
T adtype
reshape
l
out
a_pythran_build_system
a_build_system
utoo many values to unpack (expected 4)
dgesv
D aoverwrite_a
overwrite_b
tpuThe

u-th argument had an illegal value.
uSingular matrix.
shape
polynomial_matrix
linalg
matrix_rank
uSingular matrix. The matrix of monomials evaluated at the data point coordinates does not have full column rank (
w/u).
aLinAlgError
a_build_evaluation_coefficients
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
unumpy.linalg
T aLinAlgError
uscipy.linalg.lapack
T adgesv
a_rbfinterp_common
T a_monomial_powers_impl
l a_rbfinterp_pythran
T a_build_system
a_build_evaluation_coefficients
a_polynomial_matrix
a_polynomial_matrix
a_monomial_powers
a_build_and_solve_system
compute_interpolation
uscipy\interpolate\_rbfinterp_np.py
u<module scipy.interpolate._rbfinterp_np>
T wywdasmoothing
kernel
epsilon
powers
xp
lhs
rhs
shift
scale
w_acoeffs
info
msg
nmonos
pmat
rank
T wxwyakernel
epsilon
powers
shift
scale
xp
T wywdasmoothing
kernel
epsilon
powers
xp
T andim
degree
xp
out
T
wxwyakernel
epsilon
powers
shift
scale
coeffs
xp
vec
T wxapowers
xp
.scipy.interpolate._rbfinterp_xp
X
L
a_monomial_powers_impl
asarray
shape
l
reshape
out
a_build_system
utoo many values to unpack (expected 4)
linalg
solve
uSingular matrix
polynomial_matrix
T axp
matrix_rank
uSingular matrix. The matrix of monomials evaluated at the data point coordinates does not have full column rank (

w/u).
aLinAlgError
where
l alog
l l asqrt
l f
?aexp
vector_norm
T n:nnn:nnnT :nnnn:nnnD aaxis
q aprod
aNAME_TO_FUNC
min
D aaxis
l
max
Z
kernel_matrix
concat
D aaxis
l wTazeros
diag
a_build_evaluation_coefficients
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unumpy.linalg
T aLinAlgError
a_rbfinterp_common
T a_monomial_powers_impl
a_monomial_powers
a_build_and_solve_system
linear
thin_plate_spline
cubic
quintic
multiquadric
inverse_multiquadric
inverse_quadratic
gaussian
compute_interpolation
uscipy\interpolate\_rbfinterp_xp.py
u<module scipy.interpolate._rbfinterp_xp>
T wywdasmoothing
kernel
epsilon
powers
xp
lhs
rhs
shift
scale
coeffs
msg
nmonos
pmat
rank
Twxwyakernel
epsilon
powers
shift
scale
xp
kernel_func
yeps
xeps
xhat
vec
T wywdasmoothing
kernel
epsilon
powers
xp
wswrakernel_func
mins
maxs
shift
scale
yeps
yhat
out_kernels
out_poly
lhs
rhs
T andim
degree
xp
out
T
wxwyakernel
epsilon
powers
shift
scale
coeffs
xp
vec
T wraxp
T wxakernel_func
xp
T wxapowers
xp
.scipy.interpolate._rgi
utoo many values to unpack (expected 2)
np
asarray
D adtype
Ofloat
all
:l nn:nq nadescending_dimensions
flip
uThe points in dimension

u must be strictly ascending or descending
ascontiguousarray
grid
ndim
uThere are
u point arrays, but values has
u dimensions
l u must be 1-dimensional
values
shape
u points and
u values in dimension
a_ALL_METHODS
uMethod '
u' is not defined
a_SPLINE_METHODS
a_validate_grid_dimensions
array_namespace
xp_v
a_asarray
method
a_spline
bounds_error
a_check_points
a_grid
a_descending_dimensions
a_check_values
a_values
a_check_dimensionality
a_check_fill_value
fill_value
T aaxis
pchip
iscomplexobj
u`PchipInterpolator` only works with real values. If you are trying to use the real components of the passed array, use `np.real` on the array before passing to `RegularGridInterpolator`.
a_SPLINE_METHODS_ndbspl
a_construct_spline
umethod =
u does not accept the 'solver' argument. Got  solver =
u and with arguments
w.assl
gcrotmk
make_ndbspl
a_SPLINE_DEGREE_MAP
solver
is_array_api_obj
dtype
astype
issubdtype
inexact
T Ofloat
can_cast
D acasting
same_kind
ufill_value must be either 'None' or of a type compatible with values
uCan only compute derivatives for methods
u, got method =
a_prepare_xi
utoo many values to unpack (expected 5)
linear
a_find_indices
wTl aflags
writeable
float64
complex128
byteorder
w=aempty
T adtype
evaluate_linear_2d
a_evaluate_linear
nearest
a_evaluate_nearest
a_SPLINE_METHODS_recursive
a_evaluate_spline
T anu
result
any
nan
reshape
self
u<genexpr>
uRegularGridInterpolator.grid.<locals>.<genexpr>
a_ndim_coords_from_arrays
T andim
q uThe requested sample points xi have dimension
u but this RegularGridInterpolator has dimension
isnan
D aaxis
q alogical_and
l
uOne of the requested xi is out of bounds in dimension
a_find_out_of_bounds
T :nnnT naitertools
product
array
Z
f
?aweight
value
where
f
?aatleast_1d
u points in dimension
u, but method
u requires at least
u points per dimension.
size
xi
:nnq atranspose
a_do_pchip
a_do_spline_fit
:nnnalast_dim
a_eval_func
folded_values
wkamake_interp_spline
T wkaaxis
aPchipInterpolator
D aaxis
l
find_indices
zeros
D adtype
Obool
out_of_bounds
T
linear
nearest
cubic
quintic
pchip
splinef2d
slinear
slinear_legacy
cubic_legacy
quintic_legacy
uinterpn only understands the methods 'linear', 'nearest', 'slinear', 'cubic', 'quintic', 'pchip', and 'splinef2d'. You provided
splinef2d
uThe method splinef2d can only be used for 2-dimensional input data
uThe method splinef2d does not support extrapolation.
uThe method splinef2d can only be used for scalar data with one point per coordinate
u, but this RegularGridInterpolator has dimension
aRegularGridInterpolator
T amethod
bounds_error
fill_value
T :nnnl
T :nnnl aempty_like
aRectBivariateSpline
ev
logical_not
uunknown method =
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
interpn
a__all__
aGenericAlias
numpy
uscipy.sparse.linalg
sparse
linalg
uscipy._lib._array_api
T aarray_namespace
xp_capabilities
xp_capabilities
uscipy._lib.array_api_compat
T ais_array_api_obj
a_interpnd
T a_ndim_coords_from_arrays
a_cubic
T aPchipInterpolator
a_rgi_cython
T aevaluate_linear_2d
find_indices
a_bsplines
T amake_interp_spline
a_fitpack2
T aRectBivariateSpline
a_ndbspline
T amake_ndbspl
T tFL T udask.array
uhttps://github.com/data-apis/array-api-extra/issues/488
T acpu_only
jax_jit
skip_backends
