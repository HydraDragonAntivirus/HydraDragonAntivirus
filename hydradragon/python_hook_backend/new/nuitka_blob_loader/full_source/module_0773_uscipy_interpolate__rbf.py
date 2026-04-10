# Reconstructed from integrated Nuitka blob
# Module: uscipy.interpolate._rbf

a__qualname__
a_h_multiquadric
uRbf._h_multiquadric
a_h_inverse_multiquadric
uRbf._h_inverse_multiquadric
a_h_gaussian
uRbf._h_gaussian
a_h_linear
uRbf._h_linear
a_h_cubic
uRbf._h_cubic
a_h_quintic
uRbf._h_quintic
a_h_thin_plate
uRbf._h_thin_plate
uRbf._init_function
a__init__
uRbf.__init__
uRbf.A
uRbf._call_norm
uRbf.__call__
uscipy\interpolate\_rbf.py
u<module scipy.interpolate._rbf>
T aself
wrT a__class__
T aself
args
shp
xa
wrT aself
args
kwargs
ximax
ximin
edges
item
value
lu
piv
wiT aself
x1
x2
T	aself
wra_mapped
func_name
functionlist
allow_one
val
argcount
a0

.scipy.interpolate._rbfinterp
is_numpy
a_rbfinterp_np
a_rbfinterp_xp
array_namespace
a_get_backend
uneighbors not None is numpy-only because it relies on KDTree
a_asarray
float64
wCT adtype
order
xp
ndim
l u`y` must be a 2-dimensional array.
shape
utoo many values to unpack (expected 2)
asarray
isdtype
dtype
ucomplex floating
complex128
l
uExpected the first axis of `d` to have length

w.:l nnareshape
q aview
T Ofloat
HT Oint
Ofloat
full
T adtype
uExpected `smoothing` to be a scalar or have shape (
u,).
lower
a_AVAILABLE
u`kernel` must be one of
a_SCALE_INVARIANT
f
?u`epsilon` must be specified if `kernel` is not one of
a_NAME_TO_MIN_DEGREE
get
max
u`degree` must be at least -1.
warnings
warn
u`degree` should not be below
u except -1 when `kernel` is '
u'.The interpolant may not be uniquely solvable, and the smoothing parameter may have an unintuitive effect.
aUserWarning
D astacklevel
l amin
a_monomial_powers
degree
uAt least
u data points are required when `degree` is
u and the number of dimensions is
neighbors
a_build_and_solve_system
smoothing
utoo many values to unpack (expected 3)
a_shift
a_scale
a_coeffs
aKDTree
a_tree
self
wywdad_shape
d_dtype
kernel
epsilon
powers
a_xp
utoo many values to unpack (expected 9)
utoo many values to unpack (expected 1)
l aempty
a_backend
compute_interpolation
chunksize
:nnnashift
scale
coeffs
xpx
at
out
set
u`x` must be a 2-dimensional array.
uExpected the second axis of `x` to have length
xp_size
l  =a_chunk_evaluator
T amemory_budget
np
query
T :nnnnasort
D aaxis
l aunique
D areturn_inverse
axis
tl
T q aappend
D adtype
Ofloat
memory_budget
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
aGenericAlias
numpy
uscipy.spatial
T aKDTree
T a_rbfinterp_np
T a_rbfinterp_xp
uscipy._lib._array_api
T a_asarray
array_namespace
xp_size
is_numpy
xp_capabilities
xp_capabilities
uscipy._lib.array_api_extra
a_lib
array_api_extra
aRBFInterpolator
a__all__
S amultiquadric
linear
cubic
gaussian
thin_plate_spline
inverse_multiquadric
inverse_quadratic
quintic
S aquintic
thin_plate_spline
cubic
linear
D amultiquadric
linear
thin_plate_spline
cubic
quintic
l
pl pl uOnly the default ``neighbors=None`` is Array API compatible.
If a non-default value of ``neighbors`` is given, the behavior is NumPy -only.
extra_note
T udask.array
ulinalg.lu is broken; array_api_extra#488
T aarray_api_strict
uarray-api#977, diag, view
T askip_backends
extra_note
