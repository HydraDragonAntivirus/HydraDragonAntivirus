# Reconstructed from integrated Nuitka blob
# Module: uscipy.spatial.transform._rotation

a__qualname__
T tpFa__init__
uRotation.__init__
T L T udask.array
umissing linalg.cross/det functions
T askip_backends
D ascalar_first
FuRotation.from_quat
D aassume_valid
FuRotation.from_matrix
T FuRotation.from_rotvec
uRotation.from_euler
uRotation.from_davenport
uRotation.from_mrp
uRotation.as_quat
uRotation.as_matrix
uRotation.as_rotvec
D asuppress_warnings
FuRotation.as_euler
T L T udask.array
umissing linalg.cross/det functions and .mT attribute
T acupy
umissing .mT attribute in cupy<14.*
uRotation.as_davenport
uRotation.as_mrp
concatenate
uRotation.concatenate
uRotation.apply
a__mul__
uRotation.__mul__
T L T udask.array
ucannot handle zero-length rotations
T na__pow__
uRotation.__pow__
uRotation.inv
uRotation.magnitude
T nFuRotation.approx_equal
T nnuRotation.mean
T nnFuRotation.reduce
T wZuRotation.create_group
T FL T udask.array
ucannot handle zero-length rotations
T ajax_jit
skip_backends
a__getitem__
uRotation.__getitem__
a__setitem__
uRotation.__setitem__
D ashape
nuRotation.identity
T arandom_state
l T aposition_num
uRotation.random
uRotation.align_vectors
a__getstate__
uRotation.__getstate__
a__setstate__
uRotation.__setstate__
uRotation.single
uRotation.shape
a__bool__
uRotation.__bool__
a__len__
uRotation.__len__
a__repr__
uRotation.__repr__
uRotation._from_raw_quat
aSlerp
T FL T udask.array
umissing linalg.cross function
uSlerp.__init__
a__call__
uSlerp.__call__
uscipy\spatial\transform\_rotation.py
T a.0
wxu<module scipy.spatial.transform._rotation>
T a__class__
T aself
T
self
times
xp
device
compute_times
single_time
ind
invalid_ind
alpha
result
T aself
indexer
is_array
T aself
quat
normalize
copy
scalar_first
xp
T aself
times
rotations
wqaxp
neg_mask
T aself
wiT aself
other
cython_compatible
backend
quat
T aself
wnamodulus
quat
T aself
wmT aself
indexer
value
T aself
state
quat
single
xp
T aquat
xp
backend
rot
T axp
args
out
T
wawbaweights
return_sensitivity
xp
cython_compatible
backend
wqarssd
sensitivity
T aself
vectors
inverse
single_vector
cython_compatible
backend
result
T aself
other
atol
degrees
cython_compatible
backend
T aself
axes
order
degrees
suppress_warnings
davenport
T aself
seq
degrees
suppress_warnings
euler
T aself
matrix
T aself
mrp
T aself
canonical
scalar_first
quat
T aself
degrees
rotvec
T arotations
xp
quats
T acls
group
axis
T aaxes
order
angles
degrees
xp
cython_compatible
backend
quat
T aseq
angles
degrees
xp
backend
quat
T amatrix
assume_valid
xp
backend
quat
T amrp
xp
backend
quat
T aquat
scalar_first
T arotvec
degrees
xp
backend
quat
T anum
shape
quat
T aself
q_inv
T aself
magnitude
T aself
weights
axis
mean
T anum
rng
shape
sample
T aself
left
right
return_indices
reduced
left_idx
right_idx
rot
T axp
cython_compatible
.scipy.spatial.transform._rotation_groups

G
tetrahedral
as_quat
f
?aphi
l anp
array
l
f
from_quat
concatenate
sqrt
T l aeye
T l L L f
?f
f
f
?L f
?f
f
?f
?L f
?f
?f
f
?L f
?f
?f
?f
?L f
?f
f
f
L f
?f
f
?f
L f
?f
?f
f
L f
?f
?f
?f
cyclic
as_rotvec
linspace
pi
D aendpoint
Favstack
zeros
cos
sin
wTaroll
D aaxis
l afrom_rotvec
u`group` argument must be a string
L wxwywzwXwYwZu`axis` must be one of
u,
T wIwOwTl :nl nT wCwD:l nnaisdigit
u`group` must be one of 'I', 'O', 'T', 'Dn', 'Cn'
uGroup order must be positive
xyz
lower
wIaicosahedral
wOaoctahedral
wDadicyclic
T aaxis
wCa__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.constants
T agolden
golden
T wZacreate_group
uscipy\spatial\transform\_rotation_groups.py
u<module scipy.spatial.transform._rotation_groups>
T acls
group
axis
permitted_axes
symbol
order
T acls
wnaaxis
thetas
rv
T acls
wnaaxis
g1
thetas
rv
g2
T acls
g1
wawbwcag2
T acls
g1
wcag2

.scipy.spatial.transform._rotation_spline
np
zeros
l T :nnnl T :nnnl
l T :nnnl T :nnnl
l T :nnnl l
T :nnnl
T :nnnl l T :nnnl l
T :nnnl l aeinsum
uijk,ik->ij
linalg
norm
D aaxis
l aempty_like
f-C   6 ?l f
?atan
l fUUUUUU ?f l  l V?a_create_skew_matrix
empty
identity
T l :nnnT :nnnnnamatmul
cos
sin
l fUUUUUU ?lxasum
cross
l q l l  f        l bT :nnnna_matrix_vector_product_of_stacks
a_rotvec_dot_to_angular_rate_matrix
a_compute_angular_rate
a_angular_acceleration_nonlinear_term
arange
D adtype
Oint
hstack
ravel
repeat
l l
copy
a_angular_rate_to_rotvec_dot_matrix
a_create_block_3_diagonal_matrix
:l q nT :l q nnn:nq n:l nnl T :nq nnT :l nnnadot
q aMAX_ITER
wAaangular_rates
b0
solve_banded
T l pwMareshape
T T q l aabs
all
self
aTOL
vstack
uscipy.interpolate
T aPPoly
aPPoly
single
u`rotations` must be a sequence of rotations.
as_quat
ndim
uRotations with more than 1 leading dimension are not supported.
u`rotations` must contain at least 2 rotations.
asarray
D adtype
Ofloat
u`times` must be 1-dimensional.
uExpected number of rotations to be equal to number of timestamps given, got

u rotations and
u timestamps.
diff
any
uValues in `times` must be in a strictly increasing order.
inv
as_rotvec
a_solve_for_angular_rates
utoo many values to unpack (expected 2)
times
rotations
interpolator
T l
l l u`order` must be 0, 1 or 2.
u`times` must be at most 1-dimensional.
atleast_1d
searchsorted
D aside
right
aRotation
from_rotvec
a_compute_angular_acceleration
result
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.linalg
T asolve_banded
a_rotation
T aRotation
