# Reconstructed from integrated Nuitka blob
# Module: uscipy.spatial.transform._rigid_transform

a__qualname__
T tpa__init__
uRigidTransform.__init__
a__repr__
uRigidTransform.__repr__
T L T udask.array
umissing linalg.cross/det functions
T askip_backends
uRigidTransform.from_matrix
uRigidTransform.from_rotation
uRigidTransform.from_translation
from_components
uRigidTransform.from_components
uRigidTransform.from_exp_coords
D ascalar_first
FuRigidTransform.from_dual_quat
T nD ashape
naidentity
uRigidTransform.identity
concatenate
uRigidTransform.concatenate
T nnuRigidTransform.mean
uRigidTransform.as_matrix
as_components
uRigidTransform.as_components
uRigidTransform.as_exp_coords
uRigidTransform.as_dual_quat
a__len__
uRigidTransform.__len__
T FL T udask.array
ucannot handle zero-length rigid transforms
T ajax_jit
skip_backends
a__getitem__
uRigidTransform.__getitem__
a__setitem__
uRigidTransform.__setitem__
a__mul__
uRigidTransform.__mul__
a__pow__
uRigidTransform.__pow__
uRigidTransform.inv
T L T udask.array
umissing linalg.cross/det functions
T acupy
umissing .mT attribute in cupy<14.*
T FuRigidTransform.apply
uRigidTransform.rotation
uRigidTransform.translation
uRigidTransform.single
uRigidTransform.shape
a__reduce__
uRigidTransform.__reduce__
uRigidTransform._from_raw_matrix
uscipy\spatial\transform\_rigid_transform.py
T a.0
wxu<module scipy.spatial.transform._rigid_transform>
T a__class__
T aself
indexer
is_array
xp
T aself
matrix
normalize
copy
xp
T aself
wiT aself
T aself
other
cython_compatible
backend
matrix
T aself
wnamatrix
T aself
matrix
T aself
wmT aself
indexer
value
T amatrix
xp
backend
tf
T aself
vector
inverse
xp
cython_compatible
backend
result
T aself
scalar_first
dual_quat
T aself
exp_coords
T atransforms
xp
matrix
T atranslation
rotation
rotation_tf
T adual_quat
scalar_first
xp
backend
matrix
T aexp_coords
xp
backend
matrix
T amatrix
T arotation
quat
xp
backend
matrix
T atranslation
xp
backend
matrix
T anum
shape
matrix
T aself
weights
axis
mean
T adual_quat
xp
single
cython_compatible
dq
T axp
cython_compatible
.scipy.spatial.transform._rigid_transform_xp
array_namespace
asarray
D acopy
taall
matrix
T Q
l :nnnaxp_device
T L l
ppf
?T adevice
D aaxis
q ais_lazy_array
any
shape
nonzero
T l Q
uExpected last row of transformation matrix

u to be exactly [0, 0, 0, 1], got
quat_as_matrix
quat_from_matrix
T Q
:nl n:nl naxpx
at
set
where
T Q
nnanan
l
u<genexpr>
ufrom_matrix.<locals>.<genexpr>
zeros
:nq nT l adtype
T adtype
device
T Q
l pT l q l uExpected `translation` to have shape (..., 3), got
w.axp_result_type
T aforce_floating
xp
eye
atleast_nd
ndim
l T andim
xp
:nq nT Q
:nl nl axp_promote
compose_transforms
from_translation
from_rotation
T Q
:nl naquat_from_rotvec
a_compute_se3_exp_translation_transform
T Q
:l nnnT Q
l
a_create_transformation_matrix
l uExpected `dual_quat` to have shape (..., 8), got
T Q
:nl nT Q
:l nnaroll
a_normalize_dual_quaternion
utoo many values to unpack (expected 2)
from_quat
f
@acompose_quat
quat_inv
quat_as_rotvec
quat_from_matrix_orthogonal
a_compute_se3_log_translation_transform
T Q
naconcat
empty
T Q
l T Z
f
?areal_parts
broadcastable
uExpected equal number of transforms in both or a single transform in either object, got
u transforms in first and
utransforms in second object.
matrix_transpose
uExpected vector to have shape (..., 3), got
inv
uoperands could not be broadcast together
T Q
:nl nl
is_array_api_obj
uArray exponent must be a scalar
wnafrom_exp_coords
as_exp_coords
tile
uMean of an empty rotation set is undefined.
l u`axis` must be None, int, or tuple of ints.
min
max
uaxis
u is out of bounds for transform with shape
sorted
quat_mean
T aaxis
u`weights` must be non-negative.
uExpected `weights` to match transform shape, got shape
u for
u transformations.
T aweights
axis
mean
axis
sum
any_neg_weights
f
?umean.<locals>.<genexpr>
aEllipsisType
bool
uThe number of rotation matrices and translations must be the same.
T Q
l :nl nT l
xp_vector_norm
T aaxis
keepdims
xp
f    MbP?l l l  acos
fUUUUUU ?lxl 'asin
a_create_skew_matrix
T l fUUUUUU ?l   atan
T Q
l
l T Q
l T Q
l
l T Q
l T Q
l l
T Q
l l T Q
l l
T Q
l l Z
T L Z
Z
Z
f
?D aaxis
keepdims
q ta__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uscipy._lib._array_api
T aarray_namespace
aArray
aArrayLike
is_lazy_array
xp_vector_norm
xp_result_type
xp_promote
is_array_api_obj
aArray
aArrayLike
uscipy._lib.array_api_extra
a_lib
array_api_extra
uscipy.spatial.transform._rotation_xp
T	aas_matrix
from_matrix
a_from_matrix_orthogonal
from_rotvec
as_rotvec
compose_quat
from_quat
inv
mean
as_matrix
from_matrix
a_from_matrix_orthogonal
from_rotvec
as_rotvec
uscipy._lib.array_api_compat
device
uscipy._lib._util
T abroadcastable
T tpafrom_components
D ascalar_first
Fafrom_dual_quat
as_dual_quat
T Faapply
pow
T nnasetitem
normalize_dual_quaternion
uscipy\spatial\transform\_rigid_transform_xp.py
T a.0
wiT a.0
wxamatrix
u<module scipy.spatial.transform._rigid_transform_xp>
Tarot_vec
xp
device
dtype
angle
small_scale
k1_small
safe_angle
k1
k2_small
k2
wsaeye
T
rot_vec
xp
dtype
device
angle
mask
k_small
safe_angle
wkwsT avec
xp
result
T atranslations
rotation_matrices
xp
matrix
T areal_part
dual_part
xp
real_norm
zero_real_mask
unit_quat
T amatrix
vector
inverse
xp
vec
T amatrix
scalar_first
xp
real_parts
pure_translation_quats
dual_parts
dual_quats
T amatrix
xp
rot_vec
translation_transform
translations
exp_coords
T atf_matrix
other_tf_matrix
len_a
len_b
T atranslation
quat
T adual_quat
scalar_first
xp
real_part
dual_part
rot_quat
translation
matrix
T aexp_coords
rot_vec
rot_matrix
translation_transform
translations
T	amatrix
normalize
copy
xp
last_row_ok
lazy
idx
vals
rotmat
T aquat
xp
rotmat
matrix
T atranslation
xp
device
dtype
eye
matrix
T amatrix
xp
r_inv
t_inv
T amatrix
weights
axis
xp
all_axes
lazy
quats
quats_mean
neg_weights
any_neg_weights
r_mean
wtat_mean
norm
wsum
tf
mask
T adual_quat
xp
real
dual
T amatrix
wnaxp
device
result
identity
T amatrix
indexer
value
xp
.scipy.spatial.transform._rotation
O
0 ais_numpy
xp_backend
backend_registry
get
np
empty
float64
T l
T adtype
xp_promote
force_floating
xp
l
:nq naarray_namespace
a_xp
a_promote
T axp
shape
q l uExpected `quat` to have shape (..., 4), got

w.andim
l a_single
xpx
atleast_nd
l T andim
xp
select_backend
quat
l T acython_compatible
a_backend
from_quat
T anormalize
copy
scalar_first
a_quat
aRotation
T anormalize
scalar_first
from_matrix
T aassume_valid
a_from_raw_quat
T axp
backend
from_rotvec
T adegrees
from_euler
utoo many values to unpack (expected 2)
from_davenport
from_mrp
as_quat
T acanonical
scalar_first
T l
Q
as_matrix
as_rotvec
as_euler
T adegrees
suppress_warnings
asarray
dtype
xp_device
T adtype
device
as_davenport
T asuppress_warnings
as_mrp
D anormalize
copy
Ftuinput must contain Rotation objects only
concat
u<genexpr>
uRotation.concatenate.<locals>.<genexpr>
T adevice
dtype
uExpected input of shape (..., 3), got
vectors
apply
T ainverse
broadcastable
uCannot broadcast
u rotations in first to
u rotations in second object.
compose_quat
D anormalize
copy
tFumodulus not supported
pow
inv
magnitude
approx_equal
T aatol
degrees
mean
T aweights
axis
reduce
T aleft
right
utoo many values to unpack (expected 3)
create_group
T aaxis
uSingle rotation is not subscriptable.
bool
D anormalize
Faisdtype
integral
ucannot do a non-empty take from an empty axes.
take
D aaxis
l
uvalue must be a Rotation object
setitem
uOnly one of `num` or `shape` can be specified.
cython_backend
identity
T ashape
random
align_vectors
D acopy
tuSingle rotation has no len().

:l nnuRotation.from_matrix(
w
w)aself
uSingle rotation is not iterable.
D anormalize
copy
Fpa__iter__
uRotation.__iter__
a__new__
u`rotations` must be a `Rotation` instance.
single
u`rotations` must be a sequence of at least 2 rotations.
uRotations with more than 1 leading dimension are not supported.
uExpected times to be specified in a 1 dimensional array, got
u dimensions.
uExpected number of rotations to be equal to number of timestamps given, got
u rotations and
u timestamps.
times
diff
timedelta
any
is_lazy_array
where
nan
uTimes must be in strictly increasing order.
rotations
rotvecs
u`times` must be at most 1-dimensional.
searchsorted
at
set
uInterpolation times must be within the range [
u,
u], both inclusive.
T :nnnnaarange
T l T adevice
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
annotations
ucollections.abc
T aIterable
aIterator
aIterable
aIterator
aEllipsisType
aModuleType
aNotImplementedType
numpy
uscipy.spatial.transform._rotation_cy
spatial
transform
a_rotation_cy
uscipy.spatial.transform._rotation_xp
a_rotation_xp
uscipy.spatial.transform._rotation_groups
T acreate_group
uscipy._lib._array_api
T aarray_namespace
aArray
is_numpy
aArrayLike
is_lazy_array
xp_capabilities
xp_promote
aArray
aArrayLike
xp_capabilities
uscipy._lib.array_api_compat
device
uscipy._lib.array_api_extra
a_lib
array_api_extra
uscipy._lib._util
T a_transition_to_rng
broadcastable
a_transition_to_rng
