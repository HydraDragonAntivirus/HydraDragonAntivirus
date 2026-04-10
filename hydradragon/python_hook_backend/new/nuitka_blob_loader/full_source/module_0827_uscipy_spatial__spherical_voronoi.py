# Reconstructed from integrated Nuitka blob
# Module: uscipy.spatial._spherical_voronoi

a__qualname__
T l nf       >a__init__
uSphericalVoronoi.__init__
uSphericalVoronoi._calc_vertices_regions
uSphericalVoronoi.sort_vertices_of_regions
uSphericalVoronoi._calculate_areas_3d
uSphericalVoronoi._calculate_areas_2d
calculate_areas
uSphericalVoronoi.calculate_areas
uscipy\spatial\_spherical_voronoi.py
u<module scipy.spatial._spherical_voronoi>
T aself
points
radius
center
threshold
radii
max_discrepancy
T	aself
conv
simplex_indices
tri_indices
point_indices
indices
flattened_groups
intervals
groups
T aself
arcs
wdatheta
areas
indices
Taself
sizes
csizes
num_regions
point_indices
nbrs1
nbrs2
indices
pnormalized
vnormalized
triangles
triangle_solid_angles
solid_angles
T aself
T wRanumerator
denominator
.scipy.spatial.ckdtree
P
a__all__
a_sub_module_deprecation
spatial
ckdtree
a_ckdtree
T asub_package
module
private_modules
all
attribute
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
uscipy._lib.deprecation
T a_sub_module_deprecation
l
cKDTree
a__dir__
a__getattr__
uscipy\spatial\ckdtree.py
u<module scipy.spatial.ckdtree>
T aname

.scipy.spatial
3
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_scipy
u\not_existing
spatial
T aNUITKA_PACKAGE_scipy_spatial
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
a_kdtree
T w*l a_ckdtree
a_qhull
a_spherical_voronoi
T aSphericalVoronoi
aSphericalVoronoi
l
a_plotutils
a_procrustes
T aprocrustes
procrustes
a_geometric_slerp
T ageometric_slerp
geometric_slerp

T ackdtree
kdtree
qhull
ckdtree
kdtree
qhull
keys
startswith
T w_a__all__
T adistance
transform
distance
transform
uscipy._lib._testutils
T aPytestTester
aPytestTester
T uscipy.spatial
test
uscipy\spatial\__init__.py
u<module scipy.spatial>
.scipy.spatial.distance
"
base
copy
mean
T l tT aaxis
keepdims
a_distance_wrap
cdist_cosine_double_wrap
pdist_cosine_double_wrap
np
ascontiguousarray
T adtype
dtype
sum
result_type
astype
f
?wuatypes
index
l
a_convert_to_type
T aout_type
validator
wwandim
l ashape
uWeights must have same size as input vector.

u vs.
a_validate_weights
ones
D adtype
double
aVI
uThe number of observations (
u) is too small; the covariance matrix is singular. For observations with
u dimensions, at least
u observations are required.
vstack
atleast_2d
cov
float64
D acopy
FwTalinalg
inv
a_convert_to_double
a_validate_weight_with_size
wpf
@up must be greater than 0
wVavar
D aaxis
ddof
l
l aasarray
D aorder
wcuVariance vector V must be one-dimensional.
uVariance vector V must be of the same dimension as the vectors on which the distances are computed.
wcT adtype
order
uInput vector should be 1-D.
a_validate_vector
any
uInput weights should be all non-negative
uu and v need to have the same number of columns
a_hausdorff
directed_hausdorff
l asqrt
inf
power
norm
T aord
minkowski
T wpwwT nnutoo many values to unpack (expected 2)
issubdtype
inexact
dot
iscomplexobj
u`u` and `v` must be real.
wvamath
clip
Z
correlation
T wwacentered
uThe 1d arrays must have equal lengths.
u'w' should have the same length as 'u' and 'v'.
bitwise_xor
bitwise_or
T l
uV must be a 1-D array of the same dimension as u and v.
euclidean
T wwamax
errstate
T aignore
T ainvalid
a__enter__
a__exit__
nansum
T nnnwdarel_entr
log
a_nbool_correspond_all
utoo many values to unpack (expected 4)
a_nbool_correspond_ft_tf
array
uSokal-Sneath dissimilarity is not defined for vectors that are entirely false.
metric_name
a_METRICS
a_validate_cdist_input
pop
T wwnadist_func
a_cdist_callable
metric
out
a_prepare_out_argument
cdist_
w_a_wrap
a_validate_pdist_input
utoo many values to unpack (expected 3)
a_pdist_callable
pdist_
double
a_asarray
uA 2-dimensional array must be passed. (Shape was
u).
xpx
lazy_apply
a_np_pdist
T wVnT aVI
naas_numpy
a_asarray_validated
D asparse_ok
objects_ok
mask_ok
check_finite
FtpFacallable
a__name__
aUnknownCustomMetric
a_METRIC_ALIAS
get
wXakwargs
lower
pdist_func
startswith
T atest_
a_TEST_METRICS
uUnknown "Test" Distance Metric:
:l nnuUnknown Distance Metric:
u2nd argument metric must be a string identifier or a function.
tomatrix
uForcing 'tomatrix' but input X is not a distance vector.
tovector
uForcing 'tovector' but input X is not a distance matrix.
wsazeros
T T l paceil
uIncompatible vector size. It must be a binomial coefficient n choose 2 for some integer n >= 2.
a_copy_array_if_base_present
to_squareform_from_vector_wrap
uThe matrix argument must be square.
is_valid_dm
D athrow
name
twXT L
to_vector_from_squareform_wrap
uThe first argument must be one or two dimensional array. A
u-dimensional array is not permitted
uDistance matrix '
u' must have shape=2 (i.e. be two-dimensional).
uDistance matrix must have shape=2 (i.e. be two-dimensional).
all
u' must be symmetric.
uDistance matrix must be symmetric.
u' diagonal must be zero.
uDistance matrix diagonal must be zero.
u' must be symmetric within tolerance
u5.5f
w.uDistance matrix must be symmetric within tolerance
u' diagonal must be close to zero within tolerance
uDistance matrix '{}' diagonal must be close to zero within tolerance {:5.5f}.
format
warnings
warn
D astacklevel
l w'u'
uCondensed distance matrix
umust have shape=1 (i.e. be one-dimensional).
uLength n of condensed distance matrix
umust be a binomial coefficient, i.e. there must be a k such that (k \choose 2)=n)!
T atol
throw
name
is_valid_y
D athrow
name
twYuThe number of observations cannot be determined on an empty distance matrix.
uInvalid condensed distance matrix passed. Must be some k where k=(n choose 2) for some n >= 2.
empty
uOutput array has incorrect shape.
flags
c_contiguous
uOutput array must be C-contiguous.
uOutput array must be double type.
dm
wkuXA must be a 2-dimensional array.
uXB must be a 2-dimensional array.
uXA and XB must have the same number of columns (i.e. feature dimension.)
aUnknown
aXA
aXB
cdist_func
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
L abraycurtis
canberra
cdist
chebyshev
cityblock
correlation
cosine
dice
directed_hausdorff
euclidean
hamming
is_valid_dm
is_valid_y
jaccard
jensenshannon
mahalanobis
minkowski
num_obs_dm
num_obs_y
pdist
rogerstanimoto
russellrao
seuclidean
sokalsneath
sqeuclidean
squareform
yule
a__all__
dataclasses
ucollections.abc
T aCallable
aCallable
partial
numpy
uscipy._lib._array_api
T a_asarray
uscipy._lib._util
T a_asarray_validated
a_transition_to_rng
a_transition_to_rng
uscipy._lib
T aarray_api_extra
array_api_extra
uscipy.linalg
T anorm
uscipy.special
T arel_entr
T a_hausdorff
a_distance_pybind
a_distance_wrap
a_distance_pybind
a_correlation_cdist_wrap
a_correlation_pdist_wrap
T na_validate_hamming_kwargs
a_validate_mahalanobis_kwargs
a_validate_minkowski_kwargs
a_validate_seuclidean_kwargs
T aseed
l FT aposition_num
replace_doc
T l nasqeuclidean
T ntacosine
hamming
jaccard
seuclidean
cityblock
mahalanobis
chebyshev
braycurtis
canberra
D aaxis
keepdims
l
Fajensenshannon
yule
dice
rogerstanimoto
russellrao
sokalsneath
D aout_type
Obool
a_convert_to_bool
pdist_correlation_double_wrap
cdist_correlation_double_wrap
dataclass
T tT afrozen
