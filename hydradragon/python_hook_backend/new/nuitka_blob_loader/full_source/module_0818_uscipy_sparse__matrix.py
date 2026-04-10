# Reconstructed from integrated Nuitka blob
# Module: uscipy.sparse._matrix

spmatrix
a__qualname__
T l a_allow_nd
a_bsr_container
uspmatrix._bsr_container
a_coo_container
uspmatrix._coo_container
a_csc_container
uspmatrix._csc_container
a_csr_container
uspmatrix._csr_container
a_dia_container
uspmatrix._dia_container
a_dok_container
uspmatrix._dok_container
a_lil_container
uspmatrix._lil_container
a__mul__
uspmatrix.__mul__
a__rmul__
uspmatrix.__rmul__
a__pow__
uspmatrix.__pow__
set_shape
uspmatrix.set_shape
get_shape
uspmatrix.get_shape
uShape of the matrix
T afget
fset
doc
shape
asfptype
uspmatrix.asfptype
getmaxprint
uspmatrix.getmaxprint
getformat
uspmatrix.getformat
T nagetnnz
uspmatrix.getnnz
getH
uspmatrix.getH
getcol
uspmatrix.getcol
getrow
uspmatrix.getrow
T nnuspmatrix.todense
a__class_getitem__
uspmatrix.__class_getitem__
uscipy\sparse\_matrix.py
u<module scipy.sparse._matrix>
T acls
arg
aGenericAlias
T aself
other
T aself
power
matrix_power
T aself
bsr_matrix
T aself
coo_matrix
T aself
csc_matrix
T aself
csr_matrix
T aself
dia_matrix
T aself
dok_matrix
T aself
lil_matrix
T aself
T aself
wjT aself
axis
T aself
wiT aself
shape
new_self
T a__class__
T aself
order
out
a__class__

.scipy.sparse._matrix_io
@
format
T acsc
csr
bsr
indices
indptr
dia
offsets
coo
ndim
l arow
col
coords
uSave is not implemented for sparse matrix of format

w.aarrays_dict
encode
T aascii
shape
data
sp
sparse
sparray
a_is_array
np
savez_compressed
savez
load
aPICKLE_KWARGS
a__enter__
a__exit__
get
T aformat
uThe file
u does not contain a sparse array or matrix.
item
decode
T a_is_array
a_array
a_matrix
uUnknown format "
w"asparse_format
T ashape
uLoad is not implemented for sparse matrix of format
T nnna__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
l
scipy
save_npz
load_npz
a__all__
D aallow_pickle
FT tuscipy\sparse\_matrix_io.py
u<module scipy.sparse._matrix_io>
T afile
loaded
sparse_format
sparse_type
cls
weT afile
matrix
compressed
arrays_dict
msg
.scipy.sparse._spfuncs
f
5
issparse
format
T acsc
csr
csr_array
wAannz
l
T l pf
?uefficiency must satisfy 0.0 < efficiency < 1.0
f
@ashape
utoo many values to unpack (expected 2)
l l acount_blocks
T l pZ
l l	T l pl$T l pl T l pl ur and c must be positive
csr
csr_count_blocks
indptr
indices
csc
wTa__doc__
a__file__
a__spec__
origin
has_location
a__cached__
estimate_blocksize
a__all__
a_base
T aissparse
a_csr
T acsr_array
a_sparsetools
T acsr_count_blocks
T fffffff ?uscipy\sparse\_spfuncs.py
u<module scipy.sparse._spfuncs>
T wAablocksize
wrwcwMwNT
wAaefficiency
high_efficiency
nnz
wMwNae22
e33
e66
e44

.scipy.sparse._sputils
a_upcast_memo
get
np
result_type
supported_dtypes
can_cast
upcast
uno supported conversion for types:

dtype
array
T L l
T adtype
itemsize
intp
size
l
astype
max
min
iinfo
uCannot deal with arrays with indices larger than the machine maximum address size (e.g. 64-bit indices on 32-bit machine).
isnative
asarray
newbyteorder
T anative
ucould not interpret data type
u,
uscipy.sparse does not support dtype
u. The only supported types are:
w.a__name__
u<genexpr>
ugetdtype.<locals>.<genexpr>
T adtype
copy
getdtype
udtype
format
T acsc
csr
indptr
q uindptr values too large for
shape
indices
any
uindices values too large for
D acopy
Facoo
coords
ucoords values too large for
dia
offsets
uoffsets values too large for
bsr
blocksize
utoo many values to unpack (expected 2)
uindptr values too large for {msg}
uFormat
u is not associated with index arrays. DOK and LIL have dict and list, not array.
max_value
usafely_cast_index_arrays.<locals>.<genexpr>
idx_dtype
intc
l aint64
int32
ndarray
issubdtype
integer
kind
wuauint
int_
isscalar
isdense
ndim
operator
index
T ETypeError
EValueError
uInexact indices into sparse matrices are not allowed
isintlike
HT Olist
Otuple
l aissequence
l usparse does not accept 0D axis (). Either use toarray (for dense) or copy (for sparse).
uaxis must be an integer/tuple of ints, not
uaxis must be an integer. (given
w)aax
uaxis out of range for ndim
canon_axis
uduplicate value in axis
uaxis tuple has too many elements
ufunction missing 1 required positional argument: 'shape'
shape_iter
new_shape
ushape must have length in
u. Got new_shape=
u'shape' elements cannot be negative
prod
ucannot reshape array of size
u into shape
ucan only specify one unknown dimension
ucheck_shape.<locals>.<genexpr>
newshape
HT Otuple
Olist
D akey
Olen
T astart
out
ushapes cannot be broadcast to a single shape.
pop
T aorder
wCT acopy
Fureshape() got unexpected keywords arguments:
keys
modules
T asparse
aSparseArray
is_pydata_spmatrix
to_scipy_sparse
T aaccept_fv
asformat
tocsc
arg
view
matrix
sp
a_data
a_data_matrix
a_deduped_data
dok_array
fromiter
values
nnz
T adtype
count
lil_array
empty
a_csparsetools
lil_flatten_to_array
data
tocoo
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
sys
aAny
aLiteral
aUnion
numpy
math
T aprod
uscipy.sparse
sparse
uscipy._lib._util
T anp_long
np_ulong
np_long
np_ulong
L aupcast
getdtype
getdata
isscalarlike
isintlike
isshape
issequence
isdense
ismatrix
get_sum_dtype
broadcast_shapes
a__all__
bool_
byte
ubyte
short
ushort
uintc
longlong
ulonglong
float32
float64
longdouble
complex64
complex128
clongdouble
upcast_char
upcast_scalar
downcast_intp_index
to_native
T nnT nFagetdata
safely_cast_index_arrays
T T
nFaget_index_dtype
get_sum_dtype
isscalarlike
T FD aallow_nd
T l aisshape
ismatrix
D andim
l avalidateaxis
T nacheck_shape
broadcast_shapes
check_reshape_kwargs
convert_pydata_sparse_to_scipy
asmatrix
a_todata
uscipy\sparse\_sputils.py
T a.0
arg
T a.0
wdT a.0
wxT a.0
wtT a.0
co
idx_dtype
T a.0
co
max_value
u<module scipy.sparse._sputils>
T wsadata
T adata
dtype
T ashapes
big_shp
out
shp
wiwxT akwargs
order
copy
Taargs
current_shape
allow_nd
shape_iter
new_shape
current_size
negative_indexes
new_size
skip
specified
unspecified
remainder
err_shape
T aarg
target_format
accept_fv
T aarr
maxval
minval
T aarrays
maxval
check_contents
int32min
int32max
arr
minval
T aobj
dtype
copy
data
T adtype
waadefault
newdtype
weasupported_dtypes_fmt
T wmabase_cls
T wxT wxaloose_int
msg
T wtT wxanonneg
allow_nd
ndim
wdT aargs
kwargs
T	wAaidx_dtype
msg
max_value
indices
indptr
offsets
wRwCT wAadt
T aargs
wtaupcast
T aargs
wtT adtype
scalar
T aaxis
ndim
canon_axis
ax
len_axis
.scipy.sparse.base
a__all__
a_sub_module_deprecation
sparse
base
a_base
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
L aSparseEfficiencyWarning
aSparseWarning
issparse
isspmatrix
spmatrix
a__dir__
a__getattr__
uscipy\sparse\base.py
u<module scipy.sparse.base>
T aname

.scipy.sparse.bsr
Z
a__all__
a_sub_module_deprecation
sparse
bsr
a_bsr
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
bsr_matrix
isspmatrix_bsr
spmatrix
a__dir__
a__getattr__
uscipy\sparse\bsr.py
u<module scipy.sparse.bsr>
T aname

.scipy.sparse.compressed
i
a__all__
a_sub_module_deprecation
sparse
compressed
a_compressed
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
aSparseEfficiencyWarning
a__dir__
a__getattr__
uscipy\sparse\compressed.py
u<module scipy.sparse.compressed>
T aname

.scipy.sparse
Q
U
a__all__
a_submodules
uscipy.sparse.

import_module
globals
aKeyError
aAttributeError
uModule 'scipy.sparse' has no attribute '
w'a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_scipy
u\not_existing
sparse
T aNUITKA_PACKAGE_scipy_sparse
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
warnings
l
a_warnings
a_importlib
a_base
T w*l a_csr
a_csc
a_lil
a_dok
a_coo
a_dia
a_bsr
a_construct
a_extract
a_matrix
T aspmatrix
spmatrix
a_matrix_io
a_sputils
T aget_index_dtype
safely_cast_index_arrays
get_index_dtype
safely_cast_index_arrays
T abase
bsr
compressed
construct
coo
csc
csr
data
dia
dok
extract
lil
sparsetools
sputils
base
bsr
compressed
construct
coo
csc
csr
data
dia
dok
extract
lil
sparsetools
sputils
csgraph
linalg
keys
startswith
T w_uthe matrix subclass is not the recommended way
msg
filterwarnings
T aignore
T amessage
a__dir__
a__getattr__
uscipy._lib._testutils
T aPytestTester
aPytestTester
T uscipy.sparse
test
uscipy\sparse\__init__.py
u<module scipy.sparse>
T aname
.scipy.sparse.construct
a__all__
a_sub_module_deprecation
sparse
construct
a_construct
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
L ablock_diag
bmat
bsr_matrix
coo_matrix
csc_matrix
csr_matrix
dia_matrix
diags
eye
get_index_dtype
hstack
identity
issparse
kron
kronsum
rand
random
spdiags
vstack
a__dir__
a__getattr__
uscipy\sparse\construct.py
u<module scipy.sparse.construct>
T aname

.scipy.sparse.coo

a__all__
a_sub_module_deprecation
sparse
coo
a_coo
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
L aSparseEfficiencyWarning
coo_matrix
isspmatrix_coo
spmatrix
a__dir__
a__getattr__
uscipy\sparse\coo.py
u<module scipy.sparse.coo>
T aname

.scipy.sparse.csc
Z
a__all__
a_sub_module_deprecation
sparse
csc
a_csc
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
csc_matrix
isspmatrix_csc
spmatrix
a__dir__
a__getattr__
uscipy\sparse\csc.py
u<module scipy.sparse.csc>
T aname

.scipy.sparse.csgraph._laplacian
(
s
is_pydata_spmatrix
convert_pydata_sparse_to_scipy
csgraph
ndim
l ashape
l
l ucsgraph must be a square matrix or array
np
issubdtype
dtype
signedinteger
uint
astype
float64
array
issparse
a_laplacian_sparse
a_laplacian_dense
a_laplacian_sparse_flo
a_laplacian_dense_flo
T anormed
axis
copy
form
dtype
symmetrized
utoo many values to unpack (expected 2)
pydata_sparse_cls
from_scipy_sparse
flat
u<lambda>
u_laplace.<locals>.<lambda>
wd:nnnanewaxis
wma_laplace
u_laplace_normed.<locals>.<lambda>
nd
laplace
u_laplace_sym.<locals>.<lambda>
transpose
conjugate
a_laplace_sym
u_laplace_normed_sym.<locals>.<lambda>
laplace_sym
aLinearOperator
T amatvec
matmat
shape
dtype
asarray
sum
T aaxis
ravel
diagonal
where
sqrt
a_laplace_normed_sym
graph_sum
f
?a_laplace_normed
function
wwD acopy
Falo
a_linearoperator
T ashape
dtype
uInvalid form:

format
T alil
dok
tocoo
wTaconj
T acopy
data
row
col
q asetdiag
dia
copy
graph
u must be "array"
fill_diagonal
a_setdiag_dense
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.sparse
T aissparse
uscipy.sparse.linalg
T aLinearOperator
uscipy.sparse._sputils
T aconvert_pydata_sparse_to_scipy
is_pydata_spmatrix
T FppD acopy
form
dtype
symmetrized
taarray
nFalaplacian
uscipy\sparse\csgraph\_laplacian.py
T wvwdwmT wdwmT wvand
laplace
T alaplace
nd
T wvand
laplace_sym
T alaplace_sym
nd
u<module scipy.sparse.csgraph._laplacian>
T wmwdT wmwdand
laplace
T wmwdand
laplace_sym
T
graph
normed
axis
copy
form
dtype
symmetrized
wmwwaisolated_node_mask
T agraph
normed
axis
copy
form
dtype
symmetrized
wmagraph_sum
graph_diagonal
diag
isolated_node_mask
wwamd
T agraph
normed
axis
copy
form
dtype
symmetrized
needs_copy
wmwwaisolated_node_mask
T agraph
normed
axis
copy
form
dtype
symmetrized
graph_sum
graph_diagonal
diag
isolated_node_mask
wwamd
wmT amv
shape
dtype
T wmwdastep
T acsgraph
normed
return_diag
use_out_degree
copy
form
dtype
symmetrized
is_pydata_sparse
pydata_sparse_cls
create_lap
degree_axis
lap
wd.scipy.sparse.csgraph._validation
/
9
uInternal: dense or csr output must be true
np
inf
nan
convert_pydata_sparse_to_scipy
T aaccept_fv
issparse
format
csc
wTacsgraph
tocsr
T acopy
astype
aDTYPE
D acopy
Facsgraph_to_dense
T anull_value
ma
isMaskedArray
mask
array
data
T adtype
copy
csgraph_from_masked
csgraph_masked_from_dense
T acopy
null_value
nan_null
infinity_null
asarray
T adtype
csgraph_from_dense
T anull_value
infinity_null
nan_null
ndim
l ucompressed-sparse graph must be 2-D
shape
l
l ucompressed-sparse graph must be shape (N, N)
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
uscipy.sparse
T aissparse
uscipy.sparse._sputils
T aconvert_pydata_sparse_to_scipy
uscipy.sparse.csgraph._tools
T acsgraph_to_dense
csgraph_from_dense
csgraph_masked_from_dense
csgraph_from_masked
float64
validate_graph
uscipy\sparse\csgraph\_validation.py
u<module scipy.sparse.csgraph._validation>
Tacsgraph
directed
dtype
csr_output
dense_output
copy_if_dense
copy_if_sparse
null_value_in
null_value_out
infinity_null
nan_null
accept_fv
mask

.scipy.sparse.csgraph
J
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_scipy
u\not_existing
usparse\csgraph
T aNUITKA_PACKAGE_scipy_sparse
u\not_existing
csgraph
T aNUITKA_PACKAGE_scipy_sparse_csgraph
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
urestructuredtext en
a__docformat__
L aconnected_components
laplacian
shortest_path
floyd_warshall
dijkstra
bellman_ford
johnson
yen
breadth_first_order
depth_first_order
breadth_first_tree
depth_first_tree
minimum_spanning_tree
reverse_cuthill_mckee
maximum_flow
maximum_bipartite_matching
min_weight_full_bipartite_matching
structural_rank
construct_dist_matrix
reconstruct_path
csgraph_masked_from_dense
csgraph_from_dense
csgraph_from_masked
csgraph_to_dense
csgraph_to_masked
aNegativeCycleError
a__all__
a_laplacian
T alaplacian
l alaplacian
l
a_shortest_path
T ashortest_path
floyd_warshall
dijkstra
bellman_ford
johnson
yen
aNegativeCycleError
shortest_path
floyd_warshall
dijkstra
bellman_ford
johnson
yen
aNegativeCycleError
a_traversal
T abreadth_first_order
depth_first_order
breadth_first_tree
depth_first_tree
connected_components
breadth_first_order
depth_first_order
breadth_first_tree
depth_first_tree
connected_components
a_min_spanning_tree
T aminimum_spanning_tree
minimum_spanning_tree
a_flow
T amaximum_flow
maximum_flow
a_matching
T amaximum_bipartite_matching
min_weight_full_bipartite_matching
maximum_bipartite_matching
min_weight_full_bipartite_matching
a_reordering
T areverse_cuthill_mckee
structural_rank
reverse_cuthill_mckee
structural_rank
a_tools
T aconstruct_dist_matrix
reconstruct_path
csgraph_from_dense
csgraph_to_dense
csgraph_masked_from_dense
csgraph_from_masked
csgraph_to_masked
construct_dist_matrix
reconstruct_path
csgraph_from_dense
csgraph_to_dense
csgraph_masked_from_dense
csgraph_from_masked
csgraph_to_masked
uscipy._lib._testutils
T aPytestTester
aPytestTester
T uscipy.sparse.csgraph
test
uscipy\sparse\csgraph\__init__.py
u<module scipy.sparse.csgraph>

.scipy.sparse.csr
Z
a__all__
a_sub_module_deprecation
sparse
csr
a_csr
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
csr_matrix
isspmatrix_csr
spmatrix
a__dir__
a__getattr__
uscipy\sparse\csr.py
u<module scipy.sparse.csr>
T aname

.scipy.sparse.data
8
a__all__
a_sub_module_deprecation
sparse
data
a_data
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
a__dir__
a__getattr__
uscipy\sparse\data.py
u<module scipy.sparse.data>
T aname

.scipy.sparse.dia
Z
a__all__
a_sub_module_deprecation
sparse
dia
a_dia
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
dia_matrix
isspmatrix_dia
spmatrix
a__dir__
a__getattr__
uscipy\sparse\dia.py
u<module scipy.sparse.dia>
T aname

.scipy.sparse.dok
Z
a__all__
a_sub_module_deprecation
sparse
dok
a_dok
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
dok_matrix
isspmatrix_dok
spmatrix
a__dir__
a__getattr__
uscipy\sparse\dok.py
u<module scipy.sparse.dok>
T aname

.scipy.sparse.extract
d
a__all__
a_sub_module_deprecation
sparse
extract
a_extract
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
L acoo_matrix
find
tril
triu
a__dir__
a__getattr__
uscipy\sparse\extract.py
u<module scipy.sparse.extract>
T aname

.scipy.sparse.lil
[
a__all__
a_sub_module_deprecation
sparse
lil
a_lil
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
isspmatrix_lil
lil_array
lil_matrix
a__dir__
a__getattr__
uscipy\sparse\lil.py
u<module scipy.sparse.lil>
T aname

.scipy.sparse.linalg._dsolve._add_newdocs
y
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
unumpy.lib
T aadd_newdoc
l
add_newdoc
T uscipy.sparse.linalg._dsolve._superlu
aSuperLU

LU factorization of a sparse matrix.
Factorization is represented as::
Pr @ A @ Pc = L @ U
To construct these `SuperLU` objects, call the `splu` and `spilu`
functions.
Attributes
----------
shape
nnz
perm_c
perm_r
L
U
Methods
-------
solve
Notes
-----
.. versionadded:: 0.14.0
Examples
--------
The LU decomposition can be used to solve matrix equations. Consider:
>>> import numpy as np
>>> from scipy.sparse import csc_array
>>> from scipy.sparse.linalg import splu
>>> A = csc_array([[1,2,0,4], [1,0,0,1], [1,0,2,1], [2,2,1,0.]])
This can be solved for a given right-hand side:
>>> lu = splu(A)
>>> b = np.array([1, 2, 3, 4])
>>> x = lu.solve(b)
>>> A.dot(x)
rray([ 1.,  2.,  3.,  4.])
The ``lu`` object also contains an explicit representation of the
decomposition. The permutations are represented as mappings of
indices:
>>> lu.perm_r
rray([2, 1, 3, 0], dtype=int32)  # may vary
>>> lu.perm_c
rray([0, 1, 3, 2], dtype=int32)  # may vary
The L and U factors are sparse matrices in CSC format:
>>> lu.L.toarray()
rray([[ 1. ,  0. ,  0. ,  0. ],  # may vary
[ 0.5,  1. ,  0. ,  0. ],
[ 0.5, -1. ,  1. ,  0. ],
[ 0.5,  1. ,  0. ,  1. ]])
>>> lu.U.toarray()
rray([[ 2. ,  2. ,  0. ,  1. ],  # may vary
[ 0. , -1. ,  1. , -0.5],
[ 0. ,  0. ,  5. , -1. ],
[ 0. ,  0. ,  0. ,  2. ]])
The permutation matrices can be constructed:
>>> Pr = csc_array((np.ones(4), (lu.perm_r, np.arange(4))))
>>> Pc = csc_array((np.ones(4), (np.arange(4), lu.perm_c)))
We can reassemble the original matrix:
>>> (Pr.T @ (lu.L @ lu.U) @ Pc.T).toarray()
rray([[ 1.,  2.,  0.,  4.],
[ 1.,  0.,  0.,  1.],
[ 1.,  0.,  2.,  1.],
[ 2.,  2.,  1.,  0.]])
T uscipy.sparse.linalg._dsolve._superlu
aSuperLU
T asolve

solve(rhs[, trans])
Solves linear system of equations with one or several right-hand sides.
Parameters
----------
rhs : ndarray, shape (n,) or (n, k)
Right hand side(s) of equation
trans : {'N', 'T', 'H'}, optional
Type of system to solve::
'N':   A   @ x == rhs  (default)
'T':   A^T @ x == rhs
'H':   A^H @ x == rhs
i.e., normal, transposed, and hermitian conjugate.
Returns
-------
x : ndarray, shape ``rhs.shape``
Solution vector(s)
T uscipy.sparse.linalg._dsolve._superlu
aSuperLU
T wLu
Lower triangular factor with unit diagonal as a
`scipy.sparse.csc_array`.
.. versionadded:: 0.14.0
T uscipy.sparse.linalg._dsolve._superlu
aSuperLU
T wUu
Upper triangular factor as a `scipy.sparse.csc_array`.
.. versionadded:: 0.14.0
T uscipy.sparse.linalg._dsolve._superlu
aSuperLU
T ashape

Shape of the original matrix as a tuple of ints.
T uscipy.sparse.linalg._dsolve._superlu
aSuperLU
T annz

Number of nonzero elements in the matrix.
T uscipy.sparse.linalg._dsolve._superlu
aSuperLU
T aperm_c

Permutation Pc represented as an array of indices.
See the `SuperLU` docstring for details.
T uscipy.sparse.linalg._dsolve._superlu
aSuperLU
T aperm_r

Permutation Pr represented as an array of indices.
See the `SuperLU` docstring for details.
uscipy\sparse\linalg\_dsolve\_add_newdocs.py
u<module scipy.sparse.linalg._dsolve._add_newdocs>

.scipy.sparse.linalg._dsolve
(
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_scipy
u\not_existing
usparse\linalg\_dsolve
T aNUITKA_PACKAGE_scipy_sparse
u\not_existing
ulinalg\_dsolve
T aNUITKA_PACKAGE_scipy_sparse_linalg
u\not_existing
a_dsolve
T aNUITKA_PACKAGE_scipy_sparse_linalg__dsolve
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
linsolve
T w*l a_superlu
T aSuperLU
aSuperLU
l

T a_add_newdocs
a_add_newdocs
T alinsolve
L
aMatrixRankWarning
aSuperLU
factorized
spilu
splu
spsolve
is_sptriangular
spsolve_triangular
use_solver
spbandwidth
a__all__
uscipy._lib._testutils
T aPytestTester
aPytestTester
T uscipy.sparse.linalg._dsolve
test
uscipy\sparse\linalg\_dsolve\__init__.py
u<module scipy.sparse.linalg._dsolve>
.scipy.sparse.linalg._dsolve.linsolve
useUmfpack
wuaassumeSortedIndices
umfpack
configure
T aassumeSortedIndices
np
float64
int32
di
complex128
zi
int64
dl
zl
dtype
name
indices
uonly float64 or complex128 matrices with int32 or int64 indices are supported! (got: matrix:

u, indices:
w)l
wlacopy
asarray
indptr
T adtype
is_pydata_spmatrix
convert_pydata_sparse_to_scipy
issparse
format
T acsc
csr
csc_array
warn
uspsolve requires A be CSC or CSR matrix format
aSparseEfficiencyWarning
D astacklevel
l wbandim
l l ashape
wAasum_duplicates
a_asfptype
promote_types
astype
utoo many values to unpack (expected 2)
umatrix must be square (has shape
umatrix - rhs dimension mismatch (
u -
noScikit
toarray
ravel
uScikits.umfpack not installed.
char
dD
uconvert matrix data to double, please, using .astype(), or set linsolve.useUmfpack.u = False
a_get_umf_family
aUmfpackContext
linsolve
aUMFPACK_A
D aautoTranspose
tacsc
intc
D acopy
FaColPerm
a_superlu
gssv
nnz
data
T aoptions
uMatrix is exactly singular
aMatrixRankWarning
fill
nan
factorized
uspsolve is more efficient when sparse b is in the CSC matrix format
:nnnaAfactsolve
flatnonzero
row_segs
col_segs
full
D adtype
Oint
data_segs
concatenate
get_index_dtype
max
T amaxval
T ashape
dtype
from_scipy_sparse
wxacls
csc_construct_func
usplu.<locals>.csc_construct_func
to_scipy_sparse
tocsc
usplu converted its input to CSC format
ucan only factor square matrices
safely_cast_index_arrays
aSuperLU
aDiagPivotThresh
aPanelSize
aRelax
aNATURAL
aSymmetricMode
gstrf
T acsc_construct_func
ilu
options
uspilu.<locals>.csc_construct_func
uspilu converted its input to CSC format
aILU_DropRule
aILU_DropTol
aILU_FillFactor
numeric
solve
ufactorized.<locals>.solve
splu
errstate
T aignore
ignore
T adivide
invalid
a__enter__
a__exit__
umf
T nnnaresult
wNacsr
wTuCSC or CSR matrix format is required. Converting to CSC matrix.
uA must be a square matrix but its shape is
w.acatch_warnings
simplefilter
ignore
setdiag
T l adiagonal
any
aLinAlgError
T uA is singular: zero entry on diagonal.
diags_array
asanyarray
T l l ub must have 1 or 2 dims but its shape is
uThe size of the dimensions of A must be equal to the size of the first dimension of b but the shape of A is
u and the shape of b is
float32
eye_array
T adtype
format
T l
gstrs
wUT uA is singular.
invdiag
reshape
T q T acsc
csr
coo
dia
dok
lil
uis_sptriangular needs sparse and not BSR format. Converting to CSR.
csr_array
dia
offsets
min
coo
coords
all
dok
keys
lil
rows
T tpq aupper
lower
T Fparepeat
arange
diff
u<genexpr>
uis_sptriangular.<locals>.<genexpr>
T acsc
csr
coo
dia
dok
uspbandwidth needs sparse format not LIL and BSR. Converting to CSR.
item
gap
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
warnings
T awarn
catch_warnings
simplefilter
numpy
T aasarray
uscipy.sparse
T aissparse
aSparseEfficiencyWarning
csr_array
csc_array
eye_array
diags_array
uscipy.sparse._sputils
T ais_pydata_spmatrix
convert_pydata_sparse_to_scipy
get_index_dtype
safely_cast_index_arrays
uscipy.linalg
T aLinAlgError
threading
T a_superlu
uscikits.umfpack
local
L	ause_solver
spsolve
splu
spilu
factorized
aMatrixRankWarning
spsolve_triangular
is_sptriangular
spbandwidth
a__all__
aUserWarning
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
