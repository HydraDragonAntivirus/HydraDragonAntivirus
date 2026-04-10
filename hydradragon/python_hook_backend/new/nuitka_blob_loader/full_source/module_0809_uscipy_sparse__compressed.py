# Reconstructed from integrated Nuitka blob
# Module: uscipy.sparse._compressed

a__qualname__
T nnFD amaxprint
nu_cs_matrix.__init__
T na_getnnz
u_cs_matrix._getnnz
u_cs_matrix.count_nonzero
T tu_cs_matrix.check_format
a_scalar_binopt
u_cs_matrix._scalar_binopt
a_add_dense
u_cs_matrix._add_dense
a_add_sparse
u_cs_matrix._add_sparse
a_sub_sparse
u_cs_matrix._sub_sparse
a_multiply_2d_with_broadcasting
u_cs_matrix._multiply_2d_with_broadcasting
a_matmul_vector
u_cs_matrix._matmul_vector
a_matmul_multivector
u_cs_matrix._matmul_multivector
u_cs_matrix._matmul_sparse
diagonal
u_cs_matrix.diagonal
T nnnu_cs_matrix.sum
u_cs_matrix._minor_reduce
a_get_intXint
u_cs_matrix._get_intXint
a_get_sliceXslice
u_cs_matrix._get_sliceXslice
a_get_arrayXarray
u_cs_matrix._get_arrayXarray
a_get_columnXarray
u_cs_matrix._get_columnXarray
u_cs_matrix._major_index_fancy
u_cs_matrix._major_slice
u_cs_matrix._minor_index_fancy
u_cs_matrix._minor_slice
u_cs_matrix._get_submatrix
a_set_intXint
u_cs_matrix._set_intXint
a_set_arrayXarray
u_cs_matrix._set_arrayXarray
a_set_arrayXarray_sparse
u_cs_matrix._set_arrayXarray_sparse
u_cs_matrix._setdiag
u_cs_matrix._prepare_indices
u_cs_matrix._set_many
u_cs_matrix._zero_many
u_cs_matrix._insert_many
u_cs_matrix.tocoo
T nnu_cs_matrix.toarray
u_cs_matrix.eliminate_zeros
property
u_cs_matrix.has_canonical_format
setter
u_cs_matrix.sum_duplicates
u_cs_matrix.has_sorted_indices
sorted_indices
u_cs_matrix.sorted_indices
u_cs_matrix.sort_indices
u_cs_matrix.prune
u_cs_matrix.resize
u_cs_matrix._with_data
u_cs_matrix._binopt
a_divide_sparse
u_cs_matrix._divide_sparse
a_broadcast_to
u_cs_matrix._broadcast_to
a__orig_bases__
uscipy\sparse\_compressed.py
T a.0
wsu<module scipy.sparse._compressed>
T aself
arg1
shape
dtype
copy
maxprint
wMwNaidx_dtype
coo
arrays
data
indices
indptr
maxval
weanewdtype
T aself
other
dtype
order
result
wywMwNT aself
other
Taself
other
op
fn
maxnnz
idx_dtype
indptr
indices
bool_ops
data
wMwNwAT aself
shape
copy
wNadata
indices
indptr
old_shape
ndim
wMaoM
oN
T a__class__
T aself
other
wraout
coords
T	aself
row
col
idx_dtype
wMwNamajor
minor
val
T aself
row
col
major
minor
T
self
row
col
wMwNamajor
minor
indptr
indices
data
T aself
major
minor
copy
wMwNai0
i1
j0
j1
indptr
indices
data
shape
T aself
axis
w_wNT aself
wiwjwxaorder
do_sort
idx_dtype
indices_parts
data_parts
ui
ui_indptr
new_nnzs
prev
wcaii
js
je
start
stop
uj
uj_indptr
nnzs
indptr_diff
T aself
idx
idx_dtype
indices
wNwManew_shape
self_indptr
self_indices
row_nnz
res_indptr
nnz
res_indices
res_data
T aself
idx
copy
wMwNastart
stop
step
new_shape
start0
stop0
start1
stop1
row_nnz
idx_dtype
res_indptr
all_idx
res_indices
res_data
nnz
T adata
is_array
csr_array
csr_matrix
wNaidx_dtype
indptr
indices
T aself
other
wMwNan_vecs
result
fn
T aself
other
wMaK1
o_ndim
aK2
wNanew_shape
faux_shape
index_arrays
wswoaidx_dtype
s_indptr
s_indices
o_indptr
o_indices
nnz
new_idx_dtype
indptr
indices
data
res
T aself
other
wMwNaresult
fn
T aself
idx
idx_dtype
indices
indptr
wMwNwkanew_shape
col_offsets
res_indptr
col_order
nnz
res_indices
res_data
T aself
ufunc
data
major_index
value
T aself
idx
copy
wMwNastart
stop
step
T aself
other
result
sM
sN
oM
oN
is_array
new_other
copy
new_self
bshape
ret
data
other2d
idx_dtype
row
col
T aself
wiwjwMwNacheck_bounds
T asl
num
i0
i1
stride
T aself
other
op
res
T aself
row
col
wxwiwjT aself
row
col
wxwMwNabroadcast_row
broadcast_col
wrwcwiwjT
self
wiwjwxwMwNan_samples
offsets
ret
mask
T aself
values
wkwMwNabroadcast
max_index
wiwjwxan_samples
offsets
ret
is_existing
aN_new
is_new
do_sort
coo
arrays
w_T aself
data
copy
T aself
wiwjwMwNan_samples
offsets
ret
T aindices
bound
idx
T aself
full_check
wxwMwNaidx_dtype
T aself
axis
w_wNamask
idx
pairs
T aself
wkwMwNw_wyT aself
wMwNT aself
wMT aself
val
T aself
major_dim
Taself
shape
bm
bn
new_M
rm
new_N
rn
wMwNamask
major_index
val
T aself
wAT aself
axis
dtype
out
res_dtype
ret
major_index
value
T aself
order
out
wxwywMwNT aself
copy
csr
major_dim
minor_dim
minor_indices
major_indices
coords
.scipy.sparse._construct
N aisintlike
uInvalid axis

u. Must be an integer.
l
ndim
l u for N=
u. Must be in [-N-1, N].
tocoo
T tT acopy
np
zeros_like
coords
shape
T l a_shape
format
coo
has_canonical_format
arange
removeprefix
T uindex
split
T u axis
l uInvalid axis:
u ndim=
permute_dims
T aaxes
copy
:nnq uIncorrect number of axes:
u instead of
axes
T Otuple
Olist
issubdtype
dtype
integer
uaxis must be an integer/tuple of ints, not
uaxis must be an integer. (given
w)aax
uaxis out of range for ndim
canon_axes
uduplicate value in axis
copy
wAu<genexpr>
upermute_dims.<locals>.<genexpr>
utoo many values to unpack (expected 2)
dia_matrix
T ashape
asformat
isscalarlike
atleast_1d
uDifferent number of diagonals and offsets.
result_type
a_NoValue
common_type
skip_file_prefixes
a__file__
warnings
warn
uInput has data type
u, but the output has been cast to
u.  In the future, the output data type will match the input. To avoid this warning, set the `dtype` parameter to `None` to have the output dtype match the input, or set it to the desired output data type.
aFutureWarning
max
min
wmwnazeros
T adtype
uOffset
u (index
u) out of bounds
data_arr
uDiagonal length (index
u:
u at offset
u) does not agree with array size (
u,
u).
dia_array
diags_array
T aoffsets
shape
dtype
eye
T adtype
format
a_eye
csr_array
csc_array
coo_array
csr_matrix
csc_matrix
coo_matrix
diags
T acsr
csc
get_index_dtype
T amaxval
ones
csr
csc
sparray
bsr_array
bsr_matrix
bsr
l annz
math
prod
D acopy
tatoarray
data
repeat
size
reshape
q aindices
indptr
asarray
idx_dtype
wBandim_diff
new_co
ravel
ukron.<locals>.<genexpr>
eye_array
identity
ukronsum requires 2D inputs. `A` is
uD.
ukronsum requires 2D inputs. `B` is
uA is not square
uB is not square
upcast
kron
D aformat
coo
concatenate
a_shape_as_2d
T aarrays
maxval
empty
T l
uincompatible dimensions for axis
sum_indices
sum_dim
axis
:nq nalast_indptr
u_compressed_sparse_stack.<locals>.<genexpr>
uMissing block matrices
uMismatching dimensions along axis
utoo many values to unpack (expected 1)
array
empty_like
csr_hstack
a_csc_container
constant_dim
a_csr_container
u_stack_along_minor_axis.<locals>.<genexpr>
D adtype
object
flat
a_block
D areturn_spmatrix
tuhstack.<locals>.<genexpr>
uvstack.<locals>.<genexpr>
ubmat.<locals>.<genexpr>
ublocks must be 2-D
T nacsr
a_stack_along_minor_axis
:nnna_compressed_sparse_stack
blocks
T :nnnl
astype
D acopy
FT nacsc
T l
:nnnD adtype
Obool
int64
block_mask
brow_lengths
ublocks[
u,:] has incompatible row dimensions. Got blocks[
w,u].shape[0] ==
u, expected
w.abcol_lengths
ublocks[:,
u] has incompatible column dimensions. Got blocks[
u].shape[1] ==
append
cumsum
nonzero
add
row
T aout
dtype
col
issparse
u_block.<locals>.<genexpr>
numbers
aNumber
atleast_2d
idx_arrays
r_idx
c_idx
divmod
nrows
ncols
T ashape
dtype
ublock_diag.<locals>.<genexpr>
a_random
urandom_array.<locals>.<genexpr>
udensity expected to be 0 <= density <= 1
round
check_random_state
data_sampler
u_random.<locals>.data_sampler
complexfloating
uniform
iinfo
choice
T asize
replace
unravel_index
wFT ashape
order
seen
update
rng_integers
rng
T asize
wTJZ
f
?u_random.<locals>.<genexpr>
data_rvs_kw
urandom.<locals>.data_rvs_kw
data_rvs
random
a__doc__
a__spec__
origin
has_location
a__cached__
urestructuredtext en
a__docformat__
L aspdiags
eye
identity
kron
kronsum
hstack
vstack
bmat
rand
random
diags
block_diag
diags_array
block_array
eye_array
random_array
expand_dims
permute_dims
swapaxes
a__all__
os
sys
numpy
uscipy._lib._util
T acheck_random_state
rng_integers
a_transition_to_rng
a_transition_to_rng
uscipy._lib.deprecation
T a_NoValue
a_sputils
T aupcast
get_index_dtype
isscalarlike
isintlike
a_sparsetools
T acsr_hstack
a_bsr
T absr_matrix
bsr_array
a_coo
T acoo_matrix
coo_array
a_csc
T acsc_matrix
csc_array
a_csr
T acsr_matrix
csr_array
a_dia
T adia_matrix
dia_array
a_base
T aissparse
sparray
D aaxis
l
expand_dims
swapaxes
T nFT nnnaspdiags
offsets
T wdnT nD wkadtype
format
l
Ofloat
nT nl
Ofloat
nakronsum
T nnahstack
vstack
bmat
D aformat
dtype
nnablock_array
T Fablock_diag
T arandom_state
D adensity
format
dtype
rng
data_sampler
f{  G z ?acoo
nnnarandom_array
T f{  G z ?nnnnT arandom_state
l T aposition_num
T f{  G z ?acoo
nnnT f{  G z ?acoo
nnarand
uscipy\sparse\_construct.py
T a.0
wbT a.0
block
T a.0
wbaaxis
T a.0
co
idx_dtype
T a.0
waT a.0
wawbT a.0
idx
wAu<module scipy.sparse._construct>
T ablocks
format
dtype
return_spmatrix
wMwNwAablock_mask
brow_lengths
bcol_lengths
wiwjamsg
nnz
all_dtypes
row_offsets
col_offsets
shape
data
idx_dtype
row
col
ii
jj
wBaidx
T ablocks
axis
return_spmatrix
other_axis
data
constant_dim
idx_dtype
indices
indptr
last_indptr
sum_dim
sum_indices
wbaidxs
T wmwnwkadtype
format
as_sparray
csr_sparse
csc_sparse
coo_sparse
diags_sparse
idx_dtype
indptr
indices
data
cls
row
col
T ashape
density
format
dtype
rng
data_sampler
tot_prod
size
idx_dtype
raveled_ind
ind
ndim
seen
dsize
vals
T ablocks
axis
n_blocks
other_axis
other_axis_dims
constant_dim
indptr_list
data_cat
sum_dim
nnz
idx_dtype
stack_dim_cat
indptr_cat
indices_cat
indptr
indices
data
T ablocks
format
dtype
T amats
format
dtype
container
row
col
data
idx_arrays
r_idx
c_idx
waanrows
ncols
a_row
a_col
idx_dtype
new_shape
T asize
data_rvs
T adata_rvs
T asize
rng
T arng
T asize
rng
dtype
T adtype
rng
T adiagonals
offsets
shape
format
dtype
wAT adiagonals
offsets
shape
format
dtype
wmafuture_dtype
warn_kwargs
extra_msg
wnwMadata_arr
wKwjadiagonal
offset
wkalength
weT wAaaxis
idx
newA
new_coord
T wmwnwkadtype
format
T wnadtype
format
T wAwBaformat
bsr_sparse
csr_sparse
coo_sparse
output_shape
data
ndim_diff
aA_shape
aB_shape
idx_dtype
coords
new_co
co
aB_shape_i
T
wAwBaformat
coo_sparse
identity_sparse
dtype
aI_n
aI_m
wLwRT wAaaxes
copy
ndim
canon_axes
ax
T wmwnadensity
format
dtype
rng
T
wmwnadensity
format
dtype
rng
data_rvs
data_rvs_kw
vals
ind
T	ashape
density
format
dtype
rng
data_sampler
data
ind
idx_dtype
T adata
diags
wmwnaformat
T wAaaxis1
axis2
axes
err
msg
.scipy.sparse._coo
A.
a_data_matrix
a__init__
T amaxprint
copy_if_needed
isshape
a_allow_nd
T aallow_nd
check_shape
a_shape
a_get_index_dtype
max
T amaxval
getdtype
D adefault
Ofloat
coords
np
array
T L
T adtype
data
has_canonical_format
utoo many values to unpack (expected 2)
T ETypeError
EValueError
uinvalid input format
ucannot infer dimensions from zero sized index arrays
shape
T amaxval
check_contents
getdata
copy
T acopy
dtype
issparse
format
astype
tocoo
T acopy
D acopy
Faasarray
sparray
atleast_2d
ndim
l uexpected 2D array or matrix, not

wDwMuinconsistent shapes:
u !=
nonzero
a_check
idx_dtype
u<genexpr>
u_coo_base.__init__.<locals>.<genexpr>
operator
index
l aindex_dtype
int64
q azeros_like
col
setflags
T FT awrite
ucannot set row attribute of a 1-dimensional sparse array
dtype
:nq n:q nnq :nq nacheck_reshape_kwargs
a_ravel_coords
T aorder
wCl
:nnq aunravel_index
T ashape
copy
u_coo_base.reshape.<locals>.<genexpr>
uall index and data arrays must have the same length
ucoordinates and data arrays must be 1-D
uaxis out of bounds
bincount
downcast_intp_index
T aminlength
nnz
u_coo_base._getnnz.<locals>.<genexpr>
sum_duplicates
count_nonzero
umismatching number of index arrays for shape; got
u, expected
kind
wiawarn
uindex array
u has non-integer dtype (
name
w)D astacklevel
l ato_native
self
uaxis
u index
u exceeds matrix dimension
min
unegative axis
u index:
u_coo_base._check.<locals>.<genexpr>
a__len__
uaxes don't match matrix dimensions
urepeated axis in transpose
T l l
uSparse matrices do not support an 'axes' parameter because swapping dimensions is the only logical permutation.
axes
u_coo_base.transpose.<locals>.<genexpr>
uonly 1-D or 2-D input accepted
ushape argument must be 1-D or 2-D
math
prod
T q T l areshape
logical_and
reduce
all
u_coo_base.resize.<locals>.<genexpr>
mask
a_process_toarray_args
flags
f_contiguous
c_contiguous
uOutput array must be C or F contiguous
coo_todense_nd
ravel
T wAacoo_todense
row
append
cumprod
:l nnaconcatenate
uCannot convert. CSC format must be 2D. Got
a_csc_container
a_csc
T acsc_array
csc_array
a_coo_to_compressed
a_swap
utoo many values to unpack (expected 4)
T ashape
uCannot convert. CSR must be 1D or 2D. Got
a_csr_container
a_csr
T acsr_array
csr_array
a_shape_as_2d
empty
empty_like
coo_tocsr
uCannot convert. DIA format must be 2D. Got
unique
D areturn_inverse
tuConstructing a DIA matrix with
u diagonals is inefficient
aSparseEfficiencyWarning
D astacklevel
l asize
zeros
T T l
pa_dia_container
uCannot convert. DOK must be 1D or 2D. Got
a_dok_container
a_dict
udiagonal requires two dimensions
T l
a_sum_duplicates
diag_mask
u_coo_base.diagonal.<locals>.<genexpr>
usetting a diagonal requires two dimensions
logical_or
arange
max_index
:nnnanew_data
T ashape
dtype
u_coo_base._with_data.<locals>.<genexpr>
a_validate_indices
ones
bool_
index_mask
slice_coords
indices
utoo many values to unpack (expected 3)
divmod
arr_coords
arr_indices
sum
T :nnn:nnnnT aaxis
insert
new_coords
coord_like
coo_array
new_shape
a_get_sparse_data_and_coords
a_get_dense_data_and_coords
a_zero_many
isintlike
pos
x_ax
arr_shape
x_axes
broadcast_to
new_nnz
x_arr_coo_ravel
D aaxis
return_index
l tahstack
u_coo_base.__setitem__.<locals>.<genexpr>
mod
lexsort
utoo many values to unpack (expected 1)
add
reduceat
order
u_coo_base._sum_duplicates.<locals>.<genexpr>
unique_mask
u_coo_base.eliminate_zeros.<locals>.<genexpr>
uIncompatible shapes (
u and
upcast_char
char
T adtype
copy
a_container
l atocsr
a_add_sparse
D aaxis
l a_sub_sparse
coo_matvec_nd
ucoo_matvec not implemented for ndim=
coo_matvec
isscalarlike
a_mul_scalar
:q nnaother
transpose
a_matmul_dispatch
ret
multiply
isdense
asanyarray
object_
a_spbase
ndarray
a_matmul_vector
umatmul: dimension mismatch with signature (n,k=
u),(k=
u,)->(n,)
broadcast_shapes
uBatch dimensions are not broadcastable
a_matmul_multivector
umatmul: dimension mismatch with signature (n,..,k=
u,..,m)->(n,..,m)
a_matmul_sparse
a_broadcast_to
:q q nacoo_matmat_dense_nd
T wCaresult_shape
coo_matmat_dense
view
T atype
udot argument not supported type: '
w'ushapes
u are not aligned for n-D dot
a_dense_dot
a_sparse_dot
a_convert_to_2d
wTao_new_shape
utensordot arg not supported type: '
a_process_axes
usizes of the corresponding axes must match
a_dense_tensordot
a_sparse_tensordot
u_coo_base.tensordot.<locals>.<genexpr>
dot
a_block_diag
a_extract_block_diag
uNew shape must have at least as many dimensions as the current shape
ucurrent shape
u cannot be broadcast to new shape {new_shape}
get_index_dtype
tile
repeat
cum_repeat
u_coo_base._broadcast_to.<locals>.<genexpr>
a_min_or_max_axis
a_argminmax_axis
uarray must have atleast dim=2
D adtype
Oint
temp_block_idx
zeroslike
x_shape
x_coords
ushape mismatch in assignment
nn
tot_expand
squeeze
wxuaxes integer is out of bounds for input arrays
HT Otuple
Olist
uaxes must be a tuple/list of length 2
uaxes lists/tuples must be of the same length
uaxes indices are out of bounds for input arrays
uaxes must be an integer or a tuple/list of integers
axes_a
ndim_a
axes_b
ndim_b
u_process_axes.<locals>.<genexpr>
non_axis_shape
coo
u_convert_to_2d.<locals>.<genexpr>
axis
wFu'order' must be 'C' or 'F'
ravel_multi_index
coo_matrix
pop
T arow
T acol
update
u'coo_matrix' object is not subscriptable
u'coo_matrix' object does not support item assignment
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
urestructuredtext en
a__docformat__
isspmatrix_coo
a__all__
warnings
T awarn
numpy
u_lib._util
T acopy_if_needed
a_matrix
T aspmatrix
spmatrix
a_sparsetools
T acoo_tocsr
coo_todense
coo_todense_nd
coo_matvec
coo_matvec_nd
coo_matmat_dense
coo_matmat_dense_nd
a_base
T aissparse
aSparseEfficiencyWarning
a_spbase
sparray
a_data
T a_data_matrix
a_minmax_mixin
a_minmax_mixin
a_sputils
T aupcast_char
to_native
isshape
getdtype
getdata
downcast_intp_index
get_index_dtype
check_shape
check_reshape_kwargs
isscalarlike
isintlike
isdense
a_index
T a_validate_indices
a__prepare__
a_coo_base
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
