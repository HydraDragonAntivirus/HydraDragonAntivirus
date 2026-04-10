# Reconstructed from integrated Nuitka blob
# Module: unumpy._core.tests.test_nditer

utest_iter_allocate_output_subtype.<locals>.MyNDArray
a__qualname__
l a__array_priority__
a__orig_bases__
L L l l L l l L L areadonly
L areadonly
L awriteonly
allocate
no_subtype
L L awriteonly
L awriteonly
allocate
L L areadonly
L aallocate
readonly
allocate
L L awriteonly
allocate
L awriteonly
allocate
L nL l
l l L nL l
l l l
reduce_ok
L L areadonly
L areadwrite
allocate
T L nL aint64
T L nL aint64
T l l l T aop_dtypes
itershape
remove_axis
T :nnnl
:nnnT :nnq :nnn:nnnT l
:nnn:nnnaitviews
remove_multi_index
utest_iter_remove_multi_index_inner_loop.<locals>.<lambda>
enable_external_loop
l T l l l T L
L abuffered
buffersize
T abuffersize
iter_iterindices
L l
l l l l l l l l l	l
l l ll l l l l l l l l l L l l l l l l l l	l
l l ll l l l l l l l l l wFT aorder
buffersize
L l l l l l	l
l l ll l l l l l l l l l l	L l	l
l l ll l l l l l l l l l lL ll l l l l l l l l l T :nnl :nnq l D aorder
buffersize
wFl T l
l T T l
l T l l T l l T l pT l
l T l l D aorder
op_dtypes
buffersize
wFaf8
l aget_array
utest_iter_iterrange.<locals>.get_array
T L
f8
concatenate
val
T l ac16
T l
f4
T T lAai1
i4
T l ai4
T lxai4
T l l l l T l l l l l l l l  L L areadonly
nbo
aligned
T aorder
casting
buffersize
vals
L L areadwrite
nbo
aligned
D acasting
order
buffersize
equiv
wCl wxT l af4
L abuffered
delay_bufalloc
multi_index
reduce_ok
D acasting
op_dtypes
unsafe
f4
has_delayed_bufalloc
utest_iter_buffering_delayed_alloc.<locals>.<lambda>
assign_iter
utest_iter_buffering_delayed_alloc.<locals>.assign_iter
;l
l l T acasting
op_dtypes
buffersize
suppress_warnings
filter
exceptions
aComplexWarning
T l
f8
T ac8
T l
c8
JZ
f
@JZ
f
@aclongdouble
longdouble
l L T waaf4
T wbai8
T wcac8
T l l T wdwOT l af4
f
?wcL L f
?f
?f
?pwdL L f
?f
?f
?pT T l wOT f
?f
?L L f
?f
?f
?L f
?f
?f
?f
?T f
?f
?L L f
?f
?f
?L f
?f
?f
?f
?T f
@f
@L L f
@f
@f
@L f
@f
@f
@f
@T waaf4
T L T f
@T l l T wbai8
T wdwOT L T f
@l atest
T l l
l utest_iter_buffered_cast_structured_type.<locals>.<lambda>
T wdau2
T wawOT wbaf8
T L T l l l T l l l T T l l l T T l l l T wbwOT waaf8
T areadwrite
readonly
writeonly
T L l l ui,i
pytest
raises
T ETypeError
uf,f
sdt2
T EValueError
T waaS1
D aop_dtypes
casting
flags
L wiaunsafe
L abuffered
T l wiD aop_dtypes
op_flags
casting
flags
L aS1
L awriteonly
unsafe
L abuffered
textwrap
dedent
T u
import numpy as np
it = np.nditer((np.array(1, dtype="i"),), op_dtypes=["S1"],
op_flags=["writeonly"], casting="unsafe", flags=["buffered"])
buf = next(it)
buf[...] = "a"
del buf, it  # Flushing only happens during deallocate right now.
subprocess
check_output
executable
u-c
aSTDOUT
T astderr
text
T waaf8
T l l pT T l T wawOT l pT wawOT l l pT :nnnl
pacount
T l l pT wawOT l T :nnnl
ppT l l ppT T l l l pT waaf4
T l T waaf4
T l l pT lHT l l l pT waaf8
T l T waaf4
T l T l p:nl nT waaf8
T l T waaf4
T l T l l :l nnT waaf4
T l pT waaf8
T l l T waaf4
T l l T l l l T :nl nl
T :nnnl
T :nl nl T l :nnnT waaf8
T l l T l l l T :nnnl T l l l L L areadwrite
L awriteonly
T l ppT l l l T l l l abytes_
T L aabc
waaabcd
T aS4
D aop_dtypes
aS2
D aop_dtypes
aS6
cabc
T aS6
str_
T aU4
D aop_dtypes
aU2
D aop_dtypes
aU6
abc
T aU6
T l agrowinner
D abuffersize
l T l  :l  l  nL abuffered
delay_bufalloc
multi_index
reduce_ok
refs_ok
T areadonly
T areadwrite
allocate
L L T l
l l T l
l q L T l
l l T l
q paget_params
utest_iter_buffered_reduce_reuse.<locals>.get_params
op_flags
op_dtypes
T aop_axes
flags
op_flags
op_dtypes
q aint_
;l
l l aarr
op_axes
T aop_axes
flags
op_flags
buffersize
op_dtypes
skip
res
comp_res
;q	l
l aop_axes_list
xs
ys
lib
stride_tricks
as_strided
T l ppL L areadonly
no_broadcast
L areadonly
L areadonly
L L areadonly
L areadonly
no_broadcast
L areadonly
L L areadonly
L areadonly
L areadonly
no_broadcast
nested_iters
L L l
L l l L L l
l l l l l L l l l l	l
l L L l
l L l L L l
l L l l L l l L l l L l l	L l
l L L l
l L l L L l
l l L l l l L l l l
L l l	l L L l
L l l L L l l
L l L L l l
L l L L l
l l l l l L l l l
l l	l L L l
l L l l L l l L l l	L l l L l
l L L l
l l L l l l
L l l l L l l	l T :nnq :nnq :nnq L L l l
l	l l l L l l l l l l
L L l l
L l	l L l l L l l L l l L l l
L L l l	l L l
l l L l l l L l l l
L L l
L l L L L l
pL l
l L l
l L L l l
L l pL l l L L l L l
L L L l
pL l l
L L l
l L l pL L l
l L l l D aop_flags
op_dtypes
L areadonly
copy
f8
L L l
l l L l l l D aop_flags
casting
op_dtypes
L areadwrite
updateifcopy
same_kind
f8
L L l l l L l l l aclose
D aflags
op_flags
casting
op_dtypes
L abuffered
L areadwrite
same_kind
f8
L L
L l l
l L L l
l l l l l l l l l	l
l L L l l
l L
L L l
L l L l L l L l L l L l L l L l L l	L l
L l L L l l
L
L l D aop_axes
L L l
L q D aop_axes
L L l
l L q pasum
wyT T l l l D aop_axes
L nL l
q l L areduce_ok
external_loop
buffered
delay_bufalloc
D aop_axes
buffersize
L nL l
q l l
fill
T Z
f8
L L areadonly
L areadwrite
nbo
T L l
paf8
D aop_axes
L L l
l L l
q D aaxis
l L adelay_bufalloc
reduce_ok
buffered
external_loop
D aop_axes
itershape
L L q l
L q pT l pL l l l l T l ll T :l l n:l l l :l l natranspose
T l l l
T l T l pT :nnl :nnnnL L areadwrite
L areadonly
T T l l T T l l D aflags
op_flags
buffersize
L areduce_ok
external_loop
buffered
L L areadonly
L areadwrite
l abufsizes
L l l l l T T l l T T l L L tpFL FtFT L l
l pau1
T L l
l pai1
T L l
l paf4
L L areadwrite
writemasked
L areadonly
L L areadonly
writemasked
L areadonly
arraymask
L L areadonly
L areadwrite
arraymask
writemasked
L L areadwrite
writemasked
L areadonly
arraymask
L areadonly
arraymask
L L areadwrite
L areadonly
arraymask
L L areadonly
L areadwrite
writemasked
L areadonly
arraymask
L L areadonly
L areadwrite
writemasked
L areadwrite
arraymask
L L areadwrite
writemasked
L areadonly
arraymask
D aop_dtypes
casting
L af4
nasame_kind
empty
D adtype
Obool
broadcast_to
may_share_memory
is_buffered
D aop_dtypes
casting
L ai8
naunsafe
T T l l aarraymask
writeonly
writemasked
T aflags
op_flags
op_axes
T l NT u>i,O
random
randint
T l
l l NT asize
T Obool
D aop_dtypes
L u<i,O
w?abuf
mask_buf
Lavalue
shape
operands
itviews
has_delayed_bufalloc
iterationneedsapi
has_multi_index
has_index
dtypes
ndim
nop
itersize
finished
delattr
it
L amulti_index
index
iterrange
iterindex
:l l nT T L l l l nL nT ai4
T l L L l
l L l l L l l T T L L l l l nL nT ai4
T l L areduce_ok
L nT q l
T aop_dtypes
flags
op_axes
T T l
l nL nnT ai4
T l pT l
pT l l
T l pL L l l L l l anext
T l D aop_axes
L T
D aop_axes
itershape
L T
T
D aitershape
T
T f
?af4
utest_object_iter_cleanup.<locals>.<lambda>
ncu
aBUFSIZE
T l
q T Ostr
T Oobject
T :nnnq utest_object_iter_cleanup.<locals>.T
a__bool__
utest_object_iter_cleanup.<locals>.T.__bool__
logical_or
reduce
T T l   l af4
add
oarr
aAmbiguous
L L nl L q pL nl L q paintp
T l >T aaxis
dtype
out
full
T l >l Oobject
iinfo
max
l  T :nnnnabase_size
num
arrays
a_multiarray_tests
test_nditer_too_large
uexit context manager on exception
getattr
writebackifcopy
l{T naadd_close
utest_close_equivalent.<locals>.add_close
add_context
utest_close_equivalent.<locals>.add_context
T ;l
l l ;l
l l ;l
l
l aaddop
T aout
record
aRuntimeWarning
l     T aop_dtypes
flags
casting
wOT l{L4u------ BEGIN ITERATOR DUMP ------
u    | Iterator Address:
u    | ItFlags: BUFFER REDUCE REUSE_REDUCE_LOOPS
u    | NDim: 2
u    | NOp: 2
u    | IterSize: 50
u    | IterStart: 0
u    | IterEnd: 50
u    | IterIndex: 0
u    | Iterator SizeOf:
u    | BufferData SizeOf:
u    | AxisData SizeOf:
u    |
u    | Perm: 0 1
u    | DTypes:
u    | DTypes: dtype('float64') dtype('int32')
u    | InitDataPtrs:
u    | BaseOffsets: 0 0
u    | Operands:
u    | Operand DTypes: dtype('int64') dtype('float64')
u    | OpItFlags:
u    |   Flags[0]: READ CAST ALIGNED
u    |   Flags[1]: READ WRITE CAST ALIGNED REDUCE
u    |
u    | BufferData:
u    |   BufferSize: 50
u    |   Size: 5
u    |   BufIterEnd: 5
u    |   REDUCE Pos: 0
u    |   REDUCE OuterSize: 10
u    |   REDUCE OuterDim: 1
u    |   Strides: 8 4
u    |   Ptrs:
u    |   REDUCE Outer Strides: 40 0
u    |   REDUCE Outer Ptrs:
u    |   ReadTransferFn:
u    |   ReadTransferData:
u    |   WriteTransferFn:
u    |   WriteTransferData:
u    |   Buffers:
u    |
u    | AxisData[0]:
u    |   Shape: 5
u    |   Index: 0
u    |   Strides: 16 8
u    |   Ptrs:
u    | AxisData[1]:
u    |   Shape: 10
u    |   Index: 0
u    |   Strides: 80 0
u    |   Ptrs:
u    ------- END ITERATOR DUMP -------
int64
T ldT l
pT :nnn:nnl T f
@D aop_dtypes
casting
flags
op_flags
L wdai4
unsafe
L areduce_ok
buffered
L L areadonly
L areadwrite
debug_print
readouterr
out
strip
splitlines
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
sys
numpy
unumpy._core.umath
a_core
umath
unumpy._core._multiarray_tests
T aarray
arange
nditer
all
unumpy.testing
T aassert_
assert_equal
assert_array_equal
assert_raises
aIS_WASM
aHAS_REFCOUNT
suppress_warnings
break_cycles
aIS_WASM
break_cycles
mark
skipif
D areason
uPython lacks refcounts
test_iter_refcount
test_iter_best_order
test_iter_c_order
test_iter_f_order
test_iter_c_or_f_order
test_nditer_multi_index_set
test_nditer_multi_index_set_refcount
test_iter_best_order_multi_index_1d
test_iter_best_order_multi_index_2d
test_iter_best_order_multi_index_3d
test_iter_best_order_c_index_1d
test_iter_best_order_c_index_2d
test_iter_best_order_c_index_3d
test_iter_best_order_f_index_1d
test_iter_best_order_f_index_2d
test_iter_best_order_f_index_3d
test_iter_no_inner_full_coalesce
test_iter_no_inner_dim_coalescing
test_iter_dim_coalescing
test_iter_broadcasting
test_iter_itershape
test_iter_broadcasting_errors
test_iter_flags_errors
test_iter_slice
test_iter_assign_mapping
test_iter_nbo_align_contig
test_iter_array_cast
test_iter_array_cast_errors
test_iter_scalar_cast
test_iter_scalar_cast_errors
test_iter_object_arrays_basic
test_iter_object_arrays_conversions
test_iter_common_dtype
test_iter_copy_if_overlap
test_iter_op_axes
test_iter_op_axes_errors
test_iter_copy
parametrize
typecodes
aAll
filterwarnings
T uignore::numpy.exceptions.ComplexWarning
test_iter_copy_casts
test_iter_copy_casts_structured
test_iter_copy_casts_structured2
test_iter_allocate_output_simple
test_iter_allocate_output_buffered_readwrite
test_iter_allocate_output_itorder
test_iter_allocate_output_opaxes
test_iter_allocate_output_types_promotion
test_iter_allocate_output_types_byte_order
test_iter_allocate_output_types_scalar
test_iter_allocate_output_subtype
test_iter_allocate_output_errors
test_all_allocated
test_iter_remove_axis
test_iter_remove_multi_index_inner_loop
test_iter_iterindex
test_iter_iterrange
test_iter_buffering
test_iter_write_buffering
test_iter_buffering_delayed_alloc
test_iter_buffered_cast_simple
test_iter_buffered_cast_byteswapped
test_iter_buffered_cast_byteswapped_complex
test_iter_buffered_cast_structured_type
test_iter_buffered_cast_structured_type_failure_with_cleanup
test_buffered_cast_error_paths
D areason
uCannot start subprocess
D areason
uPyPy seems to not hit this.
test_buffered_cast_error_paths_unraisable
test_iter_buffered_cast_subarray
test_iter_buffering_badwriteback
test_iter_buffering_string
test_iter_buffering_growinner
slow
test_iter_buffered_reduce_reuse
test_iter_no_broadcast
aTestIterNested
test_basic
uTestIterNested.test_basic
test_reorder
uTestIterNested.test_reorder
test_flip_axes
uTestIterNested.test_flip_axes
test_broadcast
uTestIterNested.test_broadcast
test_dtype_copy
uTestIterNested.test_dtype_copy
test_dtype_buffered
uTestIterNested.test_dtype_buffered
test_0d
uTestIterNested.test_0d
test_iter_nested_iters_dtype_buffered
uTestIterNested.test_iter_nested_iters_dtype_buffered
test_iter_reduction_error
test_iter_reduction
test_iter_buffering_reduction
test_iter_buffering_reduction_reuse_reduce_loops
test_iter_writemasked_badinput
a_is_buffered
T T l af8
T T l Ml af8
T :nnl :nnnT T l l  l|l af8
T :nnl :nnn:nnl :nnnT T l	af8
:nnl T T l Ml af8
T :nnl :nnl T :nnl :nnn:nnl :nnq atest_iter_writemasked
mask
mask_axes
T nL q l
T T l l abool
T l abool
T T
bool
test_iter_writemasked_broadcast_error
test_iter_writemasked_decref
test_iter_non_writable_attribute_deletion
test_iter_writable_attribute_deletion
test_iter_element_deletion
test_iter_allocated_array_dtypes
test_0d_iter
test_object_iter_cleanup
test_object_iter_cleanup_reduce
T T l >l l Oobject
T :nnn:nnl :nnnT T l >l l Oobject
wFT adtype
order
test_object_iter_cleanup_large_reduce
test_iter_too_large
test_iter_too_large_with_multiindex
test_writebacks
test_close_equivalent
test_close_raises
test_close_parameters
test_warn_noclose
in_dtype
buf_dtype
L T wiwOT wOwiT ui,O
uO,O
T uO,i
ui,O
steps
test_partial_iteration_cleanup
T wOwiT uO,i
ui,O
test_partial_iteration_error
test_debug_print
unumpy\_core\tests\test_nditer.py
T waT wiT aoarr
arr
T aarr
oarr
u<module numpy._core.tests.test_nditer>
T a__class__
T aself
T aiterator
T	wxwyaout
addop
it
wawbwcaret
T wxwyaout
addop
it
wawbwcT wiaval
wxT axs
ys
op_axes
strides
arr
skip
op_axes_list
waT waaop_axes_list
T wiaret
T aself
wawiwjavals
wkwxwyT wiasdt
waavals
T aself
wawiwjavals
T aself
wawbwiwjavals
T ait
buf
T acode
res
T aadd_close
add_context
wzT ait
T acapfd
expected
arr1
arr2
it
res
res_line
expected_line
T aself
wawiwjwxwyT aself
wawiwjavals
wxwyT wawiwxT wawiT aMyNDArray
wawbwiT ait
wawbwcT waait
wxT ashape
waadirs
dirs_index
bit
aview
wiT weamsg
T wawiwvasup
T wawiwvT asdt
wawiavals
rc
wxasdt1
sdt2
T asdt1
sdt2
waaintent
simple_arr
T asdt1
sdt2
wawiwxacount
T waaflags
op_flags
op_axes_list
op_dtypes
get_params
arr
op_axes
skip
nditer2
a2_in
b2_in
comp_res
bufsize
nditer1
a1_in
b1_in
res
T aarrays
a_tmp
waabuffersize
vals
wiT wawbT wawbwiaassign_iter
T
wawbwiwxwywjwpait
y_base
y_base_copy
T wawbait
bufsizes
T wawiwjT adtype
loop_dtype
arr
expected
it
it_copy
res
res_copy
T	ain_dtype
out_dtype
arr
it
it_copy
res1
res2
expected
field
T ain_dtype
out_dtype
arr
it
it_copy
res1
res2
res
T	aflag
wawiwxwbwcaa2
b2
c2
T wawiaa3d
T wawiaassign_multi_index
assign_index
assign_iterindex
assign_iterrange
T abuffersize
waaflags
wiT abuffersize
waaa_fort
wiwraget_array
T waaau
wiT wawbwcT ashape
size
waadirs
dirs_index
bit
aview
wiT ait
attr
wsT aobj
waarc
wiavals
wxT wawiwxaob
rc
T wawiwbT wawiwxwywjait1
it2
T waadt
rc_a
rc_dt
it
rc2_a
rc2_dt
it2
T wawiabefore
after
T wawbwcwiT asize
arr
T abase_size
num
shape_template
arrays
wiashape
mode
T waashape
reps
msk
it
wxwmais_buffered
T wawbwmam2
m3
mbad1
mbad2
T amask
mask_axes
arr
itflags
mask_flags
a_flags
op_axes
T aarr
original
mask
it
singleton
count
buf
mask_buf
T waait
T aindex
wiastart_count
end_count
T aarr
oarr
wTT aarr
out
res
T aarr
T ain_dtype
buf_dtype
steps
value
arr
it
step
T ain_dtype
buf_dtype
value
arr
count
it
T waaau
sup
it
T waaau
it
wxaenter

.numpy._core.tests.test_nep50_promotions
y
np
uint8
T l l aarray
l aint64
T adtype
pytest
warns
aRuntimeWarning
D amatch
overflow
a__enter__
a__exit__
T ldl  T nnnafloat32
f;%_  n Tf       ?afloat64
T f       ?f
?T l adtype
type
iinfo
max
errstate
T awarn
T aover
finfo
dDG
raises
T EOverflowError
gG
skip
T u`huge_int -> string -> longdouble` failed
add
l l  f
@D amatch
u.*overflow
complex64
l  T EOverflowError
u.*uint8
T amatch
T EOverflowError
uPython integer -1 out of bounds for uint8
q ar_
arange
int8
T l l  T l
g
uint64
g
ldaconcatenate
D aaxis
nachoose
draw
strategies
lists
sampled_from
permutations
result_type
l
T L l
pOobject
astype
assert_array_equal
ones_like
D adtype
Obool
zeros_like
min
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
operator
l
threading
warnings
numpy
hypothesis
T astrategies
unumpy.testing
T aassert_array_equal
aIS_WASM
aIS_WASM
mark
skipif
D areason
uwasm doesn't have support for fp errors
test_nep50_examples
parametrize
typecodes
aAllInteger
test_nep50_weak_integers
aAllFloat
test_nep50_weak_integers_with_inexact
op
pow
test_weak_promotion_scalar_path
test_nep50_complex_promotion
test_nep50_integer_conversion_errors
test_nep50_with_axisconcatenator
ufunc
power
test_nep50_huge_integers
test_nep50_in_concat_and_choose
uexpected,dtypes,optional_dtypes
float16
Z
uint16
int16
JZ
Z
int32
bool
given
data
T adata
test_expected_promotion
sctype
uint32
other_val
L q  q l
l	l
l g
l  acomp
eq
ne
le
lt
ge
gt
test_integer_comparison
arr
ones
T T ldp:nnl T l   u>u4
T ldu>u4
test_integer_comparison_with_cast
equal
not_equal
less_equal
less
greater_equal
greater
test_integer_integer_comparison
create_with_scalar
create_with_array
create
test_oob_creation
unumpy\_core\tests\test_nep50_promotions.py
u<module numpy._core.tests.test_nep50_promotions>
T asctype
value
T aexpected
dtypes
optional_dtypes
data
optional
all_dtypes
dtypes_sample
res
T asctype
other_val
comp
val_obj
val
T aarr
res
T acomp
T ares
T aufunc
res
T adtype
scalar_type
maxint
res
T adtype
scalar_type
too_big_int
res
T asctype
create
iinfo
T aop
res

.numpy._core.tests.test_numeric
S
np
array
L L l l L l l L L l l l l L l l l l aassert_equal
resize
T l l L L l l L l l L l l L l l T l l L L l l l L l l l L l l l L l l l T l l l l l L L l l l l L l l l l L L l l L l l L l l L l l L L l l l L l l l L l l l L l l l T l
assert_array_equal
dtype
T l
l ashape
T l l
zeros
waafloat32
T adtype
T l l aarange
T l
l
pytest
raises
T EValueError
negative
T amatch
a__enter__
a__exit__
D anew_shape
T q
q T nnnandarray
l
a__prepare__
aMyArray
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
