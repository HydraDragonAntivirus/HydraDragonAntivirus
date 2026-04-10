# Reconstructed from integrated Nuitka blob
# Module: unumpy.compat.py3k

contextlib_nullcontext
a__qualname__
T na__init__
ucontextlib_nullcontext.__init__
a__enter__
ucontextlib_nullcontext.__enter__
a__exit__
ucontextlib_nullcontext.__exit__
npy_load_module
fspath
os_fspath
aPathLike
os_PathLike
unumpy\compat\py3k.py
u<module numpy.compat.py3k>
T aself
T aself
excinfo
T aself
enter_result
T wsT wxT aobj
T wfT aname
fn
info
aSourceFileLoader
T afilename
mode

.numpy.compat.tests
h
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_numpy
u\not_existing
ucompat\tests
T aNUITKA_PACKAGE_numpy_compat
u\not_existing
tests
T aNUITKA_PACKAGE_numpy_compat_tests
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
unumpy\compat\tests\__init__.py
u<module numpy.compat.tests>

.numpy.conftest
addinivalue_line
T amarkers
uvalgrind_error: Tests that are known to error under valgrind.
T amarkers
uleaks_references: Tests that are known to leak references.
T amarkers
uslow: Tests that are very slow.
T amarkers
uslow_pypy: Tests that are very slow on pypy.
addoption
T u--available-memory
store
nuSet amount of memory available for running the test suite. This can result to tests requiring especially large amounts of memory to be skipped. Equivalent to setting environment variable NPY_AVAILABLE_MEM. Default: determinedautomatically.
T aaction
default
help
config
getoption
T aavailable_memory
environ
aNPY_AVAILABLE_MEM
aNOGIL_BUILD
gil_enabled_at_start
a_is_gil_enabled
ensure_newline
section
T uGIL re-enabled
w=tpT asep
red
bold
line
T uThe GIL was re-enabled at runtime during the tests.
T uThis can happen with no test failures if the RuntimeWarning
T uraised by Python when this happens is filtered by a test.
T u
T uPlease ensure all new C modules declare support for running
T uwithout the GIL. Any new tests that intentionally imports
T ucode that re-enables the GIL should do so in a subprocess.
pytest
exit
T uGIL re-enabled during tests
l T areturncode
get_fpu_mode
a_old_fpu_mode
a_collect_results
uFPU precision mode changed from {0:#x} to {1:#x} during the test
get
request
node
utoo many values to unpack (expected 2)
uFPU precision mode changed from {0:#x} to {1:#x} when collecting the test
check_fpu_mode
numpy
np
setenv
T aPYTHONHASHSEED
w0L uThe numpy.linalg.linalg
uThe numpy.fft.helper
dep_util
pkg_resources
unumpy.core.umath
msvccompiler
uDeprecated call
unumpy.core
u`np.compat`
uImporting from numpy.matlib
uThis function is deprecated.
uData type alias 'a'
uArrays of 2-dimensional vectors
u`in1d` is deprecated
w|uinvalid value encountered
udivide by zero encountered
warnings
catch_warnings
a__enter__
a__exit__
filterwarnings
aDeprecationWarning
T aignore
T acategory
message
aRuntimeWarning
T nnnawarnings_errors_and_rng
string
ascii_letters
digits
array
D adtype
aU1
random
choice
D asize
replace
l  taview
T aU100
param
get_stringdtype_dtype
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
os
l
sys
tempfile
contextlib
T acontextmanager
contextmanager
hypothesis
unumpy._core._multiarray_tests
T aget_fpu_mode
unumpy._core.tests._natype
T apd_NA
pd_NA
unumpy.testing._private.utils
T aNOGIL_BUILD
get_stringdtype_dtype
uscipy_doctest.conftest
T adt_config
dt_config
aHAVE_SCPDT
configuration
set_hypothesis_home_dir
join
gettempdir
u.hypothesis
settings
register_profile
T unumpy-profile
ntT aname
deadline
print_blob
unp.test() profile
aHealthCheck
T aname
deadline
print_blob
database
derandomize
suppress_health_check
u..
upytest.ini
a_pytest_ini
load_profile
unumpy-profile
w1aNUMPY_EXPERIMENTAL_DTYPE_API
pytest_configure
pytest_addoption
pytest_sessionstart
pytest_terminal_summary
hookimpl
pytest_itemcollected
fixture
T afunction
tT ascope
autouse
T tT aautouse
add_np
env_setup
T nauser_context_mgr
rndm_markers
add
T u#uninitialized
T u# uninitialized
strict_check
doctest
aNORMALIZE_WHITESPACE
aELLIPSIS
optionflags
dtypes
aStringDType
check_namespace
S unumpy.savez
unumpy.__array_namespace_info__
unumpy.matlib.__array_namespace_info__
unumpy.matlib.savez
skiplist
D uhow-to-verify-bug.rst
uc-info.ufunc-tutorial.rst
ubasics.interoperability.rst
ubasics.dispatch.rst
ubasics.subclassing.rst
umisc.rst

puneeds pandas
uerrors out in /testing/overrides.py
u.. testcode:: admonitions not understood
umanipulates warnings
pytest_extra_xfail
L unumpy/distutils
unumpy/_core/cversions.py
unumpy/_pyinstaller
unumpy/random/_examples
unumpy/compat
unumpy/f2py/_backends/_distutils.py
pytest_extra_ignore
random_string_list
T L tFT aparams
coerce
unset
nan
Z a__nan__
L aunset
aNone
upandas.NA
unp.nan
ufloat('nan')
ustring nan
T aparams
ids
na_object
dtype
unumpy\conftest.py
u<module numpy.conftest>
T adoctest_namespace
T arequest
old_mode
new_mode
collect_result
T arequest
T ana_object
coerce
T amonkeypatch
T aparser
T aconfig
T aitem
mode
T asession
available_mem
T aterminalreporter
exitstatus
config
tr
T achars
ret
T atest
msgs
msg
msgs_r
msg_r

.numpy
e7
join
a__file__
u..
unumpy.libs
add_dll_directory
warnings
l
linalg
unumpy.linalg
fft
unumpy.fft
dtypes
unumpy.dtypes
random
unumpy.random
polynomial
unumpy.polynomial
ma
unumpy.ma
ctypeslib
unumpy.ctypeslib
exceptions
unumpy.exceptions
testing
unumpy.testing
matlib
unumpy.matlib
f2py
unumpy.f2py
typing
unumpy.typing
rec
unumpy.rec
char
unumpy.char
array_api
uexceptions.AttributeError does not take keyword arguments
core
unumpy.core
strings
unumpy.strings
distutils
a__numpy_submodules__
unumpy.distutils
a__future_scalars__
warn
uIn the future `np.

u` will be defined as the corresponding NumPy scalar.
aFutureWarning
D astacklevel
l a__former_attrs__
a__expired_attributes__
u`np.
u` was removed in the NumPy 2.0 release.
chararray
u`np.chararray` is deprecated and will be removed from the main namespace in the future. Use an array with a string or bytes dtype instead.
aDeprecationWarning
umodule {!r} has no attribute {!r}
numpy
keys
S aarray_api
matlib
matrixlib
distutils
version
compat
tests
conftest
ones
float32
T l T adtype
abs
dot
T f
@f h     >uThe current Numpy installation ({!r}) fails to pass simple sanity checks. This can be caused for example by incorrect BLAS library being linked in, or by mixing package managers (pip, conda, apt, ...). Search closed numpy issues for similar problems.
array
f
@f
@f
?alinspace
T l
l l apolyval
polyfit
l D acov
taos
environ
get
T aNUMPY_MADVISE_HUGEPAGE
nasys
platform
linux
l auname
release
split
T w.:nl nT l l u<genexpr>
uhugepage_setup.<locals>.<genexpr>
pathlib
T aPath
aPath
with_name
T a_pyinstaller
resolve
a__doc__
path
dirname
T aNUITKA_PACKAGE_numpy
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
a_delvewheel_patch_1_10_1
a_globals
T a_NoValue
a_CopyMode
a_NoValue
a_CopyMode
a_expired_attrs_2_0
T a__expired_attributes__
T aversion
version
T a__version__
a__version__
a__NUMPY_SETUP__
stderr
write
T uRunning from numpy source directory.
T a_distributor_init
a_distributor_init
unumpy.__config__
T ashow_config
show_config
weuError importing numpy: you should not try to import numpy from
its source directory; please exit the numpy source tree, and relaunch
your python interpreter from there.
msg
T a_core
a_core
T  aFalse_
aScalarType
aTrue_
abs
absolute
acos
acosh
add
all
allclose
amax
amin
any
arange
arccos
arccosh
arcsin
arcsinh
arctan
arctan2
arctanh
argmax
argmin
argpartition
argsort
argwhere
around
array
array2string
array_equal
array_equiv
array_repr
array_str
asanyarray
asarray
ascontiguousarray
asfortranarray
asin
asinh
atan
atanh
atan2
astype
atleast_1d
atleast_2d
atleast_3d
base_repr
binary_repr
bitwise_and
bitwise_count
bitwise_invert
bitwise_left_shift
bitwise_not
bitwise_or
bitwise_right_shift
bitwise_xor
block
bool
bool_
broadcast
busday_count
busday_offset
busdaycalendar
byte
bytes_
can_cast
cbrt
cdouble
ceil
character
choose
clip
clongdouble
complex128
complex64
complexfloating
compress
concat
concatenate
conj
conjugate
convolve
copysign
copyto
correlate
cos
cosh
count_nonzero
cross
csingle
cumprod
cumsum
cumulative_prod
cumulative_sum
datetime64
datetime_as_string
datetime_data
deg2rad
degrees
diagonal
divide
divmod
dot
double
dtype
weaeinsum
einsum_path
empty
empty_like
equal
errstate
euler_gamma
exp
exp2
expm1
fabs
finfo
flatiter
flatnonzero
flexible
float16
float32
float64
float_power
floating
floor
floor_divide
fmax
fmin
fmod
format_float_positional
format_float_scientific
frexp
from_dlpack
frombuffer
fromfile
fromfunction
fromiter
frompyfunc
fromstring
full
full_like
gcd
generic
geomspace
get_printoptions
getbufsize
geterr
geterrcall
greater
greater_equal
half
heaviside
hstack
hypot
identity
iinfo
indices
inexact
inf
inner
int16
int32
int64
int8
int_
intc
integer
intp
invert
is_busday
isclose
isdtype
isfinite
isfortran
isinf
isnan
isnat
isscalar
issubdtype
lcm
ldexp
left_shift
less
less_equal
lexsort
linspace
little_endian
log
log10
log1p
log2
logaddexp
logaddexp2
logical_and
logical_not
logical_or
logical_xor
logspace
long
longdouble
longlong
matmul
matvec
matrix_transpose
max
maximum
may_share_memory
mean
memmap
min
min_scalar_type
minimum
mod
modf
moveaxis
multiply
nan
ndarray
ndim
nditer
negative
nested_iters
newaxis
nextafter
nonzero
not_equal
number
object_
ones
ones_like
outer
partition
permute_dims
pi
positive
pow
power
printoptions
prod
promote_types
ptp
put
putmask
rad2deg
radians
ravel
recarray
reciprocal
record
remainder
repeat
require
reshape
resize
result_type
right_shift
rint
roll
rollaxis
round
sctypeDict
searchsorted
set_printoptions
setbufsize
seterr
seterrcall
shape
shares_memory
short
sign
signbit
signedinteger
sin
single
sinh
size
sort
spacing
sqrt
square
squeeze
stack
std
str_
subtract
sum
swapaxes
take
tan
tanh
tensordot
timedelta64
trace
transpose
true_divide
trunc
typecodes
ubyte
ufunc
uint
uint16
uint32
uint64
uint8
uintc
uintp
ulong
ulonglong
unsignedinteger
unstack
ushort
var
vdot
vecdot
vecmat
void
vstack
where
zeros
zeros_like
aFalse_
aScalarType
aTrue_
absolute
acos
acosh
add
all
allclose
amax
amin
any
arange
arccos
arccosh
arcsin
arcsinh
arctan
arctan2
arctanh
argmax
argmin
argpartition
argsort
argwhere
around
array2string
array_equal
array_equiv
array_repr
array_str
asanyarray
asarray
ascontiguousarray
asfortranarray
asin
asinh
atan
atanh
atan2
astype
atleast_1d
atleast_2d
atleast_3d
base_repr
binary_repr
bitwise_and
bitwise_count
bitwise_invert
bitwise_left_shift
bitwise_not
bitwise_or
bitwise_right_shift
bitwise_xor
block
bool
bool_
broadcast
busday_count
busday_offset
busdaycalendar
byte
bytes_
can_cast
cbrt
cdouble
ceil
character
choose
clip
clongdouble
complex128
complex64
complexfloating
compress
concat
concatenate
conj
conjugate
convolve
copysign
copyto
correlate
cos
cosh
count_nonzero
cross
csingle
cumprod
cumsum
cumulative_prod
cumulative_sum
datetime64
datetime_as_string
datetime_data
deg2rad
degrees
diagonal
divide
divmod
double
dtype
einsum
einsum_path
empty
empty_like
equal
errstate
euler_gamma
exp
exp2
expm1
fabs
finfo
flatiter
flatnonzero
flexible
float16
float64
float_power
floating
floor
floor_divide
fmax
fmin
fmod
format_float_positional
format_float_scientific
frexp
from_dlpack
frombuffer
fromfile
fromfunction
fromiter
frompyfunc
fromstring
full
full_like
gcd
generic
geomspace
get_printoptions
getbufsize
geterr
geterrcall
greater
greater_equal
half
heaviside
hstack
hypot
identity
iinfo
indices
inexact
inf
inner
int16
int32
int64
int8
int_
intc
integer
intp
invert
is_busday
isclose
isdtype
isfinite
isfortran
isinf
isnan
isnat
isscalar
issubdtype
lcm
ldexp
left_shift
less
less_equal
lexsort
little_endian
log
log10
log1p
log2
logaddexp
logaddexp2
logical_and
logical_not
logical_or
logical_xor
logspace
long
longdouble
longlong
matmul
matvec
matrix_transpose
max
maximum
may_share_memory
mean
memmap
min
min_scalar_type
minimum
mod
modf
moveaxis
multiply
nan
ndarray
ndim
nditer
negative
nested_iters
newaxis
nextafter
nonzero
not_equal
number
object_
ones_like
outer
partition
permute_dims
pi
positive
pow
power
printoptions
prod
promote_types
ptp
put
putmask
rad2deg
radians
ravel
recarray
reciprocal
record
remainder
repeat
require
reshape
resize
result_type
right_shift
rint
roll
rollaxis
round
sctypeDict
searchsorted
set_printoptions
setbufsize
seterr
seterrcall
shape
shares_memory
short
sign
signbit
signedinteger
sin
single
sinh
size
sort
spacing
sqrt
square
squeeze
stack
std
str_
subtract
sum
swapaxes
take
tan
tanh
tensordot
timedelta64
trace
transpose
true_divide
trunc
typecodes
ubyte
ufunc
uint
uint16
uint32
uint64
uint8
uintc
uintp
ulong
ulonglong
unsignedinteger
unstack
ushort
var
vdot
vecdot
vecmat
void
vstack
where
zeros
zeros_like
T afloat96
float128
complex192
complex256
ta
T alib
lib
T ascimath
scimath
emath
ulib._histograms_impl
T ahistogram
histogram_bin_edges
histogramdd
histogram
histogram_bin_edges
histogramdd
ulib._nanfunctions_impl
T ananargmax
nanargmin
nancumprod
nancumsum
nanmax
nanmean
nanmedian
nanmin
nanpercentile
nanprod
nanquantile
nanstd
nansum
nanvar
nanargmax
nanargmin
nancumprod
nancumsum
nanmax
nanmean
nanmedian
nanmin
nanpercentile
nanprod
nanquantile
nanstd
nansum
nanvar
ulib._function_base_impl
T&aselect
piecewise
trim_zeros
copy
iterable
percentile
diff
gradient
angle
unwrap
sort_complex
flip
rot90
extract
place
vectorize
asarray_chkfinite
average
bincount
digitize
cov
corrcoef
median
sinc
hamming
hanning
bartlett
blackman
kaiser
trapezoid
trapz
i0
meshgrid
delete
insert
append
interp
quantile
select
piecewise
trim_zeros
copy
iterable
percentile
diff
gradient
angle
unwrap
sort_complex
flip
rot90
extract
place
vectorize
asarray_chkfinite
average
bincount
digitize
cov
corrcoef
median
sinc
hamming
hanning
bartlett
blackman
kaiser
trapezoid
trapz
i0
meshgrid
delete
insert
append
interp
quantile
ulib._twodim_base_impl
T adiag
diagflat
eye
fliplr
flipud
tri
triu
tril
vander
histogram2d
mask_indices
tril_indices
tril_indices_from
triu_indices
triu_indices_from
diag
diagflat
eye
fliplr
flipud
tri
triu
tril
vander
histogram2d
mask_indices
tril_indices
tril_indices_from
triu_indices
triu_indices_from
ulib._shape_base_impl
T aapply_over_axes
apply_along_axis
array_split
column_stack
dsplit
dstack
expand_dims
hsplit
kron
put_along_axis
row_stack
split
take_along_axis
tile
vsplit
apply_over_axes
apply_along_axis
array_split
column_stack
dsplit
dstack
expand_dims
hsplit
kron
put_along_axis
row_stack
take_along_axis
tile
vsplit
ulib._type_check_impl
T aiscomplexobj
isrealobj
imag
iscomplex
isreal
nan_to_num
real
real_if_close
typename
mintypecode
common_type
iscomplexobj
isrealobj
imag
iscomplex
isreal
nan_to_num
real
real_if_close
typename
mintypecode
common_type
ulib._arraysetops_impl
T aediff1d
in1d
intersect1d
isin
setdiff1d
setxor1d
union1d
unique
unique_all
unique_counts
unique_inverse
unique_values
ediff1d
in1d
intersect1d
isin
setdiff1d
setxor1d
union1d
unique
unique_all
unique_counts
unique_inverse
unique_values
ulib._ufunclike_impl
T afix
isneginf
isposinf
fix
isneginf
isposinf
ulib._arraypad_impl
T apad
pad
ulib._utils_impl
T ashow_runtime
get_include
info
show_runtime
get_include
info
ulib._stride_tricks_impl
T abroadcast_arrays
broadcast_shapes
broadcast_to
broadcast_arrays
broadcast_shapes
broadcast_to
ulib._polynomial_impl
T apoly
polyint
polyder
polyadd
polysub
polymul
polydiv
polyval
polyfit
poly1d
roots
poly
polyint
polyder
polyadd
polysub
polymul
polydiv
poly1d
roots
ulib._npyio_impl
T
savetxt
loadtxt
genfromtxt
load
save
savez
packbits
savez_compressed
unpackbits
fromregex
savetxt
loadtxt
genfromtxt
load
save
savez
packbits
savez_compressed
unpackbits
fromregex
ulib._index_tricks_impl
T adiag_indices_from
diag_indices
fill_diagonal
ndindex
ndenumerate
ix_
c_
r_
s_
ogrid
mgrid
unravel_index
ravel_multi_index
index_exp
diag_indices_from
diag_indices
fill_diagonal
ndindex
ndenumerate
ix_
c_
r_
s_
ogrid
mgrid
unravel_index
ravel_multi_index
index_exp
T amatrixlib
matrixlib
a_mat
T aasmatrix
bmat
matrix
asmatrix
bmat
matrix
S atyping
polynomial
exceptions
char
random
fft
rec
test
f2py
ctypeslib
linalg
core
dtypes
strings
ma
testing
lib
umodule 'numpy' has no attribute '{n}'.
`np.{n}` was a deprecated alias for the builtin `{n}`. To avoid this error in existing code, use `{n}` by itself. Doing this will not modify any behavior and is safe. {extended_msg}
The aliases was originally deprecated in NumPy 1.20; for more details and guidance see the original release note at:
numpy.org/devdocs/release/1.20.0-notes.html#deprecations
a_msg
uIf you specifically wanted the numpy scalar type, use `np.{}` here.
a_specific_msg
uWhen replacing `np.{}`, you may wish to use e.g. `np.int64` or `np.int32` to specify the precision. If you wish to review your current use, check the release note link for additional information.
a_int_extended_msg
T aobject

float
complex
str
int
a_type_info
utoo many values to unpack (expected 2)
format
T wnaextended_msg
S abytes
str
object
u2023.12
a__array_api_version__
a_array_api_info
T a__array_namespace_info__
a__array_namespace_info__
getlimits
a_register_known_types
a__all__
a_histograms_impl
a_nanfunctions_impl
a_function_base_impl
a_twodim_base_impl
a_shape_base_impl
a_type_check_impl
a_arraysetops_impl
a_ufunclike_impl
a_arraypad_impl
a_utils_impl
a_stride_tricks_impl
a_polynomial_impl
a_npyio_impl
a_index_tricks_impl
S ashow_config
emath
a__version__
a__array_namespace_info__
filterwarnings
T aignore
unumpy.dtype size changed
T amessage
T aignore
unumpy.ufunc size changed
T aignore
unumpy.ndarray size changed
a__getattr__
a__dir__
unumpy._pytesttester
T aPytestTester
aPytestTester
T anumpy
test
a_sanity_check
a_mac_os_check
hugepage_setup
multiarray
a_set_madvise_hugepage
a_multiarray_umath
a_reload_guard
T aNPY_PROMOTION_STATE
weak
weak
uNPY_PROMOTION_STATE was a temporary feature for NumPy 2.0 transition and is ignored after NumPy 2.2.
aUserWarning
a_pyinstaller_hooks_dir
unumpy\__init__.py
T a.0
wvu<module numpy>
T apublic_symbols
T aattr
warnings
linalg
fft
dtypes
random
polynomial
ma
ctypeslib
exceptions
testing
matlib
f2py
typing
rec
char
core
strings
distutils
T aos
libs_dir
T wcwxwyw_T wxamsg
T ause_hugepage
kernel_version
.numpy.core._dtype
(
unumpy._core
T a_dtype
l
a_dtype
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core._dtype' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\_dtype.py
u<module numpy.core._dtype>
T aattr_name
a_dtype
a_raise_warning
ret
.numpy.core._dtype_ctypes
R
unumpy._core
T a_dtype_ctypes
l
a_dtype_ctypes
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core._dtype_ctypes' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\_dtype_ctypes.py
u<module numpy.core._dtype_ctypes>
T aattr_name
a_dtype_ctypes
a_raise_warning
ret
.numpy.core._internal
numpy
T andarray
l
ndarray
a__new__
unumpy._core
T a_internal
a_internal
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core._internal' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a_reconstruct
a_dtype_from_pep3118
a__getattr__
unumpy\core\_internal.py
u<module numpy.core._internal>
T aattr_name
a_internal
a_raise_warning
ret
T asubtype
shape
dtype
ndarray
.numpy.core._multiarray_umath
*
unumpy._core
T a_multiarray_umath
l
a_multiarray_umath
a_utils
T a_raise_warning
l a_raise_warning
P a_ARRAY_API
a_UFUNC_API
unumpy.version
T ashort_version
short_version
textwrap
traceback
dedent

A module that was compiled using NumPy 1.x cannot be run in
NumPy

u as it may crash. To support both 1.x and 2.x
versions of NumPy, modules must be compiled with NumPy 2.0.
Some module may need to rebuild instead e.g. with 'pybind11>=2.12'.
If you are a user of the module, the easiest solution will be to
downgrade to 'numpy<2' or try to upgrade the affected module.
We expect that some modules will need time to support NumPy 2.
uTraceback (most recent call last):
format_stack
:nq nufrozen importlib
tb_msg
stderr
write
umodule 'numpy.core._multiarray_umath' has no attribute
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
numpy
T aufunc
ufunc
a__dir__
item
attr
a__getattr__
unumpy\core\_multiarray_umath.py
u<module numpy.core._multiarray_umath>
T aattr_name
a_multiarray_umath
a_raise_warning
short_version
textwrap
traceback
sys
msg
tb_msg
line
ret
.numpy.core._utils
unumpy._core
unumpy.core
w.u
warnings
warn
u is deprecated and has been renamed to
u. The numpy._core namespace contains private NumPy internals and its use is discouraged, as NumPy internals can change without warning in any release. In practice, most real-world usage of numpy.core is to access functionality in the public NumPy API. If that is the case, use the public NumPy API. If not, you are using NumPy internals. If you would still like to access an internal attribute, use
aDeprecationWarning
D astacklevel
l a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
l
T na_raise_warning
unumpy\core\_utils.py
u<module numpy.core._utils>
T aattr
submodule
new_module
old_module
.numpy.core.arrayprint
@
unumpy._core
T aarrayprint
l
arrayprint
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.arrayprint' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\arrayprint.py
u<module numpy.core.arrayprint>
T aattr_name
arrayprint
a_raise_warning
ret
.numpy.core
x
!
a_core
a_raise_warning
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_numpy
u\not_existing
core
T aNUITKA_PACKAGE_numpy_core
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
numpy
T a_core
l
a_utils
T a_raise_warning
l a_ufunc_reconstruct
L aarrayprint
defchararray
a_dtype_ctypes
a_dtype
einsumfunc
fromnumeric
function_base
getlimits
a_internal
multiarray
a_multiarray_umath
numeric
numerictypes
overrides
records
shape_base
umath
a__all__
a__getattr__
unumpy\core\__init__.py
u<module numpy.core>
T aattr_name
attr
T amodule
name
mod

.numpy.core.defchararray
L
unumpy._core
T adefchararray
l
defchararray
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.defchararray' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\defchararray.py
u<module numpy.core.defchararray>
T aattr_name
defchararray
a_raise_warning
ret
.numpy.core.einsumfunc
@
unumpy._core
T aeinsumfunc
l
einsumfunc
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.einsumfunc' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\einsumfunc.py
u<module numpy.core.einsumfunc>
T aattr_name
einsumfunc
a_raise_warning
ret
.numpy.core.fromnumeric
F
unumpy._core
T afromnumeric
l
fromnumeric
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.fromnumeric' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\fromnumeric.py
u<module numpy.core.fromnumeric>
T aattr_name
fromnumeric
a_raise_warning
ret
.numpy.core.function_base
R
unumpy._core
T afunction_base
l
function_base
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.function_base' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\function_base.py
u<module numpy.core.function_base>
T aattr_name
function_base
a_raise_warning
ret
.numpy.core.getlimits
:
unumpy._core
T agetlimits
l
getlimits
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.getlimits' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\getlimits.py
u<module numpy.core.getlimits>
T aattr_name
getlimits
a_raise_warning
ret
.numpy.core.multiarray
j
unumpy._core
T amultiarray
l
multiarray
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.multiarray' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
T a_reconstruct
scalar
item
a_ARRAY_API
a__getattr__
unumpy\core\multiarray.py
u<module numpy.core.multiarray>
T aattr_name
multiarray
a_raise_warning
ret
.numpy.core.numeric
8
unumpy._core
T anumeric
l
numeric
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.numeric' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\numeric.py
u<module numpy.core.numeric>
T aattr_name
numeric
a_raise_warning
sentinel
ret
.numpy.core.numerictypes
L
unumpy._core
T anumerictypes
l
numerictypes
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.numerictypes' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\numerictypes.py
u<module numpy.core.numerictypes>
T aattr_name
numerictypes
a_raise_warning
ret
.numpy.core.overrides
:
unumpy._core
T aoverrides
l
overrides
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.overrides' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\overrides.py
u<module numpy.core.overrides>
T aattr_name
overrides
a_raise_warning
ret
.numpy.core.records
.
unumpy._core
T arecords
l
records
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.records' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\records.py
u<module numpy.core.records>
T aattr_name
records
a_raise_warning
ret
.numpy.core.shape_base
@
unumpy._core
T ashape_base
l
shape_base
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.shape_base' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\shape_base.py
u<module numpy.core.shape_base>
T aattr_name
shape_base
a_raise_warning
ret
.numpy.core.umath
"
unumpy._core
T aumath
l
umath
a_utils
T a_raise_warning
l a_raise_warning
umodule 'numpy.core.umath' has no attribute

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
a__getattr__
unumpy\core\umath.py
u<module numpy.core.umath>
T aattr_name
umath
a_raise_warning
ret
.numpy.ctypeslib
uctypes is not available.
fsdecode
splitext
l u.dll
get_config_var
T aEXT_SUFFIX
libname_ext
join
libdir
cdll
uno file with expected extension
l
num
a_flagdict
a_flagnames
res
np
ndarray
uargument must be an ndarray
a_dtype_
dtype
uarray must have data type %s
a_ndim_
ndim
uarray must have %d dimension(s)
a_shape_
shape
uarray must have shape %s
a_flags_
flags
uarray must have flags %s
a_flags_fromnum
ctypes
contents
c_char
itemsize
cast
aPOINTER
frombuffer
T adtype
squeeze
T l
T aaxis
split
T w,ainteger
flagsobj
strip
upper
uinvalid flags specification
a_num_fromflags
a_pointer_type_cache
any
names
str
u_%dd
w_wxa_concrete_ndptr
a_ndptr
undpointer_%s
unumpy.ctypeslib
u<genexpr>
undpointer.<locals>.<genexpr>
