# Reconstructed from integrated Nuitka blob
# Module: module

uarray_function_from_dispatcher.<locals>.decorator
array_function_dispatch
T averify
docs_from_dispatcher
a__file__
a__spec__
origin
has_location
a__cached__
collections
functools
a_utils
T aset_module
l aset_module
u_utils._inspect
T agetargspec
unumpy._core._multiarray_umath
T aadd_docstring
a_get_implementing_args
a_ArrayFunctionDispatcher
a_get_implementing_args
ulike : array_like, optional
Reference object to allow the creation of arrays which are not
NumPy arrays. If an array-like passed in as ``like`` supports
the ``__array_function__`` protocol, the result will be defined
by it. In this case, it ensures the creation of an array object
compatible with that passed in via this argument.
T u
finalize_array_function_like

Class to wrap functions with checks for __array_function__ overrides.
All arguments are required, and can only be passed by position.
Parameters
----------
dispatcher : function or None
The dispatcher function that returns a single sequence-like object
of all arguments relevant.  It must have the same signature (except
the default values) as the actual implementation.
If ``None``, this is a ``like=`` dispatcher and the
``_ArrayFunctionDispatcher`` must be called with ``like`` as the
first (additional and positional) argument.
implementation : function
Function that implements the operation on NumPy arrays without
overrides.  Arguments passed calling the ``_ArrayFunctionDispatcher``
will be forwarded to this (and the ``dispatcher``) as if using
``*args, **kwargs``.
Attributes
----------
_implementation : function
The original implementation passed in.

Collect arguments on which to call __array_function__.
Parameters
----------
relevant_args : iterable of array-like
Iterable of possibly array-like arguments to check for
__array_function__ methods.
Returns
-------
Sequence of arguments with __array_function__ methods, in the order in
which they should be called.
namedtuple
T aArgSpec
uargs varargs keywords defaults
T nntFT ntpaarray_function_from_dispatcher
unumpy\_core\overrides.py
u<module numpy._core.overrides>
T adispatcher
module
verify
docs_from_dispatcher
decorator
T aimplementation
module
verify
docs_from_dispatcher
decorator
T aimplementation
co
last_arg
public_api
verify
dispatcher
docs_from_dispatcher
module
T adispatcher
docs_from_dispatcher
module
verify
T adispatcher
module
verify
docs_from_dispatcher
implementation
T adocs_from_dispatcher
implementation
module
verify
T apublic_api
T apublic_api
docstring_template
docstring
T aimplementation
dispatcher
implementation_spec
dispatcher_spec
.numpy._core.printoptions
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
sys
contextvars
T aContextVar
l
aContextVar
format_options
a__all__
D aedgeitems
threshold
floatmode
precision
suppress
linewidth
nanstr
infstr
sign
formatter
legacy
override_repr
l l  amaxprec
l FlKanan
inf
w-ng            nadefault_format_options_dict
T aformat_options
T adefault
unumpy\_core\printoptions.py
u<module numpy._core.printoptions>

.numpy._core.records
aCounter
items
utoo many values to unpack (expected 2)
l a_parseFormats
a_setfieldnames
a_createdtype
uNeed formats argument
sb
dtype
uf{}
fields
f1
aligned
names
l
a_f_formats
a_offsets
a_nfields
T Olist
Otuple
split
T w,uillegal input names %s
strip
a_names
self
uf%d
find_duplicate
uDuplicate field names: %s
a_titles
formats
offsets
titles
a_byteorderconv
newbyteorder
a_get_legacy_print_mode
lqa__str__
a__class__
a__repr__
item
T asetfield
getfield
dtype
nt
void
a__getattribute__
get
getfield
:nl naview
u'record' object has no attribute '%s'
uCannot set '%s' attribute
setfield
a__setattr__
a__getitem__
max
u%% %ds: %%s
fmt
w
u<genexpr>
urecord.pprint.<locals>.<genexpr>
format_parser
ndarray
a__new__
record
T aorder
T abuffer
offset
strides
order
type
T ETypeError
EKeyError
urecarray has no attribute %s
T adtype
val
ret
a__delattr__
fielddict
urecord array has no attribute %s
T atype
urec.array(
urec.array(%s,%sdtype=%s)
uarray(
uarray(%s,%sdtype=%s).view(numpy.recarray)
size
shape
T l
array2string
u,
w,T aseparator
prefix
suffix
u[], shape=%s
w arepr_dtype
warnings
warn
uPassing `shape=0` to have the shape be inferred is deprecated, and in future will be equivalent to `shape=(0,)`. To infer the shape and suppress this warning, pass `shape=None` instead.
aFutureWarning
D astacklevel
l aasarray
a_deprecate_shape_0_as_None
umismatch between the number of fields and the number of arrays
recarray
ndim
uarray-shape mismatch in array

u ("
u")
a_array
array
D adtype
Oobject
q atolist
fromarrays
T aformats
shape
names
titles
aligned
byteorder
T ETypeError
EValueError
uCan only deal with 1-d array.
ufromrecords expected a list of tuples, may have received a list of lists instead. In the future that will raise an error
D astacklevel
l ufromstring() needs a 'dtype' or 'formats' argument
itemsize
T nq T abuf
offset
tell
seek
T l
l ufromfile() needs a 'dtype' or 'formats' argument
T q areadinto
nullcontext
fspath
rb
a__enter__
a__exit__
get_remaining_size
prod
intp
shapeprod
uNot enough bytes left in file for specified shape and type.
data
uDidn't read as many bytes as expected
T nnnT M
Ostr
uMust define formats (or dtype) if object is None, string, or an open file
byteorder
uMust define a shape if obj is None
T abuf
offset
strides
fromstring
offset
T Otuple
Olist
fromrecords
copy
fromfile
T adtype
shape
offset
a__array_interface__
uUnknown input type
obj
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
os
collections
T aCounter
contextlib
T anullcontext
a_utils
T aset_module
l aset_module
T anumeric
numeric
T anumerictypes
numerictypes
arrayprint
T a_get_legacy_print_mode
L	arecord
recarray
format_parser
fromarrays
fromrecords
fromstring
fromfile
array
find_duplicate
a__all__
D wbwlwnwBwLwNwSwsw>w<w=w|wIwiw>w<w=w>w<w=wspw>w<w=w|ppasctypeDict
numfmt
T unumpy.rec
u_rename_parameter.<locals>.decorator
wraps
wrapper
u_rename_parameter.<locals>.decorator.<locals>.wrapper
old_names
new_names
utoo many values to unpack (expected 2)
kwargs
dep_version
split
T w.l l w.uUse of keyword argument `

u` is deprecated and replaced by `
u`. Support for `
u` will be removed in NumPy
warnings
warn
aDeprecationWarning
D astacklevel
l afun
a__name__
u() got multiple values for argument now known as `
w`a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_numpy
u\not_existing
a_utils
T aNUITKA_PACKAGE_numpy__utils
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
functools
l
a_convertions
T aasunicode
asbytes
asunicode
asbytes
set_module
T na_rename_parameter
unumpy\_utils\__init__.py
u<module numpy._utils>
T aold_names
new_names
dep_version
decorator
T afun
wrapper
T adep_version
new_names
old_names
T afunc
module
T amodule
T amodule
decorator
T aargs
kwargs
a__tracebackhide__
old_name
new_name
end_version
msg
old_names
new_names
dep_version
fun
T adep_version
fun
new_names
old_names
.numpy.char
P
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_numpy
u\not_existing
char
T aNUITKA_PACKAGE_numpy_char
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
unumpy._core.defchararray
T a__all__
a__doc__
l
a__all__
T w*unumpy\char\__init__.py
u<module numpy.char>

.numpy.compat
Q
'
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_numpy
u\not_existing
compat
T aNUITKA_PACKAGE_numpy_compat
u\not_existing
a__path__
a__spec__
origin
has_location
submodule_search_locations
a__cached__
warnings
l
a_utils
T a_inspect
l a_inspect
u_utils._inspect
T agetargspec
formatargspec
getargspec
formatargspec

T apy3k
l apy3k
T w*awarn
u`np.compat`, which was used during the Python 2 to 3 transition, is deprecated since 1.26.0, and will be removed
aDeprecationWarning
D astacklevel
l a__all__
extend
unumpy\compat\__init__.py
u<module numpy.compat>
.numpy.compat.py3k
P
bytes
decode
T alatin1
encode
aFileIO
aBufferedReader
aBufferedWriter
fileno
uiso-8859-1
exc_info
l a__iter__
unicode
asbytes_nested
asbytes
asunicode_nested
asunicode
aPath
enter_result
uimportlib.machinery
T aSourceFileLoader
l
aSourceFileLoader
load_module
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
L abytes
asbytes
isfileobj
getexception
strchar
unicode
asunicode
asbytes_nested
asunicode_nested
asstr
open_latin1
long
basestring
sixu
integer_types
is_pathlib_path
npy_load_module
aPath
pickle
contextlib_nullcontext
os_fspath
os_PathLike
a__all__
sys
os
pathlib
T aPath
io
pickle5
pickle
long
T Oint
integer_types
basestring
asstr
isfileobj
T wraopen_latin1
sixu
wUastrchar
getexception
is_pathlib_path
