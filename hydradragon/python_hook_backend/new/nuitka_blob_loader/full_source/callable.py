# Reconstructed from integrated Nuitka blob
# Module: callable


startswith
T ucbor2.
cbor2
D areturn
na_init_cbor2
ucbor2\__init__.py
u<module cbor2>
T aOrderedDict
a_cbor2
canonical_encoders
default_encoders
aCBORSimpleValue
aCBORTag
undefined
a__spec__
.certifi
#
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_certifi
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
core
T acontents
where
contents
where
a__all__
u2025.01.31
a__version__
ucertifi\__init__.py
u<module certifi>

a__spec__
.certifi.core
D
*
a_CACERT_CTX
a__exit__
T nnnawhere
a__enter__
read
a__file__
join
ucacert.pem
read_text
T acertifi
ucacert.pem
ascii
T aencoding

certifi.py
~~~~~~~~~~
This module returns the installation location of cacert.pem or its contents.
a__doc__
origin
has_location
a__cached__
sys
atexit
D areturn
naexit_cacert_ctx
os
types
aUnion
aModuleType
aPackage
T Ostr
uos.PathLike
aResource
T uutf-8
strict
package
resource
encoding
errors
return
D areturn
Ostr
contents
ucertifi\core.py
u<module certifi.core>
T apackage
resource
encoding
errors
data
T wfu
a__spec__
.cffi._imp_emulation
\
W
machinery
aEXTENSION_SUFFIXES
rb
aC_EXTENSION
aSOURCE_SUFFIXES
wraPY_SOURCE
aBYTECODE_SUFFIXES
aPY_COMPILED
isinstance
str
aTypeError
u'name' must be a str, not {}
type
T nalist
aRuntimeError
u'path' must be None or a list, not {}
is_builtin

aC_BUILTIN
is_frozen
aPY_FROZEN
sys
path
os
join
name
u.py
a__init__
package_directory
isfile
aPKG_DIRECTORY
get_suffixes
entry
aImportError
T aname
wbamode
open
file_path
a__enter__
a__exit__
tokenize
detect_encoding
readline
T nnnT aencoding
suffix
type_
aExtensionFileLoader
aModuleSpec
T aname
loader
origin
a_load
a__doc__
a__file__
origin
has_location
a__cached__
imp
T w*a_imp
T aacquire_lock
release_lock
is_builtin
is_frozen
acquire_lock
release_lock
uimportlib._bootstrap
T a_load
aSEARCH_ERROR
l l l aPY_RESOURCE
l l l l aPY_CODERESOURCE
l	aIMP_HOOK
find_module
load_dynamic
ucffi\_imp_emulation.py
u<module cffi._imp_emulation>
T aname
path
entry
package_directory
suffix
package_file_name
file_path
mode
type_
file_name
encoding
file
T aextensions
source
bytecode
T aname
path
file
loader
spec
a__spec__
.cffi.api
QO
aCallable
a_cffi_backend

T a__version__
a__version__
a__file__
uVersion mismatch: this is the 'cffi' package version %s, located in %r.  When we import the top-level '_cffi_backend' extension module, we get version %s, located in %r.  The two versions should be equal; check your installation.
uVersion mismatch: this is the 'cffi' package version %s, located in %r.  This interpreter comes with a built-in '_cffi_backend' module, which is version %s.  The two versions should be equal; check your installation.
T acparser
cparser
backend
a_backend
allocate_lock
a_lock
aParser
a_parser
a_cached_btypes
aModuleType
T aparsed_types
a_parsed_types
T anew_types
a_new_types
a_function_caches
a_libraries
a_cdefsources
a_included_ffis
a_windows_unicode
a_init_once_cache
a_cdef_version
a_embedding
model
get_typecache
a_typecache
set_ffi
startswith
T aRTLD_
a__enter__
a__exit__
a_get_cached_btype
voidp_type
aBVoidP
char_array_type
aBCharA
T nnnaFFI
aNULL
cast
a_get_types
aCData
aCType
buffer
uCreate an FFI instance.  The 'backend' argument is used to
select a non-default backend, mostly for tests.
a_cdef
T aoverride
packed
pack
uParse the given C source.  This registers all declared functions,
types, and global variables.  The functions and global variables can
then be accessed via either 'ffi.dlopen()' or 'ffi.verify()'.
The types can be used in 'ffi.new()' and other functions.
If 'packed' is specified as True, all structs declared inside this
cdef are packed, i.e. laid out without any field alignment at all.
Alternatively, 'pack' can be a small integer, and requests for
lignment greater than that are ignored (pack=1 is equivalent to
packed=True).
T apacked
pack
dllexport
basestring
ucdef() argument must be a string
encode
T aascii
parse
override
append
clear
a_recomplete
finish_backend_type
self
finishlist
udlopen(name): name must be a file name, None, or an already-opened 'void *' handle
a_make_ffi_library
lib
uLoad and return a dynamic library identified by 'name'.
The standard C library can be loaded by passing None.
Note that functions and types declared by 'ffi.cdef()' are not
linked to a particular library, just like C headers; in the
library we only look for the actual (untyped) symbols.
a__cffi_close__
uClose a library obtained with ffi.dlopen().  After this call,
ccess to functions or variables from the library will fail
(possibly with a segmentation fault).
parse_type
cdecl
is_raw_function
as_function_pointer
type
a_typeof_locked
result
aCDefError
uthe type %r is a function type, not a pointer-to-function type
a_typeof
typeof
aBuiltinFunctionType
a_builtin_function_type
aFunctionType
a_cffi_base_type
uParse the C type given as a string and return the
corresponding <ctype> object.
It can also be used on 'cdata' instance to get its C type.
sizeof
uReturn the size in bytes of the argument.  It can be a
string naming a C type, or a 'cdata' instance.
alignof
uReturn the natural alignment size in bytes of the C type
given as a string.
a_typeoffsetof
uReturn the offset of the named field inside the given
structure or array, which must be given as a C type name.
You can give several field names in case of nested structures.
You can also give numeric values which correspond to array
items, in case of an array type.
newp
uAllocate an instance according to the specified C type and
return a pointer to it.  The specified C type must be either a
pointer or an array: ``new('X *')`` allocates an X and returns
a pointer to it, whereas ``new('X[n]')`` allocates an array of
n X'es and returns an array referencing it (which works
mostly like a pointer, like in C).  You can also use
``new('X[]', n)`` to allocate an array of a non-constant
length n.
The memory is initialized following the rules of declaring a
global variable in C: by default it is zero-initialized, but
n explicit initializer can be given which can be used to
fill all or part of the memory.
When the returned <cdata> object goes out of scope, the memory
is freed.  In other words the returned <cdata> object has
ownership of the value of type 'cdecl' that it points to.  This
means that the raw data can be used as long as this object is
kept alive, but must not be used for a longer time.  Be careful
bout that when copying the pointer to the memory somewhere
else, e.g. into another structure.
new_allocator
T naallocate
uFFI.new_allocator.<locals>.allocate
uReturn a new allocator, i.e. a function that behaves like ffi.new()
but uses the provided low-level 'alloc' and 'free' functions.
'alloc' is called with the size as argument.  If it returns NULL, a
MemoryError is raised.  'free' is called with the result of 'alloc'
s argument.  Both can be either Python function or directly C
functions.  If 'free' is None, then no free function is called.
If both 'alloc' and 'free' are None, the default is used.
If 'should_clear_after_alloc' is set to False, then the memory
returned by 'alloc' is assumed to be already cleared (or you are
fine with garbage); otherwise CFFI will clear it.
allocator
uSimilar to a C cast: returns an instance of the named C
type initialized with the given 'source'.  The source is
casted between integers or pointers of any type.
string
uReturn a Python string (or unicode string) from the 'cdata'.
If 'cdata' is a pointer or array of characters or bytes, returns
the null-terminated string.  The returned string extends until
the first null character, or at most 'maxlen' characters.  If
'cdata' is an array then 'maxlen' defaults to its length.
If 'cdata' is a pointer or array of wchar_t, returns a unicode
string following the same rules.
If 'cdata' is a single character or byte or a wchar_t, returns
it as a string or unicode string.
If 'cdata' is an enum, returns the value of the enumerator as a
string, or 'NUMBER' if the value is out of range.
unpack
uUnpack an array of C data of the given length,
returning a Python string/unicode/list.
If 'cdata' is a pointer to 'char', returns a byte string.
It does not stop at the first null.  This is equivalent to:
ffi.buffer(cdata, length)[:]
If 'cdata' is a pointer to 'wchar_t', returns a unicode string.
'length' is measured in wchar_t's; it is not the size in bytes.
If 'cdata' is a pointer to anything else, returns a list of
'length' items.  This is a faster equivalent to:
[cdata[i] for i in range(length)]
a_unspecified
from_buffer
uReturn a cdata of the given type pointing to the data of the
given Python object, which must support the buffer interface.
Note that this is not meant to be used on the built-in types
str or unicode (you can build 'char[]' arrays explicitly)
but only on objects containing large quantities of raw data
in some other format, like 'array.array' or numpy arrays.
The first argument is optional and default to 'char[]'.
memmove
uffi.memmove(dest, src, n) copies n bytes of memory from src to dest.
Like the C function memmove(), the memory areas may overlap;
part from that it behaves like the C function memcpy().
'src' can be any cdata ptr or array, or any Python buffer object.
'dest' can be any cdata ptr or array, or a writable Python buffer
object.  The size to copy, 'n', is always measured in bytes.
Unlike other methods, this one supports all Python buffer including
byte strings and bytearrays---but it still does not support
non-contiguous buffers.
callback_decorator_wrap
uFFI.callback.<locals>.callback_decorator_wrap
D aconsider_function_as_funcptr
tuReturn a callback object or a decorator making such a
callback object.  'cdecl' must name a C function pointer type.
The callback invokes the specified 'python_callable' (which may
be provided either directly or via a decorator).  Important: the
callback object must be manually kept alive for as long as the
callback may be invoked from the C level.
callable
uthe 'python_callable' argument is not callable
callback
error
onerror
strip
T w*u&[
getcname
w&u(%s)
u[(
w areplace_with
uReturn a string giving the C type 'cdecl', which may be itself
a string or a <ctype> object.  If 'replace_with' is given, it gives
extra text to append (or insert for more complicated C types), like
a variable name, or '*' to get actually the C type 'pointer-to-cdecl'.
gcp
uReturn a new cdata object that points to the same
data.  Later, when this new cdata object is garbage-collected,
'destructor(old_cdata_object)' will be called.
The optional 'size' gives an estimate of the size, used to
trigger the garbage collection more eagerly.  So far only used
on PyPy.  It tells the GC that the returned object keeps alive
roughly 'size' bytes of external memory.
acquire
T Faget_cached_btype
verifier
T aVerifier
a_caller_dir_pycache
aVerifier
a_caller_dir_pycache
a_apply_windows_unicode
load_library
uVerify that the current ffi signatures compile on this
machine, and return a dynamic library object.  The dynamic
library can be used to call functions and access global
variables declared in this 'ffi'.  The library is compiled
by the C compiler: it gives you C-level API compatibility
(including calling macros).  This is unlike 'ffi.dlopen()',
which requires binary compatibility in the signatures.
get_errno
set_errno
getwinerror
pointer_cache
a__addressof__
kind
pointer
uaddressof(pointer)
a_pointer_to
ctype
rawaddressof
uReturn the address of a <cdata 'struct-or-union'>.
If 'fields_or_indexes' are given, returns the address of that
field or array item in the structure or array, recursively in
case of nested structures.
typeoffsetof
offset
uffi.include() expects an argument that is also of type cffi.FFI, not %r
a__name__
uself.include(self)
include
T w[aextend
T w]uIncludes the typedefs, structs, unions and enums defined
in another FFI instance.  Usage is similar to a #include in C,
where a part of the program might include types defined in
nother part for its own usage.  Note that the include()
method has no effect on functions, constants and global
variables, which must anyway be accessed directly from the
lib object returned by the original FFI instance.
newp_handle
from_handle
release
uset_unicode() can only be called once
cdef
T utypedef wchar_t TBYTE;typedef wchar_t TCHAR;typedef const wchar_t *LPCTSTR;typedef const wchar_t *PCTSTR;typedef wchar_t *LPTSTR;typedef wchar_t *PTSTR;typedef TBYTE *PTBYTE;typedef TCHAR *PTCHAR;
T utypedef char TBYTE;typedef char TCHAR;typedef const char *LPCTSTR;typedef const char *PCTSTR;typedef char *LPTSTR;typedef char *PTSTR;typedef TBYTE *PTBYTE;typedef TCHAR *PTCHAR;
uWindows: if 'enabled_flag' is True, enable the UNICODE and
_UNICODE defines in C, and declare the types like TCHAR and LPTCSTR
to be (pointers to) wchar_t.  If 'enabled_flag' is False,
declare these types to be (pointers to) plain 8-bit characters.
This is mostly for backward compatibility; you usually want True.
get
T adefine_macros
T
T Olist
Otuple
u'define_macros' must be a list or tuple
T aUNICODE
w1T a_UNICODE
w1adefine_macros
ensure
uFFI._apply_embedding_fix.<locals>.ensure
upython%d%d
gettotalrefcount
a_d
T l l
abiflags
libraries
T aextra_link_args
u/MANIFEST
kwds
setdefault
a_assigned_source
uset_source() cannot be called several times per ffi object
u'module_name' must be a string
w\w/u'module_name' must not contain '/': use a dotted name to make a 'package.module' location
T apkgconfig
pkgconfig
uthe pkgconfig_libs argument must be a list of package names
flags_from_pkgconfig
merge_flags
set_source
uMust not call cffi.api.distutils_extension
uMust not call cffi.api.emit_c_code
uMust not call cffi.api.emit_python_code
uMust not call cffi.api.compile
uembedding_init_code() can only be called once
re
match
u\s*\n
end
pysource
splitlines
u\s*
group
rstrip
line
prefix
:nq nw
cffi_init
exec
uffi.def_extern() is only available on API-mode FFI objects
a_declarations
T utypedef
typedefs
:l nnT ustruct
structs
:l nnT uunion
unions
:l nnasort
uReturns the user type names known to this FFI instance.
This returns a tuple containing three lists of names:
(typedef_names, names_of_structs, names_of_unions)
wcw.uctypes.util
util
find_library
udlopen(None) cannot work on Windows for Python 3 (see http://bugs.python.org/issue23606)
uctypes.util.find_library() did not manage to locate a library called %r
u%s.  Additionally, %s
a_load_backend_lib
accessor_function
u_make_ffi_library.<locals>.accessor_function
accessor_variable
u_make_ffi_library.<locals>.accessor_variable
addressof_var
u_make_ffi_library.<locals>.addressof_var
accessor_constant
u_make_ffi_library.<locals>.accessor_constant
accessor_int_constant
u_make_ffi_library.<locals>.accessor_int_constant
update_accessors
u_make_ffi_library.<locals>.update_accessors
make_accessor
u_make_ffi_library.<locals>.make_accessor
T Oobject
a__prepare__
aFFILibrary
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
