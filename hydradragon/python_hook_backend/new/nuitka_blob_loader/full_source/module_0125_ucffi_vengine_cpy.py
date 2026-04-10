# Reconstructed from integrated Nuitka blob
# Module: ucffi.vengine_cpy

uVCPythonEngine.load_library.<locals>.FFILibrary
a__qualname__
module
a_cffi_python_module
self
a_cffi_ffi
a_cffi_dir
a__dir__
uVCPythonEngine.load_library.<locals>.FFILibrary.__dir__
a__orig_bases__
a_cffi_setup
warnings
warn
ureimporting %r might overwrite older definitions
loaded
T alibrary
a_cffi_original_ffi
a_cffi_types_of_builtin_funcs
a_parser
a_declarations
sort
a_get_declarations
split
T w l u_generate_cpy_%s_%s
unot implemented in verify(): %r
attach_exception_info
u_%s_cpy_%s

is_integer_type
a_Bool
a_cffi_to_c_int
u, %s
is_complex_type
T unot implemented in verify(): complex types
u(%s)_cffi_to_c_%s
get_c_name
T u
replace
T w w_u-1
aPointerType
a_convert_funcarg_to_c_ptr_or_array
aStructOrUnion
aEnumType
u  if (_cffi_to_c((char *)&%s, _cffi_type(%d), %s) < 0)
a_gettypenum
u    %s;
aFunctionPtrType
u(%s)_cffi_to_c_pointer
u, _cffi_type(%d)
aNULL
u  %s = %s(%s%s);
u  if (%s == (%s)%s && PyErr_Occurred())
tp
add
T uPy_ssize_t datasize
T ustruct _cffi_freeme_s *large_args_free = NULL
T uif (large_args_free != NULL) _cffi_free_array_arguments(large_args_free);
T u  datasize = _cffi_prepare_pointer_call_argument(
u      _cffi_type(%d), %s, (char **)&%s);
T u  if (datasize != 0) {
u    %s = ((size_t)datasize) <= 640 ? alloca((size_t)datasize) : NULL;
u    if (_cffi_convert_array_argument(_cffi_type(%d), %s, (char **)&%s,
T u            datasize, &large_args_free) < 0)
u      %s;
u_cffi_from_c_int(%s, %s)
u_cffi_from_c_%s(%s)
u_cffi_from_c_deref((char *)&%s, _cffi_type(%d))
u_cffi_from_c_pointer((char *)%s, _cffi_type(%d))
aArrayType
item
fldnames
u'%s' is used as %s, but is opaque
a_get_c_name
u_cffi_from_c_struct((char *)&%s, _cffi_type(%d))
ellipsis
a_do_collect_type
args
result
a_generate_cpy_const
noarg
arg0
T ustatic PyObject *
u_cffi_f_%s(PyObject *self, PyObject *%s)
uargument of %s
prnt
u  %s;
u x%d
context
a_extra_local_variables
localvars
freelines
sorted
aVoidType
uresult =
uresult of %s
u result
T u  PyObject *pyresult;
u  PyObject *arg%d;
u  if (!PyArg_ParseTuple(args, "%s:%s", %s))
wOu,
u&arg%d
a_convert_funcarg_to_c
uarg%d
ux%d
ureturn NULL
T u  Py_BEGIN_ALLOW_THREADS
T u  _cffi_restore_errno();
u  { %s%s(%s); }
T u  _cffi_save_errno();
T u  Py_END_ALLOW_THREADS
T u  (void)self; /* unused */
T u  (void)noarg; /* unused */
u  pyresult = %s;
a_convert_expr_from_c
uresult type

T u  return pyresult;
T u  Py_INCREF(Py_None);
T u  return Py_None;
aMETH_NOARGS
aMETH_O
aMETH_VARARGS
u  {"%s", _cffi_f_%s, %s, NULL},
a_generate_struct_or_union_decl
struct
a_generate_struct_or_union_method
a_loading_struct_or_union
a_loaded_struct_or_union
union
u_cffi_check_%s_%s
u_cffi_layout_%s_%s
u%s %s
ustatic void %s(%s *p)
T u  /* only to generate compile-time warnings or errors */
T u  (void)p;
enumfields
utoo many values to unpack (expected 4)
u  (void)((p->%s) << 1);
u  { %s = &p->%s; (void)tmp; }
u*tmp
ufield %r
T aquals
u  /* %s */
u%s(PyObject *self, PyObject *noarg)
u  struct _cffi_aligncheck { char x; %s y; };
T u  static Py_ssize_t nums[] = {
u    sizeof(%s),
T u    offsetof(struct _cffi_aligncheck, y),
u    offsetof(%s, %s),
length
u    0,  /* %s */
u    sizeof(((%s *)0)->%s),
T u    -1
T u  };
T u  return _cffi_get_struct_layout(nums);
T u  /* the next line is not executed, but compiled */
u  %s(0);
u  {"%s", %s, METH_NOARGS, NULL},
partial
l :l nl :l nl aforce_flatten
fixedlayout
check
uVCPythonEngine._loaded_struct_or_union.<locals>.check
pop
sizeof
uwrong total size
alignof
uwrong total alignment
l wiaoffsetof
aBStruct
uwrong offset for field %r
uwrong size for field %r
u%s (we have %d, but C compiler says %d)
a_generate_cpy_enum_decl
a_loading_cpy_enum
a_loaded_cpy_enum
u_cffi_%s_%s
ustatic int %s(PyObject *lib)
T u  PyObject *o;
T u  int res;
u i
a_check_int_constant_value
var
w&u  i = (%s);
u  o = %s;
uvariable type
u  o = _cffi_from_c_int_const(%s);
T u  if (o == NULL)
T u    return -1;
T u  {
T u    PyObject *o1 = o;
u    o = Py_BuildValue("On", o1, (Py_ssize_t)sizeof(%s));
T u    Py_DECREF(o1);
T u    if (o == NULL)
T u      return -1;
u  res = PyObject_SetAttrString(lib, "%s", o);
T u  Py_DECREF(o);
T u  if (res < 0)
u  return %s;
u(lib)
u  if ((%s) > 0 || (long)(%s) != %dL) {
u  if ((%s) <= 0 || (unsigned long)(%s) != %dUL) {
T u    char buf[64];
u    if ((%s) <= 0)
u        snprintf(buf, 63, "%%ld", (long)(%s));
T u    else
u        snprintf(buf, 63, "%%lu", (unsigned long)(%s));
T u    PyErr_Format(_cffi_VerificationError,
T u                 "%s%s has the real value %s, not %s",
u                 "%s", "%s", buf, "%d");
T w$a___D_
u_cffi_e_%s_%s
enumerators
D adelayed
Fa_enum_funcname
enumvalues
uenum %s:
partial_resolved
u...
T acheck_value
length_is_unknown
T avartp
size_too
D acategory
var
ubad size: %r does not seem to be an array of %s
resolve_length
cast
delattr
getter
uVCPythonEngine._loaded_cpy_variable.<locals>.getter
setter
uVCPythonEngine._loaded_cpy_variable.<locals>.setter
append
ptr
T ustatic int _cffi_setup_custom(PyObject *lib)
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
sys
T amodel
error
T aVerificationError
T a_imp_emulation
a_imp_emulation
aVCPythonEngine
wxa_class_key
a_gen_python_module
a__init__
uVCPythonEngine.__init__
patch_extension_kwds
uVCPythonEngine.patch_extension_kwds
uVCPythonEngine.find_module
uVCPythonEngine.collect_types
uVCPythonEngine._prnt
uVCPythonEngine._gettypenum
uVCPythonEngine._do_collect_type
write_source_to_f
uVCPythonEngine.write_source_to_f
T naload_library
uVCPythonEngine.load_library
uVCPythonEngine._get_declarations
uVCPythonEngine._generate
uVCPythonEngine._load
a_generate_nothing
uVCPythonEngine._generate_nothing
a_loaded_noop
uVCPythonEngine._loaded_noop
uVCPythonEngine._convert_funcarg_to_c
uVCPythonEngine._extra_local_variables
uVCPythonEngine._convert_funcarg_to_c_ptr_or_array
uVCPythonEngine._convert_expr_from_c
a_generate_cpy_typedef_collecttype
a_generate_cpy_typedef_decl
a_generate_cpy_typedef_method
a_loading_cpy_typedef
a_loaded_cpy_typedef
a_generate_cpy_function_collecttype
uVCPythonEngine._generate_cpy_function_collecttype
a_generate_cpy_function_decl
uVCPythonEngine._generate_cpy_function_decl
a_generate_cpy_function_method
uVCPythonEngine._generate_cpy_function_method
a_loading_cpy_function
a_loaded_cpy_function
uVCPythonEngine._loaded_cpy_function
a_generate_cpy_struct_collecttype
a_generate_cpy_struct_decl
uVCPythonEngine._generate_cpy_struct_decl
a_generate_cpy_struct_method
uVCPythonEngine._generate_cpy_struct_method
a_loading_cpy_struct
uVCPythonEngine._loading_cpy_struct
a_loaded_cpy_struct
uVCPythonEngine._loaded_cpy_struct
a_generate_cpy_union_collecttype
a_generate_cpy_union_decl
uVCPythonEngine._generate_cpy_union_decl
a_generate_cpy_union_method
uVCPythonEngine._generate_cpy_union_method
a_loading_cpy_union
uVCPythonEngine._loading_cpy_union
a_loaded_cpy_union
uVCPythonEngine._loaded_cpy_union
uVCPythonEngine._generate_struct_or_union_decl
uVCPythonEngine._generate_struct_or_union_method
uVCPythonEngine._loading_struct_or_union
uVCPythonEngine._loaded_struct_or_union
a_generate_cpy_anonymous_collecttype
a_generate_cpy_anonymous_decl
uVCPythonEngine._generate_cpy_anonymous_decl
a_generate_cpy_anonymous_method
uVCPythonEngine._generate_cpy_anonymous_method
a_loading_cpy_anonymous
uVCPythonEngine._loading_cpy_anonymous
a_loaded_cpy_anonymous
uVCPythonEngine._loaded_cpy_anonymous
T naconst
ntFnuVCPythonEngine._generate_cpy_const
a_generate_cpy_constant_collecttype
uVCPythonEngine._generate_cpy_constant_collecttype
a_generate_cpy_constant_decl
uVCPythonEngine._generate_cpy_constant_decl
a_generate_cpy_constant_method
a_loading_cpy_constant
a_loaded_cpy_constant
uVCPythonEngine._check_int_constant_value
uVCPythonEngine._enum_funcname
T aenum
uVCPythonEngine._generate_cpy_enum_decl
a_generate_cpy_enum_collecttype
a_generate_cpy_enum_method
uVCPythonEngine._loading_cpy_enum
uVCPythonEngine._loaded_cpy_enum
a_generate_cpy_macro_decl
uVCPythonEngine._generate_cpy_macro_decl
a_generate_cpy_macro_collecttype
a_generate_cpy_macro_method
a_loading_cpy_macro
a_loaded_cpy_macro
a_generate_cpy_variable_collecttype
uVCPythonEngine._generate_cpy_variable_collecttype
a_generate_cpy_variable_decl
uVCPythonEngine._generate_cpy_variable_decl
a_generate_cpy_variable_method
a_loading_cpy_variable
a_loaded_cpy_variable
uVCPythonEngine._loaded_cpy_variable
uVCPythonEngine._generate_setup_custom

#include <Python.h>
#include <stddef.h>
/* this block of #ifs should be kept exactly identical between
c/_cffi_backend.c, cffi/vengine_cpy.py, cffi/vengine_gen.py
nd cffi/_cffi_include.h */
#if defined(_MSC_VER)
# include <malloc.h>   /* for alloca() */
# if _MSC_VER < 1600   /* MSVC < 2010 */
typedef __int8 int8_t;
typedef __int16 int16_t;
typedef __int32 int32_t;
typedef __int64 int64_t;
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
typedef __int8 int_least8_t;
typedef __int16 int_least16_t;
typedef __int32 int_least32_t;
typedef __int64 int_least64_t;
typedef unsigned __int8 uint_least8_t;
typedef unsigned __int16 uint_least16_t;
typedef unsigned __int32 uint_least32_t;
typedef unsigned __int64 uint_least64_t;
typedef __int8 int_fast8_t;
typedef __int16 int_fast16_t;
typedef __int32 int_fast32_t;
typedef __int64 int_fast64_t;
typedef unsigned __int8 uint_fast8_t;
typedef unsigned __int16 uint_fast16_t;
typedef unsigned __int32 uint_fast32_t;
typedef unsigned __int64 uint_fast64_t;
typedef __int64 intmax_t;
typedef unsigned __int64 uintmax_t;
# else
#  include <stdint.h>
# endif
# if _MSC_VER < 1800   /* MSVC < 2013 */
#  ifndef __cplusplus
typedef unsigned char _Bool;
#  endif
# endif
# define _cffi_float_complex_t   _Fcomplex    /* include <complex.h> for it */
# define _cffi_double_complex_t  _Dcomplex    /* include <complex.h> for it */
#else
# include <stdint.h>
# if (defined (__SVR4) && defined (__sun)) || defined(_AIX) || defined(__hpux)
#  include <alloca.h>
# endif
# define _cffi_float_complex_t   float _Complex
# define _cffi_double_complex_t  double _Complex
#endif
#if PY_MAJOR_VERSION < 3
# undef PyCapsule_CheckExact
# undef PyCapsule_GetPointer
# define PyCapsule_CheckExact(capsule) (PyCObject_Check(capsule))
# define PyCapsule_GetPointer(capsule, name) \
(PyCObject_AsVoidPtr(capsule))
#endif
#if PY_MAJOR_VERSION >= 3
# define PyInt_FromLong PyLong_FromLong
#endif
#define _cffi_from_c_double PyFloat_FromDouble
#define _cffi_from_c_float PyFloat_FromDouble
#define _cffi_from_c_long PyInt_FromLong
#define _cffi_from_c_ulong PyLong_FromUnsignedLong
#define _cffi_from_c_longlong PyLong_FromLongLong
#define _cffi_from_c_ulonglong PyLong_FromUnsignedLongLong
#define _cffi_from_c__Bool PyBool_FromLong
#define _cffi_to_c_double PyFloat_AsDouble
#define _cffi_to_c_float PyFloat_AsDouble
#define _cffi_from_c_int_const(x)                                        \
(((x) > 0) ?                                                         \
((unsigned long long)(x) <= (unsigned long long)LONG_MAX) ?      \
PyInt_FromLong((long)(x)) :                                  \
PyLong_FromUnsignedLongLong((unsigned long long)(x)) :       \
((long long)(x) >= (long long)LONG_MIN) ?                        \
PyInt_FromLong((long)(x)) :                                  \
PyLong_FromLongLong((long long)(x)))
#define _cffi_from_c_int(x, type)                                        \
(((type)-1) > 0 ? /* unsigned */                                     \
(sizeof(type) < sizeof(long) ?                                   \
PyInt_FromLong((long)x) :                                    \
sizeof(type) == sizeof(long) ?                                  \
PyLong_FromUnsignedLong((unsigned long)x) :                  \
PyLong_FromUnsignedLongLong((unsigned long long)x)) :        \
(sizeof(type) <= sizeof(long) ?                                  \
PyInt_FromLong((long)x) :                                    \
PyLong_FromLongLong((long long)x)))
#define _cffi_to_c_int(o, type)                                          \
((type)(                                                             \
sizeof(type) == 1 ? (((type)-1) > 0 ? (type)_cffi_to_c_u8(o)        \
: (type)_cffi_to_c_i8(o)) :     \
sizeof(type) == 2 ? (((type)-1) > 0 ? (type)_cffi_to_c_u16(o)       \
: (type)_cffi_to_c_i16(o)) :    \
sizeof(type) == 4 ? (((type)-1) > 0 ? (type)_cffi_to_c_u32(o)       \
: (type)_cffi_to_c_i32(o)) :    \
sizeof(type) == 8 ? (((type)-1) > 0 ? (type)_cffi_to_c_u64(o)       \
: (type)_cffi_to_c_i64(o)) :    \
(Py_FatalError("unsupported size for type " #type), (type)0)))
#define _cffi_to_c_i8                                                    \
((int(*)(PyObject *))_cffi_exports[1])
#define _cffi_to_c_u8                                                    \
((int(*)(PyObject *))_cffi_exports[2])
#define _cffi_to_c_i16                                                   \
((int(*)(PyObject *))_cffi_exports[3])
#define _cffi_to_c_u16                                                   \
((int(*)(PyObject *))_cffi_exports[4])
#define _cffi_to_c_i32                                                   \
((int(*)(PyObject *))_cffi_exports[5])
#define _cffi_to_c_u32                                                   \
((unsigned int(*)(PyObject *))_cffi_exports[6])
#define _cffi_to_c_i64                                                   \
((long long(*)(PyObject *))_cffi_exports[7])
#define _cffi_to_c_u64                                                   \
((unsigned long long(*)(PyObject *))_cffi_exports[8])
#define _cffi_to_c_char                                                  \
((int(*)(PyObject *))_cffi_exports[9])
#define _cffi_from_c_pointer                                             \
((PyObject *(*)(char *, CTypeDescrObject *))_cffi_exports[10])
#define _cffi_to_c_pointer                                               \
((char *(*)(PyObject *, CTypeDescrObject *))_cffi_exports[11])
#define _cffi_get_struct_layout                                          \
((PyObject *(*)(Py_ssize_t[]))_cffi_exports[12])
#define _cffi_restore_errno                                              \
((void(*)(void))_cffi_exports[13])
#define _cffi_save_errno                                                 \
((void(*)(void))_cffi_exports[14])
#define _cffi_from_c_char                                                \
((PyObject *(*)(char))_cffi_exports[15])
#define _cffi_from_c_deref                                               \
((PyObject *(*)(char *, CTypeDescrObject *))_cffi_exports[16])
#define _cffi_to_c                                                       \
((int(*)(char *, CTypeDescrObject *, PyObject *))_cffi_exports[17])
#define _cffi_from_c_struct                                              \
((PyObject *(*)(char *, CTypeDescrObject *))_cffi_exports[18])
#define _cffi_to_c_wchar_t                                               \
((wchar_t(*)(PyObject *))_cffi_exports[19])
#define _cffi_from_c_wchar_t                                             \
((PyObject *(*)(wchar_t))_cffi_exports[20])
#define _cffi_to_c_long_double                                           \
((long double(*)(PyObject *))_cffi_exports[21])
#define _cffi_to_c__Bool                                                 \
((_Bool(*)(PyObject *))_cffi_exports[22])
#define _cffi_prepare_pointer_call_argument                              \
((Py_ssize_t(*)(CTypeDescrObject *, PyObject *, char **))_cffi_exports[23])
#define _cffi_convert_array_from_object                                  \
((int(*)(char *, CTypeDescrObject *, PyObject *))_cffi_exports[24])
#define _CFFI_NUM_EXPORTS 25
typedef struct _ctypedescr CTypeDescrObject;
static void *_cffi_exports[_CFFI_NUM_EXPORTS];
static PyObject *_cffi_types, *_cffi_VerificationError;
static int _cffi_setup_custom(PyObject *lib);   /* forward */
static PyObject *_cffi_setup(PyObject *self, PyObject *args)
{
PyObject *library;
int was_alive = (_cffi_types != NULL);
(void)self; /* unused */
if (!PyArg_ParseTuple(args, "OOO", &_cffi_types, &_cffi_VerificationError,
&library))
return NULL;
Py_INCREF(_cffi_types);
Py_INCREF(_cffi_VerificationError);
if (_cffi_setup_custom(library) < 0)
return NULL;
return PyBool_FromLong(was_alive);
}
union _cffi_union_alignment_u {
unsigned char m_char;
unsigned short m_short;
unsigned int m_int;
unsigned long m_long;
unsigned long long m_longlong;
float m_float;
double m_double;
long double m_longdouble;
};
struct _cffi_freeme_s {
struct _cffi_freeme_s *next;
union _cffi_union_alignment_u alignment;
};
#ifdef __GNUC__
__attribute__((unused))
#endif
static int _cffi_convert_array_argument(CTypeDescrObject *ctptr, PyObject *arg,
char **output_data, Py_ssize_t datasize,
struct _cffi_freeme_s **freeme)
{
char *p;
if (datasize < 0)
return -1;
p = *output_data;
if (p == NULL) {
struct _cffi_freeme_s *fp = (struct _cffi_freeme_s *)PyObject_Malloc(
offsetof(struct _cffi_freeme_s, alignment) + (size_t)datasize);
if (fp == NULL)
return -1;
fp->next = *freeme;
*freeme = fp;
p = *output_data = (char *)&fp->alignment;
}
memset((void *)p, 0, (size_t)datasize);
return _cffi_convert_array_from_object(p, ctptr, arg);
}
#ifdef __GNUC__
__attribute__((unused))
#endif
static void _cffi_free_array_arguments(struct _cffi_freeme_s *freeme)
{
do {
void *p = (void *)freeme;
freeme = freeme->next;
PyObject_Free(p);
} while (freeme != NULL);
}
static int _cffi_init(void)
{
PyObject *module, *c_api_object = NULL;
module = PyImport_ImportModule("_cffi_backend");
if (module == NULL)
goto failure;
c_api_object = PyObject_GetAttrString(module, "_C_API");
if (c_api_object == NULL)
goto failure;
if (!PyCapsule_CheckExact(c_api_object)) {
PyErr_SetNone(PyExc_ImportError);
goto failure;
}
memcpy(_cffi_exports, PyCapsule_GetPointer(c_api_object, "cffi"),
_CFFI_NUM_EXPORTS * sizeof(void *));
Py_DECREF(module);
Py_DECREF(c_api_object);
return 0;
failure:
Py_XDECREF(module);
Py_XDECREF(c_api_object);
return -1;
}
#define _cffi_type(num) ((CTypeDescrObject *)PyList_GET_ITEM(_cffi_types, num))
/**********/
ucffi\vengine_cpy.py
u<module cffi.vengine_cpy>
T a__class__
module
self
T a__class__
T aself
aFFILibrary
T aFFILibrary
T aself
verifier
T aself
name
value
err_prefix
prnt
T aself
tp
var
context
T aself
tp
fromvar
tovar
errcode
extraarg
converter
errvalue
T aself
tp
fromvar
tovar
errcode
T aself
tp
num
T aself
prefix
name
T aself
tp
localvars
freelines
T aself
step_name
name
tp
kind
realname
method
weT aself
tp
name
T aself
is_int
name
tp
category
vartp
delayed
size_too
check_value
prnt
funcname
realexpr
T aself
tp
name
is_int
T aself
tp
name
prefix
enumerator
funcname
prnt
enumvalue
T aself
tp
name
type
T aself
tp
name
prnt
numargs
argname
context
wiatype
localvars
freelines
decl
result_code
rng
freeline
T aself
tp
name
numargs
meth
T aself
tp
name
check_value
T aself
tp
name
tp_ptr
T aself
prnt
Taself
tp
prefix
name
checkfuncname
layoutfuncname
cname
prnt
fname
ftype
fbitsize
fqual
weT aself
tp
prefix
name
layoutfuncname
T aself
lst
T aself
type
T
self
module
step_name
kwds
name
tp
kind
realname
method
weT aself
tp
name
module
kwds
T aself
tp
name
module
library
enumerator
enumvalue
T aself
tp
name
module
library
func
T aself
tp
name
module
library
value
size
aBItemType
length
rest
aBArray
ptr
getter
setter
Taself
tp
check
ffi
aBStruct
layout
cname
wiafname
ftype
fbitsize
fqual
aBField
T aself
tp
name
module
T aself
tp
name
module
enumvalues
Taself
tp
prefix
name
module
layoutfuncname
function
layout
totalsize
totalalignment
fieldofs
fieldsize
cname
T aself
what
T arealvalue
expectedvalue
msg
T aself
T aself
module_name
path
so_suffixes
wfafilename
descr
T alibrary
ptr
T aptr
T aself
flags
previous_flags
module
weaerror
revmapping
lst
aFFILibrary
library
warnings
T aself
kwds
T alibrary
value
ptr
T aself
prnt
modname
constants
.cffi.vengine_gen
(
verifier
ffi
export_symbols
a_struct_pending_verification
setdefault
module_name
path
join
basename
a_f
write
w
a_prnt
cffimod_header
preamble
a_generate
T adecl
get_module_name
uvoid %s%s(void) { }
aPyInit_
a_backend
w.amodulefilename
load_library
a_load
loading
aModuleType
l
a__prepare__
aFFILibrary
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
