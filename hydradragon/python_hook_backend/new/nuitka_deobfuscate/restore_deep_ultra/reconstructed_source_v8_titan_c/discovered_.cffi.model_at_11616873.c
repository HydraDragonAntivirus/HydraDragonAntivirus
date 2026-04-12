// ============================================================================
// V8 TITAN C-DECOMPILER OUTPUT
// Generated C++ module file for: discovered_.cffi.model_at_11616873
// ============================================================================
#include "nuitka/prelude.h"
#include "nuitka/unfreezing.h"
#include "nuitka/builtins.h"

static PyObject *impl_StructOrUnion__anonymous_struct_fields( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('0',)");
    PyObject *str_const_1 = MAKE_STRING('expand_anonymous_struct_union');
    PyObject *cb_2 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("enumfields"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_StructOrUnion__enumfields( PyObject *par_self, PyObject *par___prepare__, PyObject *par_BaseTypeByIdentity, PyObject *par___getitem__ ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_CDefError = NULL;
    PyObject *var_VerificationError = NULL;
    PyObject *var_VerificationMissing = NULL;
    PyObject *var_None = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('names');
    PyObject *str_const_1 = MAKE_STRING('bitsizes');
    PyObject *str_const_2 = MAKE_STRING('StructOrUnionOrEnum');
    PyObject *cb_3 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("finish_backend_type"));
    PyObject *str_const_4 = MAKE_STRING('completed');
    PyObject *val_5 = MAKE_INT(2);
    PyObject *str_const_6 = MAKE_STRING("recursive structure declaration for '%s'");
    PyObject *str_const_7 = MAKE_STRING('fixedlayout');
    PyObject *str_const_8 = MAKE_STRING('packed');
    PyObject *tuple_9 = MAKE_TUPLE("('8',)");
    PyObject *str_const_10 = MAKE_STRING('complete_struct_or_union');
    PyObject *str_const_11 = MAKE_STRING('sizeof');
    PyObject *str_const_12 = MAKE_STRING("field '%s.%s' has a bogus size?");
    PyObject *str_const_13 = MAKE_STRING('resolve_length');
    PyObject *str_const_14 = MAKE_STRING('ftype');
    PyObject *str_const_15 = MAKE_STRING("field '%s.%s' is declared as %d bytes, but is really %d bytes");
    PyObject *str_const_16 = MAKE_STRING('partial');
    PyObject *str_const_17 = MAKE_STRING('VerificationMissing');
    PyObject *cb_18 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("check_not_partial"));
    PyObject *str_const_19 = MAKE_STRING('new_%s_type');
    PyObject *str_const_20 = MAKE_STRING('get_official_name');
    PyObject *tuple_21 = MAKE_TUPLE("('key',)");
    PyObject *str_const_22 = MAKE_STRING('enumerators');
    PyObject *str_const_23 = MAKE_STRING('enumvalues');
    PyObject *str_const_24 = MAKE_STRING('baseinttype');
    PyObject *str_const_25 = MAKE_STRING('force_the_name');
    PyObject *str_const_26 = MAKE_STRING('partial_resolved');
    PyObject *str_const_27 = MAKE_STRING('build_baseinttype');
    PyObject *str_const_28 = MAKE_STRING('new_enum_type');
    PyObject *str_const_29 = MAKE_STRING('min');
    PyObject *str_const_30 = MAKE_STRING('max');
    PRINT_ITEM(MAKE_STRING('warnings'));
    PRINT_NEW_LINE();
    PRINT_ITEM(MAKE_STRING('__warningregistry__'));
    PRINT_NEW_LINE();
    PyObject *str_const_33 = MAKE_STRING('clear');
    PyObject *str_const_34 = MAKE_STRING('warn');
    PyObject *str_const_35 = MAKE_STRING("%r has no values explicitly defined; guessing that it is equivalent to 'unsigned int'");
    PyObject *str_const_36 = MAKE_STRING('PrimitiveType');
    PyObject *tuple_37 = MAKE_TUPLE("('int',)");
    PyObject *tuple_38 = MAKE_TUPLE("('long',)");
    PyObject *tuple_39 = MAKE_TUPLE("('unsigned int',)");
    PyObject *tuple_40 = MAKE_TUPLE("('unsigned long',)");
    PyObject *val_41 = MAKE_INT(8);
    PyObject *str_const_42 = MAKE_STRING("%s values don't all fit into either 'long' or 'unsigned long'");
    PyObject *str_const_43 = MAKE_STRING('$%s');
    PyObject *str_const_44 = MAKE_STRING('StructType');
    PyObject *str_const_45 = MAKE_STRING('unknown_type');
    PyObject *str_const_46 = MAKE_STRING('origin');
    PyObject *str_const_47 = MAKE_STRING('$$%s');
    PyObject *str_const_48 = MAKE_STRING('NamedPointerType');
    PyObject *str_const_49 = MAKE_STRING('ModuleType');
    PyObject *str_const_50 = MAKE_STRING('global_lock');
    PyObject *str_const_51 = MAKE_STRING('__typecache');
    PyObject *str_const_52 = MAKE_STRING('weakref');
    PyObject *str_const_53 = MAKE_STRING('WeakValueDictionary');
    PyObject *str_const_54 = MAKE_STRING('key');
    PyObject *str_const_55 = MAKE_STRING('%s: %r: %s');
    PyObject *str_const_56 = MAKE_STRING('%s: %s');
    PyObject *str_const_57 = MAKE_STRING('has_location');
    PyObject *str_const_58 = MAKE_STRING('lock');
    PyObject *tuple_59 = MAKE_TUPLE("('allocate_lock',)");
    PyObject *str_const_60 = MAKE_STRING('allocate_lock');
    PRINT_ITEM(MAKE_STRING('error'));
    PRINT_NEW_LINE();
    PyObject *val_62 = MAKE_INT(4);
    PyObject *tuple_63 = MAKE_TUPLE("('None',)");
    PyObject *str_const_64 = MAKE_STRING('ss>');
    PyObject *str_const_65 = MAKE_STRING('cffi.model');
    PyObject *str_const_66 = MAKE_STRING('__qualname__');
    // Discovered Timeout Logic
    time_sleep((double)25 / 1000.0);
    PyObject *str_const_68 = MAKE_STRING('__firstlineno__');
    PyObject *str_const_69 = MAKE_STRING('is_raw_function');
    PyObject *str_const_70 = MAKE_STRING('get_c_name');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_StructOrUnion____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('True',)");
    PyObject *cb_1 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("force_flatten"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_StructOrUnion__force_flatten( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_StructOrUnion__get_cached_btype( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_StructOrUnion__finish_backend_type( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_StructOrUnion___verification_error( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_StructOrUnion__check_not_partial( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_StructOrUnion__build_backend_type( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_name = NULL;
    PyObject *var_fldnames = NULL;
    PyObject *var_fldtypes = NULL;
    PyObject *var_fldbitsize = NULL;
    PyObject *var_fldquals = NULL;
    PyObject *var_completed = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    // Discovered Timeout Logic
    time_sleep((double)482 / 1000.0);
    PyObject *str_const_1 = MAKE_STRING('struct');
    PyObject *str_const_2 = MAKE_STRING('UnionType');
    // Discovered Timeout Logic
    time_sleep((double)486 / 1000.0);
    PyObject *str_const_4 = MAKE_STRING('union');
    PyObject *str_const_5 = MAKE_STRING('EnumType');
    // Discovered Timeout Logic
    time_sleep((double)490 / 1000.0);
    PyObject *str_const_7 = MAKE_STRING('enum');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_BaseTypeByIdentity__get_c_name( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_BaseTypeByIdentity___get_c_name( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("has_c_name"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_BaseTypeByIdentity__has_c_name( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("is_integer_type"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_BaseTypeByIdentity__is_integer_type( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('False',)");

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_BaseTypeByIdentity__get_cached_btype( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("__repr__"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_BaseTypeByIdentity____repr__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_BaseTypeByIdentity___get_items( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('__static_attributes__');
    PyObject *str_const_1 = MAKE_STRING('__orig_bases__');
    PyObject *str_const_2 = MAKE_STRING('BaseType');
    // Discovered Timeout Logic
    time_sleep((double)72 / 1000.0);
    PyObject *str_const_4 = MAKE_STRING('__eq__');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_BaseType____eq__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("__ne__"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_BaseType____ne__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *cb_0 = LOOKUP_ATTRIBUTE(tstate, par_self, MAKE_STRING("__hash__"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_BaseType____hash__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('VoidType');
    // Discovered Timeout Logic
    time_sleep((double)85 / 1000.0);

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_VoidType____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_VoidType__build_backend_type( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('c_name_with_marker',)");
    PyObject *str_const_1 = MAKE_STRING('void_type');
    PyObject *str_const_2 = MAKE_STRING('BasePrimitiveType');
    // Discovered Timeout Logic
    time_sleep((double)97 / 1000.0);
    PyObject *str_const_4 = MAKE_STRING('is_complex_type');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_BasePrimitiveType__is_complex_type( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    // Discovered Timeout Logic
    time_sleep((double)102 / 1000.0);
    PyObject *tuple_1 = MAKE_TUPLE("('name',)");
    PyObject *dict_2 = _PyDict_NewPresized( 51 );
    PyDict_SetItemString(dict_2, 'char', MAKE_STRING('None'));
    PyDict_SetItemString(dict_2, 'short', MAKE_STRING('wipppppppppwfppwjpwiwcppwippppppppppppppppppppppppppppppuPrimitiveType.__init__'));
    PyDict_SetItemString(dict_2, 'int', MAKE_STRING('is_char_type'));
    PyDict_SetItemString(dict_2, 'long', MAKE_STRING("'PrimitiveType.is_char_type'"));
    PyDict_SetItemString(dict_2, 'long long', MAKE_STRING("'PrimitiveType.is_integer_type'"));
    PyDict_SetItemString(dict_2, 'signed char', MAKE_STRING('is_float_type'));
    PyDict_SetItemString(dict_2, 'unsigned char', MAKE_STRING("'PrimitiveType.is_float_type'"));
    PyDict_SetItemString(dict_2, 'unsigned short', MAKE_STRING("'PrimitiveType.is_complex_type'"));
    PyDict_SetItemString(dict_2, 'unsigned int', MAKE_STRING("'PrimitiveType.build_backend_type'"));
    PyDict_SetItemString(dict_2, 'unsigned long', MAKE_STRING("(b'name', b'c_name_with_marker')"));
    PyDict_SetItemString(dict_2, 'unsigned long long', MAKE_STRING('UnknownIntegerType'));
    PyDict_SetItemString(dict_2, 'float', MAKE_STRING('178'));
    PyDict_SetItemString(dict_2, 'double', MAKE_STRING("'UnknownIntegerType.__init__'"));
    PyDict_SetItemString(dict_2, 'long double', MAKE_STRING("'UnknownIntegerType.is_integer_type'"));
    PyDict_SetItemString(dict_2, '_cffi_float_complex_t', MAKE_STRING("'UnknownIntegerType.build_backend_type'"));
    PyDict_SetItemString(dict_2, '_cffi_double_complex_t', MAKE_STRING('UnknownFloatType'));
    PyDict_SetItemString(dict_2, '_Bool', MAKE_STRING('192'));
    PyDict_SetItemString(dict_2, 'wchar_t', MAKE_STRING("'UnknownFloatType.__init__'"));
    PyDict_SetItemString(dict_2, 'char16_t', MAKE_STRING("'UnknownFloatType.build_backend_type'"));
    PyDict_SetItemString(dict_2, 'char32_t', MAKE_STRING('BaseFunctionType'));
    PyDict_SetItemString(dict_2, 'int8_t', MAKE_STRING('204'));
    PyDict_SetItemString(dict_2, 'uint8_t', MAKE_STRING("(b'args', b'result', b'ellipsis', b'abi')"));
    PyDict_SetItemString(dict_2, 'int16_t', MAKE_STRING('(None,)'));
    PyDict_SetItemString(dict_2, 'uint16_t', MAKE_STRING("'BaseFunctionType.__init__'"));
    PyDict_SetItemString(dict_2, 'int32_t', MAKE_STRING("(b'args', b'result', b'ellipsis', b'abi', b'c_name_with_marker')"));
    PyDict_SetItemString(dict_2, 'uint32_t', MAKE_STRING('224'));
    PyDict_SetItemString(dict_2, 'int64_t', MAKE_STRING("'(&)(%s)'"));
    PyDict_SetItemString(dict_2, 'uint64_t', MAKE_STRING("'RawFunctionType.build_backend_type'"));
    PyDict_SetItemString(dict_2, 'int_least8_t', MAKE_STRING('as_function_pointer'));
    PyDict_SetItemString(dict_2, 'uint_least8_t', MAKE_STRING("'RawFunctionType.as_function_pointer'"));
    PyDict_SetItemString(dict_2, 'int_least16_t', MAKE_STRING('239'));
    PyDict_SetItemString(dict_2, 'uint_least16_t', MAKE_STRING("'(*&)(%s)'"));
    PyDict_SetItemString(dict_2, 'int_least32_t', MAKE_STRING("'FunctionPtrType.build_backend_type'"));
    PyDict_SetItemString(dict_2, 'uint_least32_t', MAKE_STRING('as_raw_function'));
    PyDict_SetItemString(dict_2, 'int_least64_t', MAKE_STRING("'FunctionPtrType.as_raw_function'"));
    PyDict_SetItemString(dict_2, 'uint_least64_t', MAKE_STRING('261'));
    PyDict_SetItemString(dict_2, 'int_fast8_t', MAKE_STRING("(b'totype', b'quals')"));
    PyDict_SetItemString(dict_2, 'uint_fast8_t', MAKE_STRING("'PointerType.__init__'"));
    PyDict_SetItemString(dict_2, 'int_fast16_t', MAKE_STRING("'PointerType.build_backend_type'"));
    PyDict_SetItemString(dict_2, 'uint_fast16_t', MAKE_STRING("(b'totype', b'quals', b'c_name_with_marker')"));
    PyDict_SetItemString(dict_2, 'int_fast32_t', MAKE_STRING('voidp_type'));
    PyDict_SetItemString(dict_2, 'uint_fast32_t', MAKE_STRING('ConstPointerType'));
    PyDict_SetItemString(dict_2, 'int_fast64_t', MAKE_STRING('const_voidp_type'));
    PyDict_SetItemString(dict_2, 'uint_fast64_t', MAKE_STRING('285'));
    PyDict_SetItemString(dict_2, 'intptr_t', MAKE_STRING("(b'totype', b'name')"));
    PyDict_SetItemString(dict_2, 'uintptr_t', MAKE_STRING("'NamedPointerType.__init__'"));
    PyDict_SetItemString(dict_2, 'intmax_t', MAKE_STRING('294'));
    PyDict_SetItemString(dict_2, 'uintmax_t', MAKE_STRING("(b'item', b'length')"));
    PyDict_SetItemString(dict_2, 'ptrdiff_t', MAKE_STRING("'ArrayType.__init__'"));
    PyDict_SetItemString(dict_2, 'size_t', MAKE_STRING("'ArrayType.length_is_unknown'"));
    PyDict_SetItemString(dict_2, 'ssize_t', MAKE_STRING("'ArrayType.resolve_length'"));

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_ArrayType__build_backend_type( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_item = NULL;
    PyObject *var_length = NULL;
    PyObject *var_c_name_with_marker = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *tuple_0 = MAKE_TUPLE("('char',)");
    PyObject *str_const_1 = MAKE_STRING('char_array_type');
    // Discovered Timeout Logic
    time_sleep((double)328 / 1000.0);

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_StructOrUnionOrEnum__build_c_name_with_marker( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_StructOrUnionOrEnum__force_the_name( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_StructOrUnionOrEnum__get_official_name( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_c_name_with_marker = NULL;
    PyObject *var_forcename = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    // Discovered Timeout Logic
    time_sleep((double)345 / 1000.0);

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}

static PyObject *impl_EnumType____init__( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_EnumType__force_the_name( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_EnumType__check_not_partial( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_EnumType__build_backend_type( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // Empty block
}

static PyObject *impl_EnumType__build_baseinttype( PyObject *par_self ) {
    PyThreadState *tstate = PyThreadState_GET();
    PyObject *exception_type = NULL;
    PyObject *exception_value = NULL;
    PyTracebackObject *exception_tb = NULL;
    NUITKA_MAY_BE_UNUSED int exception_lineno = 0;

    // --- FRAME VARIABLE ALLOCATION ---
    PyObject *var_name = NULL;
    PyObject *var_enumerators = NULL;
    PyObject *var_enumvalues = NULL;
    PyObject *var_baseinttype = NULL;
    PyObject *var_forcename = NULL;
    PyObject *var_self = NULL;
    PyObject *var_other = NULL;
    PyObject *var_self = NULL;
    PyObject *var_item = NULL;
    PyObject *var_length = NULL;
    PyObject *var_brackets = NULL;
    PyObject *var_self = NULL;
    PyObject *var_args = NULL;
    PyObject *var_result = NULL;
    PyObject *var_ellipsis = NULL;
    PyObject *var_abi = NULL;
    PyObject *var_reprargs = NULL;
    PyObject *var_replace_with = NULL;
    PyObject *var_self = NULL;
    PyObject *var_name = NULL;
    PyObject *var_enumerators = NULL;
    PyObject *var_enumvalues = NULL;
    PyObject *var_baseinttype = NULL;
    PyObject *var_self = NULL;
    PyObject *var_totype = NULL;
    PyObject *var_name = NULL;
    PyObject *var_quals = NULL;
    PyObject *var_self = NULL;
    PyObject *var_totype = NULL;
    PyObject *var_quals = NULL;
    PyObject *var_extra = NULL;
    PyObject *var_self = NULL;
    PyObject *var_name = NULL;
    PyObject *var_self = NULL;
    PyObject *var_name = NULL;
    PyObject *var_fldnames = NULL;
    PyObject *var_fldtypes = NULL;
    PyObject *var_fldbitsize = NULL;
    PyObject *var_fldquals = NULL;
    PyObject *var_self = NULL;
    PyObject *var_msg = NULL;
    PyObject *var_self = NULL;
    PyObject *var_name = NULL;
    PyObject *var_type = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_finishlist = NULL;
    PyObject *var_BPtrItem = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_finishlist = NULL;
    PyObject *var_base_btype = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_finishlist = NULL;
    PyObject *var_result = NULL;
    PyObject *var_args = NULL;
    PyObject *var_tp = NULL;
    PyObject *var_abi_args = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_finishlist = NULL;
    PyObject *var_BItem = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_finishlist = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_finishlist = NULL;
    PyObject *var_smallest_value = NULL;
    PyObject *var_largest_value = NULL;
    PyObject *var_warnings = NULL;
    PyObject *var_sign = NULL;
    PyObject *var_candidate1 = NULL;
    PyObject *var_candidate2 = NULL;
    PyObject *var_btype1 = NULL;
    PyObject *var_btype2 = NULL;
    PyObject *var_size1 = NULL;
    PyObject *var_size2 = NULL;
    PyObject *var_self = NULL;
    PyObject *var_expand_anonymous_struct_union = NULL;
    PyObject *var_fldquals = NULL;
    PyObject *var_name = NULL;
    PyObject *var_type = NULL;
    PyObject *var_bitsize = NULL;
    PyObject *var_quals = NULL;
    PyObject *var_result = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_finishlist = NULL;
    PyObject *var_BType = NULL;
    PyObject *var_fldtypes = NULL;
    PyObject *var_lst = NULL;
    PyObject *var_extra_flags = NULL;
    PyObject *var_fieldofs = NULL;
    PyObject *var_fieldsize = NULL;
    PyObject *var_totalsize = NULL;
    PyObject *var_totalalignment = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_BItemType = NULL;
    PyObject *var_nlen = NULL;
    PyObject *var_self = NULL;
    PyObject *var_names = NULL;
    PyObject *var_types = NULL;
    PyObject *var_bitsizes = NULL;
    PyObject *var_fldquals = NULL;
    PyObject *var_name = NULL;
    PyObject *var_type = NULL;
    PyObject *var_bitsize = NULL;
    PyObject *var_quals = NULL;
    PyObject *var_self = NULL;
    PyObject *var_forcename = NULL;
    PyObject *var_name = NULL;
    PyObject *var_self = NULL;
    PyObject *var_forcename = NULL;
    PyObject *var_self = NULL;
    PyObject *var_replace_with = NULL;
    PyObject *var_context = NULL;
    PyObject *var_quals = NULL;
    PyObject *var_result = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_finishlist = NULL;
    PyObject *var_can_delay = NULL;
    PyObject *var_BType = NULL;
    PyObject *var_BType2 = NULL;
    PyObject *var_self = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_finishlist = NULL;
    PyObject *var_can_delay = NULL;
    PyObject *var_BType = NULL;
    PyObject *var_srctype = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_funcname = NULL;
    PyObject *var_args = NULL;
    PyObject *var_kwds = NULL;
    PyObject *var_key = NULL;
    PyObject *var_res = NULL;
    PyObject *var_None = NULL;
    PyObject *var_None = NULL;
    PyObject *var_cache = NULL;
    PyObject *var_ffi = NULL;
    PyObject *var_BType = NULL;
    PyObject *var_quals = NULL;
    PyObject *var_replace_with = NULL;
    PyObject *var_self = NULL;
    PyObject *var_newlength = NULL;
    PyObject *var_name = NULL;
    PyObject *var_structname = NULL;
    PyObject *var_tp = NULL;

    // --- HEURISTIC MACRO EXECUTION TRACE ---
    PyObject *str_const_0 = MAKE_STRING('unknown_ptr_type');
    PyObject *str_const_1 = MAKE_STRING('get_typecache');
    PyObject *str_const_2 = MAKE_STRING('pointer_cache');
    PyObject *str_const_3 = MAKE_STRING('attach_exception_info');
    PyObject *str_const_4 = MAKE_STRING('cffi\\model.py');
    PyObject *str_const_5 = MAKE_STRING('<module cffi.model>');
    PyObject *tuple_6 = MAKE_TUPLE("('__class__',)");
    PyObject *tuple_7 = MAKE_TUPLE("('totype',)");
    PyObject *tuple_8 = MAKE_TUPLE("('self',)");
    PyObject *str_const_9 = MAKE_STRING('name');
    PyObject *str_const_10 = MAKE_STRING('nrest');
    PyObject *str_const_11 = MAKE_STRING('BFieldType');
    PyObject *str_const_12 = MAKE_STRING('bitemsize');
    PyObject *tuple_13 = MAKE_TUPLE("('backend',)");
    PyObject *str_const_14 = MAKE_STRING('res1');

    // Return block
    return Py_None;

exception_handler:
    // Nuitka Exception Routing
    RESTORE_ERROR_OCCURRED(tstate, exception_type, exception_value, exception_tb);
    return NULL;
}
