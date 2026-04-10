# Reconstructed from integrated Nuitka blob
# Module: a__pydantic_decorators__

a__qualname__
a__pydantic_complete__
complete_dataclass
config_wrapper
D araise_errors
Fais_dataclass
u<genexpr>
udataclass.<locals>.create_dataclass.<locals>.<genexpr>
u'InitVar' object is not callable
uThis function does nothing but raise an error that is as similar as possible to what you'd get
if you were to try calling `InitVar[int]()` without this monkeypatch. The whole purpose is just
to ensure typing._type_check does not error if the type hint evaluates to `InitVar[<parameter>]`.
a__pydantic_core_schema__
delattr
a_typing_extra
parent_frame_namespace
T aparent_depth
force
a_namespace_utils
aNsResolver
T aparent_namespace
D acheck
FT araise_errors
ns_resolver
a_force_build
uTry to rebuild the pydantic-core schema for the dataclass.
This may be necessary when one of the annotations is a ForwardRef which could not be resolved during
the initial attempt to build the schema, and automatic rebuilding fails.
This is analogous to `BaseModel.model_rebuild`.
Args:
cls: The class to rebuild the pydantic-core schema for.
force: Whether to force the rebuilding of the schema, defaults to `False`.
raise_errors: Whether to raise errors, defaults to `True`.
_parent_namespace_depth: The depth level of the parent namespace, defaults to 2.
_types_namespace: The types namespace, defaults to `None`.
Returns:
Returns `None` if the schema is already "complete" and rebuilding was not required.
If rebuilding _was_ required, returns `True` if rebuilding was successful, otherwise `False`.
a__pydantic_validator__
uWhether a class is a pydantic dataclass.
Args:
class_: The class.
Returns:
`True` if the class is a pydantic dataclass, `False` otherwise.
uProvide an enhanced dataclass that performs validation.
a__file__
origin
has_location
a__cached__
annotations
a_annotations
sys
types
aTYPE_CHECKING
aAny
aCallable
aNoReturn
aTypeVar
overload
warnings
T awarn
typing_extensions
T aLiteral
aTypeGuard
dataclass_transform
aLiteral
aTypeGuard
dataclass_transform
a_internal
T a_config
a_decorators
a_namespace_utils
a_typing_extra
T a_dataclasses
a_dataclasses
a_migration
T agetattr_migration
getattr_migration
upydantic.config
aConfigDict
upydantic.errors
upydantic.fields
aField
aPrivateAttr
T adataclass
rebuild_dataclass
a__all__
T a_T
a_T
T afield_specifiers
D
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
kw_only
slots
FtpFppnnQ
Q
D ainit
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
kw_only
slots
return
uLiteral[False]
bool
ppppuConfigDict | type[object] | None
ubool | None
bool
puCallable[[type[_T]], type[PydanticDataclass]]
D
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
kw_only
slots
FtpFpnnnQ
Q
D a_cls
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
kw_only
slots
return
utype[_T]
uLiteral[False]
bool
pppubool | None
uConfigDict | type[object] | None
ubool | None
bool
putype[PydanticDataclass]
T nD
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
kw_only
slots
FtpFpnnnFpD a_cls
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
kw_only
slots
return
utype[_T] | None
uLiteral[False]
bool
pppubool | None
uConfigDict | type[object] | None
ubool | None
bool
puCallable[[type[_T]], type[PydanticDataclass]] | type[PydanticDataclass]
T upydantic.dataclasses
a__getattr__
D aargs
kwargs
return
aAny
paNoReturn
a_call_initvar
aInitVar
a__call__
D aforce
raise_errors
a_parent_namespace_depth
a_types_namespace
Ftl nD acls
force
raise_errors
a_parent_namespace_depth
a_types_namespace
return
utype[PydanticDataclass]
bool
paint
uMappingNamespace | None
ubool | None
rebuild_dataclass
D aclass_
return
utype[Any]
uTypeGuard[type[PydanticDataclass]]
is_pydantic_dataclass
upydantic\dataclasses.py
T a.0
base
T aconfig
eq
frozen
kwargs
make_pydantic_fields_compatible
order
repr
unsafe_hash
u<module pydantic.dataclasses>
T aargs
kwargs
T acls
is_model_class
original_cls
has_dataclass_base
config_dict
config_wrapper
decorators
original_doc
bases
generic_base
frozen_
config
make_pydantic_fields_compatible
frozen
repr
eq
order
unsafe_hash
kwargs
T a_cls
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
kw_only
slots
T a_cls
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
kw_only
slots
kwargs
make_pydantic_fields_compatible
create_dataclass
T
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
kw_only
slots
T aclass_
T acls
field_args
annotation_cls
annotations
field_name
field_value
T acls
force
raise_errors
a_parent_namespace_depth
a_types_namespace
rebuild_ns
ns_resolver
a__spec__
.pydantic.datetime_parse
uThe `datetime_parse` module is a backport module from V1.
a__doc__
a__file__
origin
has_location
a__cached__
a_migration
T agetattr_migration
getattr_migration
T upydantic.datetime_parse
a__getattr__
upydantic\datetime_parse.py
u<module pydantic.datetime_parse>

a__spec__
.pydantic.deprecated
7
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_pydantic
u\not_existing
deprecated
T aNUITKA_PACKAGE_pydantic_deprecated
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
upydantic\deprecated\__init__.py
u<module pydantic.deprecated>

a__spec__
.pydantic.deprecated.copy_internals
i
\
exclude
a_utils
aValueItems
merge
self
a__pydantic_fields__
items
include
D aintersect
ta_calculate_keys
exclude_unset
T ainclude
exclude
exclude_unset
to_dict
by_alias
exclude_defaults
exclude_none
a__pydantic_extra__
field
is_required
default
alias
value_include
value_exclude
a_get_value
for_element
T ato_dict
by_alias
include
exclude
exclude_unset
exclude_defaults
exclude_none
a_iter
deepcopy
a__new__
a_object_setattr
a__dict__
a__pydantic_fields_set__
a__pydantic_private__
upydantic.main
aBaseModel
model_dump
T aby_alias
exclude_unset
exclude_defaults
include
exclude
exclude_none
copy
T ainclude
exclude
is_excluded
is_included
cls
T ato_dict
by_alias
exclude_unset
exclude_defaults
include
exclude
exclude_none
sequence_like
a_typing_extra
is_namedtuple
aEnum
model_config
use_enum_values
value
u<genexpr>
u_get_value.<locals>.<genexpr>
keys
is_true
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
a_annotations
typing
T adeepcopy
enum
T aEnum
aAny
aTuple
typing_extensions
a_internal
T a_model_construction
a_typing_extra
a_utils
l a_model_construction
object_setattr
T FpnnFppD	aself
to_dict
by_alias
include
exclude
exclude_unset
exclude_defaults
exclude_none
return
aBaseModel
bool
puAbstractSetIntStr | MappingIntStrAny | None
uAbstractSetIntStr | MappingIntStrAny | None
bool
ppaTupleGenerator
T nnD aself
values
fields_set
extra
private
deep
return
aModel
udict[str, Any]
uset[str]
udict[str, Any] | None
udict[str, Any] | None
bool
aModel
a_copy_and_set_values
no_type_check
D
cls
wvato_dict
by_alias
include
exclude
exclude_unset
exclude_defaults
exclude_none
return
utype[BaseModel]
aAny
bool
puAbstractSetIntStr | MappingIntStrAny | None
uAbstractSetIntStr | MappingIntStrAny | None
bool
ppaAny
T nD aself
include
exclude
exclude_unset
update
return
aBaseModel
uMappingIntStrAny | None
uMappingIntStrAny | None
bool
utyping.Dict[str, Any] | None
utyping.AbstractSet[str] | None
upydantic\deprecated\copy_internals.py
T a.0
wiav_
value_exclude
value_include
cls
to_dict
by_alias
exclude_unset
exclude_defaults
exclude_none
u<module pydantic.deprecated.copy_internals>
T aself
include
exclude
exclude_unset
update
keys
T aself
values
fields_set
extra
private
deep
cls
wmTacls
wvato_dict
by_alias
include
exclude
exclude_unset
exclude_defaults
exclude_none
aBaseModel
value_exclude
value_include
seq_args
T aself
to_dict
by_alias
include
exclude
exclude_unset
exclude_defaults
exclude_none
allowed_keys
value_exclude
value_include
items
field_key
wvafield
dict_key

a__spec__
.pydantic.deprecated.decorator
B
warnings
warn
uThe `validate_arguments` method is deprecated; use `validate_call` instead.
aPydanticDeprecatedSince20
D astacklevel
l D a_func
return
aAnyCallable
aAnyCallable
validate
uvalidate_arguments.<locals>.validate
uDecorator to validate the arguments passed to a function.
aValidatedFunction
config
wraps
args
aAny
kwargs
return
wrapper_function
uvalidate_arguments.<locals>.validate.<locals>.wrapper_function
vd
init_model_instance
raw_function
model
call
inspect
T aParameter
signature
aParameter
signature
parameters
keys
aALT_V_ARGS
aALT_V_KWARGS
aV_POSITIONAL_ONLY_NAME
aV_DUPLICATE_KWARGS
aPydanticUserError
w"u
u", "
u" and "
u" are not permitted as argument names when using the "
validate_arguments
a__name__
u" decorator
D acode
naarg_mapping
positional_only_args
v_args_name
v_kwargs_name
a_typing_extra
get_type_hints
D ainclude_extras
taitems
annotation
empty
default
kind
aPOSITIONAL_ONLY
self
fields
aList
add
aPOSITIONAL_OR_KEYWORD
aKEYWORD_ONLY
aVAR_POSITIONAL
aTuple
aVAR_KEYWORD
aDict
takes_args
takes_kwargs
create_model
build_values
execute
get
values
a__pydantic_fields__
alias
wrong_positional_args
duplicate_kwargs
var_kwargs
wma__pydantic_fields_set__
default_factory
pop
in_kwargs
args_
a_config
aConfigWrapper
alias_generator
T uSetting the "alias_generator" property on custom Config for @validate_arguments is not yet supported, please remove.
nT acode
extra
forbid
config_dict
aBaseModel
a__prepare__
aDecoratorBaseModel
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
