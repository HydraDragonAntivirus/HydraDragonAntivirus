# Reconstructed from integrated Nuitka blob
# Module: typed_dict_cls

typing
T uPlease use `typing_extensions.TypedDict` instead of `typing.TypedDict` on Python < 3.12.
utyped-dict-version
get_attribute_from_bases
a__pydantic_config__
a__required_keys__
aDecoratorInfos
build
use_attribute_docstrings
extract_docstrings_from_cls
D ause_inspect
taget_cls_type_hints
T ans_resolver
typevars_map
is_not_required
aFieldInfo
a_generate_td_field_schema
T arequired
typed_dict_schema
T acls
computed_fields
ref
config
all
uGenerate schema for a TypedDict.
It is not possible to track required/optional keys in TypedDict without __required_keys__
since TypedDict.__new__ erases the base classes (it replaces them with just `dict`)
nd thus we can track usage of total=True/False
__required_keys__ was added in Python 3.9
(https://github.com/miss-islington/cpython/blob/1e9939657dd1f8eb9f596f77c1084d2d351172fc/Doc/library/typing.rst?plain=1#L1546-L1548)
however it is buggy
(https://github.com/python/typing_extensions/blob/ac52ac5f2cb0e00e7988bae1e2a1b8257ac88d6d/src/typing_extensions.py#L657-L666).
On 3.11 but < 3.12 TypedDict does not preserve inheritance information.
Hence to avoid creating validators that do not do what users expect we only
support typing.TypedDict on Python >= 3.12 or typing_extension.TypedDict on all versions
namedtuple_cls
a_fields
arguments_schema
a_generate_parameter_schema
a_field_defaults
aParameter
empty
T adefault
D ametadata
D apydantic_js_prefer_positional_arguments
tacall_schema
T aref
uGenerate schema for a NamedTuple.
from_annotated_attribute
T ufield.annotation should not be None when generating a schema
arguments_parameter
uPrepare a ArgumentsParameter to represent a field in a namedtuple or function signature.
tuple_schema
D avariadic_item_index
l
aEllipsis
uVariable tuples can only have one type
uGenerate schema for a Tuple, e.g. `tuple[int, str]` or `tuple[int, ...]`.
uGenerateSchema._tuple_schema.<locals>.<genexpr>
custom_error_schema
T Otype
D acustom_error_type
custom_error_message
is_type
uInput should be a type
zoneinfo
T aZoneInfo
aZoneInfoNotFoundError
aZoneInfo
aZoneInfoNotFoundError
D avalue
return
aAny
aZoneInfo
validate_str_is_valid_iana_tz
uGenerateSchema._zoneinfo_schema.<locals>.validate_str_is_valid_iana_tz
uGenerateSchema._zoneinfo_schema.<locals>.<lambda>
T aserialization
metadata
uGenerate schema for a zone_info.ZoneInfo object
aPydanticCustomError
zoneinfo_str
uinvalid timezone: {value}
D atype
format
string
zoneinfo
uGenerate schema for `Type[Union[X, ...]]`.
annotated_type
a__bound__
a_union_is_subclass_schema
is_subclass_schema
a__constraints__
type_param
uExpected a class, got
uGenerate schema for a Type, e.g. `Type[int]`.
a_serializers
T aserialize_sequence_via_list
serialize_sequence_via_list
smart_deepcopy
aSequence
D acls_repr
aSequence
T asequence_validator
sequence_validator
no_info_wrap_validator_function
wrap_serializer_function_ser_schema
T aschema
info_arg
T ajson_schema
python_schema
serialization
uGenerate schema for a Sequence, e.g. `Sequence[int]`.
generator_schema
uGenerate a schema for an `Iterable`.
T a_validators
uGenerateSchema._pattern_schema.<locals>.<lambda>
T apattern
json
T awhen_used
return_schema
pattern_either_validator
pattern_str_validator
pattern_bytes_validator
D atype
format
string
regex
aHashable
uInput should be hashable
T aschema
custom_error_type
custom_error_message
dataclass
T ais_pydantic_dataclass
l ais_pydantic_dataclass
deepcopy
apply_typevars_map
collect_dataclass_fields
T atypevars_map
extra
uField
u has `init=False` and dataclass has config setting `extra="allow"`. This combination is not allowed.
D acode
udataclass-init-false-extra-allow
T a__pydantic_decorators__
sorted
uGenerateSchema._dataclass_schema.<locals>.<lambda>
T akey
a__post_init__
a__slots__
dataclass_args_schema
T acomputed_fields
collect_init_only
dataclass_schema
name
T ageneric_origin
post_init
ref
fields
slots
config
frozen
uGenerate schema for a dataclass.
a_generate_dc_field_schema
uGenerateSchema._dataclass_schema.<locals>.<genexpr>
T akw_only
signature
get_function_type_hints
T aglobalns
localns
aPOSITIONAL_ONLY
positional_only
aPOSITIONAL_OR_KEYWORD
positional_or_keyword
aKEYWORD_ONLY
keyword_only
parameters
sig
kind
default
arguments_list
aVAR_POSITIONAL
aVAR_KEYWORD
unpack_type
uExpected a `TypedDict` class, got
D acode
uunpack-typed-dict
intersection
uTyped dictionary
u overlaps with parameter
wsw u,
D acode
uoverlapping-unpack-typed-dict
uunpacked-typed-dict
uniform
validate_return
return_annotation
var_args_schema
var_kwargs_mode
var_kwargs_schema
populate_by_name
T avar_args_schema
var_kwargs_mode
var_kwargs_schema
populate_by_name
T areturn_schema
uGenerate schema for a Callable.
TODO support functional validators once we support them in Config
uGenerateSchema._call_schema.<locals>.<genexpr>
has_default
a__default__
uPydantic does not support mixing more than one of TypeVar bounds, constraints and defaults
aUnion
uGenerateSchema._unsubstituted_typevar_schema.<locals>.<lambda>
T aschema
a_decorators
get_function_return_type
func
return_type
locals
T alocalns
aPydanticUndefined
T uComputed field is missing return type annotation or specifying `return_type` to the `@computed_field` decorator (e.g. `@computed_field(return_type=int|str)`)
umodel-field-missing-annotation
replace
T areturn_type
a_apply_alias_generator_to_computed_field_info
T aalias_generator
computed_field_info
computed_field_name
D areadOnly
tacomputed_field
T areturn_schema
alias
metadata
unot enough values to unpack (expected at least 1, got %d)
uGenerate schema for an Annotated type, e.g. `Annotated[int, Field(...)]` or `Annotated[int, Gt(0)]`.
a_std_types_schema
T adeque_schema_prepare_pydantic_annotations
mapping_like_prepare_pydantic_annotations
path_schema_prepare_pydantic_annotations
deque_schema_prepare_pydantic_annotations
mapping_like_prepare_pydantic_annotations
path_schema_prepare_pydantic_annotations
aPATH_TYPES
aDEQUE_TYPES
aMAPPING_TYPES
a_known_annotated_metadata
expand_grouped_metadata
D aobj
return
aAny
aCoreSchema
inner_handler
uGenerateSchema._apply_annotations.<locals>.inner_handler
annotations
a_get_wrapped_inner_schema
get_inner_schema
pydantic_js_annotation_functions
source_type
T apydantic_js_annotation_functions
uApply arguments from `Annotated` or from `FieldInfo` to a schema.
This gets called by `GenerateSchema._annotated_schema` but differs from it in that it does
not expect `source_type` to be an `Annotated` object, it expects it to be  the first argument of that
(in other words, `GenerateSchema._annotated_schema` just unpacks `Annotated`, this process it).
transform_inner_schema
a_apply_single_annotation
copy
w_udefinition-ref
schema_ref
apply_known_metadata
a_apply_single_annotation_json_schema
uGenerateSchema._get_wrapped_inner_schema.<locals>.<lambda>
D asource
return
aAny
ucore_schema.CoreSchema
new_handler
uGenerateSchema._get_wrapped_inner_schema.<locals>.new_handler
metadata_get_schema
ustr|None
inspect_field_serializer
wrap
when_used
T ais_field_serializer
info_arg
return_schema
when_used
plain
uApply field serializers to a schema.
inspect_model_serializer
T ainfo_arg
return_schema
when_used
uApply model serializers to a schema.
no_info_before_validator_function
with_info_before_validator_function
T afield_name
with_info_after_validator_function
with_info_wrap_validator_function
inspect_validator
uwith-info
uno-info
a_VALIDATOR_F_MATCH
field_name
uApply validators to a schema.
Args:
schema: The schema to apply validators on.
validators: An iterable of validators.
field_name: The name of the field if validators are being applied to a model field.
Returns:
The updated schema.
always
uIn v1, if any of the validators for a field had `always=True`, the default value would be validated.
This serves as an auxiliary function for re-implementing that logic, by looping over a provided
collection of (v1-style) ValidatorDecoratorInfo's and checking if any of them have `always=True`.
We should be able to drop this function and the associated logic calling it once we drop support
for v1-style validator decorators. (Or we can extend it and keep it if we add something equivalent
to the v1-validator `always` kwarg to `field_validator`.)
before
T afunction
schema
after
uApply model validators to a schema.
If mode == 'inner', only "before" validators are applied
If mode == 'outer', validators other than "before" are applied
If mode == 'all', all validators are applied
Args:
schema: The schema to apply validators on.
validators: An iterable of validators.
mode: The validator mode.
Returns:
The updated schema.
default_factory
with_default_schema
takes_validated_data_argument
T adefault_factory
default_factory_takes_data
validate_default
T adefault
validate_default
uWrap schema with default schema if default value or `default_factory` are available.
Args:
field_info: The field info object.
schema: The schema to apply default on.
Returns:
Updated schema by default value or `default_factory`.
a__get_pydantic_json_schema__
a__modify_schema__
uThe `__modify_schema__` method is not supported in Pydantic v2. Use `__get_pydantic_json_schema__` instead
u in class `
w`D acode
ucustom-json-schema
a__origin__
uExtract `__get_pydantic_json_schema__` from a type, handling the deprecated `__modify_schema__`.
seen
uGet a definition for `tp` if one exists.
If a definition exists, a tuple of `(ref_string, CoreSchema)` is returned.
If no definition exists yet, a tuple of `(ref_string, None)` is returned.
Note that the returned `CoreSchema` will always be a `DefinitionReferenceSchema`,
not the actual definition itself.
This should be called for any type that can be identified by reference.
This includes any recursive types.
At present the following types can be named/recursive:
- BaseModel
- Dataclasses
- TypedDict
- TypeAliasType
add
discard
u_Definitions.get_schema_or_ref
a_stack
u_FieldNameStack.push
type_obj
u_ModelTypeStack.push
uConvert python types to pydantic-core schema.
a__file__
origin
has_location
a__cached__
a_annotations
ucollections.abc
os
pathlib
sys
contextlib
T acontextmanager
contextmanager
T acopy
deepcopy
decimal
T aDecimal
enum
T aEnum
fractions
T aFraction
partial
T aParameter
a_ParameterKind
signature
a_ParameterKind
ipaddress
T aIPv4Address
aIPv4Interface
aIPv4Network
aIPv6Address
aIPv6Interface
aIPv6Network
itertools
T achain
operator
T aattrgetter
aFunctionType
aLambdaType
aMethodType
aTYPE_CHECKING
aIterator
aMapping
overload
uuid
T aUUID
T awarn
typing_extensions
pydantic_core
aCoreSchema
core_schema
T aLiteral
aTypeAliasType
aTypedDict
get_args
get_origin
is_typeddict
aLiteral
aTypeAliasType
aTypedDict
upydantic.aliases
upydantic.annotated_handlers
aGetCoreSchemaHandler
aGetJsonSchemaHandler
upydantic.config
aConfigDict
aJsonDict
aJsonEncoder
aJsonSchemaExtraCallable
upydantic.errors
upydantic.functional_validators
aAfterValidator
aBeforeValidator
aFieldValidatorModes
aPlainValidator
aWrapValidator
upydantic.json_schema
aJsonSchemaValue
version
T aversion_short
upydantic.warnings
T a_core_utils
a_decorators
a_discriminated_union
a_known_annotated_metadata
a_typing_extra
a_config
T aConfigWrapper
aConfigWrapperStack
a_core_metadata
T aupdate_core_metadata
T acollect_invalid_schemas
define_expected_missing_refs
get_ref
get_type_ref
is_function_with_inner_schema
is_list_like_schema_with_items_schema
simplify_schema_references
validate_core_schema
T aDecorator
aDecoratorInfos
aFieldSerializerDecoratorInfo
aFieldValidatorDecoratorInfo
aModelSerializerDecoratorInfo
aModelValidatorDecoratorInfo
aRootValidatorDecoratorInfo
aValidatorDecoratorInfo
get_attribute_from_bases
inspect_field_serializer
inspect_model_serializer
inspect_validator
aDecorator
aFieldSerializerDecoratorInfo
aFieldValidatorDecoratorInfo
aModelSerializerDecoratorInfo
aModelValidatorDecoratorInfo
aRootValidatorDecoratorInfo
aValidatorDecoratorInfo
a_docs_extraction
T aextract_docstrings_from_cls
T acollect_dataclass_fields
takes_validated_data_argument
a_forward_ref
T aPydanticRecursiveRef
a_generics
T aget_standard_typevars_map
has_instance_in_type
recursively_defined_type_refs
replace_types
a_import_utils
T aimport_cached_base_model
import_cached_field_info
a_mock_val_ser
T aMockCoreSchema
a_namespace_utils
T aNamespacesTuple
aNsResolver
aNamespacesTuple
a_schema_generation_shared
T aCallbackGetCoreSchemaHandler
a_utils
T alenient_issubclass
smart_deepcopy
aFieldDecoratorInfo
T aFieldDecoratorInfoType
T abound
aFieldDecoratorInfoType
aAnyFieldDecorator
aModifyCoreSchemaWrapHandler
aGetCoreSchemaFunction
aTuple
ulist[type]
aList
aMutableSequence
aSet
aMutableSet
aFrozenSet
aPathLike
aPath
aPurePath
aPosixPath
aPurePosixPath
aPureWindowsPath
aMutableMapping
aOrderedDict
aDefaultDict
defaultdict
aCounter
deque
aDeque
aValidateCallSupportedTypes
udict[FieldValidatorModes, type[BeforeValidator | AfterValidator | PlainValidator | WrapValidator]]
D ainfo
field
return
aFieldDecoratorInfo
str
bool
D adecorators
fields
return
uIterable[AnyFieldDecorator]
uIterable[str]
aNone
D avalidator_functions
field
return
uIterable[Decorator[FieldDecoratorInfoType]]
str
ulist[Decorator[FieldDecoratorInfoType]]
D aschema
each_item_validators
field_name
return
ucore_schema.CoreSchema
ulist[Decorator[ValidatorDecoratorInfo]]
ustr | None
ucore_schema.CoreSchema
D ainfo
return
uFieldInfo | ComputedFieldInfo
utuple[JsonDict | None, JsonDict | JsonSchemaExtraCallable | None]
aJsonEncoders
D ajson_encoders
tp
schema
return
uJsonEncoders | None
aAny
aCoreSchema
pD wawbareturn
aAny
ppupydantic._internal._generate_schema
uGenerate core schema for a Pydantic model, dataclass and types like `str`, `datetime`, ... .
aGenerateSchema
a__qualname__
T a_config_wrapper_stack
a_ns_resolver
a_typevars_map
field_name_stack
model_type_stack
defs
T nnD aconfig_wrapper
ns_resolver
typevars_map
return
aConfigWrapper
uNsResolver | None
udict[Any, Any] | None
aNone
a__init__
uGenerateSchema.__init__
D areturn
aNone
uGenerateSchema.__init_subclass__
D areturn
aConfigWrapper
uGenerateSchema._config_wrapper
D areturn
aNamespacesTuple
uGenerateSchema._types_namespace
D areturn
bool
uGenerateSchema._arbitrary_types
D aitems_type
return
aAny
aCoreSchema
uGenerateSchema._list_schema
D akeys_type
values_type
return
aAny
paCoreSchema
uGenerateSchema._dict_schema
uGenerateSchema._set_schema
uGenerateSchema._frozenset_schema
D aenum_type
return
utype[Enum]
aCoreSchema
uGenerateSchema._enum_schema
D atp
return
aAny
aCoreSchema
uGenerateSchema._ip_schema
D areturn
aCoreSchema
uGenerateSchema._fraction_schema
uGenerateSchema._arbitrary_type_schema
uGenerateSchema._unknown_type_schema
D aschema
discriminator
return
aCoreSchema
ustr | Discriminator | None
aCoreSchema
uGenerateSchema._apply_discriminator_to_union
T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
uGenerateSchema.CollectedInvalid
a__orig_bases__
clean_schema
uGenerateSchema.clean_schema
uGenerateSchema.collect_definitions
D ametadata_schema
js_function
return
aCoreSchema
uCallable[..., Any]
aNone
uGenerateSchema._add_js_function
T tD aobj
from_dunder_get_core_schema
return
aAny
bool
ucore_schema.CoreSchema
uGenerateSchema.generate_schema
D acls
return
utype[BaseModel]
ucore_schema.CoreSchema
uGenerateSchema._model_schema
uGenerateSchema._unpack_refs_defs
D aobj
return
aAny
puGenerateSchema._resolve_self_type
D aobj
source
return
aAny
pucore_schema.CoreSchema | None
uGenerateSchema._generate_schema_from_property
uGenerateSchema._resolve_forward_ref
D aobj
required
return
aAny
uLiteral[True]
utuple[Any, ...]
uGenerateSchema._get_args_resolving_forward_refs
D aobj
return
aAny
utuple[Any, ...] | None
T FD aobj
required
return
aAny
bool
utuple[Any, ...] | None
uGenerateSchema._get_first_arg_or_any
D aobj
return
aAny
utuple[Any, Any]
uGenerateSchema._get_first_two_args_or_any
D aobj
return
aAny
ucore_schema.CoreSchema
uGenerateSchema._generate_schema_inner
uGenerateSchema.match_type
D aobj
origin
return
aAny
paCoreSchema
uGenerateSchema._match_generic_type
D aname
field_info
decorators
required
return
str
aFieldInfo
aDecoratorInfos
bool
ucore_schema.TypedDictField
uGenerateSchema._generate_td_field_schema
D aname
field_info
decorators
return
str
aFieldInfo
aDecoratorInfos
ucore_schema.ModelField
uGenerateSchema._generate_md_field_schema
D aname
field_info
decorators
return
str
aFieldInfo
aDecoratorInfos
ucore_schema.DataclassField
uGenerateSchema._generate_dc_field_schema
D aalias_generator
field_info
field_name
return
uCallable[[str], str] | AliasGenerator
aFieldInfo
str
aNone
uGenerateSchema._apply_alias_generator_to_field_info
D aalias_generator
computed_field_info
computed_field_name
uCallable[[str], str] | AliasGenerator
aComputedFieldInfo
str
uGenerateSchema._apply_alias_generator_to_computed_field_info
D aconfig_wrapper
field_info
field_name
return
aConfigWrapper
uFieldInfo | ComputedFieldInfo
str
aNone
uGenerateSchema._apply_field_title_generator_to_field_info
D aname
field_info
decorators
return
str
aFieldInfo
aDecoratorInfos
a_CommonField
uGenerateSchema._common_field_schema
D aunion_type
return
aAny
ucore_schema.CoreSchema
uGenerateSchema._union_schema
D aobj
return
aTypeAliasType
aCoreSchema
uGenerateSchema._type_alias_type_schema
D aliteral_type
return
aAny
aCoreSchema
uGenerateSchema._literal_schema
D atyped_dict_cls
origin
return
aAny
pucore_schema.CoreSchema
uGenerateSchema._typed_dict_schema
D anamedtuple_cls
origin
return
aAny
pucore_schema.CoreSchema
uGenerateSchema._namedtuple_schema
D aname
annotation
default
mode
return
str
utype[Any]
aAny
uLiteral['positional_only', 'positional_or_keyword', 'keyword_only'] | None
ucore_schema.ArgumentsParameter
uGenerateSchema._generate_parameter_schema
D atuple_type
return
aAny
ucore_schema.CoreSchema
uGenerateSchema._tuple_schema
D areturn
ucore_schema.CoreSchema
uGenerateSchema._type_schema
uGenerateSchema._zoneinfo_schema
uGenerateSchema._union_is_subclass_schema
D atype_
return
aAny
ucore_schema.CoreSchema
uGenerateSchema._subclass_schema
D aitems_type
return
aAny
ucore_schema.CoreSchema
uGenerateSchema._sequence_schema
D atype_
return
aAny
ucore_schema.GeneratorSchema
uGenerateSchema._iterable_schema
D apattern_type
return
aAny
ucore_schema.CoreSchema
uGenerateSchema._pattern_schema
uGenerateSchema._hashable_schema
D adataclass
origin
return
utype[StandardDataclass]
utype[StandardDataclass] | None
ucore_schema.CoreSchema
uGenerateSchema._dataclass_schema
D afunction
return
aValidateCallSupportedTypes
ucore_schema.CallSchema
uGenerateSchema._call_schema
D atypevar
return
utyping.TypeVar
ucore_schema.CoreSchema
uGenerateSchema._unsubstituted_typevar_schema
D wdafield_serializers
return
uDecorator[ComputedFieldInfo]
udict[str, Decorator[FieldSerializerDecoratorInfo]]
ucore_schema.ComputedField
uGenerateSchema._computed_field_schema
D aannotated_type
return
aAny
ucore_schema.CoreSchema
uGenerateSchema._annotated_schema
D aobj
annotations
return
aAny
utuple[Any, ...]
utuple[Any, list[Any]] | None
uGenerateSchema._get_prepare_pydantic_annotations_for_known_type
uGenerateSchema.<lambda>
D asource_type
annotations
transform_inner_schema
return
aAny
ulist[Any]
uCallable[[CoreSchema], CoreSchema]
aCoreSchema
uGenerateSchema._apply_annotations
D aschema
metadata
return
ucore_schema.CoreSchema
aAny
ucore_schema.CoreSchema
uGenerateSchema._apply_single_annotation
uGenerateSchema._apply_single_annotation_json_schema
D aget_inner_schema
annotation
pydantic_js_annotation_functions
return
aGetCoreSchemaHandler
aAny
ulist[GetJsonSchemaFunction]
aCallbackGetCoreSchemaHandler
uGenerateSchema._get_wrapped_inner_schema
D aschema
serializers
return
ucore_schema.CoreSchema
ulist[Decorator[FieldSerializerDecoratorInfo]]
ucore_schema.CoreSchema
uGenerateSchema._apply_field_serializers
D aschema
serializers
return
ucore_schema.CoreSchema
uIterable[Decorator[ModelSerializerDecoratorInfo]]
ucore_schema.CoreSchema
uGenerateSchema._apply_model_serializers
T abefore
uno-info
T aafter
uno-info
T aplain
uno-info
T awrap
uno-info
T abefore
uwith-info
T aafter
uwith-info
T aplain
uwith-info
T awrap
uwith-info
uMapping[tuple[FieldValidatorModes, Literal['no-info', 'with-info']], Callable[[Callable[..., Any], core_schema.CoreSchema, str | None], core_schema.CoreSchema]]
D aschema
validators
field_name
return
ucore_schema.CoreSchema
uIterable[Decorator[RootValidatorDecoratorInfo]] | Iterable[Decorator[ValidatorDecoratorInfo]] | Iterable[Decorator[FieldValidatorDecoratorInfo]]
ustr | None
ucore_schema.CoreSchema
D avalidators
return
uIterable[Decorator[ValidatorDecoratorInfo]]
bool
D aschema
validators
mode
return
ucore_schema.CoreSchema
uIterable[Decorator[ModelValidatorDecoratorInfo]]
uLiteral['inner', 'outer', 'all']
ucore_schema.CoreSchema
D afield_info
schema
return
aFieldInfo
ucore_schema.CoreSchema
ucore_schema.CoreSchema
D atp
schema
return
aAny
aCoreSchema
uGetJsonSchemaFunction | None
a_CommonField
ucore_schema.CoreSchema
ustr | list[str | int] | list[list[str | int]] | None
ubool | None
udict[str, Any]
D avalidation_alias
serialization_alias
serialization_exclude
frozen
metadata
nnnnnD aschema
validation_alias
serialization_alias
serialization_exclude
frozen
metadata
return
ucore_schema.CoreSchema
ustr | list[str | int] | list[list[str | int]] | None
ustr | None
ubool | None
ubool | None
aAny
a_CommonField
uKeeps track of references and definitions.
u_Definitions.__init__
D atp
return
aAny
uIterator[tuple[str, None] | tuple[str, CoreSchema]]
D aschema
definitions
return
aCoreSchema
udict[str, CoreSchema]
uCoreSchema | None
T a_stack
u_FieldNameStack.__init__
D afield_name
return
str
uIterator[None]
D areturn
ustr | None
u_FieldNameStack.get
u_ModelTypeStack.__init__
D atype_obj
return
type
uIterator[None]
D areturn
utype | None
u_ModelTypeStack.get
upydantic\_internal\_generate_schema.py
T a.0
wpT a.0
wkwvaself
decorators
T a.0
waT a.0
waaself
T a.0
wvT a.0
param
typevars_map
T wfw_afield_name
T wfa_1
a_2
T wfaschema
w_T wfaschema
field_name
T wxT waT a_1
a_2
T asource
handler
T a_1
a_2
ip_type_json_schema_format
tp
T aip_type_json_schema_format
tp
T wvT wxwhu<module pydantic._internal._generate_schema>
T a__class__
T aself
config_wrapper
ns_resolver
typevars_map
T aself
T acls
a__class__
T ajson_encoders
tp
schema
base
encoder
T aself
metadata_schema
js_function
metadata
pydantic_js_functions
T aself
annotated_type
aFieldInfo
source_type
annotations
schema
annotation
T aalias_generator
computed_field_info
computed_field_name
alias
validation_alias
serialization_alias
T aalias_generator
field_info
field_name
alias
validation_alias
serialization_alias
T aself
source_type
annotations
transform_inner_schema
pydantic_js_annotation_functions
res
inner_handler
get_inner_schema
annotation
schema
core_metadata
T aself
schema
discriminator
T aself
schema
serializers
inner_schema
ref
serializer
is_field_serializer
info_arg
return_type
weareturn_schema
T aconfig_wrapper
field_info
field_name
field_title_generator
title
T
self
schema
serializers
ref
ser_schema
serializer
info_arg
return_type
weareturn_schema
T
self
schema
metadata
aFieldInfo
field_metadata
inner
original_schema
ref
new_ref
maybe_updated_schema
T aself
schema
metadata
aFieldInfo
field_metadata
pydantic_js_updates
pydantic_js_extra
core_metadata
T aself
tp
T aself
function
mode_lookup
arguments_list
var_args_schema
var_kwargs_schema
var_kwargs_mode
return_schema
sig
globalns
localns
type_hints
name
wpaannotation
parameter_mode
arg_schema
unpack_type
non_pos_only_param_names
overlapping_params
config_wrapper
return_hint
T aschema
validation_alias
serialization_alias
serialization_exclude
frozen
metadata
T aself
name
field_info
decorators
core_metadata
aFieldInfo
evaluated_type
weanew_field_info
wkwvasource_type
annotations
set_discriminator
validators_from_decorators
decorator
schema
this_field_validators
each_item_validators
pydantic_js_updates
pydantic_js_extra
alias_generator
validation_alias
T
self
wdafield_serializers
core_metadata
return_type
weareturn_type_schema
alias_generator
pydantic_js_updates
pydantic_js_extra
T aself
dataclass
origin
dataclass_ref
maybe_schema
typevars_map
config
is_pydantic_dataclass
fields
field
field_name
decorators
args
has_post_init
has_slots
args_schema
inner_schema
model_validators
core_config
dc_schema
schema
T aself
keys_type
values_type
T aself
enum_type
cases
sub_type
value_ser_type
enum_ref
description
js_updates
get_json_schema
default_missing
enum_schema
get_json_schema_no_cases
T atp
schema
js_modify_function
aBaseModel
has_custom_v2_modify_js_func
cls_name
T ainfo
json_schema_updates
T aself
fraction_validator
T aself
items_type
T aself
name
field_info
decorators
common_field
T
self
name
annotation
default
mode
aFieldInfo
field
schema
parameter_schema
alias_generator
T aself
obj
source
schema
w_amaybe_schema
ref_mode
get_schema
existing_schema
validators
aBaseModelV1
ref
T aself
obj
aBaseModel
T aself
name
field_info
decorators
required
common_field
T aself
obj
T aself
obj
required
T aself
obj
required
args
aGenericAlias
T aself
obj
args
T wawbT aself
obj
args
origin
T aself
obj
annotations
deque_schema_prepare_pydantic_annotations
mapping_like_prepare_pydantic_annotations
path_schema_prepare_pydantic_annotations
obj_origin
T aself
get_inner_schema
annotation
pydantic_js_annotation_functions
metadata_get_schema
new_handler
T aself
tp
ip_type_json_schema_format
aIP_VALIDATOR_LOOKUP
aIpType
ser_ip
T aself
type_
item_type
T aself
literal_type
expected
schema
T aself
obj
origin
from_property
res
source_type
annotations
T aself
cls
generic_origin
fields_schema
model_ref
maybe_schema
fields
decorators
computed_fields
config_wrapper
core_config
model_validators
extras_schema
candidate_cls
extras_annotation
tp
extra_items_type
root_field
inner_schema
model_schema
new_inner_schema
schema
T	aself
namedtuple_cls
origin
annotations
namedtuple_ref
maybe_schema
typevars_map
weaarguments_schema
T aself
pattern_type
a_validators
metadata
ser
param
T aself
obj
weT	aself
items_type
serialize_sequence_via_list
item_type_schema
list_schema
json_schema
python_schema
sequence_validator
serialization
T aself
type_
type_param
T aself
tuple_type
typevars_map
params
T	aself
obj
origin
ref
maybe_schema
typevars_map
annotation
weaschema
T aself
typed_dict_cls
origin
config
required_keys
fields
aFieldInfo
typed_dict_ref
maybe_schema
typevars_map
core_config
decorators
field_docstrings
annotations
weafield_name
annotation
required
field_info
td_schema
schema
T aself
union_type
args
T
self
union_type
choices
choices_with_tags
args
nullable
arg
wsachoice
tag
T aself
schema
definitions
wsT aself
typevar
bound
constraints
typevar_has_default
schema
T avalidators
validator
T aself
aZoneInfo
aZoneInfoNotFoundError
validate_str_is_valid_iana_tz
metadata
T aschema
each_item_validators
field_name
variadic_item_index
inner_schema
T aschema
validators
mode
ref
validator
info_arg
T aschema
validators
field_name
validator
info_arg
val_type
T adecorators
fields
dec
field
T ainfo
field
v_field_name
T aself
schema
T aself
schema
ref
T avalidator_functions
field
T aself
obj
from_dunder_get_core_schema
schema
from_property
metadata_js_function
metadata_schema
T aschema
handler
json_schema
original_schema
js_updates
T ajs_updates
T	w_ahandler
json_schema
original_schema
enum_type
cases
sub_type
enum_ref
js_updates
T acases
enum_ref
enum_type
js_updates
sub_type
T aself
tp
ref
T aobj
from_property
schema
metadata_js_function
metadata_schema
self
source_type
transform_inner_schema
T aself
source_type
transform_inner_schema
T aself
obj
origin
res
source_type
annotations
T asource
schema
metadata_js_function
metadata_get_schema
get_inner_schema
self
annotation
pydantic_js_annotation_functions
T aannotation
get_inner_schema
metadata_get_schema
pydantic_js_annotation_functions
self
T aself
field_name
T aself
type_obj
T aschema
definitions
T aip
info
tp
T atp
T aschema
self
field_info
T afield_info
self
T avalue
aZoneInfo
aZoneInfoNotFoundError
T afield_info
schema
a__spec__
.pydantic._internal._generics
v/
size_limit
a__class__
a__init__
a__setitem__
l
keys
maps
clear
value
