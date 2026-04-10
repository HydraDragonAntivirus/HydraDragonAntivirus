# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._forward_ref

aPydanticRecursiveRef
a__qualname__
a__annotations__
str
type_ref
a__name__
a__hash__
D areturn
aNone
uDefining __call__ is necessary for the `typing` module to let you use an instance of
this class as the result of resolving a standard ForwardRef.
a__call__
uPydanticRecursiveRef.__call__
a__or__
uPydanticRecursiveRef.__or__
a__ror__
uPydanticRecursiveRef.__ror__
upydantic\_internal\_forward_ref.py
u<module pydantic._internal._forward_ref>
T a__class__
T aself
T aself
other

a__spec__
.pydantic._internal._generate_schema
Y
w*afields
uCheck if field name is in validator fields.
Args:
info: The field info.
field: The field name to check.
Returns:
`True` if field name is in validator fields, `False` otherwise.
info
check_fields
aPydanticUserError
uDecorators defined with incorrect fields:
cls_ref

w.acls_var_name
u (use check_fields=False if you're inheriting from the model and intended this)
D acode
udecorator-missing-field
uCheck if the defined fields in decorators exist in `fields` param.
It ignores the check for a decorator if the decorator has `*` as field or `check_fields=False`.
Args:
decorators: An iterable of decorators.
fields: An iterable of fields name.
Raises:
PydanticUserError: If one of the field names does not exist in `fields` param.
check_validator_fields_against_field_name
field
type
nullable
apply_each_item_validators
schema
tuple
get
T avariadic_item_index
apply_validators
items_schema
is_list_like_schema_with_items_schema
upydantic_core.core_schema
any_schema
dict
values_schema
u`@validator(..., each_item=True)` cannot be applied to fields with a schema of
title
description
deprecated
examples
to_jsonable_python
json_schema_extra
serialization
a__mro__
:nq najson_encoders
warnings
warn
u`json_encoders` is deprecated. See https://docs.pydantic.dev/
version_short
u/concepts/serialization/#custom-serializers for alternatives
aPydanticDeprecatedSince20
plain_serializer_function_ser_schema
D awhen_used
json
uIterate over the json_encoders and add the first matching encoder to the schema.
Args:
json_encoders: A dictionary of types and their encoder functions.
tp: The type to check for a matching encoder.
schema: The schema to add the encoder to.
uReturn the first argument if it is not None, otherwise return the second argument.
Use case: serialization_alias (argument a) and alias (argument b) are both defined, and serialization_alias is ''.
This function will return serialization_alias, which is the first argument, even though it is an empty string.
aConfigWrapperStack
a_config_wrapper_stack
aNsResolver
a_ns_resolver
a_typevars_map
a_FieldNameStack
field_name_stack
a_ModelTypeStack
model_type_stack
a_Definitions
defs
a__class__
a__init_subclass__
uSubclassing `GenerateSchema` is not supported. The API is highly subject to change in minor versions.
aUserWarning
D astacklevel
l atail
types_namespace
a_config_wrapper
arbitrary_types_allowed
list_schema
generate_schema
dict_schema
set_schema
frozenset_schema
a__members__
values
get_type_ref
a__doc__
inspect
cleandoc
uAn enumeration.
a__name__
int
simple_ser_schema
T aint
str
T astr
float
T afloat
u<lambda>
uGenerateSchema._enum_schema.<locals>.<lambda>
D aschema
handler
return
aCoreSchema
aGetJsonSchemaHandler
aJsonSchemaValue
get_json_schema
uGenerateSchema._enum_schema.<locals>.get_json_schema
a_missing_
a__func__
aEnum
enum_schema
pydantic_js_functions
T asub_type
missing
ref
metadata
use_enum_values
no_info_after_validator_function
attrgetter
T avalue
T aserialization
D ahandler
return
aGetJsonSchemaHandler
aJsonSchemaValue
get_json_schema_no_cases
uGenerateSchema._enum_schema.<locals>.get_json_schema_no_cases
is_instance_schema
T ametadata
resolve_ref_schema
update
js_updates
enum_type
cases
sub_type
enum_ref
T asub_type
ref
a_validators
T aIP_VALIDATOR_LOOKUP
aIpType
aIP_VALIDATOR_LOOKUP
aIpType
aIPv4Address
ipv4
aIPv4Network
ipv4network
aIPv4Interface
ipv4interface
aIPv6Address
ipv6
aIPv6Network
ipv6network
aIPv6Interface
ipv6interface
D aip
info
return
aAny
ucore_schema.SerializationInfo
ustr | IpType
ser_ip
uGenerateSchema._ip_schema.<locals>.ser_ip
lax_or_strict_schema
no_info_plain_validator_function
json_or_python_schema
str_schema
T ajson_schema
python_schema
D ainfo_arg
when_used
taalways
uGenerateSchema._ip_schema.<locals>.<lambda>
T alax_schema
strict_schema
serialization
metadata
tp
aPydanticSerializationUnexpectedValue
uExpected `
u` but got `
u` with value `'
u'` - serialized value may not be as expected.
mode
python
string
format
ip_type_json_schema_format
T afraction_validator
fraction_validator
aFraction
to_string_ser_schema
T aalways
T awhen_used
uGenerateSchema._fraction_schema.<locals>.<lambda>
uSupport for [`fractions.Fraction`][fractions.Fraction].
D atype
format
string
fraction
u is not a Python type (it may be an instance of an object), Pydantic will allow any object with no validation since we cannot even enforce that the input is an instance of the given type. To get rid of this error wrap the type with `pydantic.SkipValidation`.
aPydanticSchemaGenerationError
uUnable to generate pydantic-core schema for
u. Set `arbitrary_types_allowed=True` in the model_config to ignore this error or implement `__get_pydantic_core_schema__` on your type to fully support it.
If you got this error by calling handler(<some type>) within `__get_pydantic_core_schema__` then you likely need to call `handler.generate_schema(<some type>)` since we do not call `__get_pydantic_core_schema__` on `<some type>` otherwise to avoid infinite recursion.
a_discriminated_union
apply_discriminator
aMissingDefinitionForUnionRef
set_discriminator_in_metadata
collect_definitions
simplify_schema_references
collect_invalid_schemas
aCollectedInvalid
apply_discriminators
validate_core_schema
cast
ustr | None
T aref
nadefinitions
ref
definition_reference_schema
definitions_schema
metadata
setdefault
append
a_generate_schema_from_property
a_generate_schema_inner
a_extract_get_pydantic_json_schema
resolve_original_schema
a_add_js_function
a_add_custom_serialization_from_json_encoders
uGenerate core schema.
Args:
obj: The object to generate core schema for.
from_dunder_get_core_schema: Whether to generate schema from either the
`__get_pydantic_core_schema__` function or `__pydantic_core_schema__` property.
Returns:
The generated core schema.
Raises:
PydanticUndefinedAnnotation:
If it is not possible to evaluate forward reference.
PydanticSchemaGenerationError:
If it is not possible to generate pydantic-core schema.
TypeError:
- If `alias_generator` returns a disallowed type (must be str, AliasPath or AliasChoices).
- If V1 style validator with `each_item=True` applied on a wrong field.
PydanticUserError:
- If `typing.TypedDict` is used instead of `typing_extensions.TypedDict` on Python < 3.12.
- If `__modify_schema__` method is used instead of `__get_pydantic_json_schema__`.
get_schema_or_ref
a__enter__
a__exit__
a__pydantic_fields__
a__pydantic_decorators__
computed_fields
check_decorator_fields_exist
chain
field_validators
field_serializers
validators
keys
aConfigWrapper
model_config
D acheck
Facore_config
T atitle
model_validators
push
T aextra_fields_behavior
allow
a__annotations__
T a__pydantic_extra__
na_typing_extra
eval_type_backport
a_make_forward_ref
D ais_argument
is_class
Ftaself
a_types_namespace
get_origin
aDict
T uThe type annotation for `__pydantic_extra__` must be `Dict[str, ...]`
a_get_args_resolving_forward_refs
D arequired
tais_any
a__pydantic_generic_metadata__
T aorigin
a__pydantic_root_model__
a_common_field_schema
root
apply_model_validators
inner
model_schema
a__pydantic_custom_init__
a__pydantic_post_init__
T ageneric_origin
custom_init
root_model
post_init
config
ref
model_fields_schema
items
a_generate_md_field_schema
decorators
a_computed_field_schema
T acomputed_fields
extras_schema
model_name
root_validators
define_expected_missing_refs
recursively_defined_type_refs
inner_schema
a_apply_model_serializers
model_serializers
outer
model_ref
T nnnuGenerate schema for a Pydantic model.
uUnpack all 'definitions' schemas into `GenerateSchema.defs.definitions`
nd return the inner schema.
T u`typing.Self` is invalid in this context
uinvalid-self-type
T acode
is_self
a_resolve_self_type
obj
unpack
uto-def
a__get_pydantic_core_schema__
aCallbackGetCoreSchemaHandler
T aref_mode
a__dict__
T a__pydantic_core_schema__
aMockCoreSchema
existing_schema
a__get_validators__
upydantic.v1
T aBaseModel
aBaseModel
uMixing V1 models and V2 models (or constructs, like `TypeAdapter`) is not supported. Please upgrade `
u` to V2.
u`__get_validators__` is deprecated and will be removed, use `__get_pydantic_core_schema__` instead.
chain_schema
with_info_plain_validator_function
a_unpack_refs_defs
is_function_with_inner_schema
pop
get_ref
uTry to generate schema from either the `__get_pydantic_core_schema__` function or
`__pydantic_core_schema__` property.
Note: `__get_pydantic_core_schema__` takes priority so it can
decide whether to use a `__pydantic_core_schema__` attribute, or generate a fresh schema.
aPydanticUndefinedAnnotation
from_name_error
aForwardRef
a__forward_arg__
uUnable to evaluate forward reference
replace_types
get_args
aGenericAlias
uExpected
u to have generic parameters but it had none
u<genexpr>
uGenerateSchema._get_args_resolving_forward_refs.<locals>.<genexpr>
a_resolve_forward_ref
aAny
uExpected two type arguments for
u, got 1
is_annotated
a_annotated_schema
import_cached_base_model
lenient_issubclass
a_model_schema
aPydanticRecursiveRef
type_ref
T aschema_ref
match_type
bytes_schema
int_schema
float_schema
bool_schema
complex_schema
datetime
date
date_schema
datetime_schema
time
time_schema
timedelta
timedelta_schema
aDecimal
decimal_schema
aUUID
uuid_schema
aUrl
url_schema
a_fraction_schema
aMultiHostUrl
multi_host_url_schema
aNoneType
none_schema
aIP_TYPES
a_ip_schema
aTUPLE_TYPES
a_tuple_schema
aLIST_TYPES
a_list_schema
aSET_TYPES
a_set_schema
aFROZEN_SET_TYPES
a_frozenset_schema
aSEQUENCE_TYPES
a_sequence_schema
aDICT_TYPES
a_dict_schema
is_type_alias_type
a_type_alias_type_schema
a_type_schema
is_callable
callable_schema
is_literal
a_literal_schema
is_typeddict
a_typed_dict_schema
is_namedtuple
a_namedtuple_schema
is_new_type
a__supertype__
re
aPattern
a_pattern_schema
is_hashable
a_hashable_schema
aTypeVar
a_unsubstituted_typevar_schema
is_finalvar
aFinal
a_get_first_arg_or_any
aVALIDATE_CALL_SUPPORTED_TYPES
a_call_schema
isclass
a_enum_schema
is_zoneinfo_type
a_zoneinfo_schema
dataclasses
is_dataclass
a_dataclass_schema
a_match_generic_type
a_get_prepare_pydantic_annotations_for_known_type
a_apply_annotations
a_arbitrary_types
a_arbitrary_type_schema
a_unknown_type_schema
uMain mapping of types to schemas.
The general structure is a series of if statements starting with the simple cases
(non-generic primitive types) and then handling generics and other more complex cases.
Each case either generates a schema directly, calls into a public user-overridable method
(like `GenerateSchema.tuple_variable_schema`) or calls into a private method that handles some
boilerplate before calling into the user-facing method (e.g. `GenerateSchema._tuple_schema`).
The idea is that we'll evolve this into adding more and more user facing methods over time
s they get requested and we figure out what the right API for them is.
origin_is_union
a_union_schema
a_get_first_two_args_or_any
aType
a_subclass_schema
aIterable
collections
abc
aGenerator
a_iterable_schema
typed_dict_field
is_required
serialization_exclude
validation_alias
serialization_alias
T arequired
serialization_exclude
validation_alias
serialization_alias
metadata
uPrepare a TypedDictField to represent a model or typeddict field.
model_field
frozen
T aserialization_exclude
validation_alias
serialization_alias
frozen
metadata
uPrepare a ModelField to represent a model field.
dataclass_field
init
init_var
kw_only
T ainit
init_only
kw_only
serialization_exclude
validation_alias
serialization_alias
frozen
metadata
uPrepare a DataclassField to represent the parameter/field, of a dataclass.
alias_priority
alias
aAliasGenerator
generate_aliases
aCallable
ualias_generator
u must return str, not
a_get_first_non_null
uApply an alias_generator to aliases on a FieldInfo instance if appropriate.
Args:
lias_generator: A callable that takes a string and returns a string, or an AliasGenerator instance.
field_info: The FieldInfo instance to which the alias_generator is (maybe) applied.
field_name: The name of the field from which to generate the alias.
uApply an alias_generator to alias on a ComputedFieldInfo instance if appropriate.
Args:
lias_generator: A callable that takes a string and returns a string, or an AliasGenerator instance.
computed_field_info: The ComputedFieldInfo instance to which the alias_generator is (maybe) applied.
computed_field_name: The name of the computed field from which to generate the alias.
field_title_generator
ufield_title_generator
uApply a field_title_generator on a FieldInfo or ComputedFieldInfo instance if appropriate
Args:
config_wrapper: The config of the model
field_info: The FieldInfo or ComputedField instance to which the title_generator is (maybe) applied.
field_name: The name of the field from which to generate the title.
import_cached_field_info
evaluated
eval_type
annotation
has_instance_in_type
from_annotation
a_attributes_set
field_info
metadata_lookup
D aschema
return
aCoreSchema
paset_discriminator
uGenerateSchema._common_field_schema.<locals>.set_discriminator
filter_field_decorator_info_by_field
validators_from_decorators
a_mode_to_validator
a_from_decorator
discriminator
T atransform_inner_schema
a_validators_require_validate_default
validate_default
each_item
wrap_default
a_apply_field_serializers
a_apply_field_title_generator_to_field_info
a_extract_json_schema_info_from_field_info
update_core_metadata
T apydantic_js_updates
pydantic_js_extra
alias_generator
a_apply_alias_generator_to_field_info
aAliasChoices
aAliasPath
convert_to_aliases
a_common_field
exclude
a_apply_discriminator_to_union
choices
a_core_utils
aTAGGED_UNION_TAG_KEY
choices_with_tags
union_schema
nullable_schema
uGenerate schema for a Union.
get_standard_typevars_map
a__value__
literal_values
uliteral "expected" cannot be empty, obj=
literal_schema
uGenerateSchema._literal_schema.<locals>.<lambda>
uGenerate schema for a Literal.
uGenerateSchema._literal_schema.<locals>.<genexpr>
value
a_SUPPORTS_TYPEDDICT
