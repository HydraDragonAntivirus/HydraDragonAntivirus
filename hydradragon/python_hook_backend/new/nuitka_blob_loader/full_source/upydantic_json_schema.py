# Reconstructed from integrated Nuitka blob
# Module: upydantic.json_schema

uThis class is used to emit warnings produced during JSON schema generation.
See the [`GenerateJsonSchema.emit_warning`][pydantic.json_schema.GenerateJsonSchema.emit_warning] and
[`GenerateJsonSchema.render_warning_message`][pydantic.json_schema.GenerateJsonSchema.render_warning_message]
methods for more details; these can be overridden to control warning behavior.
a__qualname__
a__orig_bases__
u#/$defs/{model}
aDEFAULT_REF_TEMPLATE
T aCoreRef
Ostr
T aDefsRef
Ostr
T aJsonRef
Ostr
aCoreModeRef
T aJsonSchemaKeyT
T abound
aJsonSchemaKeyT
dataclass
slots_true
udict[DefsRef, DefsRef]
udict[JsonRef, JsonRef]
D aprioritized_choices
defs_to_json
definitions
return
udict[DefsRef, list[DefsRef]]
udict[DefsRef, JsonRef]
udict[DefsRef, JsonSchemaValue]
a_DefinitionsRemapping
u_DefinitionsRemapping.from_prioritized_choices
D aref
return
aDefsRef
pu_DefinitionsRemapping.remap_defs_ref
D aref
return
aJsonRef
pu_DefinitionsRemapping.remap_json_ref
D aschema
return
aAny
pu_DefinitionsRemapping.remap_json_schema
uUsage docs: https://docs.pydantic.dev/2.10/concepts/json_schema/#customizing-the-json-schema-generation-process
A class for generating JSON schemas.
This class generates JSON schemas based on configured parameters. The default schema dialect
is [https://json-schema.org/draft/2020-12/schema](https://json-schema.org/draft/2020-12/schema).
The class uses `by_alias` to configure how fields with
multiple names are handled and `ref_template` to format reference names.
Attributes:
schema_dialect: The JSON schema dialect used to generate the schema. See
[Declaring a Dialect](https://json-schema.org/understanding-json-schema/reference/schema.html#id4)
in the JSON Schema documentation for more information about dialects.
ignored_warning_kinds: Warnings to ignore when generating the schema. `self.render_warning_message` will
do nothing if its argument `kind` is in `ignored_warning_kinds`;
this value can be modified on subclasses to easily control which warnings are emitted.
by_alias: Whether to use field aliases when generating the schema.
ref_template: The format string used when generating reference names.
core_to_json_refs: A mapping of core refs to JSON refs.
core_to_defs_refs: A mapping of core refs to definition refs.
defs_to_core_refs: A mapping of definition refs to core refs.
json_to_defs_refs: A mapping of JSON refs to definition refs.
definitions: Definitions in the schema.
Args:
by_alias: Whether to use field aliases in the generated schemas.
ref_template: The format string to use when generating reference names.
Raises:
JsonSchemaError: If the instance of the class is inadvertently reused after generating a schema.
aGenerateJsonSchema
uhttps://json-schema.org/draft/2020-12/schema
schema_dialect
S uskipped-choice
uset[JsonSchemaWarningKind]
D aby_alias
ref_template
bool
str
a__init__
uGenerateJsonSchema.__init__
D areturn
u_config.ConfigWrapper
uGenerateJsonSchema._config
D areturn
aJsonSchemaMode
uGenerateJsonSchema.mode
D areturn
udict[CoreSchemaOrFieldType, Callable[[CoreSchemaOrField], JsonSchemaValue]]
uGenerateJsonSchema.build_schema_type_to_method
D ainputs
return
uSequence[tuple[JsonSchemaKeyT, JsonSchemaMode, core_schema.CoreSchema]]
utuple[dict[tuple[JsonSchemaKeyT, JsonSchemaMode], JsonSchemaValue], dict[DefsRef, JsonSchemaValue]]
uGenerateJsonSchema.generate_definitions
T avalidation
D aschema
mode
return
aCoreSchema
aJsonSchemaMode
aJsonSchemaValue
uGenerateJsonSchema.generate
D aschema
return
aCoreSchemaOrField
aJsonSchemaValue
uGenerateJsonSchema.generate_inner
T nD avalue
parent_key
return
aJsonSchemaValue
ustr | None
aJsonSchemaValue
uGenerateJsonSchema.sort
D avalue
parent_key
return
aAny
ustr | None
aAny
uGenerateJsonSchema._sort_recursive
D aschema
return
ucore_schema.InvalidSchema
aJsonSchemaValue
invalid_schema
uGenerateJsonSchema.invalid_schema
D aschema
return
ucore_schema.AnySchema
aJsonSchemaValue
uGenerateJsonSchema.any_schema
D aschema
return
ucore_schema.NoneSchema
aJsonSchemaValue
none_schema
uGenerateJsonSchema.none_schema
D aschema
return
ucore_schema.BoolSchema
aJsonSchemaValue
bool_schema
uGenerateJsonSchema.bool_schema
D aschema
return
ucore_schema.IntSchema
aJsonSchemaValue
int_schema
uGenerateJsonSchema.int_schema
D aschema
return
ucore_schema.FloatSchema
aJsonSchemaValue
uGenerateJsonSchema.float_schema
D aschema
return
ucore_schema.DecimalSchema
aJsonSchemaValue
decimal_schema
uGenerateJsonSchema.decimal_schema
D aschema
return
ucore_schema.StringSchema
aJsonSchemaValue
uGenerateJsonSchema.str_schema
D aschema
return
ucore_schema.BytesSchema
aJsonSchemaValue
bytes_schema
uGenerateJsonSchema.bytes_schema
D aschema
return
ucore_schema.DateSchema
aJsonSchemaValue
date_schema
uGenerateJsonSchema.date_schema
D aschema
return
ucore_schema.TimeSchema
aJsonSchemaValue
time_schema
uGenerateJsonSchema.time_schema
D aschema
return
ucore_schema.DatetimeSchema
aJsonSchemaValue
datetime_schema
uGenerateJsonSchema.datetime_schema
D aschema
return
ucore_schema.TimedeltaSchema
aJsonSchemaValue
timedelta_schema
uGenerateJsonSchema.timedelta_schema
D aschema
return
ucore_schema.LiteralSchema
aJsonSchemaValue
literal_schema
uGenerateJsonSchema.literal_schema
D aschema
return
ucore_schema.EnumSchema
aJsonSchemaValue
enum_schema
uGenerateJsonSchema.enum_schema
D aschema
return
ucore_schema.IsInstanceSchema
aJsonSchemaValue
is_instance_schema
uGenerateJsonSchema.is_instance_schema
D aschema
return
ucore_schema.IsSubclassSchema
aJsonSchemaValue
is_subclass_schema
uGenerateJsonSchema.is_subclass_schema
D aschema
return
ucore_schema.CallableSchema
aJsonSchemaValue
callable_schema
uGenerateJsonSchema.callable_schema
D aschema
return
ucore_schema.ListSchema
aJsonSchemaValue
list_schema
uGenerateJsonSchema.list_schema
T u`tuple_positional_schema` is deprecated. Use `tuple_schema` instead.
nT acategory
D aschema
return
ucore_schema.TupleSchema
aJsonSchemaValue
tuple_positional_schema
uGenerateJsonSchema.tuple_positional_schema
T u`tuple_variable_schema` is deprecated. Use `tuple_schema` instead.
natuple_variable_schema
uGenerateJsonSchema.tuple_variable_schema
uGenerateJsonSchema.tuple_schema
D aschema
return
ucore_schema.SetSchema
aJsonSchemaValue
set_schema
uGenerateJsonSchema.set_schema
D aschema
return
ucore_schema.FrozenSetSchema
aJsonSchemaValue
frozenset_schema
uGenerateJsonSchema.frozenset_schema
D aschema
return
ucore_schema.SetSchema | core_schema.FrozenSetSchema
aJsonSchemaValue
uGenerateJsonSchema._common_set_schema
D aschema
return
ucore_schema.GeneratorSchema
aJsonSchemaValue
generator_schema
uGenerateJsonSchema.generator_schema
D aschema
return
ucore_schema.DictSchema
aJsonSchemaValue
dict_schema
uGenerateJsonSchema.dict_schema
D aschema
return
ucore_schema.BeforeValidatorFunctionSchema
aJsonSchemaValue
function_before_schema
uGenerateJsonSchema.function_before_schema
D aschema
return
ucore_schema.AfterValidatorFunctionSchema
aJsonSchemaValue
function_after_schema
uGenerateJsonSchema.function_after_schema
D aschema
return
ucore_schema.PlainValidatorFunctionSchema
aJsonSchemaValue
function_plain_schema
uGenerateJsonSchema.function_plain_schema
D aschema
return
ucore_schema.WrapValidatorFunctionSchema
aJsonSchemaValue
function_wrap_schema
uGenerateJsonSchema.function_wrap_schema
D aschema
return
ucore_schema.WithDefaultSchema
aJsonSchemaValue
default_schema
uGenerateJsonSchema.default_schema
D aschema
return
ucore_schema.NullableSchema
aJsonSchemaValue
nullable_schema
uGenerateJsonSchema.nullable_schema
D aschema
return
ucore_schema.UnionSchema
aJsonSchemaValue
union_schema
uGenerateJsonSchema.union_schema
D aschema
return
ucore_schema.TaggedUnionSchema
aJsonSchemaValue
tagged_union_schema
uGenerateJsonSchema.tagged_union_schema
D aschema
one_of_choices
return
ucore_schema.TaggedUnionSchema
ulist[JsonDict]
ustr | None
uGenerateJsonSchema._extract_discriminator
D aschema
return
ucore_schema.ChainSchema
aJsonSchemaValue
chain_schema
uGenerateJsonSchema.chain_schema
D aschema
return
ucore_schema.LaxOrStrictSchema
aJsonSchemaValue
lax_or_strict_schema
uGenerateJsonSchema.lax_or_strict_schema
D aschema
return
ucore_schema.JsonOrPythonSchema
aJsonSchemaValue
json_or_python_schema
uGenerateJsonSchema.json_or_python_schema
D aschema
return
ucore_schema.TypedDictSchema
aJsonSchemaValue
typed_dict_schema
uGenerateJsonSchema.typed_dict_schema
D acomputed_fields
return
ulist[ComputedField]
ulist[tuple[str, bool, core_schema.ComputedField]]
uGenerateJsonSchema._name_required_computed_fields
D anamed_required_fields
return
uSequence[tuple[str, bool, CoreSchemaField]]
aJsonSchemaValue
uGenerateJsonSchema._named_required_fields_schema
D afield
name
return
aCoreSchemaField
str
puGenerateJsonSchema._get_alias_name
D aschema
return
ucore_schema.TypedDictField
aJsonSchemaValue
typed_dict_field_schema
uGenerateJsonSchema.typed_dict_field_schema
D aschema
return
ucore_schema.DataclassField
aJsonSchemaValue
dataclass_field_schema
uGenerateJsonSchema.dataclass_field_schema
D aschema
return
ucore_schema.ModelField
aJsonSchemaValue
model_field_schema
uGenerateJsonSchema.model_field_schema
D aschema
return
ucore_schema.ComputedField
aJsonSchemaValue
computed_field_schema
uGenerateJsonSchema.computed_field_schema
D aschema
return
ucore_schema.ModelSchema
aJsonSchemaValue
model_schema
uGenerateJsonSchema.model_schema
D ajson_schema
cls
config
return
aJsonSchemaValue
utype[Any]
aConfigDict
aNone
uGenerateJsonSchema._update_class_schema
D ajson_schema
return
aJsonSchemaValue
puGenerateJsonSchema.resolve_ref_schema
D aschema
return
ucore_schema.ModelFieldsSchema
aJsonSchemaValue
model_fields_schema
uGenerateJsonSchema.model_fields_schema
D afield
return
aCoreSchemaField
bool
uGenerateJsonSchema.field_is_present
D afield
total
return
ucore_schema.ModelField | core_schema.DataclassField | core_schema.TypedDictField
bool
puGenerateJsonSchema.field_is_required
D aschema
return
ucore_schema.DataclassArgsSchema
aJsonSchemaValue
dataclass_args_schema
uGenerateJsonSchema.dataclass_args_schema
D aschema
return
ucore_schema.DataclassSchema
aJsonSchemaValue
dataclass_schema
uGenerateJsonSchema.dataclass_schema
D aschema
return
ucore_schema.ArgumentsSchema
aJsonSchemaValue
uGenerateJsonSchema.arguments_schema
D aarguments
var_kwargs_schema
return
ulist[core_schema.ArgumentsParameter]
uCoreSchema | None
aJsonSchemaValue
uGenerateJsonSchema.kw_arguments_schema
D aarguments
var_args_schema
return
ulist[core_schema.ArgumentsParameter]
uCoreSchema | None
aJsonSchemaValue
uGenerateJsonSchema.p_arguments_schema
D aargument
return
ucore_schema.ArgumentsParameter
str
uGenerateJsonSchema.get_argument_name
D aschema
return
ucore_schema.CallSchema
aJsonSchemaValue
call_schema
uGenerateJsonSchema.call_schema
D aschema
return
ucore_schema.CustomErrorSchema
aJsonSchemaValue
custom_error_schema
uGenerateJsonSchema.custom_error_schema
D aschema
return
ucore_schema.JsonSchema
aJsonSchemaValue
uGenerateJsonSchema.json_schema
D aschema
return
ucore_schema.UrlSchema
aJsonSchemaValue
url_schema
uGenerateJsonSchema.url_schema
D aschema
return
ucore_schema.MultiHostUrlSchema
aJsonSchemaValue
multi_host_url_schema
uGenerateJsonSchema.multi_host_url_schema
D aschema
return
ucore_schema.UuidSchema
aJsonSchemaValue
uuid_schema
uGenerateJsonSchema.uuid_schema
D aschema
return
ucore_schema.DefinitionsSchema
aJsonSchemaValue
uGenerateJsonSchema.definitions_schema
D aschema
return
ucore_schema.DefinitionReferenceSchema
aJsonSchemaValue
definition_ref_schema
uGenerateJsonSchema.definition_ref_schema
D aschema
return
ucore_schema.SerSchema | core_schema.IncExSeqSerSchema | core_schema.IncExDictSerSchema
uJsonSchemaValue | None
uGenerateJsonSchema.ser_schema
D aschema
return
ucore_schema.ComplexSchema
aJsonSchemaValue
complex_schema
uGenerateJsonSchema.complex_schema
D aname
return
str
puGenerateJsonSchema.get_title_from_name
D aschema
return
aCoreSchemaOrField
bool
uGenerateJsonSchema.field_title_should_be_set
uGenerateJsonSchema.normalize_name
D acore_mode_ref
return
aCoreModeRef
aDefsRef
uGenerateJsonSchema.get_defs_ref
D acore_ref
return
aCoreRef
utuple[DefsRef, JsonSchemaValue]
uGenerateJsonSchema.get_cache_defs_ref_schema
uGenerateJsonSchema.handle_ref_overrides
D ajson_ref
return
aJsonRef
uJsonSchemaValue | None
uGenerateJsonSchema.get_schema_from_definitions
D adft
return
aAny
puGenerateJsonSchema.encode_default
D ajson_schema
core_schema
mapping
return
aJsonSchemaValue
aCoreSchema
udict[str, str]
aNone
uGenerateJsonSchema.update_with_validations
uThis class just contains mappings from core_schema attribute names to the corresponding
JSON schema attribute names. While I suspect it is unlikely to be necessary, you can in
principle override this class in a subclass of GenerateJsonSchema (by inheriting from
GenerateJsonSchema.ValidationsMapping) to change these mappings.
uGenerateJsonSchema.ValidationsMapping
D amultiple_of
le
ge
lt
gt
multipleOf
maximum
minimum
exclusiveMaximum
exclusiveMinimum
D amin_length
max_length
minLength
maxLength
D amin_length
max_length
pattern
minLength
maxLength
pattern
D amin_length
max_length
minItems
maxItems
D amin_length
max_length
minProperties
maxProperties
D aschemas
return
ulist[JsonSchemaValue]
aJsonSchemaValue
uGenerateJsonSchema.get_flattened_anyof
D ajson_schema
return
aJsonSchemaValue
udict[JsonRef, int]
uGenerateJsonSchema.get_json_ref_counts
D aschema
error_info
return
aCoreSchemaOrField
str
aJsonSchemaValue
uGenerateJsonSchema.handle_invalid_for_json_schema
D akind
detail
return
aJsonSchemaWarningKind
str
aNone
uGenerateJsonSchema.emit_warning
D akind
detail
return
aJsonSchemaWarningKind
str
ustr | None
uGenerateJsonSchema.render_warning_message
D areturn
a_DefinitionsRemapping
uGenerateJsonSchema._build_definitions_remapping
D aschema
return
aJsonSchemaValue
aNone
uGenerateJsonSchema._garbage_collect_definitions
D acls
by_alias
ref_template
schema_generator
mode
return
utype[BaseModel] | type[PydanticDataclass]
bool
str
utype[GenerateJsonSchema]
aJsonSchemaMode
udict[str, Any]
model_json_schema
schema_generator
D amodels
by_alias
title
description
ref_template
schema_generator
return
uSequence[tuple[type[BaseModel] | type[PydanticDataclass], JsonSchemaMode]]
bool
ustr | None
ustr | None
str
utype[GenerateJsonSchema]
utuple[dict[tuple[type[BaseModel] | type[PydanticDataclass], JsonSchemaMode], JsonSchemaValue], JsonSchemaValue]
models_json_schema
T a_HashableJsonValue
Q
T Ostr
a_HashableJsonValue
a_HashableJsonValue
D aschemas
return
uIterable[JsonDict]
ulist[JsonDict]
D avalue
return
aJsonValue
a_HashableJsonValue
uUsage docs: https://docs.pydantic.dev/2.10/concepts/json_schema/#withjsonschema-annotation
Add this as an annotation on a field to override the (base) JSON schema that would be generated for that field.
This provides a way to set a JSON schema for types that would otherwise raise errors when producing a JSON schema,
such as Callable, or types that have an is-instance core schema, without needing to go so far as creating a
custom subclass of pydantic.json_schema.GenerateJsonSchema.
Note that any _modifications_ to the schema that would normally be made (such as setting the title for model fields)
will still be performed.
If `mode` is set this will only apply to that schema generation mode, allowing you
to set different json schemas for validation and serialization.
aWithJsonSchema
uJsonSchemaValue | None
uLiteral['validation', 'serialization'] | None
D acore_schema
handler
return
ucore_schema.CoreSchema
aGetJsonSchemaHandler
aJsonSchemaValue
a__get_pydantic_json_schema__
uWithJsonSchema.__get_pydantic_json_schema__
D areturn
int
a__hash__
uWithJsonSchema.__hash__
uAdd examples to a JSON schema.
If the JSON Schema already contains examples, the provided examples
will be appended.
If `mode` is set this will only apply to that schema generation mode,
llowing you to add different examples for validation and serialization.
aExamples
T uUsing a dict for `examples` is deprecated since v2.9 and will be removed in v3.0. Use a list instead.
D aexamples
mode
return
udict[str, Any]
uLiteral['validation', 'serialization'] | None
aNone
uExamples.__init__
D aexamples
mode
return
ulist[Any]
uLiteral['validation', 'serialization'] | None
aNone
D aexamples
mode
return
udict[str, Any] | list[Any]
uLiteral['validation', 'serialization'] | None
aNone
uExamples.__get_pydantic_json_schema__
uExamples.__hash__
D aitem
return
aAny
uset[JsonRef]
T aAnyType
aAnyType
uUsage docs: https://docs.pydantic.dev/2.10/concepts/json_schema/#skipjsonschema-annotation
Add this as an annotation on a field to skip generating a JSON schema for that field.
Example:
```python
from typing import Union
from pydantic import BaseModel
from pydantic.json_schema import SkipJsonSchema
from pprint import pprint
class Model(BaseModel):
a: Union[int, None] = None  # (1)!
b: Union[int, SkipJsonSchema[None]] = None  # (2)!
c: SkipJsonSchema[Union[int, None]] = None  # (3)!
pprint(Model.model_json_schema())
'''
{
'properties': {
'a': {
'anyOf': [
{'type': 'integer'},
{'type': 'null'}
],
'default': None,
'title': 'A'
},
'b': {
'default': None,
'title': 'B',
'type': 'integer'
}
},
'title': 'Model',
'type': 'object'
}
'''
```
1. The integer and null types are both included in the schema for `a`.
2. The integer type is the only type included in the schema for `b`.
3. The entirety of the `c` field is omitted from the schema.
aSkipJsonSchema
D aitem
return
aAnyType
pa__class_getitem__
uSkipJsonSchema.__class_getitem__
D acore_schema
handler
return
aCoreSchema
aGetJsonSchemaHandler
aJsonSchemaValue
uSkipJsonSchema.__get_pydantic_json_schema__
uSkipJsonSchema.__hash__
D acls
return
utype[Any] | None
aConfigDict
upydantic\json_schema.py
T a.0
wxaschemas_for_alternatives
T a.0
wkwvT a.0
wvu<module pydantic.json_schema>
T a__class__
T acls
item
T aself
core_schema
handler
mode
json_schema
examples
T aself
core_schema
handler
T aself
core_schema
handler
mode
T aself
T aself
examples
mode
T aself
by_alias
ref_template
T	aschema
json_ref
already_visited
defs_ref
wkwvajson_refs
self
a_add_json_refs
T a_add_json_refs
json_refs
self
T aself
defs_to_json
defs_refs
defs_ref
json_ref
T aself
schema
items_schema
json_schema
T aschemas
T
self
schema
one_of_choices
openapi_discriminator
alias_path
alias
alias_is_present_on_all_choices
choice
exc
properties
T aself
schema
visited_defs_refs
unvisited_json_refs
next_json_ref
next_defs_ref
T aself
field
name
alias
path
T aitem
refs
stack
current
key
value
T avalue
T acomputed_fields
T
self
named_required_fields
properties
required_fields
name
required
field
field_json_schema
title
json_schema
T aself
value
parent_key
sorted_dict
sorted_list
keys
key
item
T aself
json_schema
cls
config
aBaseModel
aRootModel
config_title
model_title_generator
title
docstring
root_description
extra
json_schema_extra
root_json_schema_extra
T aself
schema
T aself
schema
prefer_positional
arguments
kw_only_arguments
kw_or_p_arguments
p_only_arguments
var_args_schema
var_kwargs_schema
positional_possible
keyword_possible
T aself
mapping
core_schema_types
key
method_name
weT aself
schema
json_schema
T aself
schema
step_index
T aself
schema
named_required_fields
T aself
schema
config
is_builtin_dataclass
cls
json_schema
description
T aself
schema
json_schema
multiple_of
le
ge
lt
gt
T aself
schema
json_schema
default
ser_schema
ser_func
encoded_default
T aself
schema
core_ref
w_aref_json_schema
T aself
schema
core_ref
definition
weT aself
schema
json_schema
keys_schema
keys_pattern
values_schema
T aself
kind
detail
message
T aself
dft
aTypeAdapter
a_type_has_config
config
default
T aself
schema
result
enum_type
description
expected
types
T aself
field
T aself
field
total
T aself
schema
field_schema
T aprioritized_choices
defs_to_json
definitions
schemas_for_alternatives
defs_remapping
json_remapping
copied_definitions
definitions_schema
a_iter
defs_ref
alternatives
alternative
original_defs_ref
remapped_defs_ref
remapping
new_definitions_schema
T aself
schema
input_schema
T aself
schema
mode
json_schema
json_ref_counts
ref
ref_json_schema
definitions_remapping
T	aself
inputs
json_schemas_map
w_amode
schema
definitions_remapping
key
json_schema
T aself
schema
core_ref
core_mode_ref
populate_defs
handler_func
current_handler
metadata
js_updates
js_updates_handler_func
js_extra
js_extra_handler_func
js_modify_function
new_handler_func
json_schema
T aself
argument
name
alias
T aself
core_ref
core_mode_ref
maybe_defs_ref
json_ref
defs_ref
ref_json_schema
T aself
core_mode_ref
core_ref
mode
components
core_ref_no_id
short_ref
mode_title
name
name_mode
module_qualname
module_qualname_mode
module_qualname_id
occurrence_index
module_qualname_occurrence
module_qualname_occurrence_mode
T aself
schemas
members
schema
T aself
json_schema
json_refs
a_add_json_refs
T aself
json_ref
def_ref
T aself
name
T aself
schema
error_info
T aself
json_schema
referenced_json_schema
wkwvT aschema_or_field
json_schema
ser_schema
generate_for_schema_type
self
populate_defs
T apopulate_defs
self
T aschema_or_field
current_handler
json_schema
js_extra
T ajs_extra
T aschema_or_field
current_handler
json_schema
js_updates
T ajs_updates
T aself
schema
content_core_schema
content_json_schema
T
self
arguments
var_kwargs_schema
properties
required
json_schema
argument
name
argument_schema
additional_properties_schema
T aself
schema
use_strict
T aself
schema
result
expected
types
T aself
schema
named_required_fields
json_schema
extras_schema
schema_to_update
T acls
by_alias
ref_template
schema_generator
mode
aBaseModel
schema_generator_instance
T aself
schema
cls
config
json_schema
Tamodels
by_alias
title
description
ref_template
schema_generator
inputs
json_schema
cls
w_ainstance
json_schemas_map
definitions
T aschema_or_field
current_handler
js_modify_function
json_schema
original_schema
ref
populate_defs
T apopulate_defs
T aschema_or_field
current_handler
js_modify_function
json_schema
populate_defs
T aself
schema
null_schema
inner_json_schema
T
self
arguments
var_args_schema
prefix_items
json_schema
min_items
argument
name
argument_schema
items_schema
T acore_schema
json_schema
core_ref
defs_ref
ref_json_schema
json_ref
self
T aself
ref
T aself
schema
key
value
T aself
kind
detail
T aself
json_schema
ref
schema_to_update
T aself
schema
schema_type
return_schema
T aself
value
parent_key
sorted_dict
keys
key
T	aself
schema
generated
json_schema
wkwvaexc
one_of_choices
openapi_discriminator
T aself
schema
json_schema
variadic_item_index
prefixItems
T aself
schema
named_required_fields
total
cls
config
json_schema
extra
T aself
schema
generated
choices
choice
choice_schema
exc
T aself
json_schema
core_schema
mapping
core_key
json_schema_key
a__spec__
.pydantic.main
x a__pydantic_validator__
validate_python
T aself_instance
warnings
warn
T uA custom validator is returning a value other than `self`.
Returning anything other than `self` from a top level model validator isn't supported when validating via `__init__`.
See the `model_validator` docs (https://docs.pydantic.dev/latest/concepts/validators/#model-validators) for more details.
l T astacklevel
uCreate a new model by parsing and validating input data from keyword arguments.
Raises [`ValidationError`][pydantic_core.ValidationError] if the input data cannot be
validated to form a valid model.
`self` is explicitly positional-only to allow `self` as a field name.
a__pydantic_fields__
uGet metadata about the fields defined on the model.
Deprecation warning: you should be getting this information from the model class, not from an instance.
In V3, this property will be removed from the `BaseModel` class.
Returns:
A mapping of field names to [`FieldInfo`][pydantic.fields.FieldInfo] objects.
a__pydantic_computed_fields__
uGet metadata about the computed fields defined on the model.
Deprecation warning: you should be getting this information from the model class, not from an instance.
In V3, this property will be removed from the `BaseModel` class.
Returns:
A mapping of computed field names to [`ComputedFieldInfo`][pydantic.fields.ComputedFieldInfo] objects.
a__pydantic_extra__
uGet extra fields set during validation.
Returns:
A dictionary of extra fields, or `None` if `config.extra` is not set to `"allow"`.
a__pydantic_fields_set__
uReturns the set of fields that have been explicitly set on this model instance.
Returns:
A set of strings representing the fields that have been set,
i.e. that were not filled from defaults.
a__new__
items
alias
values
fields_values
fields_set
add
validation_alias
aAliasChoices
choices
aAliasPath
search_dict_for_path
aPydanticUndefined
pop
is_required
get_default
T acall_default_factory
validated_data
model_config
get
T aextra
allow
a_object_setattr
a__dict__
a__pydantic_root_model__
a__pydantic_post_init__
model_post_init
T na__pydantic_private__
wma__private_attributes__
uCreates a new instance of the `Model` class with validated data.
Creates a new model setting `__dict__` and `__pydantic_fields_set__` from trusted or pre-validated data.
Default values are respected, but no other validation is performed.
!!! note
`model_construct()` generally respects the `model_config.extra` setting on the provided model.
That is, if `model_config.extra == 'allow'`, then all extra passed values are added to the model instance's `__dict__`
nd `__pydantic_extra__` fields. If `model_config.extra == 'ignore'` (the default), then all extra passed values are ignored.
Because no validation is performed with a call to `model_construct()`, having `model_config.extra == 'forbid'` does not result in
n error if extra values are passed, but they will be ignored.
Args:
_fields_set: A set of field names that were originally explicitly set during instantiation. If provided,
this is directly used for the [`model_fields_set`][pydantic.BaseModel.model_fields_set] attribute.
Otherwise, the field names from the `values` argument will be used.
values: Trusted or pre-validated data dictionary.
Returns:
A new instance of the `Model` class with validated data.
a__deepcopy__
a__copy__
self
copied
update
keys
uUsage docs: https://docs.pydantic.dev/2.10/concepts/serialization/#model_copy
Returns a copy of the model.
Args:
update: Values to change/add in the new model. Note: the data is not validated
before creating the new model. You should trust this data.
deep: Set to `True` to make a deep copy of the model.
Returns:
New model instance.
a__pydantic_serializer__
to_python
T amode
by_alias
include
exclude
context
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
uUsage docs: https://docs.pydantic.dev/2.10/concepts/serialization/#modelmodel_dump
Generate a dictionary representation of the model, optionally specifying which fields to include or exclude.
Args:
mode: The mode in which `to_python` should run.
If mode is 'json', the output will only contain JSON serializable types.
If mode is 'python', the output may contain non-JSON-serializable Python objects.
include: A set of fields to include in the output.
exclude: A set of fields to exclude from the output.
context: Additional context to pass to the serializer.
by_alias: Whether to use the field's alias in the dictionary key if defined.
exclude_unset: Whether to exclude fields that have not been explicitly set.
exclude_defaults: Whether to exclude fields that are set to their default value.
exclude_none: Whether to exclude fields that have a value of `None`.
round_trip: If True, dumped values should be valid as input for non-idempotent types such as Json[T].
warnings: How to handle serialization errors. False/"none" ignores them, True/"warn" logs errors,
"error" raises a [`PydanticSerializationError`][pydantic_core.PydanticSerializationError].
serialize_as_any: Whether to serialize fields with duck-typing serialization behavior.
Returns:
A dictionary representation of the model.
to_json
T aindent
include
exclude
context
by_alias
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
decode
uUsage docs: https://docs.pydantic.dev/2.10/concepts/serialization/#modelmodel_dump_json
Generates a JSON representation of the model using Pydantic's `to_json` method.
Args:
indent: Indentation to use in the JSON output. If None is passed, the output will be compact.
include: Field(s) to include in the JSON output.
exclude: Field(s) to exclude from the JSON output.
context: Additional context to pass to the serializer.
by_alias: Whether to serialize using field aliases.
exclude_unset: Whether to exclude fields that have not been explicitly set.
exclude_defaults: Whether to exclude fields that are set to their default value.
exclude_none: Whether to exclude fields that have a value of `None`.
round_trip: If True, dumped values should be valid as input for non-idempotent types such as Json[T].
warnings: How to handle serialization errors. False/"none" ignores them, True/"warn" logs errors,
"error" raises a [`PydanticSerializationError`][pydantic_core.PydanticSerializationError].
serialize_as_any: Whether to serialize fields with duck-typing serialization behavior.
Returns:
A JSON string representation of the model.
model_json_schema
T aby_alias
ref_template
schema_generator
mode
uGenerates a JSON schema for a model class.
Args:
by_alias: Whether to use attribute aliases or not.
ref_template: The reference template.
schema_generator: To override the logic used to generate the JSON schema, as a subclass of
`GenerateJsonSchema` with your desired modifications
mode: The mode in which to generate the schema.
Returns:
The JSON schema for the given model class.
aGeneric
uConcrete names should only be generated for generic models.
a_repr
display_as_type
u,
a__name__

w[w]uCompute the class name for parametrizations of generic classes.
This method can be overridden to achieve a custom naming scheme for generic BaseModels.
Args:
params: Tuple of types of the class. Given a generic class
`Model` with 2 type variables and a concrete model `Model[str, int]`,
the value `(str, int)` would be passed to `params`.
Returns:
String representing the new class where `params` are passed to `cls` as type variables.
Raises:
TypeError: Raised when trying to generate concrete names for non-generic models.
a__pydantic_complete__
a__pydantic_core_schema__
delattr
a_typing_extra
parent_frame_namespace
T aparent_depth
force
a_model_construction
unpack_lenient_weakvaluedict
a__pydantic_parent_namespace__
a_namespace_utils
aNsResolver
T aparent_namespace
D adefer_build
Facomplete_model_class
a_config
aConfigWrapper
D acheck
FT araise_errors
ns_resolver
uTry to rebuild the pydantic-core schema for the model.
This may be necessary when one of the annotations is a ForwardRef which could not be resolved during
the initial attempt to build the schema, and automatic rebuilding fails.
Args:
force: Whether to force the rebuilding of the model schema, defaults to `False`.
raise_errors: Whether to raise errors, defaults to `True`.
_parent_namespace_depth: The depth level of the parent namespace, defaults to 2.
_types_namespace: The types namespace, defaults to `None`.
Returns:
Returns `None` if the schema is already "complete" and rebuilding was not required.
If rebuilding _was_ required, returns `True` if rebuilding was successful, otherwise `False`.
T astrict
from_attributes
context
uValidate a pydantic model instance.
Args:
obj: The object to validate.
strict: Whether to enforce types strictly.
from_attributes: Whether to extract data from object attributes.
context: Additional context to pass to the validator.
Raises:
ValidationError: If the object could not be validated.
Returns:
The validated model instance.
validate_json
T astrict
context
uUsage docs: https://docs.pydantic.dev/2.10/concepts/json/#json-parsing
Validate the given JSON data against the Pydantic model.
Args:
json_data: The JSON data to validate.
strict: Whether to enforce types strictly.
context: Extra variables to pass to the validator.
Returns:
The validated Pydantic model.
Raises:
ValidationError: If `json_data` is not a JSON string or the object could not be validated.
validate_strings
uValidate the given object with string data against the Pydantic model.
Args:
obj: The object containing string data to validate.
strict: Whether to enforce types strictly.
context: Extra variables to pass to the validator.
Returns:
The validated Pydantic model.
T a__pydantic_core_schema__
a_mock_val_ser
aMockCoreSchema
a__pydantic_generic_metadata__
origin
uHook into generating the model's CoreSchema.
Args:
source: The class we are generating a schema for.
This will generally be the same as the `cls` argument if this is a classmethod.
handler: A callable that calls into Pydantic's internal CoreSchema generation logic.
Returns:
A `pydantic-core` `CoreSchema`.
uHook into generating the model's JSON schema.
Args:
core_schema: A `pydantic-core` CoreSchema.
You can ignore this argument and call the handler with a new CoreSchema,
wrap this CoreSchema (`{'type': 'nullable', 'schema': current_schema}`),
or just call the handler with the original schema.
handler: Call into Pydantic's internal JSON schema generation.
This will raise a `pydantic.errors.PydanticInvalidForJsonSchema` if JSON schema
generation fails.
Since this gets called by `BaseModel.model_json_schema` you can override the
`schema_generator` argument to that function to change JSON schema generation globally
for a type.
Returns:
A JSON schema, as a Python object.
a_generics
get_cached_generic_type_early
aBaseModel
uType parameters should be placed on typing.Generic, not BaseModel
a__parameters__
u cannot be parametrized because it does not inherit from typing.Generic
parameters
a__bases__
u is not a generic class
check_parameters_count
typevar_values
a_utils
all_identical
set_cached_generic_type
args
model_parametrized_name
iter_contained_typevars
generic_recursion_self_type
a__enter__
a__exit__
get_cached_generic_type_late
T l T aparent_depth
model_rebuild
T a_types_namespace
aPydanticUndefinedAnnotation
create_generic_submodel
T nnnasubmodel
replace_types
typevars_map
u<genexpr>
uBaseModel.__class_getitem__.<locals>.<genexpr>
copy
uReturns a shallow copy of the model.
deepcopy
T amemo
uReturns a deep copy of the model.
a__getattribute__
a__get__
u object has no attribute
a__class__
a__class_vars__
u is a ClassVar of `
u` and cannot be set on an instance. If you want to set a value on the class, use `
w.u = value`.
a_fields
is_valid_field_name
a__set__
a_check_frozen
cached_property
T avalidate_assignment
navalidate_assignment
w"u" object has no field "
model_extra
a__delete__
a__delattr__
model_copy
T aupdate
T afrozen
nafrozen_instance
frozen
frozen_field
type
loc
input
pydantic_core
aValidationError
from_exception_data
operator
itemgetter
u<lambda>
uBaseModel.__eq__.<locals>.<lambda>
aSafeGetItemProxy
a_SENTINEL
uSo `dict(model)` works.
startswith
T w_a__iter__
uBaseModel.__iter__
a__repr_name__
w(a__repr_str__
T u,
w)arepr
a__repr_recursion__
a__repr_args__
uBaseModel.__repr_args__
uBaseModel.__repr_args__.<locals>.<genexpr>
T w aPydanticDeprecatedSince20
l T uThe `__fields__` attribute is deprecated, use `model_fields` instead.
T acategory
stacklevel
model_fields
T uThe `__fields_set__` attribute is deprecated, use `model_fields_set` instead.
T uThe `dict` method is deprecated; use `model_dump` instead.
model_dump
T ainclude
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
T uThe `json` method is deprecated; use `model_dump_json` instead.
uThe `encoder` argument is no longer supported; use field serializers instead.
uThe `models_as_dict` argument is no longer supported; use a model serializer instead.
u`dumps_kwargs` keyword arguments are no longer supported.
model_dump_json
T uThe `parse_obj` method is deprecated; use `model_validate` instead.
model_validate
T uThe `parse_raw` method is deprecated; if your data is JSON use `model_validate_json`, otherwise load the data then use `model_validate` instead.
deprecated
T aparse
parse
load_str_bytes
T aproto
content_type
encoding
allow_pickle
T EValueError
ETypeError
json
uvalue_error.unicodedecode
aJSONDecodeError
uvalue_error.jsondecode
value_error
type_error
aPydanticCustomError
T a__root__
T uThe `parse_file` method is deprecated; load the data from file, then if your data is JSON use `model_validate_json`, otherwise `model_validate` instead.
load_file
parse_obj
T uThe `from_orm` method is deprecated; set `model_config['from_attributes']=True` and use `model_validate` instead.
T afrom_attributes
naPydanticUserError
T uYou must set the config attribute `from_attributes=True` to use from_orm
nT acode
T uThe `construct` method is deprecated; use `model_construct` instead.
model_construct
a_fields_set
T uThe `copy` method is deprecated; use `model_copy` instead. See the docstring of `BaseModel.copy` for details about how to handle `include` and `exclude`.
T acopy_internals
copy_internals
a_iter
T ato_dict
by_alias
include
exclude
exclude_unset
extra
a_copy_and_set_values
T adeep
uReturns a copy of the model.
!!! warning "Deprecated"
This method is now deprecated; use `model_copy` instead.
If you need `include` or `exclude`, use:
```python {test="skip" lint="skip"}
data = self.model_dump(include=include, exclude=exclude, round_trip=True)
data = {**data, **(update or {})}
copied = self.model_validate(data)
```
Args:
include: Optional set or mapping specifying which fields to include in the copied model.
exclude: Optional set or mapping specifying which fields to exclude in the copied model.
update: Optional dictionary of field-value pairs to override field values in the copied model.
deep: If True, the values of fields that are Pydantic models will be deep-copied.
Returns:
A copy of the model with included, excluded and updated fields as specified.
T uThe `schema` method is deprecated; use `model_json_schema` instead.
T aby_alias
ref_template
T uThe `schema_json` method is deprecated; use `model_json_schema` and json.dumps instead.
udeprecated.json
T apydantic_encoder
pydantic_encoder
dumps
default
T uThe `validate` method is deprecated; use `model_validate` instead.
T uThe `update_forward_refs` method is deprecated; use `model_rebuild` instead.
u`localns` arguments are not longer accepted.
T tT aforce
T uThe private method `_iter` will be removed and should no longer be used.
T uThe private method `_copy_and_set_values` will be removed and should no longer be used.
T uThe private method `_get_value` will be removed and should no longer be used.
a_get_value
T uThe private method `_calculate_keys` will be removed and should no longer be used.
a_calculate_keys
u__slots__ should not be passed to create_model
aRuntimeWarning
T uto avoid confusion `__config__` and `__base__` cannot be used together
ucreate-model-config-base
cast
utype[ModelT]
ufields may not start with an underscore, ignoring "
utuple[str, Any]
T uField definitions should be a `(<type>, <default>)`.
ucreate-model-field-definitions
is_annotated
typing_extensions
get_args
unot enough values to unpack (expected at least 2, got %d)
a_import_utils
import_cached_field_info
T uField definitions should be a Annotated[<type>, <FieldInfo>]
ucreate-model-field-definitions
annotations
fields
a_getframe
T l af_globals
