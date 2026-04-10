# Reconstructed from integrated Nuitka blob
# Module: upydantic.functional_validators

uUsage docs: https://docs.pydantic.dev/2.10/concepts/validators/#field-validators
A metadata class that indicates that a validation should be applied **after** the inner validation logic.
Attributes:
func: The validator function.
Example:
```python
from typing_extensions import Annotated
from pydantic import AfterValidator, BaseModel, ValidationError
MyInt = Annotated[int, AfterValidator(lambda v: v + 1)]
class Model(BaseModel):
a: MyInt
print(Model(a=1).a)
#> 2
try:
Model(a='a')
except ValidationError as e:
print(e.json(indent=2))
'''
[
{
"type": "int_parsing",
"loc": [
"a"
],
"msg": "Input should be a valid integer, unable to parse string as an integer",
"input": "a",
"url": "https://errors.pydantic.dev/2/v/int_parsing"
}
]
'''
```
aAfterValidator
a__qualname__
ucore_schema.NoInfoValidatorFunction | core_schema.WithInfoValidatorFunction
D asource_type
handler
return
aAny
aGetCoreSchemaHandler
ucore_schema.CoreSchema
a__get_pydantic_core_schema__
uAfterValidator.__get_pydantic_core_schema__
D adecorator
return
u_decorators.Decorator[_decorators.FieldValidatorDecoratorInfo]
aSelf
a_from_decorator
uAfterValidator._from_decorator
uUsage docs: https://docs.pydantic.dev/2.10/concepts/validators/#field-validators
A metadata class that indicates that a validation should be applied **before** the inner validation logic.
Attributes:
func: The validator function.
json_schema_input_type: The input type of the function. This is only used to generate the appropriate
JSON Schema (in validation mode).
Example:
```python
from typing_extensions import Annotated
from pydantic import BaseModel, BeforeValidator
MyInt = Annotated[int, BeforeValidator(lambda v: v + 1)]
class Model(BaseModel):
a: MyInt
print(Model(a=1).a)
#> 2
try:
Model(a='a')
except TypeError as e:
print(e)
#> can only concatenate str (not "int") to str
```
aBeforeValidator
uBeforeValidator.__get_pydantic_core_schema__
uBeforeValidator._from_decorator
uUsage docs: https://docs.pydantic.dev/2.10/concepts/validators/#field-validators
A metadata class that indicates that a validation should be applied **instead** of the inner validation logic.
!!! note
Before v2.9, `PlainValidator` wasn't always compatible with JSON Schema generation for `mode='validation'`.
You can now use the `json_schema_input_type` argument to specify the input type of the function
to be used in the JSON schema when `mode='validation'` (the default). See the example below for more details.
Attributes:
func: The validator function.
json_schema_input_type: The input type of the function. This is only used to generate the appropriate
JSON Schema (in validation mode). If not provided, will default to `Any`.
Example:
```python
from typing import Union
from typing_extensions import Annotated
from pydantic import BaseModel, PlainValidator
MyInt = Annotated[
int,
PlainValidator(
lambda v: int(v) + 1, json_schema_input_type=Union[str, int]  # (1)!
),
]
class Model(BaseModel):
a: MyInt
print(Model(a='1').a)
#> 2
print(Model(a=1).a)
#> 2
```
1. In this example, we've specified the `json_schema_input_type` as `Union[str, int]` which indicates to the JSON schema
generator that in validation mode, the input type for the `a` field can be either a `str` or an `int`.
aPlainValidator
uPlainValidator.__get_pydantic_core_schema__
uPlainValidator._from_decorator
uUsage docs: https://docs.pydantic.dev/2.10/concepts/validators/#field-validators
A metadata class that indicates that a validation should be applied **around** the inner validation logic.
Attributes:
func: The validator function.
json_schema_input_type: The input type of the function. This is only used to generate the appropriate
JSON Schema (in validation mode).
```python
from datetime import datetime
from typing_extensions import Annotated
from pydantic import BaseModel, ValidationError, WrapValidator
def validate_timestamp(v, handler):
if v == 'now':
# we don't want to bother with further validation, just return the new value
return datetime.now()
try:
return handler(v)
except ValidationError:
# validation failed, in this case we want to return a default value
return datetime(2000, 1, 1)
MyTimestamp = Annotated[datetime, WrapValidator(validate_timestamp)]
class Model(BaseModel):
a: MyTimestamp
print(Model(a='now').a)
#> 2032-01-02 03:04:05.000006
print(Model(a='invalid').a)
#> 2000-01-01 00:00:00
```
aWrapValidator
ucore_schema.NoInfoWrapValidatorFunction | core_schema.WithInfoWrapValidatorFunction
uWrapValidator.__get_pydantic_core_schema__
uWrapValidator._from_decorator
T abefore
after
wrap
plain
aFieldValidatorModes
D acheck_fields
json_schema_input_type
Q
Q
D afield
mode
check_fields
json_schema_input_type
fields
return
str
uLiteral['wrap']
ubool | None
aAny
str
uCallable[[_V2WrapValidatorType], _V2WrapValidatorType]
field_validator
D afield
mode
check_fields
json_schema_input_type
fields
return
str
uLiteral['before', 'plain']
ubool | None
aAny
str
uCallable[[_V2BeforeAfterOrPlainValidatorType], _V2BeforeAfterOrPlainValidatorType]
D amode
check_fields
Q
Q
D afield
mode
check_fields
fields
return
str
uLiteral['after']
ubool | None
str
uCallable[[_V2BeforeAfterOrPlainValidatorType], _V2BeforeAfterOrPlainValidatorType]
D afield
mode
check_fields
json_schema_input_type
fields
return
str
aFieldValidatorModes
ubool | None
aAny
str
uCallable[[Any], Any]
T a_ModelType
a_ModelType
T a_ModelTypeCo
tT acovariant
a_ModelTypeCo
aValidatorFunctionWrapHandler
a__prepare__
aModelWrapValidatorHandler
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
u`@model_validator` decorated function handler argument type. This is used when `mode='wrap'`.
T nD avalue
outer_location
return
aAny
ustr | int | None
a_ModelTypeCo
a__call__
uModelWrapValidatorHandler.__call__
a__orig_bases__
aModelWrapValidatorWithoutInfo
uA `@model_validator` decorated function signature.
This is used when `mode='wrap'` and the function does not have info argument.
D acls
value
handler
return
utype[_ModelType]
aAny
uModelWrapValidatorHandler[_ModelType]
a_ModelType
uModelWrapValidatorWithoutInfo.__call__
aModelWrapValidator
uA `@model_validator` decorated function signature. This is used when `mode='wrap'`.
D acls
value
handler
info
return
utype[_ModelType]
aAny
uModelWrapValidatorHandler[_ModelType]
u_core_schema.ValidationInfo
a_ModelType
uModelWrapValidator.__call__
aFreeModelBeforeValidatorWithoutInfo
uA `@model_validator` decorated function signature.
This is used when `mode='before'` and the function does not have info argument.
D avalue
return
aAny
puFreeModelBeforeValidatorWithoutInfo.__call__
aModelBeforeValidatorWithoutInfo
D acls
value
return
aAny
ppuModelBeforeValidatorWithoutInfo.__call__
aFreeModelBeforeValidator
uA `@model_validator` decorated function signature. This is used when `mode='before'`.
D avalue
info
return
aAny
u_core_schema.ValidationInfo
aAny
uFreeModelBeforeValidator.__call__
aModelBeforeValidator
D acls
value
info
return
aAny
pu_core_schema.ValidationInfo
aAny
uModelBeforeValidator.__call__
aModelAfterValidatorWithoutInfo
aValidationInfo
aModelAfterValidator
a_AnyModelWrapValidator
a_AnyModelBeforeValidator
a_AnyModelAfterValidator
D amode
return
uLiteral['wrap']
uCallable[[_AnyModelWrapValidator[_ModelType]], _decorators.PydanticDescriptorProxy[_decorators.ModelValidatorDecoratorInfo]]
model_validator
D amode
return
uLiteral['before']
uCallable[[_AnyModelBeforeValidator], _decorators.PydanticDescriptorProxy[_decorators.ModelValidatorDecoratorInfo]]
D amode
return
uLiteral['after']
uCallable[[_AnyModelAfterValidator[_ModelType]], _decorators.PydanticDescriptorProxy[_decorators.ModelValidatorDecoratorInfo]]
D amode
return
uLiteral['wrap', 'before', 'after']
aAny
T aAnyType
aAnyType
uGeneric type for annotating a type that is an instance of a given class.
Example:
```python
from pydantic import BaseModel, InstanceOf
class Foo:
...
class Bar(BaseModel):
foo: InstanceOf[Foo]
Bar(foo=Foo())
try:
Bar(foo=42)
except ValidationError as e:
print(e)
"""
[
{
'type': 'is_instance_of',
'loc': ('foo',),
'msg': 'Input should be an instance of Foo',
'input': 42,
'ctx': {'class': 'Foo'},
'url': 'https://errors.pydantic.dev/0.38.0/v/is_instance_of'
}
]
"""
```
aInstanceOf
D aitem
return
aAnyType
pa__class_getitem__
uInstanceOf.__class_getitem__
D asource
handler
return
aAny
aGetCoreSchemaHandler
ucore_schema.CoreSchema
uInstanceOf.__get_pydantic_core_schema__
a__hash__
uIf this is applied as an annotation (e.g., via `x: Annotated[int, SkipValidation]`), validation will be
skipped. You can also use `SkipValidation[int]` as a shorthand for `Annotated[int, SkipValidation]`.
This can be useful if you want to use a type annotation for documentation/IDE/type-checking purposes,
nd know that it is safe to skip validation for one or more of the fields.
Because this converts the validation schema to `any_schema`, subsequent annotation-applied transformations
may not have the expected effects. Therefore, when used, this annotation should generally be the final
nnotation applied to a type.
D aitem
return
aAny
puSkipValidation.__class_getitem__
uSkipValidation.__get_pydantic_core_schema__
upydantic\functional_validators.py
T a.0
field
T wvwhT a_c
whaoriginal_schema
T aoriginal_schema
u<module pydantic.functional_validators>
T a__class__
T aself
value
info
T aself
value
T aself
cls
value
info
T aself
cls
value
T aself
cls
value
handler
info
T aself
value
outer_location
T aself
cls
value
handler
T acls
item
T aself
source_type
handler
schema
info_arg
func
T aself
source_type
handler
schema
input_schema
info_arg
func
T acls
source
handler
aPydanticSchemaGenerationError
instance_of_schema
original_schema
T	aself
source_type
handler
aPydanticSchemaGenerationError
schema
serialization
input_schema
info_arg
func
T acls
source
handler
original_schema
metadata
T acls
decorator
T wfadec_info
fields
mode
check_fields
json_schema_input_type
T acheck_fields
fields
json_schema_input_type
mode
T wfadec_info
mode
T afield
mode
check_fields
fields
T afield
mode
check_fields
json_schema_input_type
fields
T afield
mode
check_fields
json_schema_input_type
fields
dec
T amode
dec
a__spec__
.pydantic.json
uThe `json` module is a backport module from V1.
a__doc__
a__file__
origin
has_location
a__cached__
a_migration
T agetattr_migration
getattr_migration
T upydantic.json
a__getattr__
upydantic\json.py
u<module pydantic.json>

a__spec__
.pydantic.json_schema
deepcopy
u$defs
;l
ldl adefaultdict
T Olist
copied_definitions
schemas_for_alternatives
append
a_deduplicate_schemas
definitions
defs_remapping
json_remapping
a_DefinitionsRemapping
remap_json_schema
definitions_schema
aPydanticInvalidForJsonSchema
T uFailed to simplify the JSON schema definitions

This function should produce a remapping that replaces complex DefsRef with the simpler ones from the
prioritized_choices such that applying the name remapping would result in an equivalent JSON schema.
u<genexpr>
u_DefinitionsRemapping.from_prioritized_choices.<locals>.<genexpr>
get
remap_json_ref
aJsonRef
self
items
u$ref
schema
remap_defs_ref
aDefsRef

Recursively update the JSON schema replacing all $refs
by_alias
ref_template
core_to_json_refs
core_to_defs_refs
defs_to_core_refs
json_to_defs_refs
a_config
aConfigWrapperStack
aConfigWrapper
a_config_wrapper_stack
validation
a_mode
a_prioritized_defsref_choices
T Oint
a_collision_counter
a_collision_index
build_schema_type_to_method
a_schema_type_to_method
a_core_defs_invalid_for_json_schema
a_used
tail
json_schema_mode_override
a_typing_extra
literal_values
aCoreSchemaOrFieldType
replace
T w-w_u
a_schema
mapping
environ
aPYDANTIC_PRIVATE_ALLOW_UNHANDLED_SCHEMA_TYPES
w1uNo method for generating JsonSchema for core_schema.type=
u (expected:
a__name__
w.w)uBuilds a dictionary mapping fields to methods for generating JSON schemas.
Returns:
A dictionary containing the mapping of `CoreSchemaOrFieldType` to a handler method.
Raises:
TypeError: If no method has been defined for generating a JSON schema for a given pydantic core schema type.
aPydanticUserError
uThis JSON schema generator has already been used to generate a JSON schema. You must create a new instance of
u to generate a new JSON schema.
D acode
ujson-schema-already-used
generate_inner
a_build_definitions_remapping
definitions_remapping
json_schemas_map
sort
uGenerates JSON schema definitions from a list of core schemas, pairing the generated definitions with a
mapping that links the input keys to the definition references.
Args:
inputs: A sequence of tuples, where:
- The first element is a JSON schema key type.
- The second element is the JSON mode: either 'validation' or 'serialization'.
- The third element is a core schema.
Returns:
A tuple where:
- The first element is a dictionary whose keys are tuples of JSON schema key type and JSON mode, and
whose values are the JSON schema corresponding to that pair of inputs. (These schemas may have
JsonRef references to definitions that are defined in the second returned element.)
- The second element is a dictionary whose keys are definition references for the JSON schemas
from the first returned element, and whose values are the actual JSON schema definitions.
Raises:
PydanticUserError: Raised if the JSON schema generator has already been used to generate a JSON schema.
get_json_ref_counts
cast
T u$ref
ref
get_schema_from_definitions
json_ref_counts
json_schema
copy
a_garbage_collect_definitions
uGenerates a JSON schema for a specified schema in a specified mode.
Args:
schema: A Pydantic model.
mode: The mode in which to generate the schema. Defaults to 'validation'.
Returns:
A JSON schema representing the specified schema.
Raises:
PydanticUserError: If the JSON schema generator has already been used to generate a JSON schema.
aCoreRef
mode
D acore_schema
json_schema
return
aCoreSchema
aJsonSchemaValue
papopulate_defs
uGenerateJsonSchema.generate_inner.<locals>.populate_defs
D aschema_or_field
return
aCoreSchemaOrField
aJsonSchemaValue
uGenerate a JSON schema based on the input schema.
Args:
schema_or_field: The core schema to generate a JSON schema from.
Returns:
The generated JSON schema.
Raises:
TypeError: If an unexpected schema type is encountered.
handler_func
uGenerateJsonSchema.generate_inner.<locals>.handler_func
a_schema_generation_shared
aGenerateJsonSchemaHandler
a_core_metadata
aCoreMetadata
metadata
T apydantic_js_updates
D aschema_or_field
current_handler
return
aCoreSchemaOrField
aGetJsonSchemaHandler
aJsonSchemaValue
js_updates_handler_func
uGenerateJsonSchema.generate_inner.<locals>.js_updates_handler_func
T apydantic_js_extra
js_extra_handler_func
uGenerateJsonSchema.generate_inner.<locals>.js_extra_handler_func
T apydantic_js_functions
T
current_handler
D aschema_or_field
current_handler
js_modify_function
return
aCoreSchemaOrField
aGetJsonSchemaHandler
aGetJsonSchemaFunction
aJsonSchemaValue
new_handler_func
uGenerateJsonSchema.generate_inner.<locals>.new_handler_func
T apydantic_js_annotation_functions
T
a_core_utils
is_core_schema
uGenerates a JSON schema for a given core schema.
Args:
schema: The given core schema.
Returns:
The generated JSON schema.
TODO: the nested function definitions here seem like bad practice, I'd like to unpack these
in a future PR. It'd be great if we could shorten the call stack a bit for JSON schema generation,
nd I think there's potential for that here.
get_cache_defs_ref_schema
T u$ref
napop
serialization
ser_schema
T awhen_used
T uunless-none
ujson-unless-none
type
nullable
get_flattened_anyof
D atype
null
is_core_schema_field
uUnexpected schema type: schema=
js_updates
js_extra
update
to_jsonable_python
callable
resolve_ref_schema
keys
T aproperties
default
sorted
a_sort_recursive
T aparent_key
sorted_dict
uOverride this method to customize the sorting of the JSON schema (e.g., don't sort at all, sort all keys unconditionally, etc.)
By default, alphabetically sort the keys in the JSON schema, skipping the 'properties' and 'default' keys to preserve field definition order.
This sort is recursive, so it will sort all nested dictionaries as well.
sorted_list
parent_key
uRecursively sort a JSON schema value.
uCannot generate schema for invalid_schema. This is a bug! Please report it.
uPlaceholder - should never be called.
uGenerates a JSON schema that matches any value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches `None`.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
boolean
uGenerates a JSON schema that matches a bool value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
integer
update_with_validations
aValidationsMapping
numeric
math
inf
uGenerates a JSON schema that matches an int value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
number
uGenerates a JSON schema that matches a float value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
str_schema
upydantic_core.core_schema
T amultiple_of
T ale
T age
T alt
T agt
anyOf
float_schema
T aallow_inf_nan
T aallow_inf_nan
multiple_of
le
ge
lt
gt
uGenerates a JSON schema that matches a decimal value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
string
string
pattern
aPattern
uGenerates a JSON schema that matches a string value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
format
ser_json_bytes
base64
base64url
binary
bytes
uGenerates a JSON schema that matches a bytes value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
format
string
date
uGenerates a JSON schema that matches a date value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
format
string
time
uGenerates a JSON schema that matches a time value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
format
string
udate-time
uGenerates a JSON schema that matches a datetime value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
ser_json_timedelta
float
D atype
format
string
duration
uGenerates a JSON schema that matches a timedelta value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
expected
aEnum
value
const
enum
S Ostr
result
S Oint
integer
S Ofloat
number
S Obool
boolean
S Olist
array
S M
null
uGenerates a JSON schema that matches a literal value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
cls
a__doc__
inspect
cleandoc
uAn enumeration.
title
description
members
uGenerates a JSON schema that matches an Enum value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
handle_invalid_for_json_schema
ucore_schema.IsInstanceSchema (
uHandles JSON schema generation for a core schema that checks if a value is an instance of a class.
Unless overridden in a subclass, this raises an error.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uHandles JSON schema generation for a core schema that checks if a value is a subclass of a class.
For backwards compatibility with v1, this does not raise an error, but can be overridden to change this.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
ucore_schema.CallableSchema
uGenerates a JSON schema that matches a callable value.
Unless overridden in a subclass, this raises an error.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
items_schema
uReturns a schema that matches a list schema.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
warnings
warn
u`tuple_positional_schema` is deprecated. Use `tuple_schema` instead.
aPydanticDeprecatedSince26
D astacklevel
l atuple_schema
uReplaced by `tuple_schema`.
u`tuple_variable_schema` is deprecated. Use `tuple_schema` instead.
D atype
array
variadic_item_index
minItems
prefixItems
maxItems
uGenerates a JSON schema that matches a tuple schema e.g. `Tuple[int,
str, bool]` or `Tuple[int, ...]`.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
a_common_set_schema
uGenerates a JSON schema that matches a set schema.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches a frozenset schema.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uniqueItems
uReturns a JSON schema that represents the provided GeneratorSchema.
Args:
schema: The schema.
Returns:
The generated JSON schema.
D atype
object
keys_schema
T apattern
nT atitle
navalues_schema
additionalProperties
patternProperties
T atype
T atype
napropertyNames
object
uGenerates a JSON schema that matches a dict schema.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
T ajson_schema_input_schema
input_schema
uGenerates a JSON schema that matches a function-before schema.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches a function-after schema.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
ucore_schema.PlainValidatorFunctionSchema (
function
uGenerates a JSON schema that matches a function-plain schema.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches a function-wrap schema.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
default
T aserialization
T afunction
ufunction-plain
T ainfo_arg
ser_func
emit_warning
unon-serializable-default
uUnable to serialize value
u with the plain serializer; excluding default from JSON schema
encode_default
pydantic_core
aPydanticSerializationError
uDefault value
u is not JSON serializable; excluding default from JSON schema
uGenerates a JSON schema that matches a schema with a default value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches a schema that allows null values.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
choices
generated
aPydanticOmit
uskipped-choice
message
uGenerates a JSON schema that matches a schema that allows values matching any of the given schemas.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
oneOf
a_extract_discriminator
propertyName
discriminator
uGenerates a JSON schema that matches a schema that allows values matching any of the given schemas, where
the schemas are tagged with a discriminator field that indicates which schema should be used to validate
the value.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
one_of_choices
uskipped-discriminator
properties
uExtract a compatible OpenAPI discriminator from the schema and one_of choices that end up in the final
schema.
steps
uGenerates a JSON schema that matches a core_schema.ChainSchema.
When generating a schema for validation, we return the validation JSON schema for the first step in the chain.
For serialization, we return the serialization JSON schema for the last step in the chain.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
T astrict
Fastrict_schema
lax_schema
uGenerates a JSON schema that matches a schema that allows values matching either the lax schema or the
strict schema.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches a schema that allows values matching either the JSON schema or the
Python schema.
The JSON schema is used instead of the Python schema. If you want to use the Python schema, you should override
this method.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
T atotal
tafields
field_is_present
field_is_required
total
extend
a_name_required_computed_fields
computed_fields
T acls
a_get_typed_dict_config
push
a__enter__
a__exit__
a_named_required_fields_schema
T nnna_update_class_schema
T aextra
forbid
allow
uGenerates a JSON schema that matches a schema that defines a typed dict.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
property_name
a_get_alias_name
field_title_should_be_set
get_title_from_name
handle_ref_overrides
required_fields
required
ucomputed-field
alias
validation_alias
serialization_alias
ulist[str] | str
assert_never
name
uGenerates a JSON schema that matches a schema that defines a typed dict field.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches a schema that defines a dataclass field.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches a schema that defines a model field.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
return_schema
uGenerates a JSON schema that matches a schema that defines a computed field.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
utype[BaseModel]
model_config
uGenerates a JSON schema that matches a schema that defines a model.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
upydantic.main
aBaseModel
upydantic.root_model
aRootModel
T atitle
setdefault
T amodel_title_generator
umodel_title_generator
u must return str, not
dataclasses
is_dataclass
a__pydantic_fields__
root
root_description
T ajson_schema_extra
a__pydantic_root_model__
model_fields
json_schema_extra
u"model_config['json_schema_extra']" and "Field.json_schema_extra" on "RootModel.root" field must not be set simultaneously
T Ostaticmethod
Oclassmethod
a__get__
signature
parameters
umodel_config['json_schema_extra']=
u should be a dict, callable, or None
a__deprecated__
deprecated
uUpdate json_schema with the following, extracted from `config` and `cls`:
* title
* description
* additional properties
* json_schema_extra
* deprecated
Done in place, hence there's no return value as the original json_schema is mutated.
No ref resolving is involved here, as that's not appropriate for simple updates.
uCannot update undefined schema for $ref=
uResolve a JsonSchemaValue to the non-ref schema if it is a $ref schema.
Args:
json_schema: The schema to resolve.
Returns:
The resolved schema.
Raises:
RuntimeError: If the schema reference can't be found in definitions.
D atotal
tT aextras_schema
nuGenerates a JSON schema that matches a schema that defines a model's fields.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
T aserialization_exclude
uWhether the field should be included in the generated JSON schema.
Args:
field: The schema for the field itself.
Returns:
`True` if the field should be included in the generated JSON schema, `False` otherwise.
json_schema_serialization_defaults_required
utyped-dict-field
uWhether the field should be marked as required in the generated JSON schema.
(Note that this is irrelevant if the field is not present in the JSON schema.).
Args:
field: The schema for the field itself.
total: Only applies to `TypedDictField`s.
Indicates if the `TypedDict` this field belongs to is total, in which case any fields that don't
explicitly specify `required=False` are required.
Returns:
`True` if the field should be marked as required in the generated JSON schema, `False` otherwise.
uGenerates a JSON schema that matches a schema that defines a dataclass's constructor arguments.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
u_internal._dataclasses
T ais_builtin_dataclass
is_builtin_dataclass
a__pydantic_config__
aConfigDict
uGenerates a JSON schema that matches a schema that defines a dataclass.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
T apydantic_js_prefer_positional_arguments
arguments_schema
T amode
keyword_only
P apositional_or_keyword
napositional_only
T avar_args_schema
T avar_kwargs_schema
p_arguments_schema
kw_arguments_schema
T uUnable to generate JSON schema for arguments validator with positional-only and keyword-only arguments
uGenerates a JSON schema that matches a schema that defines a function's arguments.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
get_argument_name
uGenerates a JSON schema that matches a schema that defines a function's keyword arguments.
Args:
rguments: The core schema.
Returns:
The generated JSON schema.
prefix_items
min_items
uGenerates a JSON schema that matches a schema that defines a function's positional arguments.
Args:
rguments: The core schema.
Returns:
The generated JSON schema.
T aalias
uRetrieves the name of an argument.
Args:
rgument: The core schema.
Returns:
The name of the argument.
uGenerates a JSON schema that matches a schema that defines a function call.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches a schema that defines a custom error.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
T aschema
any_schema
contentMediaType
uapplication/json
contentSchema
uGenerates a JSON schema that matches a schema that defines a JSON object.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
format
minLength
string
uri
l uGenerates a JSON schema that matches a schema that defines a URL.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
format
minLength
string
umulti-host-uri
l uGenerates a JSON schema that matches a schema that defines a URL that can be used with multiple hosts.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
D atype
format
string
uuid
uGenerates a JSON schema that matches a UUID.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
get_defs_ref
uGenerates a JSON schema that matches a schema that defines a JSON object with definitions.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
schema_ref
uGenerates a JSON schema that matches a schema that references a definition.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
ufunction-wrap
T areturn_schema
uto-string
model
uGenerates a JSON schema that matches a schema that defines a serialized object.
Args:
schema: The core schema.
Returns:
The generated JSON schema.
uGenerates a JSON schema that matches a complex number.
JSON has no standard way to represent complex numbers. Complex number is not a numeric
type. Here we represent complex number as strings following the rule defined by Python.
For instance, '1+2j' is an accepted complex string. Details can be found in
[Python's `complex` documentation][complex].
Args:
schema: The core schema.
Returns:
The generated JSON schema.
T w_w astrip
uRetrieves a title from a name.
Args:
name: The name to retrieve a title from.
Returns:
The title.
T aref
P adefault
definitions
nullable
is_function_with_inner_schema
udefinition-ref
uReturns true if a field with the given schema should have a title set based on the field name.
Intuitively, we want this to return true for schemas that wouldn't otherwise provide their own title
(e.g., int, float, str), and false for those that would (e.g., BaseModel subclasses).
Args:
schema: The schema to check.
Returns:
`True` if the field should have a title set, `False` otherwise.
re
sub
u[^a-zA-Z0-9.\-_]
w_T w.a__
uNormalizes a name to be used as a key in a dictionary.
Args:
name: The name to normalize.
Returns:
The normalized name.
split
u([\][,])
rsplit
T w:l u(?:[^.[\]]+\.)+((?:[^.[\]]+))
u\1
a_MODE_TITLE_MAPPING
normalize_name
w-a__
uOverride this method to change the way that definitions keys are generated from a core reference.
Args:
core_mode_ref: The core reference.
Returns:
The definitions key.
T amodel
uThis method wraps the get_defs_ref method with some cache-lookup/population logic,
nd returns both the produced defs_ref and the JSON schema that will refer to the right definition.
Args:
core_ref: The core reference to get the definitions reference for.
Returns:
A tuple of the definitions reference and the JSON schema that will refer to it.
uRemove any sibling keys that are redundant with the referenced schema.
Args:
json_schema: The schema to remove redundant sibling keys from.
Returns:
The schema with redundant sibling keys removed.
startswith
T T uhttp://
uhttps://
upydantic.type_adapter
aTypeAdapter
a_type_has_config
config_dict
T aconfig
dump_python
D amode
json
aPydanticSchemaGenerationError
uUnable to encode default value
T atimedelta_mode
bytes_mode
uEncode a default value to a JSON-serializable value.
This is used to encode default values for fields in the generated JSON schema.
Args:
dft: The default value to encode.
Returns:
The encoded default value.
uUpdate the json_schema with the corresponding validations specified in the core_schema,
using the provided mapping to translate keys in core_schema to the appropriate keys for a JSON schema.
Args:
json_schema: The JSON schema to update.
core_schema: The core schema to get the validations from.
mapping: A mapping from core_schema attribute names to the corresponding JSON schema attribute names.
aCounter
D aschema
return
aAny
aNone
a_add_json_refs
uGenerateJsonSchema.get_json_ref_counts.<locals>._add_json_refs
uGet all values corresponding to the key '$ref' anywhere in the json_schema.
json_refs
examples
uCannot generate a JsonSchema for
render_warning_message
aPydanticJsonSchemaWarning
uThis method simply emits PydanticJsonSchemaWarnings based on handling in the `warning_message` method.
ignored_warning_kinds
u [
w]uThis method is responsible for ignoring warnings as desired, and for formatting the warning messages.
You can override the value of `ignored_warning_kinds` in a subclass of GenerateJsonSchema
to modify what warnings are generated. If you want more control, you can override this method;
just return None in situations where you don't want warnings to be emitted.
Args:
kind: The kind of warning to render. It can be one of the following:
- 'skipped-choice': A choice field was skipped because it had no valid choices.
- 'non-serializable-default': A default value was skipped because it was not JSON-serializable.
detail: A string with additional details about the warning.
Returns:
The formatted warning message, or `None` if no warning should be emitted.
values
defs_to_json
from_prioritized_choices
a_get_all_json_refs
unvisited_json_refs
visited_defs_refs
add
T aby_alias
ref_template
a__pydantic_core_schema__
a_mock_val_ser
aMockCoreSchema
rebuild
umodel_json_schema() must be called on a subclass of BaseModel, not BaseModel itself.
T uthis is a bug! please report it
generate
uUtility function to generate a JSON Schema for a model.
Args:
cls: The model class to generate a JSON Schema for.
by_alias: If `True` (the default), fields will be serialized according to their alias.
If `False`, fields will be serialized according to their attribute name.
ref_template: The template to use for generating JSON Schema references.
schema_generator: The class to use for generating the JSON Schema.
mode: The mode to use for generating the JSON Schema. It can be one of the following:
- 'validation': Generate a JSON Schema for validating data.
- 'serialization': Generate a JSON Schema for serializing data.
Returns:
The generated JSON Schema.
generate_definitions
uUtility function to generate a JSON Schema for multiple models.
Args:
models: A sequence of tuples of the form (model, mode).
by_alias: Whether field aliases should be used as keys in the generated JSON Schema.
title: The title of the generated JSON Schema.
description: The description of the generated JSON Schema.
ref_template: The reference template to use for generating JSON Schema references.
schema_generator: The schema generator to use for generating the JSON Schema.
Returns:
A tuple where:
- The first element is a dictionary whose keys are tuples of JSON schema key type and JSON mode, and
whose values are the JSON schema corresponding to that pair of inputs. (These schemas may have
JsonRef references to definitions that are defined in the second returned element.)
- The second element is a JSON schema containing all definitions referenced in the first returned
element, along with the optional title and description keys.
a_make_json_hashable
u_make_json_hashable.<locals>.<genexpr>
uUsing a dict for `examples` is deprecated, use a list instead.
aPydanticDeprecatedSince29
T aexamples
uUpdating existing JSON Schema examples of type dict with examples of type list. Only the existing examples values will be retained. Note that dict support for examples is deprecated and will be removed in v3.0.
aUserWarning
uUpdating existing JSON Schema examples of type list with examples of type dict. Only the examples values will be retained. Note that dict support for examples is deprecated and will be removed in v3.0.
stack
refs
uGet all the definitions references from a JSON schema.
aAnnotated
a_decorators
get_attribute_from_bases

Usage docs: https://docs.pydantic.dev/2.5/concepts/json_schema/
The `json_schema` module contains classes and functions to allow the way [JSON Schema](https://json-schema.org/)
is generated to be customized.
In general you shouldn't need to use this module directly; instead, you can use
[`BaseModel.model_json_schema`][pydantic.BaseModel.model_json_schema] and
[`TypeAdapter.json_schema`][pydantic.TypeAdapter.json_schema].
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
a_annotations
os
collections
T adefaultdict
T adeepcopy
T aEnum
aTYPE_CHECKING
aAny
aCallable
aDict
aHashable
aIterable
aNewType
aSequence
aTuple
aTypeVar
aUnion
overload
aCoreSchema
core_schema
aComputedField
typing_extensions
T aAnnotated
aLiteral
aTypeAlias
assert_never
deprecated
final
aLiteral
aTypeAlias
final
upydantic.warnings
a_internal
T a_config
a_core_metadata
a_core_utils
a_decorators
a_internal_dataclass
a_mock_val_ser
a_schema_generation_shared
a_typing_extra
a_internal_dataclass
upydantic.annotated_handlers
aGetJsonSchemaHandler
upydantic.config
aJsonDict
aJsonValue
upydantic.errors
aCoreSchemaType
aCoreSchemaFieldType
aJsonSchemaValue
T avalidation
serialization
aJsonSchemaMode
D avalidation
serialization
aInput
aOutput
udict[JsonSchemaMode, str]
T uskipped-choice
unon-serializable-default
uskipped-discriminator
aJsonSchemaWarningKind
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
