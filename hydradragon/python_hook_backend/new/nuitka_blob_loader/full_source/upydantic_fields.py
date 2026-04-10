# Reconstructed from integrated Nuitka blob
# Module: upydantic.fields

uThis class exists solely to add type checking for the `**kwargs` in `FieldInfo.from_field`.
a__qualname__
utype[Any] | None
uCallable[[], Any] | Callable[[dict[str, Any]], Any] | None
ustr | None
uint | None
ustr | AliasPath | AliasChoices | None
uCallable[[str, FieldInfo], str] | None
ulist[Any] | None
ubool | None
uannotated_types.SupportsGt | None
gt
uannotated_types.SupportsGe | None
ge
uannotated_types.SupportsLt | None
lt
uannotated_types.SupportsLe | None
le
ufloat | None
multiple_of
strict
min_length
max_length
ustr | typing.Pattern[str] | None
pattern
allow_inf_nan
max_digits
decimal_places
uLiteral['smart', 'left_to_right'] | None
union_mode
ustr | types.Discriminator | None
uDeprecated | str | bool | None
uJsonDict | Callable[[JsonDict], None] | None
bool
coerce_numbers_to_str
fail_fast
a__orig_bases__
a_FieldInfoInputs
uThis class exists solely to add type checking for the `**kwargs` in `FieldInfo.__init__`.
aRepresentation
uThis class holds information about a field.
`FieldInfo` is used for any field definition regardless of whether the [`Field()`][pydantic.fields.Field]
function is explicitly used.
!!! warning
You generally shouldn't be creating `FieldInfo` directly, you'll only need to use it when accessing
[`BaseModel`][pydantic.main.BaseModel] `.model_fields` internals.
Attributes:
nnotation: The type annotation of the field.
default: The default value of the field.
default_factory: A callable to generate the default value. The callable can either take 0 arguments
(in which case it is called as is) or a single argument containing the already validated data.
lias: The alias name of the field.
lias_priority: The priority of the field's alias.
validation_alias: The validation alias of the field.
serialization_alias: The serialization alias of the field.
title: The title of the field.
field_title_generator: A callable that takes a field name and returns title for it.
description: The description of the field.
examples: List of examples of the field.
exclude: Whether to exclude the field from the model serialization.
discriminator: Field name or Discriminator for discriminating the type in a tagged union.
deprecated: A deprecation message, an instance of `warnings.deprecated` or the `typing_extensions.deprecated` backport,
or a boolean. If `True`, a default deprecation message will be emitted when accessing the field.
json_schema_extra: A dict or callable to provide extra JSON schema properties.
frozen: Whether the field is frozen.
validate_default: Whether to validate the default value of the field.
repr: Whether to include the field in representation of the model.
init: Whether the field should be included in the constructor of the dataclass.
init_var: Whether the field should _only_ be included in the constructor of the dataclass, and not stored.
kw_only: Whether the field should be a keyword-only argument in the constructor of the dataclass.
metadata: List of metadata constraints.
ulist[Any]
T aannotation
evaluated
default
default_factory
alias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
metadata
a_attributes_set
aStrict
aGt
aGe
aLt
aLe
aMultipleOf
aMinLen
aMaxLen
aFailFast
uClassVar[dict[str, typing.Callable[[Any], Any] | None]]
D akwargs
return
uUnpack[_FieldInfoInputs]
aNone
a__init__
uFieldInfo.__init__
staticmethod
D adefault
kwargs
return
aAny
uUnpack[_FromFieldInfoInputs]
aFieldInfo
uFieldInfo.from_field
D aannotation
return
utype[Any]
aFieldInfo
from_annotation
uFieldInfo.from_annotation
D aannotation
default
return
utype[Any]
aAny
aFieldInfo
from_annotated_attribute
uFieldInfo.from_annotated_attribute
D afield_infos
overrides
return
aFieldInfo
aAny
aFieldInfo
uFieldInfo.merge_field_infos
D adc_field
return
uDataclassField[Any]
aFieldInfo
uFieldInfo._from_dataclass_field
D aannotation
return
utype[Any] | None
utuple[type[Any] | None, list[Any]]
uFieldInfo._extract_metadata
D akwargs
return
udict[str, Any]
ulist[Any]
uFieldInfo._collect_metadata
property
D areturn
ustr | None
deprecation_message
uFieldInfo.deprecation_message
D areturn
ubool | None
uFieldInfo.default_factory_takes_validated_data
D avalidated_data
nD acall_default_factory
validated_data
return
uLiteral[True]
udict[str, Any] | None
aAny
get_default
uFieldInfo.get_default
D acall_default_factory
Q
D acall_default_factory
return
uLiteral[False]
aAny
D acall_default_factory
validated_data
FnD acall_default_factory
validated_data
return
bool
udict[str, Any] | None
aAny
D areturn
bool
uFieldInfo.is_required
D areturn
aAny
rebuild_annotation
uFieldInfo.rebuild_annotation
T nnD atypevars_map
globalns
localns
return
udict[Any, Any] | None
uGlobalsNamespace | None
uMappingNamespace | None
aNone
apply_typevars_map
uFieldInfo.apply_typevars_map
D areturn
aReprArgs
a_EmptyKwargs
uThis class exists solely to ensure that type checking warns about passing `**extra` in `Field`.
D adefault
default_factory
alias
alias_priority
validation_alias
serialization_alias
title
description
examples
exclude
discriminator
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
coerce_numbers_to_str
Q
nnnnnnnnnnnnntnnnnnnnnnnnnnnnnT a_T
a_T
D$adefault
alias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
coerce_numbers_to_str
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
union_mode
fail_fast
extra
return
ellipsis
ustr | None
uint | None
ustr | AliasPath | AliasChoices | None
ustr | None
ustr | None
uCallable[[str, FieldInfo], str] | None
ustr | None
ulist[Any] | None
ubool | None
ustr | types.Discriminator | None
uDeprecated | str | bool | None
uJsonDict | Callable[[JsonDict], None] | None
ubool | None
ubool | None
bool
ubool | None
ubool | None
ubool | None
ustr | typing.Pattern[str] | None
ubool | None
ubool | None
uannotated_types.SupportsGt | None
uannotated_types.SupportsGe | None
uannotated_types.SupportsLt | None
uannotated_types.SupportsLe | None
ufloat | None
ubool | None
uint | None
uint | None
uint | None
uint | None
uLiteral['smart', 'left_to_right']
ubool | None
uUnpack[_EmptyKwargs]
aAny
D$adefault
alias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
coerce_numbers_to_str
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
union_mode
fail_fast
extra
return
a_T
ustr | None
uint | None
ustr | AliasPath | AliasChoices | None
ustr | None
ustr | None
uCallable[[str, FieldInfo], str] | None
ustr | None
ulist[Any] | None
ubool | None
ustr | types.Discriminator | None
uDeprecated | str | bool | None
uJsonDict | Callable[[JsonDict], None] | None
ubool | None
ubool | None
bool
ubool | None
ubool | None
ubool | None
ustr | typing.Pattern[str] | None
ubool | None
ubool | None
uannotated_types.SupportsGt | None
uannotated_types.SupportsGe | None
uannotated_types.SupportsLt | None
uannotated_types.SupportsLe | None
ufloat | None
ubool | None
uint | None
uint | None
uint | None
uint | None
uLiteral['smart', 'left_to_right']
ubool | None
uUnpack[_EmptyKwargs]
a_T
D$adefault_factory
alias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
coerce_numbers_to_str
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
union_mode
fail_fast
extra
return
uCallable[[], _T] | Callable[[dict[str, Any]], _T]
ustr | None
uint | None
ustr | AliasPath | AliasChoices | None
ustr | None
ustr | None
uCallable[[str, FieldInfo], str] | None
ustr | None
ulist[Any] | None
ubool | None
ustr | types.Discriminator | None
uDeprecated | str | bool | None
uJsonDict | Callable[[JsonDict], None] | None
ubool | None
ubool | None
bool
ubool | None
ubool | None
ubool | None
ustr | typing.Pattern[str] | None
ubool | None
ubool | None
uannotated_types.SupportsGt | None
uannotated_types.SupportsGe | None
uannotated_types.SupportsLt | None
uannotated_types.SupportsLe | None
ufloat | None
ubool | None
uint | None
uint | None
uint | None
uint | None
uLiteral['smart', 'left_to_right']
ubool | None
uUnpack[_EmptyKwargs]
a_T
D#aalias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
coerce_numbers_to_str
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
union_mode
fail_fast
extra
return
ustr | None
uint | None
ustr | AliasPath | AliasChoices | None
ustr | None
ustr | None
uCallable[[str, FieldInfo], str] | None
ustr | None
ulist[Any] | None
ubool | None
ustr | types.Discriminator | None
uDeprecated | str | bool | None
uJsonDict | Callable[[JsonDict], None] | None
ubool | None
ubool | None
bool
ubool | None
ubool | None
ubool | None
ustr | typing.Pattern[str] | None
ubool | None
ubool | None
uannotated_types.SupportsGt | None
uannotated_types.SupportsGe | None
uannotated_types.SupportsLt | None
uannotated_types.SupportsLe | None
ufloat | None
ubool | None
uint | None
uint | None
uint | None
uint | None
uLiteral['smart', 'left_to_right']
ubool | None
uUnpack[_EmptyKwargs]
aAny
D%adefault
default_factory
alias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
coerce_numbers_to_str
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
union_mode
fail_fast
extra
return
aAny
uCallable[[], Any] | Callable[[dict[str, Any]], Any] | None
ustr | None
uint | None
ustr | AliasPath | AliasChoices | None
ustr | None
ustr | None
uCallable[[str, FieldInfo], str] | None
ustr | None
ulist[Any] | None
ubool | None
ustr | types.Discriminator | None
uDeprecated | str | bool | None
uJsonDict | Callable[[JsonDict], None] | None
ubool | None
ubool | None
bool
ubool | None
ubool | None
ubool | None
ustr | typing.Pattern[str] | None
ubool | None
ubool | None
uannotated_types.SupportsGt | None
uannotated_types.SupportsGe | None
uannotated_types.SupportsLt | None
uannotated_types.SupportsLe | None
ufloat | None
ubool | None
uint | None
uint | None
uint | None
uint | None
uLiteral['smart', 'left_to_right']
ubool | None
uUnpack[_EmptyKwargs]
aAny
signature
parameters
remove
T aextra
uA descriptor for private attributes in class models.
!!! warning
You generally shouldn't be creating `ModelPrivateAttr` instances directly, instead use
`pydantic.fields.PrivateAttr`. (This is similar to `FieldInfo` vs. `Field`.)
Attributes:
default: The default value of the attribute if not provided.
default_factory: A callable function that generates the default value of the
ttribute if not provided.
T adefault
default_factory
D adefault_factory
nD adefault
default_factory
return
aAny
utyping.Callable[[], Any] | None
aNone
uModelPrivateAttr.__init__
aTYPE_CHECKING
D aitem
return
str
aAny
a__getattr__
uModelPrivateAttr.__getattr__
D acls
name
return
utype[Any]
str
aNone
uModelPrivateAttr.__set_name__
uModelPrivateAttr.get_default
D aother
return
aAny
bool
a__eq__
uModelPrivateAttr.__eq__
D ainit
FD adefault
init
return
a_T
uLiteral[False]
a_T
aPrivateAttr
D adefault_factory
init
return
uCallable[[], _T]
uLiteral[False]
a_T
D ainit
return
uLiteral[False]
aAny
D adefault_factory
init
nFD adefault
default_factory
init
return
aAny
uCallable[[], Any] | None
uLiteral[False]
aAny
dataclass
slots_true
uA container for data from `@computed_field` so that we can access it while building the pydantic-core schema.
Attributes:
decorator_repr: A class variable representing the decorator string, '@computed_field'.
wrapped_property: The wrapped computed field property.
return_type: The type of the computed field property's return value.
lias: The alias of the property to be used during serialization.
lias_priority: The priority of the alias. This affects whether an alias generator is used.
title: Title of the computed field to include in the serialization JSON schema.
field_title_generator: A callable that takes a field name and returns title for it.
description: Description of the computed field to include in the serialization JSON schema.
deprecated: A deprecation message, an instance of `warnings.deprecated` or the `typing_extensions.deprecated` backport,
or a boolean. If `True`, a default deprecation message will be emitted when accessing the field.
examples: Example values of the computed field to include in the serialization JSON schema.
json_schema_extra: A dict or callable to provide extra JSON schema properties.
repr: A boolean indicating whether to include the field in the __repr__ output.
u@computed_field
decorator_repr
uClassVar[str]
wrapped_property
utyping.Callable[[str, ComputedFieldInfo], str] | None
uJsonDict | typing.Callable[[JsonDict], None] | None
uComputedFieldInfo.deprecation_message
D aproperty_
return
ucached_property | property
bool
T aPropertyT
aPropertyT
D aalias
alias_priority
title
field_title_generator
description
deprecated
examples
json_schema_extra
repr
return_type
return
ustr | None
uint | None
ustr | None
utyping.Callable[[str, ComputedFieldInfo], str] | None
ustr | None
uDeprecated | str | bool | None
ulist[Any] | None
uJsonDict | typing.Callable[[JsonDict], None] | None
bool
aAny
utyping.Callable[[PropertyT], PropertyT]
computed_field
D a__func
return
aPropertyT
pT nD afunc
alias
alias_priority
title
field_title_generator
description
deprecated
examples
json_schema_extra
repr
return_type
return
uPropertyT | None
ustr | None
uint | None
ustr | None
utyping.Callable[[str, ComputedFieldInfo], str] | None
ustr | None
uDeprecated | str | bool | None
ulist[Any] | None
uJsonDict | typing.Callable[[JsonDict], None] | None
ubool | None
aAny
uPropertyT | typing.Callable[[PropertyT], PropertyT]
upydantic\fields.py
T a.0
wkT a.0
alias
u<module pydantic.fields>
T a__class__
T"aalias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
coerce_numbers_to_str
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
union_mode
fail_fast
extra
T#adefault
alias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
coerce_numbers_to_str
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
union_mode
fail_fast
extra
T+adefault
default_factory
alias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
coerce_numbers_to_str
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
union_mode
fail_fast
extra
const
min_items
max_items
unique_items
allow_mutation
regex
include
T#adefault_factory
alias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
validate_default
repr
init
init_var
kw_only
pattern
strict
coerce_numbers_to_str
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_length
max_length
union_mode
fail_fast
extra
T adefault
default_factory
init
T adefault
init
T adefault_factory
init
T ainit
T aself
other
T aself
item
T aself
kwargs
annotation_metadata
default
alias_is_set
T aself
default
default_factory
T aself
wsavalue
T aself
cls
name
default
set_name
T akwargs
metadata
general_metadata
key
value
marker
T aannotation
first_arg
extra_args
T adc_field
default
default_factory
dc_field_metadata
T aproperty_
wrapped_name
T aself
typevars_map
globalns
localns
annotation
w_T a__func
T
alias
alias_priority
title
field_title_generator
description
deprecated
examples
json_schema_extra
repr
return_type
T afunc
alias
alias_priority
title
field_title_generator
description
deprecated
examples
json_schema_extra
repr
return_type
dec
T wfarepr_
description
deprecated
return_type
alias_priority
unwrapped
dec_info
alias
repr
title
field_title_generator
examples
json_schema_extra
T
alias
alias_priority
deprecated
description
examples
field_title_generator
json_schema_extra
repr
return_type
title
T aself
T aannotation
default
metadata
final
annotation_metadata
init_var
pydantic_field
first_arg
extra_args
field_infos
field_info
waT	aannotation
metadata
final
first_arg
extra_args
field_info_annotations
field_info
new_field_info
waT adefault
kwargs
T aself
call_default_factory
T aself
call_default_factory
validated_data
T aself
call_default_factory
validated_data
fac
T afield_infos
overrides
merged_field_info_kwargs
field_info
default_override
wkwvametadata
attributes_set
json_schema_extra
existing_json_schema_extra
wxa__spec__
.pydantic.functional_validators
G
a_inspect_validator
func
after
cast
upydantic_core.core_schema
aWithInfoValidatorFunction
with_info_after_validator_function
field_name
T aschema
field_name
aNoInfoValidatorFunction
no_info_after_validator_function
T aschema
T afunc
json_schema_input_type
aPydanticUndefined
generate_schema
before
with_info_before_validator_function
T aschema
field_name
json_schema_input_schema
no_info_before_validator_function
T aschema
json_schema_input_schema
info
T afunc
json_schema_input_type
upydantic.errors
aPydanticSchemaGenerationError
get
serialization
wrap_serializer_function_ser_schema
u<lambda>
uPlainValidator.__get_pydantic_core_schema__.<locals>.<lambda>
T afunction
schema
return_schema
plain
with_info_plain_validator_function
T afield_name
serialization
json_schema_input_schema
no_info_plain_validator_function
T aserialization
json_schema_input_schema
wrap
aWithInfoWrapValidatorFunction
with_info_wrap_validator_function
aNoInfoWrapValidatorFunction
no_info_wrap_validator_function
aFunctionType
aPydanticUserError
T u`@field_validator` should be used with fields and keyword arguments, not bare. E.g. usage should be `@validator('<field_name>', ...)`
uvalidator-no-fields
T acode
T abefore
plain
wrap
u`json_schema_input_type` can't be used when mode is set to

D acode
uvalidator-input-type
aAny
T u`@field_validator` fields should be passed as separate string args. E.g. usage should be `@validator('<field_name_1>', '<field_name_2>', ...)`
uvalidator-invalid-fields
D wfareturn
uCallable[..., Any] | staticmethod[Any, Any] | classmethod[Any, Any, Any]
u_decorators.PydanticDescriptorProxy[Any]
dec
ufield_validator.<locals>.dec
uUsage docs: https://docs.pydantic.dev/2.10/concepts/validators/#field-validators
Decorate methods on the class indicating that they should be used to validate fields.
Example usage:
```python
from typing import Any
from pydantic import (
BaseModel,
ValidationError,
field_validator,
)
class Model(BaseModel):
a: str
@field_validator('a')
@classmethod
def ensure_foobar(cls, v: Any):
if 'foobar' not in v:
raise ValueError('"foobar" not found in a')
return v
print(repr(Model(a='this is foobar good')))
#> Model(a='this is foobar good')
try:
Model(a='snap')
except ValidationError as exc_info:
print(exc_info)
'''
1 validation error for Model
a
def Value error, "foobar" not found in a [type=value_error, input_value='snap', input_type=str]
'''
```
For more in depth examples, see [Field Validators](../concepts/validators.md#field-validators).
Args:
field: The first field the `field_validator` should be called on; this is separate
from `fields` to ensure an error is raised if you don't pass at least one.
*fields: Additional field(s) the `field_validator` should be called on.
mode: Specifies whether to validate the fields before or after validation.
check_fields: Whether to check that the fields actually exist on the model.
json_schema_input_type: The input type of the function. This is only used to generate
the appropriate JSON Schema (in validation mode) and can only specified
when `mode` is either `'before'`, `'plain'` or `'wrap'`.
Returns:
A decorator that can be used to decorate a function to be used as a field_validator.
Raises:
PydanticUserError:
- If `@field_validator` is used bare (with no fields).
- If the args passed to `@field_validator` as fields are not strings.
- If `@field_validator` applied to instance methods.
u<genexpr>
ufield_validator.<locals>.<genexpr>
a_decorators
is_instance_method_from_sig
T u`@field_validator` cannot be applied to instance methods
uvalidator-instance-method
ensure_classmethod_based_on_signature
aFieldValidatorDecoratorInfo
fields
mode
check_fields
T afields
mode
check_fields
json_schema_input_type
aPydanticDescriptorProxy
D wfareturn
aAny
u_decorators.PydanticDescriptorProxy[Any]
umodel_validator.<locals>.dec
uUsage docs: https://docs.pydantic.dev/2.10/concepts/validators/#model-validators
Decorate model methods for validation purposes.
Example usage:
```python
from typing_extensions import Self
from pydantic import BaseModel, ValidationError, model_validator
class Square(BaseModel):
width: float
height: float
@model_validator(mode='after')
def verify_square(self) -> Self:
if self.width != self.height:
raise ValueError('width and height do not match')
return self
s = Square(width=1, height=1)
print(repr(s))
#> Square(width=1.0, height=1.0)
try:
Square(width=1, height=2)
except ValidationError as e:
print(e)
'''
1 validation error for Square
Value error, width and height do not match [type=value_error, input_value={'width': 1, 'height': 2}, input_type=dict]
'''
```
For more in depth examples, see [Model Validators](../concepts/validators.md#model-validators).
Args:
mode: A required string literal that specifies the validation mode.
It can be one of the following: 'wrap', 'before', or 'after'.
Returns:
A decorator that can be used to decorate a function to be used as a model validator.
aModelValidatorDecoratorInfo
T amode
aAnnotated
is_instance_schema
a_generics
get_origin
uInstanceOf.__get_pydantic_core_schema__.<locals>.<lambda>
T afunction
schema
json_or_python_schema
T apython_schema
json_schema
aSkipValidation
pydantic_js_annotation_functions
uSkipValidation.__get_pydantic_core_schema__.<locals>.<lambda>
any_schema
T ametadata
serialization
original_schema
uThis module contains related classes and functions for validation.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
a_annotations
dataclasses
sys
partialmethod
aTYPE_CHECKING
aCallable
aTypeVar
aUnion
overload
pydantic_core
core_schema
a_core_schema
typing_extensions
T aAnnotated
aLiteral
aSelf
aTypeAlias
aLiteral
aSelf
aTypeAlias
a_internal
T a_decorators
a_generics
a_internal_dataclass
a_internal_dataclass
upydantic.annotated_handlers
aGetCoreSchemaHandler
T aProtocol
aProtocol
inspect_validator
dataclass
D afrozen
taslots_true
