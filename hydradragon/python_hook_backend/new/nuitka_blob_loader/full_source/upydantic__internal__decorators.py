# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._decorators

uA container for data from `@validator` so that we can access it
while building the pydantic-core schema.
Attributes:
decorator_repr: A class variable representing the decorator string, '@validator'.
fields: A tuple of field names the validator should be called on.
mode: The proposed validator mode.
each_item: For complex objects (sets, lists etc.) whether to validate individual
elements rather than the whole object.
lways: Whether this method and other validators should be called even if the value is missing.
check_fields: Whether to check that the fields actually exist on the model.
a__qualname__
u@validator
decorator_repr
uClassVar[str]
utuple[str, ...]
uLiteral['before', 'after']
bool
each_item
always
ubool | None
check_fields
uA container for data from `@field_validator` so that we can access it
while building the pydantic-core schema.
Attributes:
decorator_repr: A class variable representing the decorator string, '@field_validator'.
fields: A tuple of field names the validator should be called on.
mode: The proposed validator mode.
check_fields: Whether to check that the fields actually exist on the model.
json_schema_input_type: The input type of the function. This is only used to generate
the appropriate JSON Schema (in validation mode) and can only specified
when `mode` is either `'before'`, `'plain'` or `'wrap'`.
u@field_validator
aFieldValidatorModes
json_schema_input_type
uA container for data from `@root_validator` so that we can access it
while building the pydantic-core schema.
Attributes:
decorator_repr: A class variable representing the decorator string, '@root_validator'.
mode: The proposed validator mode.
u@root_validator
uA container for data from `@field_serializer` so that we can access it
while building the pydantic-core schema.
Attributes:
decorator_repr: A class variable representing the decorator string, '@field_serializer'.
fields: A tuple of field names the serializer should be called on.
mode: The proposed serializer mode.
return_type: The type of the serializer's return value.
when_used: The serialization condition. Accepts a string with values `'always'`, `'unless-none'`, `'json'`,
nd `'json-unless-none'`.
check_fields: Whether to check that the fields actually exist on the model.
u@field_serializer
uLiteral['plain', 'wrap']
return_type
ucore_schema.WhenUsed
when_used
uA container for data from `@model_serializer` so that we can access it
while building the pydantic-core schema.
Attributes:
decorator_repr: A class variable representing the decorator string, '@model_serializer'.
mode: The proposed serializer mode.
return_type: The type of the serializer's return value.
when_used: The serialization condition. Accepts a string with values `'always'`, `'unless-none'`, `'json'`,
nd `'json-unless-none'`.
u@model_serializer
uA container for data from `@model_validator` so that we can access it
while building the pydantic-core schema.
Attributes:
decorator_repr: A class variable representing the decorator string, '@model_validator'.
mode: The proposed serializer mode.
u@model_validator
uLiteral['wrap', 'before', 'after']
uUnion[
ValidatorDecoratorInfo,
FieldValidatorDecoratorInfo,
RootValidatorDecoratorInfo,
FieldSerializerDecoratorInfo,
ModelSerializerDecoratorInfo,
ModelValidatorDecoratorInfo,
ComputedFieldInfo,
]
aDecoratorInfo
T aReturnType
aReturnType
uUnion[classmethod[Any, Any, ReturnType], staticmethod[Any, ReturnType], Callable[..., ReturnType], property]
aDecoratedType
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uWrap a classmethod, staticmethod, property or unbound function
nd act as a descriptor that allows us to detect decorated items
from the class' attributes.
This class' __get__ returns the wrapped item's __get__ result,
which makes it transparent for classmethods and staticmethods.
Attributes:
wrapped: The decorator that has to be wrapped.
decorator_info: The decorator info.
shim: A wrapper function to wrap V1 style function.
uDecoratedType[ReturnType]
uCallable[[Callable[..., Any]], Callable[..., Any]] | None
a__post_init__
uPydanticDescriptorProxy.__post_init__
D afunc
name
return
uCallable[[Any], None]
str
uPydanticDescriptorProxy[ReturnType]
uPydanticDescriptorProxy._call_wrapped_attr
T nD aobj
obj_type
return
uobject | None
utype[object] | None
uPydanticDescriptorProxy[ReturnType]
uPydanticDescriptorProxy.__get__
D ainstance
name
return
aAny
str
aNone
uPydanticDescriptorProxy.__set_name__
D a_PydanticDescriptorProxy__name
return
str
aAny
a__getattr__
uPydanticDescriptorProxy.__getattr__
T aDecoratorInfoType
T abound
aDecoratorInfoType
uA generic container class to join together the decorator metadata
(metadata from decorator itself, which we have when the
decorator is called but not when we are building the core-schema)
nd the bound function (which we have after the class itself is created).
Attributes:
cls_ref: The class ref.
cls_var_name: The decorated function name.
func: The decorated function.
shim: A wrapper function to wrap V1 style function.
info: The decorator info.
str
cls_ref
uCallable[..., Any]
uCallable[[Any], Any] | None
staticmethod
D acls_
cls_var_name
shim
info
return
aAny
str
uCallable[[Any], Any] | None
aDecoratorInfoType
uDecorator[DecoratorInfoType]
uDecorator.build
D acls
return
aAny
uDecorator[DecoratorInfoType]
uDecorator.bind_to_cls
D atp
return
utype[Any]
utuple[type[Any], ...]
D abases
return
utuple[type[Any], ...]
utuple[type[Any], ...]
D atp
name
return
utype[Any] | tuple[type[Any], ...]
str
aAny
D atp
name
return
utype[Any]
str
aAny
uMapping of name in the class namespace to decorator info.
note that the name in the class namespace is the function or attribute name
not the field name!
T Odict
T adefault_factory
udict[str, Decorator[ValidatorDecoratorInfo]]
udict[str, Decorator[FieldValidatorDecoratorInfo]]
udict[str, Decorator[RootValidatorDecoratorInfo]]
udict[str, Decorator[FieldSerializerDecoratorInfo]]
udict[str, Decorator[ModelSerializerDecoratorInfo]]
udict[str, Decorator[ModelValidatorDecoratorInfo]]
udict[str, Decorator[ComputedFieldInfo]]
D amodel_dc
return
utype[Any]
aDecoratorInfos
uDecoratorInfos.build
D avalidator
mode
return
uCallable[..., Any]
aFieldValidatorModes
bool
inspect_validator
D aserializer
mode
return
uCallable[..., Any]
uLiteral['plain', 'wrap']
utuple[bool, bool]
inspect_field_serializer
D aserializer
mode
return
uCallable[..., Any]
uLiteral['plain', 'wrap']
bool
inspect_annotated_serializer
inspect_model_serializer
D amode
n_positional
return
uLiteral['plain', 'wrap']
int
ubool | None
uUnion[classmethod[Any, Any, Any], staticmethod[Any, Any], partialmethod[Any], Callable[..., Any]]
aAnyDecoratorCallable
D afunction
return
aAnyDecoratorCallable
bool
D afunction
return
aAnyDecoratorCallable
aAny
ensure_classmethod_based_on_signature
D aunwrap_partial
unwrap_class_static_method
tpD afunc
unwrap_partial
unwrap_class_static_method
return
aAny
bool
paAny
T nnD afunc
explicit_return_type
globalns
localns
return
aAny
puGlobalsNamespace | None
uMappingNamespace | None
aAny
get_function_return_type
D asig
return
aSignature
int
D wfareturn
aAny
paensure_property
upydantic\_internal\_decorators.py
T a.0
param
parameters
u<module pydantic._internal._decorators>
T a__class__
T aself
obj
obj_type
T aself
a_PydanticDescriptorProxy__name
T aself
attr
wfT aself
instance
name
T aself
func
name
aComputedFieldInfo
T afunction
sig
first
T amode
n_positional
T aself
cls
T acls_
cls_var_name
shim
info
func
attribute
Tamodel_dc
existing
to_replace
res
base
var_name
var_value
info
field_serializer_decorator
wfaComputedFieldInfo
name
value
T asig
parameters
T afunction
T wfT atp
name
base
T atp
name
base
attribute
attribute_get
T atp
T afunc
explicit_return_type
globalns
localns
hints
T aserializer
mode
sig
info_arg
T aserializer
mode
sig
first
is_field_serializer
n_positional
info_arg
T avalidator
mode
sig
n_positional
T aseqs
candidate
non_empty
seq
not_head
T atp
bases
T abases
merge_seqs
seqs
T afunc
unwrap_partial
unwrap_class_static_method
unwrap_types
a__spec__
.pydantic._internal._discriminated_union
(
ref
a__class__
a__init__
uMissing definition for ref

setdefault
metadata
get
T ametadata
aCORE_SCHEMA_METADATA_DISCRIMINATOR_PLACEHOLDER_KEY
collect_definitions
D wsarecurse
return
ucore_schema.CoreSchema
u_core_utils.Recurse
ucore_schema.CoreSchema
inner
uapply_discriminators.<locals>.inner
a_core_utils
walk_core_schema
D acopy
Fatype
utagged-union
pop
apply_discriminator
global_definitions
wsupydantic.types
aDiscriminator
discriminator
a_convert_schema
a_ApplyInferredDiscriminator
apply
uApplies the discriminator and returns a new core schema.
Args:
schema: The input schema.
discriminator: The name of the field which will serve as the discriminator.
definitions: A mapping of schema ref to schema.
Returns:
The new core schema.
Raises:
TypeError:
- If `discriminator` is used with invalid union variant.
- If `discriminator` is used with `Union` type with one variant.
- If `discriminator` value mapped to multiple choices.
MissingDefinitionForUnionRef:
If the definition for ref is missing.
PydanticUserError:
- If a model in union doesn't have a discriminator field.
- If discriminator field has a non-string alias.
- If discriminator fields have different aliases.
- If discriminator field not of type `Literal`.
definitions
a_discriminator_alias
a_should_be_nullable
a_is_nullable
a_choices_to_handle
a_tagged_union_choices
a_used
a_apply_to_root
upydantic_core.core_schema
nullable_schema
uReturn a new CoreSchema based on `schema` that uses a tagged-union with the discriminator provided
to this class.
Args:
schema: The input schema.
Returns:
The new core schema.
Raises:
TypeError:
- If `discriminator` is used with invalid union variant.
- If `discriminator` is used with `Union` type with one variant.
- If `discriminator` value mapped to multiple choices.
ValueError:
If the definition for ref is missing.
PydanticUserError:
- If a model in union doesn't have a discriminator field.
- If discriminator field has a non-string alias.
- If discriminator fields have different aliases.
- If discriminator field not of type `Literal`.
nullable
schema
copy
union
union_schema
choices
:nnq aextend
self
a_handle_choice
tagged_union_schema
T acustom_error_type
T acustom_error_message
T acustom_error_context
T aref
T aserialization
T
choices
discriminator
custom_error_type
custom_error_message
custom_error_context
strict
from_attributes
ref
metadata
serialization
uThis method handles the outer-most stage of recursion over the input schema:
unwrapping nullable or definitions schemas, and calling the `_handle_choice`
method iteratively on the choices extracted (recursively) from the possibly-wrapped union.
udefinition-ref
schema_ref
aMissingDefinitionForUnionRef
none
P udefinition-ref
udataclass-args
utyped-dict
model
ulax-or-strict
utagged-union
dataclass
is_function_with_inner_schema
u is not a valid discriminated union variant; should be a `BaseModel` or `dataclass`
a_is_discriminator_shared
values
T Ostr
Oint
a_infer_discriminator_values_for_choice
D asource_name
na_set_unique_choice_for_values
uThis method handles the "middle" stage of recursion over the input schema.
Specifically, it is responsible for handling each choice of the outermost union
(and any "coalesced" choices obtained from inner unions).
Here, "handling" entails:
* Coalescing nested unions and compatible tagged-unions
* Tracking the presence of 'none' and 'nullable' schemas occurring as choices
* Validating that each allowed discriminator value maps to a unique choice
* Updating the _tagged_union_choices mapping that will ultimately be used to build the TaggedUnionSchema.
uThis method returns a boolean indicating whether the discriminator for the `choice`
is the same as that being used for the outermost tagged union. This is used to
determine whether this TaggedUnionSchema choice should be "coalesced" into the top level,
or whether it should be treated as a separate (nested) choice.
T asource_name
ufunction-plain
ulax-or-strict
sorted
lax_schema
strict_schema
model
cls
a__name__
dataclass
umodel-fields
a_infer_discriminator_values_for_model_choice
udataclass-args
a_infer_discriminator_values_for_dataclass_choice
utyped-dict
a_infer_discriminator_values_for_typed_dict_choice
uThis function recurses over `choice`, extracting all discriminator values that should map to this choice.
`model_name` is accepted for the purpose of producing useful error messages.
aTypedDict
uTypedDict
fields
aPydanticUserError
u needs a discriminator field for key
D acode
udiscriminator-no-field
a_infer_discriminator_values_for_field
uThis method just extracts the _infer_discriminator_values_for_choice logic specific to TypedDictSchema
for the sake of readability.
aModelFields
uModel
aDataclassArgs
uDataclass
name
field
ucomputed-field
validation_alias
uAlias
u is not supported in a discriminated union
D acode
udiscriminator-alias-type
uAliases for discriminator
u must be the same (got
u,
w)D acode
udiscriminator-alias
a_infer_discriminator_values_for_inner_schema
literal
expected
source
default
ufunction-after
P ufunction-before
ufunction-plain
ufunction-wrap
split
T w-uCannot use a mode=
u validator in the discriminator field
u of
D acode
udiscriminator-validator
u needs field
u to be of type `Literal`
D acode
udiscriminator-needs-literal
uWhen inferring discriminator values for a field, we typically extract the expected values from a literal
schema. This function does that, but also handles nested unions and defaults.
choice
uValue
u for discriminator
u mapped to multiple choices
uThis method updates `self.tagged_union_choices` so that all provided (discriminator) `values` map to the
provided `choice`, validating that none of these values already map to another (different) choice.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
a_annotations
aTYPE_CHECKING
aAny
aHashable
aSequence
pydantic_core
aCoreSchema
core_schema
upydantic.errors
T a_core_utils
T aCoreSchemaField
collect_definitions
aCoreSchemaField
upydantic.internal.union_discriminator
T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
