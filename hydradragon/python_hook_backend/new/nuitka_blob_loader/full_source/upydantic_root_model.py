# Reconstructed from integrated Nuitka blob
# Module: upydantic.root_model

uUsage docs: https://docs.pydantic.dev/2.10/concepts/models/#rootmodel-and-custom-root-types
A Pydantic `BaseModel` for the root object of the model.
Attributes:
root: The root object of the model.
__pydantic_root_model__: Whether the model is a RootModel.
__pydantic_private__: Private fields in the model.
__pydantic_extra__: Extra fields in the model.
a__qualname__
a__annotations__
a__pydantic_root_model__
a__pydantic_private__
a__pydantic_extra__
uRootModel.__init_subclass__
D aroot
return
aRootModelRootType
aNone
a__init__
uRootModel.__init__
a__pydantic_base_init__
classmethod
T nD aroot
a_fields_set
return
aRootModelRootType
uset[str] | None
aSelf
uRootModel.model_construct
D areturn
udict[Any, Any]
a__getstate__
uRootModel.__getstate__
D astate
return
udict[Any, Any]
aNone
a__setstate__
uRootModel.__setstate__
D areturn
aSelf
a__copy__
uRootModel.__copy__
D amemo
return
udict[int, Any] | None
aSelf
a__deepcopy__
uRootModel.__deepcopy__
aTYPE_CHECKING
D amode
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
python
nnnFpppptFD amode
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
return
uLiteral['json', 'python'] | str
aAny
pudict[str, Any] | None
bool
ppppubool | Literal['none', 'warn', 'error']
bool
aAny
uThis method is included just to get a more accurate return type for type checkers.
It is included in this `if TYPE_CHECKING:` block since no override is actually necessary.
See the documentation of `BaseModel.model_dump` for more details about the arguments.
Generally, this method will have a return type of `RootModelRootType`, assuming that `RootModelRootType` is
not a `BaseModel` subclass. If `RootModelRootType` is a `BaseModel` subclass, then the return
type will likely be `dict[str, Any]`, as `model_dump` calls are recursive. The return type could
even be something different, in the case of a custom serializer.
Thus, `Any` is used here to catch all of these cases.
model_dump
uRootModel.model_dump
D aother
return
aAny
bool
uRootModel.__eq__
D areturn
u_repr.ReprArgs
a__orig_bases__
upydantic\root_model.py
u<module pydantic.root_model>
T a__class__
T aself
cls
wmT aself
memo
cls
wmT aself
other
a__class__
T aself
T aself
root
data
a__tracebackhide__
T acls
kwargs
extra
a__class__
T aself
state
T acls
root
a_fields_set
a__class__
T aself
mode
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
a__spec__
.pydantic.schema
uThe `schema` module is a backport module from V1.
a__doc__
a__file__
origin
has_location
a__cached__
a_migration
T agetattr_migration
getattr_migration
T upydantic.schema
a__getattr__
upydantic\schema.py
u<module pydantic.schema>

a__spec__
.pydantic.type_adapter
S
a__dict__
a__slots__
uReturns the attribute value without attempting to look up attributes from parent types.
a_typing_extra
annotated_type
aBaseModel
is_dataclass
is_typeddict
uReturns whether the type has config.
a_type_has_config
aPydanticUserError
T uCannot use `config` when the type is a BaseModel, dataclass or TypedDict. These types can have their own config and setting the config via the `config` parameter to TypeAdapter will not override it, thus the `config` you passed to TypeAdapter becomes meaningless, which is probably not what you want.
utype-adapter-config-unused
T acode
a_type
a_config
a_parent_depth
pydantic_complete
a_fetch_parent_frame
f_globals
f_locals
cast
get
T a__name__

a_module_name
a_init_core_attrs
a_namespace_utils
aNsResolver
aNamespacesTuple
T alocals
globals
T anamespaces_tuple
parent_namespace
T ans_resolver
force
a_getframe
T a__name__
typing
f_back
a_defer_build
a_mock_val_ser
set_type_adapter_mocks
a_getattr_no_parents
a__pydantic_core_schema__
core_schema
a__pydantic_validator__
validator
a__pydantic_serializer__
serializer
aMockCoreSchema
aMockValSer
aConfigWrapper
a_generate_schema
aGenerateSchema
T ans_resolver
generate_schema
aPydanticUndefinedAnnotation
clean_schema
aCollectedInvalid
core_config
T nacreate_schema_validator
aTypeAdapter
plugin_settings
T aschema
schema_type
schema_type_module
schema_type_name
schema_kind
config
plugin_settings
aSchemaSerializer
uInitialize the core schema, validator, and serializer for the type.
Args:
ns_resolver: The namespace resolver to use when building the core schema for the adapted type.
force: Whether to force the construction of the core schema, validator, and serializer.
If `force` is set to `False` and `_defer_build` is `True`, the core schema, validator, and serializer will be set to mocks.
raise_errors: Whether to raise errors if initializing any of the core attrs fails.
Returns:
`True` if the core schema, validator, and serializer were successfully initialized, otherwise `False`.
Raises:
PydanticUndefinedAnnotation: If `PydanticUndefinedAnnotation` occurs in`__get_pydantic_core_schema__`
nd `raise_errors=True`.
a_model_config
T adefer_build
a_utils
lenient_issubclass
model_config
a__pydantic_config__
uTypeAdapter(
a_repr
display_as_type

w)aparent_frame_namespace
T aparent_depth
force
max
T ans_resolver
force
raise_errors
uTry to rebuild the pydantic-core schema for the adapter's type.
This may be necessary when one of the annotations is a ForwardRef which could not be resolved during
the initial attempt to build the schema, and automatic rebuilding fails.
Args:
force: Whether to force the rebuilding of the type adapter's schema, defaults to `False`.
raise_errors: Whether to raise errors, defaults to `True`.
_parent_namespace_depth: Depth at which to search for the [parent frame][frame-objects]. This
frame is used when resolving forward annotations during schema rebuilding, by looking for
the locals of this frame. Defaults to 2, which will result in the frame where the method
was called.
_types_namespace: An explicit types namespace to use, instead of using the local namespace
from the parent frame. Defaults to `None`.
Returns:
Returns `None` if the schema is already "complete" and rebuilding was not required.
If rebuilding _was_ required, returns `True` if rebuilding was successful, otherwise `False`.
validate_python
T astrict
from_attributes
context
allow_partial
uValidate a Python object against the model.
Args:
object: The Python object to validate against the model.
strict: Whether to strictly check types.
from_attributes: Whether to extract data from object attributes.
context: Additional context to pass to the validator.
experimental_allow_partial: **Experimental** whether to enable
[partial validation](../concepts/experimental.md#partial-validation), e.g. to process streams.
* False / 'off': Default behavior, no partial validation.
* True / 'on': Enable partial validation.
* 'trailing-strings': Enable partial validation and allow trailing strings in the input.
!!! note
When using `TypeAdapter` with a Pydantic `dataclass`, the use of the `from_attributes`
rgument is not supported.
Returns:
The validated object.
validate_json
T astrict
context
allow_partial
uUsage docs: https://docs.pydantic.dev/2.10/concepts/json/#json-parsing
Validate a JSON string or bytes against the model.
Args:
data: The JSON data to validate against the model.
strict: Whether to strictly check types.
context: Additional context to use during validation.
experimental_allow_partial: **Experimental** whether to enable
[partial validation](../concepts/experimental.md#partial-validation), e.g. to process streams.
* False / 'off': Default behavior, no partial validation.
* True / 'on': Enable partial validation.
* 'trailing-strings': Enable partial validation and allow trailing strings in the input.
Returns:
The validated object.
validate_strings
uValidate object contains string data against the model.
Args:
obj: The object contains string data to validate.
strict: Whether to strictly check types.
context: Additional context to use during validation.
experimental_allow_partial: **Experimental** whether to enable
[partial validation](../concepts/experimental.md#partial-validation), e.g. to process streams.
* False / 'off': Default behavior, no partial validation.
* True / 'on': Enable partial validation.
* 'trailing-strings': Enable partial validation and allow trailing strings in the input.
Returns:
The validated object.
get_default_value
T astrict
context
uGet the default value for the wrapped type.
Args:
strict: Whether to strictly check types.
context: Additional context to pass to the validator.
Returns:
The default value wrapped in a `Some` if there is one or None if not.
to_python
T amode
by_alias
include
exclude
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
context
uDump an instance of the adapted type to a Python object.
Args:
instance: The Python object to serialize.
mode: The output format.
include: Fields to include in the output.
exclude: Fields to exclude from the output.
by_alias: Whether to use alias names for field names.
exclude_unset: Whether to exclude unset fields.
exclude_defaults: Whether to exclude fields with default values.
exclude_none: Whether to exclude fields with None values.
round_trip: Whether to output the serialized data in a way that is compatible with deserialization.
warnings: How to handle serialization errors. False/"none" ignores them, True/"warn" logs errors,
"error" raises a [`PydanticSerializationError`][pydantic_core.PydanticSerializationError].
serialize_as_any: Whether to serialize fields with duck-typing serialization behavior.
context: Additional context to pass to the serializer.
Returns:
The serialized object.
to_json
T aindent
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
context
uUsage docs: https://docs.pydantic.dev/2.10/concepts/json/#json-serialization
Serialize an instance of the adapted type to JSON.
Args:
instance: The instance to be serialized.
indent: Number of spaces for JSON indentation.
include: Fields to include.
exclude: Fields to exclude.
by_alias: Whether to use alias names for field names.
exclude_unset: Whether to exclude unset fields.
exclude_defaults: Whether to exclude fields with default values.
exclude_none: Whether to exclude fields with a value of `None`.
round_trip: Whether to serialize and deserialize the instance to ensure round-tripping.
warnings: How to handle serialization errors. False/"none" ignores them, True/"warn" logs errors,
"error" raises a [`PydanticSerializationError`][pydantic_core.PydanticSerializationError].
serialize_as_any: Whether to serialize fields with duck-typing serialization behavior.
context: Additional context to pass to the serializer.
Returns:
The JSON representation of the given instance as bytes.
T aby_alias
ref_template
rebuild
T uthis is a bug! please report it
generate
T amode
uGenerate a JSON schema for the adapted type.
Args:
by_alias: Whether to use alias names for field names.
ref_template: The format string used for generating $ref strings.
schema_generator: The generator class used for creating the schema.
mode: The mode to use for schema generation.
Returns:
The JSON schema for the model as a dictionary.
inputs_
generate_definitions
u$defs
title
description
uGenerate a JSON schema including definitions from multiple type adapters.
Args:
inputs: Inputs to schema generation. The first two items will form the keys of the (first)
output mapping; the type adapters will provide the core schemas that get converted into
definitions in the output JSON schema.
by_alias: Whether to use alias names.
title: The title for the schema.
description: The description for the schema.
ref_template: The format string used for generating $ref strings.
schema_generator: The generator class used for creating the schema.
Returns:
A tuple where:
- The first element is a dictionary whose keys are tuples of JSON schema key type and JSON mode, and
whose values are the JSON schema corresponding to that pair of inputs. (These schemas may have
JsonRef references to definitions that are defined in the second returned element.)
- The second element is a JSON schema containing all definitions referenced in the first returned
element, along with the optional title and description keys.
uType adapter specification.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
a_annotations
sys
dataclasses
T ais_dataclass
aFrameType
aAny
aGeneric
aIterable
aLiteral
aTypeVar
final
overload
pydantic_core
aCoreSchema
aSchemaValidator
aSome
typing_extensions
T aParamSpec
is_typeddict
aParamSpec
upydantic.errors
upydantic.main
aIncEx
a_internal
T a_config
a_generate_schema
a_mock_val_ser
a_namespace_utils
a_repr
a_typing_extra
a_utils
upydantic.config
aConfigDict
upydantic.json_schema
aDEFAULT_REF_TEMPLATE
aGenerateJsonSchema
aJsonSchemaKeyT
aJsonSchemaMode
aJsonSchemaValue
uplugin._schema_validator
T aPluggableSchemaValidator
create_schema_validator
aPluggableSchemaValidator
T wTwTT wRwRT wPwPT aTypeAdapterT
aTypeAdapter
T abound
aTypeAdapterT
D aobj
attribute
return
aAny
str
aAny
D atype_
return
aAny
bool
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
