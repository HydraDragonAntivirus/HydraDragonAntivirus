# Reconstructed from integrated Nuitka blob
# Module: upydantic.plugin

uPath defining where `schema_type` was defined, or where `TypeAdapter` was called.
a__qualname__
str
module
name
a__orig_bases__
T aBaseModel
aTypeAdapter
dataclass
create_model
validate_call
aSchemaKind
aPydanticPluginProtocol
uProtocol defining the interface for Pydantic plugins.
D aschema
schema_type
schema_type_path
schema_kind
config
plugin_settings
return
aCoreSchema
aAny
aSchemaTypePath
aSchemaKind
uCoreConfig | None
udict[str, object]
utuple[ValidatePythonHandlerProtocol | None, ValidateJsonHandlerProtocol | None, ValidateStringsHandlerProtocol | None]
new_schema_validator
uPydanticPluginProtocol.new_schema_validator
aBaseValidateHandlerProtocol
uBase class for plugin callbacks protocols.
You shouldn't implement this protocol directly, instead use one of the subclasses with adds the correctly
typed `on_error` method.
uCallable[..., None]
on_enter
D aresult
return
aAny
aNone
uCallback to be notified of successful validation.
Args:
result: The result of the validation.
on_success
uBaseValidateHandlerProtocol.on_success
D aerror
return
aValidationError
aNone
uCallback to be notified of validation errors.
Args:
error: The validation error.
on_error
uBaseValidateHandlerProtocol.on_error
D aexception
return
aException
aNone
uCallback to be notified of validation exceptions.
Args:
exception: The exception raised during validation.
on_exception
uBaseValidateHandlerProtocol.on_exception
aValidatePythonHandlerProtocol
uEvent handler for `SchemaValidator.validate_python`.
D astrict
from_attributes
context
self_instance
nnnnD ainput
strict
from_attributes
context
self_instance
return
aAny
ubool | None
ubool | None
udict[str, Any] | None
uAny | None
aNone
uCallback to be notified of validation start, and create an instance of the event handler.
Args:
input: The input to be validated.
strict: Whether to validate the object in strict mode.
from_attributes: Whether to validate objects as inputs by extracting attributes.
context: The context to use for validation, this is passed to functional validators.
self_instance: An instance of a model to set attributes on from validation, this is used when running
validation from the `__init__` method of a model.
uValidatePythonHandlerProtocol.on_enter
aValidateJsonHandlerProtocol
uEvent handler for `SchemaValidator.validate_json`.
D astrict
context
self_instance
nnnD ainput
strict
context
self_instance
return
ustr | bytes | bytearray
ubool | None
udict[str, Any] | None
uAny | None
aNone
uCallback to be notified of validation start, and create an instance of the event handler.
Args:
input: The JSON data to be validated.
strict: Whether to validate the object in strict mode.
context: The context to use for validation, this is passed to functional validators.
self_instance: An instance of a model to set attributes on from validation, this is used when running
validation from the `__init__` method of a model.
uValidateJsonHandlerProtocol.on_enter
udict[str, StringInput]
aStringInput
aValidateStringsHandlerProtocol
uEvent handler for `SchemaValidator.validate_strings`.
D astrict
context
nnD ainput
strict
context
return
aStringInput
ubool | None
udict[str, Any] | None
aNone
uCallback to be notified of validation start, and create an instance of the event handler.
Args:
input: The string data to be validated.
strict: Whether to validate the object in strict mode.
context: The context to use for validation, this is passed to functional validators.
uValidateStringsHandlerProtocol.on_enter
upydantic\plugin\__init__.py
u<module pydantic.plugin>
T a__class__
T aself
schema
schema_type
schema_type_path
schema_kind
config
plugin_settings
T aself
input
strict
context
self_instance
T aself
input
strict
from_attributes
context
self_instance
T aself
input
strict
context
T aself
error
T aself
exception
T aself
result

a__spec__
.pydantic.root_model
v
model_config
get
T aextra
aPydanticUserError
T u`RootModel` does not support setting `model_config['extra']`
uroot-model-extra
T acode
a__class__
a__init_subclass__
aPydanticUndefined
u"RootModel.__init__" accepts either a single positional argument or arbitrary keyword arguments
a__pydantic_validator__
validate_python
T aself_instance
model_construct
T aroot
a_fields_set
uCreate a new model using the provided root object and update fields set.
Args:
root: The root object of the model.
_fields_set: The set of fields to be updated.
Returns:
The new model.
Raises:
NotImplemented: If the model is not a subclass of `RootModel`.
a__dict__
a__pydantic_fields_set__
a_object_setattr
a__new__
copy
uReturns a shallow copy of the model.
deepcopy
T amemo
uReturns a deep copy of the model.
aRootModel
a__pydantic_fields__
root
annotation
a__eq__
self
a__repr_args__
uRootModel.__repr_args__
uRootModel class and type definitions.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
a_annotations
typing
T acopy
deepcopy
pydantic_core

T aPydanticUserError
a_internal
T a_model_construction
a_repr
a_model_construction
a_repr
upydantic.main
aBaseModel
aModelMetaclass
a_RootModelMetaclass
T aRootModel
a__all__
aTypeVar
T aRootModelRootType
aRootModelRootType
aGeneric
metaclass
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
