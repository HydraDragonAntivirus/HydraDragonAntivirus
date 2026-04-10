# Reconstructed from integrated Nuitka blob
# Module: a__annotations__

a__doc__
config_dict
resolve_bases
prepare_class
T akwds
a__orig_bases__
a__pydantic_reset_parent_namespace__
a_create_model_module
uUsage docs: https://docs.pydantic.dev/2.10/concepts/models/#dynamic-model-creation
Dynamically creates and returns a new Pydantic model, in other words, `create_model` dynamically creates a
subclass of [`BaseModel`][pydantic.BaseModel].
Args:
model_name: The name of the newly created model.
__config__: The configuration of the new model.
__doc__: The docstring of the new model.
__base__: The base class or classes for the new model.
__module__: The name of the module that the model belongs to;
if `None`, the value is taken from `sys._getframe(1)`
__validators__: A dictionary of methods that validate fields. The keys are the names of the validation methods to
be added to the model, and the values are the validation methods themselves. You can read more about functional
validators [here](https://docs.pydantic.dev/2.9/concepts/validators/#field-validators).
__cls_kwargs__: A dictionary of keyword arguments for class creation, such as `metaclass`.
__slots__: Deprecated. Should not be passed to `create_model`.
**field_definitions: Attributes of the new model. They should be passed in the format:
`<name>=(<type>, <default value>)`, `<name>=(<type>, <FieldInfo>)`, or `typing.Annotated[<type>, <FieldInfo>]`.
Any additional metadata in `typing.Annotated[<type>, <FieldInfo>, ...]` will be ignored.
Note, `FieldInfo` instances should be created via `pydantic.Field(...)`.
Initializing `FieldInfo` instances directly is not supported.
Returns:
The new [model][pydantic.BaseModel].
Raises:
PydanticUserError: If `__base__` and `__config__` are both passed.
uLogic for creating models.
a__file__
has_location
a__cached__
a_annotations
sys
types
typing
T acopy
deepcopy
aTYPE_CHECKING
aAny
aCallable
aClassVar
aDict
aGenerator
aLiteral
aMapping
aSet
aTuple
aTypeVar
aUnion
overload
T aSelf
aTypeAlias
aUnpack
aSelf
aTypeAlias
aUnpack
a_internal
T a_config
a_decorators
a_fields
a_forward_ref
a_generics
a_import_utils
a_mock_val_ser
a_model_construction
a_namespace_utils
a_repr
a_typing_extra
a_utils
a_decorators
a_forward_ref
a_migration
T agetattr_migration
getattr_migration
upydantic.aliases
upydantic.annotated_handlers
aGetCoreSchemaHandler
aGetJsonSchemaHandler
upydantic.config
aConfigDict
upydantic.errors
upydantic.json_schema
aDEFAULT_REF_TEMPLATE
aGenerateJsonSchema
aJsonSchemaMode
aJsonSchemaValue
uplugin._schema_validator
T aPluggableSchemaValidator
aPluggableSchemaValidator
upydantic.warnings
aDeprecationWarning
T aBaseModel
create_model
a__all__
aTupleGenerator
T aIncEx
Obool
aIncEx
object_setattr
metaclass
aModelMetaclass
a__prepare__
T aBaseModel
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
upydantic.main
uUsage docs: https://docs.pydantic.dev/2.10/concepts/models/
A base class for creating Pydantic models.
Attributes:
__class_vars__: The names of the class variables defined on the model.
__private_attributes__: Metadata about the private attributes of the model.
__signature__: The synthesized `__init__` [`Signature`][inspect.Signature] of the model.
__pydantic_complete__: Whether model building is completed, or if there are still undefined fields.
__pydantic_core_schema__: The core schema of the model.
__pydantic_custom_init__: Whether the model has a custom `__init__` function.
__pydantic_decorators__: Metadata containing the decorators defined on the model.
This replaces `Model.__validators__` and `Model.__root_validators__` from Pydantic V1.
__pydantic_generic_metadata__: Metadata for generic models; contains data used for a similar purpose to
__args__, __origin__, __parameters__ in typing-module generics. May eventually be replaced by these.
__pydantic_parent_namespace__: Parent namespace of the model, used for automatic rebuilding of models.
__pydantic_post_init__: The name of the post-init method for the model, if defined.
__pydantic_root_model__: Whether the model is a [`RootModel`][pydantic.root_model.RootModel].
__pydantic_serializer__: The `pydantic-core` `SchemaSerializer` used to dump instances of the model.
__pydantic_validator__: The `pydantic-core` `SchemaValidator` used to validate instances of the model.
__pydantic_fields__: A dictionary of field names and their corresponding [`FieldInfo`][pydantic.fields.FieldInfo] objects.
__pydantic_computed_fields__: A dictionary of computed field names and their corresponding [`ComputedFieldInfo`][pydantic.fields.ComputedFieldInfo] objects.
__pydantic_extra__: A dictionary containing extra values, if [`extra`][pydantic.config.ConfigDict.extra]
is set to `'allow'`.
__pydantic_fields_set__: The names of fields explicitly set during instantiation.
__pydantic_private__: Values of private attributes set on the model instance.
a__qualname__
uClassVar[ConfigDict]
uClassVar[set[str]]
uClassVar[Dict[str, ModelPrivateAttr]]
uClassVar[Signature]
a__signature__
uClassVar[bool]
uClassVar[CoreSchema]
a__pydantic_custom_init__
aDecoratorInfos
a__pydantic_decorators__
uClassVar[_decorators.DecoratorInfos]
uClassVar[_generics.PydanticGenericMetadata]
uClassVar[Dict[str, Any] | None]
uClassVar[None | Literal['model_post_init']]
uClassVar[SchemaSerializer]
uClassVar[SchemaValidator | PluggableSchemaValidator]
uClassVar[Dict[str, FieldInfo]]
uClassVar[Dict[str, ComputedFieldInfo]]
aNoInitField
T FT ainit
udict[str, Any] | None
uset[str]
T uPydantic models should inherit from BaseModel, BaseModel cannot be instantiated directly
ubase-model-instantiated
aMockValSer
T uPydantic models should inherit from BaseModel, BaseModel cannot be instantiated directly
validator
ubase-model-instantiated
T aval_or_ser
code
T uPydantic models should inherit from BaseModel, BaseModel cannot be instantiated directly
serializer
ubase-model-instantiated
T a__dict__
a__pydantic_fields_set__
a__pydantic_extra__
a__pydantic_private__
a__slots__
D adata
return
aAny
aNone
a__init__
uBaseModel.__init__
a__pydantic_base_init__
uClassVar[dict[str, FieldInfo]]
uClassVar[dict[str, ComputedFieldInfo]]
model_computed_fields
property
D areturn
udict[str, FieldInfo]
uBaseModel.model_fields
D areturn
udict[str, ComputedFieldInfo]
uBaseModel.model_computed_fields
D areturn
udict[str, Any] | None
uBaseModel.model_extra
D areturn
uset[str]
model_fields_set
uBaseModel.model_fields_set
classmethod
D a_fields_set
values
return
uset[str] | None
aAny
aSelf
uBaseModel.model_construct
D aupdate
deep
nFD aupdate
deep
return
uMapping[str, Any] | None
bool
aSelf
uBaseModel.model_copy
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
uIncEx | None
uIncEx | None
uAny | None
bool
ppppubool | Literal['none', 'warn', 'error']
bool
udict[str, Any]
uBaseModel.model_dump
D aindent
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
nnnnFpppptFD aindent
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
uint | None
uIncEx | None
uIncEx | None
uAny | None
bool
ppppubool | Literal['none', 'warn', 'error']
bool
str
uBaseModel.model_dump_json
validation
D aby_alias
ref_template
schema_generator
mode
return
bool
str
utype[GenerateJsonSchema]
aJsonSchemaMode
udict[str, Any]
uBaseModel.model_json_schema
D aparams
return
utuple[type[Any], ...]
str
uBaseModel.model_parametrized_name
D a_BaseModel__context
return
aAny
aNone
uOverride this method to perform additional initialization after `__init__` and `model_construct`.
This is useful if you want to do some validation that requires the entire model to be initialized.
uBaseModel.model_post_init
D aforce
raise_errors
a_parent_namespace_depth
a_types_namespace
Ftl nD aforce
raise_errors
a_parent_namespace_depth
a_types_namespace
return
bool
paint
uMappingNamespace | None
ubool | None
uBaseModel.model_rebuild
D astrict
from_attributes
context
nnnD aobj
strict
from_attributes
context
return
aAny
ubool | None
ubool | None
uAny | None
aSelf
uBaseModel.model_validate
D astrict
context
nnD ajson_data
strict
context
return
ustr | bytes | bytearray
ubool | None
uAny | None
aSelf
model_validate_json
uBaseModel.model_validate_json
D aobj
strict
context
return
aAny
ubool | None
uAny | None
aSelf
model_validate_strings
uBaseModel.model_validate_strings
D asource
handler
return
utype[BaseModel]
aGetCoreSchemaHandler
aCoreSchema
a__get_pydantic_core_schema__
uBaseModel.__get_pydantic_core_schema__
D acore_schema
handler
return
aCoreSchema
aGetJsonSchemaHandler
aJsonSchemaValue
a__get_pydantic_json_schema__
uBaseModel.__get_pydantic_json_schema__
D akwargs
return
aAny
aNone
uThis is intended to behave just like `__init_subclass__`, but is called by `ModelMetaclass`
only after the class is actually fully initialized. In particular, attributes like `model_fields` will
be present when this is called.
This is necessary because `__init_subclass__` will always be called by `type.__new__`,
nd it would require a prohibitively large refactor to the `ModelMetaclass` to ensure that
`type.__new__` was called in such a manner that the class would already be sufficiently initialized.
This will receive the same `kwargs` that would be passed to the standard `__init_subclass__`, namely,
ny kwargs passed to the class definition that aren't used internally by pydantic.
Args:
**kwargs: Any keyword arguments passed to the class definition that aren't used internally
by pydantic.
a__pydantic_init_subclass__
uBaseModel.__pydantic_init_subclass__
D atypevar_values
return
utype[Any] | tuple[type[Any], ...]
utype[BaseModel] | _forward_ref.PydanticRecursiveRef
a__class_getitem__
uBaseModel.__class_getitem__
D areturn
aSelf
uBaseModel.__copy__
D amemo
return
udict[int, Any] | None
aSelf
uBaseModel.__deepcopy__
D aitem
return
str
aAny
a__getattr__
uBaseModel.__getattr__
D aname
value
return
str
aAny
aNone
a__setattr__
uBaseModel.__setattr__
uBaseModel.__delattr__
D achanges
return
aAny
aSelf
a__replace__
uBaseModel.__replace__
uBaseModel._check_frozen
D areturn
udict[Any, Any]
a__getstate__
uBaseModel.__getstate__
D astate
return
udict[Any, Any]
aNone
a__setstate__
uBaseModel.__setstate__
D aother
return
aAny
bool
a__eq__
uBaseModel.__eq__
D akwargs
uUnpack[ConfigDict]
uThis signature is included purely to help type-checkers check arguments to class declaration, which
provides a way to conveniently set model_config key/value pairs.
```python
from pydantic import BaseModel
class MyModel(BaseModel, extra='allow'): ...
```
However, this may be deceiving, since the _actual_ calls to `__init_subclass__` will not receive any
of the config arguments, and will only receive any keyword arguments passed during class initialization
that are _not_ expected keys in ConfigDict. (This is due to the way `ModelMetaclass.__new__` works.)
Args:
**kwargs: Keyword arguments passed to the class definition, which set model_config
Note:
You may want to override `__pydantic_init_subclass__` instead, which behaves similarly but is called
*after* the class is fully initialized.
a__init_subclass__
uBaseModel.__init_subclass__
D areturn
aTupleGenerator
D areturn
str
a__repr__
uBaseModel.__repr__
D areturn
u_repr.ReprArgs
aRepresentation
a__pretty__
a__rich_repr__
a__str__
uBaseModel.__str__
T uThe `__fields__` attribute is deprecated, use `model_fields` instead.
nT acategory
a__fields__
uBaseModel.__fields__
T uThe `__fields_set__` attribute is deprecated, use `model_fields_set` instead.
na__fields_set__
uBaseModel.__fields_set__
T uThe `dict` method is deprecated; use `model_dump` instead.
nD ainclude
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
nnFpppD ainclude
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
return
uIncEx | None
uIncEx | None
bool
pppuDict[str, Any]
dict
uBaseModel.dict
T uThe `json` method is deprecated; use `model_dump_json` instead.
nainclude
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
encoder
models_as_dict
D
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
encoder
models_as_dict
dumps_kwargs
return
uIncEx | None
uIncEx | None
bool
pppuCallable[[Any], Any] | None
bool
aAny
str
uBaseModel.json
T uThe `parse_obj` method is deprecated; use `model_validate` instead.
nD aobj
return
aAny
aSelf
uBaseModel.parse_obj
T uThe `parse_raw` method is deprecated; if your data is JSON use `model_validate_json`, otherwise load the data then use `model_validate` instead.
nD acontent_type
encoding
proto
allow_pickle
nautf8
nFD wbacontent_type
encoding
proto
allow_pickle
return
ustr | bytes
ustr | None
str
uDeprecatedParseProtocol | None
bool
aSelf
parse_raw
uBaseModel.parse_raw
T uThe `parse_file` method is deprecated; load the data from file, then if your data is JSON use `model_validate_json`, otherwise `model_validate` instead.
nD apath
content_type
encoding
proto
allow_pickle
return
ustr | Path
ustr | None
str
uDeprecatedParseProtocol | None
bool
aSelf
parse_file
uBaseModel.parse_file
T uThe `from_orm` method is deprecated; set `model_config['from_attributes']=True` and use `model_validate` instead.
nafrom_orm
uBaseModel.from_orm
T uThe `construct` method is deprecated; use `model_construct` instead.
naconstruct
uBaseModel.construct
T uThe `copy` method is deprecated; use `model_copy` instead. See the docstring of `BaseModel.copy` for details about how to handle `include` and `exclude`.
nD ainclude
exclude
update
deep
nnnFD ainclude
exclude
update
deep
return
uAbstractSetIntStr | MappingIntStrAny | None
uAbstractSetIntStr | MappingIntStrAny | None
uDict[str, Any] | None
bool
aSelf
uBaseModel.copy
T uThe `schema` method is deprecated; use `model_json_schema` instead.
nD aby_alias
ref_template
return
bool
str
uDict[str, Any]
schema
uBaseModel.schema
T uThe `schema_json` method is deprecated; use `model_json_schema` and json.dumps instead.
naref_template
D aby_alias
ref_template
dumps_kwargs
return
bool
str
aAny
str
schema_json
uBaseModel.schema_json
T uThe `validate` method is deprecated; use `model_validate` instead.
nD avalue
return
aAny
aSelf
validate
uBaseModel.validate
T uThe `update_forward_refs` method is deprecated; use `model_rebuild` instead.
nD alocalns
return
aAny
aNone
update_forward_refs
uBaseModel.update_forward_refs
T uThe private method `_iter` will be removed and should no longer be used.
nD aargs
kwargs
return
aAny
ppuBaseModel._iter
T uThe private method `_copy_and_set_values` will be removed and should no longer be used.
nuBaseModel._copy_and_set_values
T uThe private method `_get_value` will be removed and should no longer be used.
nuBaseModel._get_value
T uThe private method `_calculate_keys` will be removed and should no longer be used.
nuBaseModel._calculate_keys
T aModelT
T abound
aModelT
D a__config__
a__doc__
