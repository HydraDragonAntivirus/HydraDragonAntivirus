# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._mock_val_ser

uMocker for `pydantic_core.CoreSchema` which optionally attempts to
rebuild the thing it's mocking when one of its methods is accessed and raises an error if that fails.
a__qualname__
T a_error_message
a_code
a_attempt_rebuild
a_built_memo
a__slots__
D aattempt_rebuild
nD aerror_message
code
attempt_rebuild
return
str
aPydanticErrorCodes
uCallable[[], CoreSchema | None] | None
aNone
a__init__
uMockCoreSchema.__init__
D akey
return
str
aAny
uMockCoreSchema.__getitem__
D areturn
int
uMockCoreSchema.__len__
D areturn
uIterator[str]
uMockCoreSchema.__iter__
D areturn
aCoreSchema
uMockCoreSchema._get_built
D areturn
uCoreSchema | None
uMockCoreSchema.rebuild
a__orig_bases__
uMocker for `pydantic_core.SchemaValidator` or `pydantic_core.SchemaSerializer` which optionally attempts to
rebuild the thing it's mocking when one of its methods is accessed and raises an error if that fails.
T a_error_message
a_code
a_val_or_ser
a_attempt_rebuild
D aerror_message
code
val_or_ser
attempt_rebuild
return
str
aPydanticErrorCodes
uLiteral['validator', 'serializer']
uCallable[[], ValSer | None] | None
aNone
uMockValSer.__init__
D aitem
return
str
aNone
a__getattr__
uMockValSer.__getattr__
D areturn
uValSer | None
uMockValSer.rebuild
D aadapter
type_repr
return
aTypeAdapter
str
aNone
set_type_adapter_mocks
T uall referenced types
D acls
cls_name
undefined_name
return
utype[BaseModel]
str
paNone
set_model_mocks
D acls
cls_name
undefined_name
return
utype[PydanticDataclass]
str
paNone
set_dataclass_mocks
upydantic\_internal\_mock_val_ser.py
T wcT ata
u<module pydantic._internal._mock_val_ser>
T a__class__
T aself
item
a__tracebackhide__
val_ser
T aself
key
T aself
error_message
code
attempt_rebuild
T aself
error_message
code
val_or_ser
attempt_rebuild
T aself
T aself
schema
T aattr_fn
handler
T acls
rebuild_dataclass
T acls
T aadapter
T arebuild_dataclass
cls
attr_fn
T aattr_fn
cls
rebuild_dataclass
T acls
attr_fn
T aattr_fn
cls
T aadapter
attr_fn
T aself
val_ser
T acls
cls_name
undefined_name
rebuild_dataclass
undefined_type_error_message
attempt_rebuild_fn
T acls
cls_name
undefined_name
undefined_type_error_message
attempt_rebuild_fn
T aadapter
type_repr
undefined_type_error_message
attempt_rebuild_fn
a__spec__
.pydantic._internal._model_construction
?
get
aPydanticDescriptorProxy
warnings
warn
w`u
u` overrides an existing Pydantic `
decorator_info
decorator_repr
u` decorator
a__class__
a__setitem__
a_collect_bases_data
aConfigWrapper
for_model
config_dict
model_config
inspect_namespace
ignored_types
get_model_post_init
D aself
context
return
aBaseModel
aAny
aNone
uWe need to both initialize private attributes and call the user-defined model_post_init
method.
wrapped_model_post_init
uModelMetaclass.__new__.<locals>.wrapped_model_post_init
model_post_init
init_private_attributes
a__class_vars__
a__private_attributes__
cast
utype[BaseModel]
a__new__
import_cached_base_model
a__mro__
aGeneric
index
aGenericBeforeBaseModelWarning
T uClasses should inherit from `BaseModel` before generic classes (e.g. `typing.Generic[T]`) for pydantic generics to work properly.
D astacklevel
l a__init__
a__pydantic_base_init__
a__pydantic_custom_init__
a__pydantic_post_init__
aDecoratorInfos
build
a__pydantic_decorators__
a__pydantic_generic_metadata__
T aparameters
T
a__parameters__
upydantic.root_model
aRootModelRootType
u,
a__name__
u is a subclass of `RootModel`, but does not include the generic type identifier(s)
u in its parameters. You should parametrize RootModel directly, e.g., `class
u(RootModel[
u]): ...`.
utyping.Generic[
w]uAll parameters must be present on typing.Generic; you should inherit from
w.u Note: `typing.Generic` must go last: `class
w(u): ...`)
origin
args
parameters
a__pydantic_complete__
items
a__set_name__
cls
build_lenient_weakvaluedict
parent_frame_namespace
a__pydantic_parent_namespace__
unpack_lenient_weakvaluedict
aNsResolver
T aparent_namespace
set_model_fields
frozen
a__hash__
set_default_hash_func
complete_model_class
T araise_errors
ns_resolver
create_model_module
computed_fields
info
a__pydantic_computed_fields__
set_deprecated_descriptors
a__pydantic_init_subclass__
T a__pydantic_fields_set__
a__pydantic_extra__
a__pydantic_private__
namespace
pop
a__annotations__
clear
uMetaclass for creating Pydantic models.
Args:
cls_name: The name of the class to be created.
bases: The base classes of the class to be created.
namespace: The attribute dictionary of the class to be created.
__pydantic_generic_metadata__: Metadata for generic models.
__pydantic_reset_parent_namespace__: Reset parent namespace.
_create_model_module: The module of the class to be created, if created by `create_model`.
**kwargs: Catch-all for any other keyword arguments.
Returns:
The new class created by the metaclass.
original_model_post_init
u<genexpr>
uModelMetaclass.__new__.<locals>.<genexpr>
parent_parameters
T a__private_attributes__
uThis is necessary to keep attribute access working for class attribute access.
a_ModelNamespaceDict
a__pydantic_validator__
a__instancecheck__
uAvoid calling ABC _abc_subclasscheck unless we're pretty sure.
See #3829 and python/cpython#92810
field_names
update
a__pydantic_fields__
keys
class_vars
private_attributes
uThe `__fields__` attribute is deprecated, use `model_fields` instead.
aPydanticDeprecatedSince20
model_fields
uGet metadata about the fields defined on the model.
Returns:
A mapping of field names to [`FieldInfo`][pydantic.fields.FieldInfo] objects.
uGet metadata about the computed fields defined on the model.
Returns:
A mapping of computed field names to [`ComputedFieldInfo`][pydantic.fields.ComputedFieldInfo] objects.
a__dir__
a__fields__
a__pydantic_private__
get_default
aPydanticUndefined
pydantic_private
object_setattr
uThis function is meant to behave like a BaseModel method to initialise private attributes.
It takes context as an argument since that's what pydantic-core passes when calling it.
Args:
self: The BaseModel instance.
context: The context.
get_attribute_from_bases
uGet the `model_post_init` method from the namespace or the class bases, or `None` if not defined.
upydantic.fields
aModelPrivateAttr
aPrivateAttr
import_cached_field_info
default_ignored_types
a__root__
uTo define root models, use `pydantic.RootModel` rather than a field called '__root__'
