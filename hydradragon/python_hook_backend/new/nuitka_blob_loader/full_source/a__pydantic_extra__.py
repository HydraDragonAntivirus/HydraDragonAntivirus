# Reconstructed from integrated Nuitka blob
# Module: a__pydantic_extra__

a__qualname__
startswith
functools
ignored_names
add
T a__
uPrivate attributes must not use dunder names; use a single underscore prefix instead of
is_valid_field_name
uPrivate attributes must not use valid field names; use sunder names, e.g.
w_u instead of
lstrip
T w_amy_field
uFields must not use names with leading underscores; e.g., use
is_valid_privateattr_name
is_classvar_annotation
T adefault
aPydanticUserError
uField
u defined on a base class was overridden by a non-annotated attribute. All field definitions, including overrides, require a type annotation.
D acode
umodel-field-overridden
u requires a type annotation
D acode
umodel-field-missing-annotation
uA non-annotated attribute was detected: `
u =
u`. All model fields require a type annotation; if `
u` is not meant to be a field, you may be able to resolve this error by annotating it as a `ClassVar` or updating `model_config['ignored_types']`.
a_getframe
T l aeval_type_backport
a_make_forward_ref
D ais_argument
is_class
Ftaf_globals
f_locals
T aglobalns
localns
T ENameError
ETypeError
is_annotated
ann_type
get_args
unot enough values to unpack (expected at least 1, got %d)
uIterate over the namespace and:
* gather private attributes
* check for items which look like fields but are not (e.g. have no annotation) and warn.
Args:
namespace: The attribute dictionary of the class to be created.
ignored_types: A tuple of ignore types.
base_class_vars: A set of base class class variables.
base_class_fields: A set of base class fields.
Returns:
A dict contains private attributes info.
Raises:
TypeError: If there is a `__root__` field in model.
NameError: If private attribute name is invalid.
PydanticUserError:
- If a field does not have a type annotation.
- If a field on base class was overridden by a non-annotated attribute.
uinspect_namespace.<locals>.<genexpr>
make_hash_func
a__code__
operator
itemgetter
u<lambda>
umake_hash_func.<locals>.<lambda>
D aself
return
aAny
int
hash_func
umake_hash_func.<locals>.hash_func
getter
aSafeGetItemProxy
get_model_typevars_map
collect_model_fields
T atypevars_map
default
uCollect and set `cls.__pydantic_fields__` and `cls.__class_vars__`.
Args:
cls: BaseModel or dataclass.
bases: Parents of the class, generally `cls.__bases__`.
config_wrapper: The config wrapper instance.
ns_resolver: Namespace resolver to use when getting model annotations.
defer_build
set_model_mocks
aGenerateSchema
aCallbackGetCoreSchemaHandler
partial
generate_schema
D afrom_dunder_get_core_schema
FD aref_mode
unpack
a__get_pydantic_core_schema__
aPydanticUndefinedAnnotation
name
core_config
T atitle
clean_schema
aCollectedInvalid
a__pydantic_core_schema__
create_schema_validator
create_model
aBaseModel
plugin_settings
aSchemaSerializer
a__pydantic_serializer__
aLazyClassAttribute
a__signature__
generate_pydantic_signature
populate_by_name
extra
T ainit
fields
populate_by_name
extra
uFinish building a model class.
This logic must be called after class has been created since validation functions must be bound
nd `get_type_hints` requires a class object.
Args:
cls: BaseModel or dataclass.
cls_name: The model or dataclass name.
config_wrapper: The config wrapper instance.
raise_errors: Whether to raise errors.
ns_resolver: The namespace resolver instance to use during schema building.
create_model_module: The module of the class to be created, if created by `create_model`.
Returns:
`True` if the model is successfully completed, else `False`.
Raises:
PydanticUndefinedAnnotation: If `PydanticUndefinedAnnotation` occurs in`__get_pydantic_core_schema__`
nd `raise_errors=True`.
deprecation_message
a_DeprecatedFieldDescriptor
unwrap_wrapped_function
wrapped_property
a__deprecated__
uSet data descriptors on the class for deprecated fields.
msg
field_name
a__get__
aDeprecationWarning
a_wr
weakref
ref
a_PydanticWeakRef
result
uTakes an input dictionary, and produces a new value that (invertibly) replaces the values with weakrefs.
We can't just use a WeakValueDictionary because many types (including int, str, etc.) can't be stored as values
in a WeakValueDictionary.
The `unpack_lenient_weakvaluedict` function can be used to reverse this operation.
uInverts the transform performed by `build_lenient_weakvaluedict`.
aComputedFieldInfo
aFunctionType
aTypeAliasType
uPrivate logic for creating models.
a__doc__
a__file__
has_location
a__cached__
annotations
a_annotations
builtins
sys
typing
abc
T aABCMeta
aABCMeta
lru_cache
aAny
aCallable
aLiteral
aNoReturn
pydantic_core
typing_extensions
T aTypeAliasType
dataclass_transform
deprecated
get_args
dataclass_transform
deprecated
upydantic.errors
uplugin._schema_validator
T acreate_schema_validator
l upydantic.warnings
a_config
T aConfigWrapper
a_decorators
T aDecoratorInfos
aPydanticDescriptorProxy
get_attribute_from_bases
unwrap_wrapped_function
a_fields
T acollect_model_fields
is_valid_field_name
is_valid_privateattr_name
upydantic._internal._generate_schema
a_generics
T aPydanticGenericMetadata
get_model_typevars_map
aPydanticGenericMetadata
a_import_utils
T aimport_cached_base_model
import_cached_field_info
a_mock_val_ser
T aset_model_mocks
a_namespace_utils
T aNsResolver
a_schema_generation_shared
T aCallbackGetCoreSchemaHandler
a_signature
T agenerate_pydantic_signature
a_typing_extra
T a_make_forward_ref
eval_type_backport
is_annotated
is_classvar_annotation
parent_frame_namespace
a_utils
T aLazyClassAttribute
aSafeGetItemProxy
aPydanticModelField
aPydanticModelPrivateAttr
a__setattr__
T Odict
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
upydantic._internal._model_construction
uA dictionary subclass that intercepts attribute setting on model classes and
warns about overriding of decorators.
D wkwvareturn
str
object
aNone
u_ModelNamespaceDict.__setitem__
a__orig_bases__
D ainit
FD ainit
return
uLiteral[False]
aAny
uOnly for typing purposes. Used as default value of `__pydantic_fields_set__`,
`__pydantic_extra__`, `__pydantic_private__`, so they could be ignored when
synthesizing the `__init__` signature.
aNoInitField
aModelMetaclass
T akw_only_default
field_specifiers
T ntnD acls_name
bases
namespace
a__pydantic_generic_metadata__
a__pydantic_reset_parent_namespace__
a_create_model_module
kwargs
return
str
utuple[type[Any], ...]
udict[str, Any]
uPydanticGenericMetadata | None
bool
ustr | None
aAny
type
uModelMetaclass.__new__
aTYPE_CHECKING
D aitem
return
str
aAny
a__getattr__
uModelMetaclass.__getattr__
classmethod
D aargs
kwargs
return
aAny
pudict[str, object]
uModelMetaclass.__prepare__
D ainstance
return
aAny
bool
uModelMetaclass.__instancecheck__
staticmethod
D abases
return
utuple[type[Any], ...]
utuple[set[str], set[str], dict[str, ModelPrivateAttr]]
uModelMetaclass._collect_bases_data
property
T uThe `__fields__` attribute is deprecated, use `model_fields` instead.
nT acategory
D areturn
udict[str, FieldInfo]
uModelMetaclass.__fields__
uModelMetaclass.model_fields
D areturn
udict[str, ComputedFieldInfo]
model_computed_fields
uModelMetaclass.model_computed_fields
D areturn
ulist[str]
uModelMetaclass.__dir__
D anamespace
bases
return
udict[str, Any]
utuple[type[Any], ...]
uCallable[..., Any] | None
D anamespace
ignored_types
base_class_vars
base_class_fields
return
udict[str, Any]
utuple[type[Any], ...]
uset[str]
uset[str]
udict[str, ModelPrivateAttr]
D acls
bases
return
utype[BaseModel]
utuple[type[Any], ...]
aNone
D acls
return
utype[BaseModel]
aAny
D acls
bases
config_wrapper
ns_resolver
return
utype[BaseModel]
utuple[type[Any], ...]
aConfigWrapper
uNsResolver | None
aNone
D araise_errors
ns_resolver
create_model_module
tnnD acls
cls_name
config_wrapper
raise_errors
ns_resolver
create_model_module
return
utype[BaseModel]
str
aConfigWrapper
bool
uNsResolver | None
ustr | None
bool
D acls
return
utype[BaseModel]
aNone
uRead-only data descriptor used to emit a runtime deprecation warning before accessing a deprecated field.
Attributes:
msg: The deprecation message to be emitted.
wrapped_property: The property instance if the deprecated field is a computed field, or `None`.
field_name: The name of the field being deprecated.
str
T nD amsg
wrapped_property
return
str
uproperty | None
aNone
u_DeprecatedFieldDescriptor.__init__
D acls
name
return
utype[BaseModel]
str
aNone
u_DeprecatedFieldDescriptor.__set_name__
D aobj
obj_type
return
uBaseModel | None
utype[BaseModel] | None
aAny
u_DeprecatedFieldDescriptor.__get__
D aobj
value
return
aAny
paNoReturn
a__set__
u_DeprecatedFieldDescriptor.__set__
uWrapper for `weakref.ref` that enables `pickle` serialization.
Cloudpickle fails to serialize `weakref.ref` objects due to an arcane error related
to abstract base classes (`abc.ABC`). This class works around the issue by wrapping
`weakref.ref` instead of subclassing it.
See https://github.com/pydantic/pydantic/issues/6763 for context.
Semantics:
- If not pickled, behaves the same as a `weakref.ref`.
- If pickled along with the referenced object, the same `weakref.ref` behavior
will be maintained between them after unpickling.
- If pickled without the referenced object, after unpickling the underlying
reference will be cleared (`__call__` will always return `None`).
D aobj
aAny
u_PydanticWeakRef.__init__
D areturn
aAny
a__call__
u_PydanticWeakRef.__call__
D areturn
utuple[Callable, tuple[weakref.ReferenceType | None]]
a__reduce__
u_PydanticWeakRef.__reduce__
D wdareturn
udict[str, Any] | None
udict[str, Any] | None
T amaxsize
D areturn
utuple[type[Any], ...]
upydantic\_internal\_model_construction.py
T a.0
wxaparameters
T a__class__
T a.0
wxaparent_parameters
T a.0
wvaModelPrivateAttr
u<module pydantic._internal._model_construction>
T ainit
T aself
T aself
attributes
a__class__
T aself
obj
obj_type
T aself
item
private_attributes
T aself
msg
wrapped_property
T aself
obj
T aself
instance
a__class__
T!amcs
cls_name
bases
namespace
a__pydantic_generic_metadata__
a__pydantic_reset_parent_namespace__
a_create_model_module
kwargs
parent_namespace
base_field_names
class_vars
base_private_attributes
config_wrapper
private_attributes
original_model_post_init
wrapped_model_post_init
cls
aBaseModel_
mro
parent_parameters
parameters
aRootModelRootType
missing_parameters
parameters_str
error_message
combined_parameters
generic_type_label
bases_str
name
obj
ns_resolver
instance_slot
a__class__
T acls
args
kwargs
T aself
obj
value
T aself
cls
name
T aself
wkwvaexisting
a__class__
T abases
field_names
class_vars
private_attributes
aBaseModel
base
T wdaresult
wkwvaproxy
T acls
cls_name
config_wrapper
raise_errors
ns_resolver
create_model_module
typevars_map
gen_schema
handler
schema
weacore_config
T aComputedFieldInfo
ignored_types
T anamespace
bases
aBaseModel
model_post_init
T aself
getter
T agetter
T aself
context
pydantic_private
name
private_attr
default
T anamespace
ignored_types
base_class_vars
base_class_fields
private_attributes
ignored_names
aModelPrivateAttr
aPrivateAttr
aFieldInfo
all_ignored_types
raw_annotations
var_name
value
suggested_name
ann_name
ann_type
frame
w_ametadata
private_attr
T acls
getter
hash_func
T acls
bases
base_hash_func
new_hash_func
T acls
field
field_info
msg
desc
computed_field_info
T	acls
bases
config_wrapper
ns_resolver
typevars_map
fields
class_vars
wkavalue
T wdaresult
wkwvT aself
context
original_model_post_init
T aoriginal_model_post_init
a__spec__
.pydantic._internal._namespace_utils
