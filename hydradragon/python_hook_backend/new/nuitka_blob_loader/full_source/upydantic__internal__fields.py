# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._fields

uPydantic general metadata like `max_digits`.
a__doc__
u_general_metadata_cls.<locals>._PydanticGeneralMetadata
a__qualname__
D ametadata
aAny
a__init__
u_general_metadata_cls.<locals>._PydanticGeneralMetadata.__init__
a__orig_bases__
uDo it this way to avoid importing `annotated_types` at import time.
use_attribute_docstrings
extract_docstrings_from_cls
items
description
import_cached_base_model
import_cached_field_info
a__pydantic_fields__
parent_fields_lookup
a_typing_extra
get_model_type_hints
T ans_resolver
get
a__annotations__
model_config
config_wrapper
protected_namespaces
aPattern
match
ann_name
startswith
bases
uField "

u" conflicts with member
u of protected namespace "
protected_namespace
u".
valid_namespaces
ure.compile(
pattern
w)awarnings
warn
u" in
cls
u has conflict with protected namespace "
u".
You may be able to resolve this warning by setting `model_config['protected_namespaces'] =
u`.
aUserWarning
is_classvar_annotation
class_vars
add
a_is_finalvar_with_default_val
aPydanticUndefined
is_valid_field_name
a__pydantic_root_model__
root
uUnexpected field with name
u; only 'root' is allowed as a field of a `RootModel`
a__pydantic_generic_metadata__
T aorigin
dataclasses
is_dataclass
fields
name
uField name "
u" in "
u" shadows an attribute in parent "
w"aFieldInfo_
from_annotation
evaluated
copy
a_warn_on_nested_alias_in_annotation
default
ismethoddescriptor
a__get__
from_annotated_attribute
delattr
a__pydantic_decorators__
computed_fields
uyou can't override a field with a computed field
field_info
apply_typevars_map
typevars_map
a_update_fields_from_docstrings
uCollect the fields of a nascent pydantic model.
Also collect the names of any ClassVars present in the type hints.
The returned value is a tuple of two items: the fields dict, and the set of ClassVar names.
Args:
cls: BaseModel or dataclass.
bases: Parents of the class, generally `cls.__bases__`.
config_wrapper: The config wrapper instance.
ns_resolver: Namespace resolver to use when getting model annotations.
typevars_map: A dictionary mapping type variables to their concrete types.
Returns:
A tuple contains fields and class variables.
Raises:
NameError:
- If there is a conflict between a field name and protected namespaces.
- If there is a field other than `root` in `RootModel`.
- If a field shadows an attribute in the parent model.
a__args__
is_annotated
get_args
alias
u`alias` specification on field "
u" must be set on outermost annotation to take effect.
is_finalvar
default_factory
aNsResolver
a__dataclass_fields__
a__mro__
ns_resolver
push
a__enter__
a__exit__
dataclass_fields
base
types_namespace
try_eval_type
type
init
aMISSING
init_var
aPydanticUserError
uDataclass field
u has init=False and init_var=True, but these are mutually exclusive.
D acode
uclashing-init-and-init-var
T nnnuCollect the fields of a dataclass.
Args:
cls: dataclass.
ns_resolver: Namespace resolver to use when getting dataclass annotations.
Defaults to an empty instance.
typevars_map: A dictionary mapping type variables to their concrete types.
config_wrapper: The config wrapper instance.
Returns:
The dataclass fields.
T w_T a__
signature
T EValueError
ETypeError
parameters
values
can_be_positional
aParameter
empty
uWhether the provided default factory callable has a validated data parameter.
uPrivate logic related to fields (the `Field()` function and `FieldInfo` class), and arguments to `Annotated`.
a__file__
origin
has_location
a__cached__
annotations
a_annotations
T acopy
lru_cache
inspect
T aParameter
ismethoddescriptor
signature
aTYPE_CHECKING
aAny
aCallable
pydantic_core
typing_extensions
T aTypeIs
aTypeIs
upydantic.errors
T a_typing_extra
a_config
T aConfigWrapper
aConfigWrapper
a_docs_extraction
T aextract_docstrings_from_cls
a_import_utils
T aimport_cached_base_model
import_cached_field_info
a_namespace_utils
T aNsResolver
a_repr
T aRepresentation
aRepresentation
a_utils
T acan_be_positional
uBase class for annotation markers like `Strict`.
a__slots__
D ametadata
return
aAny
aBaseMetadata
pydantic_general_metadata
T nT amaxsize
D areturn
utype[BaseMetadata]
D acls
fields
config_wrapper
return
utype[Any]
udict[str, FieldInfo]
aConfigWrapper
aNone
D atypevars_map
nD acls
bases
config_wrapper
ns_resolver
typevars_map
return
utype[BaseModel]
utuple[type[Any], ...]
aConfigWrapper
uNsResolver | None
udict[Any, Any] | None
utuple[dict[str, FieldInfo], set[str]]
collect_model_fields
D aann_type
ann_name
return
utype[Any]
str
aNone
D atype_
val
return
utype[Any]
aAny
bool
D ans_resolver
typevars_map
config_wrapper
nnnD acls
ns_resolver
typevars_map
config_wrapper
return
utype[StandardDataclass]
uNsResolver | None
udict[Any, Any] | None
uConfigWrapper | None
udict[str, FieldInfo]
collect_dataclass_fields
D aname
return
str
bool
is_valid_privateattr_name
D adefault_factory
return
uCallable[[], Any] | Callable[[dict[str, Any]], Any]
uTypeIs[Callable[[dict[str, Any]], Any]]
takes_validated_data_argument
upydantic\_internal\_fields.py
u<module pydantic._internal._fields>
T a__class__
T aself
metadata
T aBaseMetadata
a_PydanticGeneralMetadata
T atype_
val
aFieldInfo
T acls
fields
config_wrapper
fields_docs
ann_name
field_info
T aann_type
ann_name
aFieldInfo
args
anno_arg
anno_type_arg
T acls
ns_resolver
typevars_map
config_wrapper
fields
aFieldInfo_
dataclass_fields
base
ann_name
dataclass_field
globalns
localns
ann_type
w_afield_info
field
T acls
bases
config_wrapper
ns_resolver
typevars_map
parent_fields_lookup
fields
class_vars
ns_violation
decorators
aBaseModel
aFieldInfo_
base
model_fields
type_hints
annotations
ann_name
ann_type
evaluated
protected_namespace
wbavalid_namespaces
pn
generic_origin
dataclass_fields
default
field_info
field
T aname
T ametadata
T adefault_factory
sig
parameters
a__spec__
.pydantic._internal._forward_ref
#
aUnion
a__doc__
a__file__
origin
has_location
a__cached__
annotations
a_annotations
dataclasses
T adataclass
dataclass
