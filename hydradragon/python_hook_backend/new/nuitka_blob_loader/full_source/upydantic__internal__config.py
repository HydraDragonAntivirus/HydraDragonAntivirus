# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._config

uInternal wrapper for Config which exposes ConfigDict items as attributes.
a__qualname__
T aconfig_dict
a__slots__
ustr | None
bool
int
uint | None
uExtraValues | None
extra
frozen
use_enum_values
validate_assignment
arbitrary_types_allowed
uCallable[[str], str] | AliasGenerator | None
alias_generator
uCallable[[type], str] | None
model_title_generator
uCallable[[str, FieldInfo | ComputedFieldInfo], str] | None
field_title_generator
utuple[type, ...]
ignored_types
uJsonDict | JsonSchemaExtraCallable | None
json_schema_extra
udict[type[object], JsonEncoder] | None
json_encoders
uLiteral['always', 'never', 'subclass-instances']
uLiteral['iso8601', 'float']
uLiteral['utf8', 'base64', 'hex']
uLiteral['null', 'constants', 'strings']
validate_return
utuple[str | Pattern[str], ...]
protected_namespaces
defer_build
udict[str, object] | None
plugin_settings
utype[GenerateSchema] | None
schema_generator
json_schema_serialization_defaults_required
uLiteral['validation', 'serialization', None]
json_schema_mode_override
uLiteral['rust-regex', 'python-re']
use_attribute_docstrings
ubool | Literal['all', 'keys', 'none']
D acheck
tD aconfig
check
uConfigDict | dict[str, Any] | type[Any] | None
bool
a__init__
uConfigWrapper.__init__
D abases
namespace
kwargs
return
utuple[type[Any], ...]
udict[str, Any]
udict[str, Any]
aSelf
for_model
uConfigWrapper.for_model
D aname
return
str
aAny
a__getattr__
uConfigWrapper.__getattr__
D atitle
return
ustr | None
ucore_schema.CoreConfig
core_config
uConfigWrapper.core_config
a__repr__
uConfigWrapper.__repr__
uA stack of `ConfigWrapper` instances.
aConfigWrapperStack
D aconfig_wrapper
aConfigWrapper
uConfigWrapperStack.__init__
D areturn
aConfigWrapper
tail
uConfigWrapperStack.tail
D aconfig_wrapper
uConfigWrapper | ConfigDict | None
T)nFppl
nnFppppptnnnT
tnFanever
iso8601
utf8
utf8
null
FpT amodel_validate
model_dump
FnFnnFnFurust-regex
FptT)atitle
str_to_lower
str_to_upper
str_strip_whitespace
str_min_length
str_max_length
extra
frozen
populate_by_name
use_enum_values
validate_assignment
arbitrary_types_allowed
from_attributes
loc_by_alias
alias_generator
model_title_generator
field_title_generator
ignored_types
allow_inf_nan
json_schema_extra
strict
revalidate_instances
ser_json_timedelta
ser_json_bytes
val_json_bytes
ser_json_inf_nan
validate_default
validate_return
protected_namespaces
hide_input_in_errors
json_encoders
defer_build
schema_generator
plugin_settings
json_schema_serialization_defaults_required
json_schema_mode_override
coerce_numbers_to_str
regex_engine
validation_error_cause
use_attribute_docstrings
cache_strings
D aconfig
return
uConfigDict | dict[str, Any] | type[Any] | None
aConfigDict
S
smart_union
json_dumps
copy_on_model_validation
underscore_attrs_are_private
error_msg_templates
getter_dict
fields
json_loads
allow_mutation
post_init_call
D
allow_population_by_field_name
anystr_lower
anystr_strip_whitespace
anystr_upper
keep_untouched
max_anystr_length
min_anystr_length
orm_mode
schema_extra
validate_all
populate_by_name
str_to_lower
str_strip_whitespace
str_to_upper
ignored_types
str_max_length
str_min_length
from_attributes
json_schema_extra
validate_default
D aconfig_dict
return
aConfigDict
aNone
upydantic\_internal\_config.py
T a.0
wkwvu<module pydantic._internal._config>
T a__class__
T aself
name
T aself
config
check
T aself
config_wrapper
T aself
wcT aconfig_dict
deprecated_removed_keys
deprecated_renamed_keys
renamings
renamed_bullets
removed_bullets
message
T aself
title
config
core_config_values
T acls
bases
namespace
kwargs
config_new
base
config
config_class_from_namespace
config_dict_from_namespace
raw_annotations
config_from_namespace
wkT aconfig
config_dict
T aself
a__spec__
.pydantic._internal._core_metadata
6
upydantic.json_schema
aPydanticJsonSchemaWarning
cast
aCoreMetadata
setdefault
pydantic_js_functions
extend
pydantic_js_annotation_functions
get
T apydantic_js_updates
pydantic_js_updates
T apydantic_js_extra
pydantic_js_extra
callable
warn
uComposing `dict` and `callable` type `json_schema_extra` is not supported.The `callable` type is being ignored.If you'd like support for this behavior, please open an issue on pydantic.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
a_annotations
aTYPE_CHECKING
aAny
aTypedDict
warnings
T awarn
D atotal
Fa__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
