# Reconstructed from integrated Nuitka blob
# Module: upydantic.config

uA TypedDict for configuring Pydantic behaviour.
a__qualname__
ustr | None
title
uCallable[[type], str] | None
model_title_generator
uCallable[[str, FieldInfo | ComputedFieldInfo], str] | None
field_title_generator
bool
str_to_lower
str_to_upper
str_strip_whitespace
int
str_min_length
uint | None
str_max_length
uExtraValues | None
extra
frozen
populate_by_name
use_enum_values
validate_assignment
arbitrary_types_allowed
from_attributes
loc_by_alias
uCallable[[str], str] | AliasGenerator | None
alias_generator
utuple[type, ...]
ignored_types
allow_inf_nan
uJsonDict | JsonSchemaExtraCallable | None
json_schema_extra
udict[type[object], JsonEncoder] | None
json_encoders
strict
uLiteral['always', 'never', 'subclass-instances']
revalidate_instances
uLiteral['iso8601', 'float']
ser_json_timedelta
uLiteral['utf8', 'base64', 'hex']
ser_json_bytes
val_json_bytes
uLiteral['null', 'constants', 'strings']
ser_json_inf_nan
validate_default
validate_return
utuple[str | Pattern[str], ...]
protected_namespaces
hide_input_in_errors
defer_build
udict[str, object] | None
plugin_settings
utype[_GenerateSchema] | None
schema_generator
json_schema_serialization_defaults_required
uLiteral['validation', 'serialization', None]
json_schema_mode_override
coerce_numbers_to_str
uLiteral['rust-regex', 'python-re']
regex_engine
validation_error_cause
use_attribute_docstrings
ubool | Literal['all', 'keys', 'none']
cache_strings
a__orig_bases__
T a_TypeT
Otype
T abound
a_TypeT
D aconfig
return
aConfigDict
uCallable[[_TypeT], _TypeT]
with_config
T upydantic.config
a__getattr__
upydantic\config.py
u<module pydantic.config>
T a__class__
T aclass_
is_model_class
config
T aconfig
T aconfig
inner
a__spec__
.pydantic
a_deprecated_dynamic_imports
warn
uImporting

u from `pydantic` is deprecated. This feature is either no longer supported, or is not public.
aDeprecationWarning
D astacklevel
l a_dynamic_imports
get
