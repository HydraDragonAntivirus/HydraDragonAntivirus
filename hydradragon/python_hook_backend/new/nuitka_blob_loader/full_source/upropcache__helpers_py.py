# Reconstructed from integrated Nuitka blob
# Module: upropcache._helpers_py

a__qualname__
a__annotations__
dict
str
a__orig_bases__
under_cached_property
uUse as a class method decorator.
It operates almost exactly like
the Python `@property` decorator, but it puts the result of the
method it decorates into the instance dict after the first call,
effectively replacing the function it decorates with an instance
variable.  It is, in Python parlance, a data descriptor.
return
a__init__
uunder_cached_property.__init__
T nainst
owner
type
object
a__get__
uunder_cached_property.__get__
value
a__set__
uunder_cached_property.__set__
upropcache\_helpers_py.py
u<module propcache._helpers_py>
T a__class__
T aself
inst
owner
T aself
inst
owner
val
T aself
wrapped
T aself
inst
value

a__spec__
.propcache.api
uPublic API of the property caching library.
a__doc__
a__file__
origin
has_location
a__cached__
a_helpers
T acached_property
under_cached_property
cached_property
under_cached_property
a__all__
upropcache\api.py
u<module propcache.api>

a__spec__
.propcache
%
a_PUBLIC_API

T aapi
api
umodule 'propcache' has no attribute '
w'uImport the public API from the `api` module.
keys
uInclude the public API in the module's dir() output.
upropcache: An accelerated property cache for Python classes.
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_propcache
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
aTYPE_CHECKING
T acached_property
under_cached_property
u0.3.0
a__version__
a__all__
D aattr
return
Ostr
Oobject
a_import_facade
D areturn
AOlist
T Ostr
a_dir_facade
a__getattr__
a__dir__
upropcache\__init__.py
u<module propcache>
T aattr
api
a__spec__
.pydantic._internal._config
prepare_config
config_dict
cast
aConfigDict
model_config
config_new
update
copy
get
T aConfig
T amodel_config
a__annotations__
aPydanticUserError
T u`model_config` cannot be used as a model field name. Use `model_config` for model configuration.
umodel-config-invalid-field-name
T acode
T u"Config" and "model_config" cannot be used together
uconfig-both
keys
config_keys
kwargs
pop
uBuild a new `ConfigWrapper` instance for a `BaseModel`.
The config wrapper built based on (in descending order of priority):
- options from `kwargs`
- options from the `namespace`
- options from the base classes (`bases`)
Args:
bases: A tuple of base classes.
namespace: The namespace of the class being created.
kwargs: The kwargs passed to the class being created.
Returns:
A `ConfigWrapper` instance for `BaseModel`.
config_defaults
uConfig has no attribute

T aschema_generator
warnings
warn
uThe `schema_generator` setting has been deprecated since v2.10. This setting no longer has any effect.
aPydanticDeprecatedSince210
D astacklevel
l atitle
T atitle
extra_fields_behavior
T aextra
allow_inf_nan
T aallow_inf_nan
populate_by_name
T apopulate_by_name
str_strip_whitespace
T astr_strip_whitespace
str_to_lower
T astr_to_lower
str_to_upper
T astr_to_upper
strict
T astrict
ser_json_timedelta
T aser_json_timedelta
ser_json_bytes
T aser_json_bytes
val_json_bytes
T aval_json_bytes
ser_json_inf_nan
T aser_json_inf_nan
from_attributes
T afrom_attributes
loc_by_alias
T aloc_by_alias
revalidate_instances
T arevalidate_instances
validate_default
T avalidate_default
str_max_length
T astr_max_length
str_min_length
T astr_min_length
hide_input_in_errors
T ahide_input_in_errors
coerce_numbers_to_str
T acoerce_numbers_to_str
regex_engine
T aregex_engine
validation_error_cause
T avalidation_error_cause
cache_strings
T acache_strings
upydantic_core.core_schema
aCoreConfig
uCreate a pydantic-core config.
We don't use getattr here since we don't want to populate with defaults.
Args:
title: The title to use if not set in config.
Returns:
A `CoreConfig` object created from config.
u,
items
uConfigWrapper(
w)w=u<genexpr>
uConfigWrapper.__repr__.<locals>.<genexpr>
a_config_wrapper_stack
config_wrapper
aConfigWrapper
D acheck
Faself
append
push
uConfigWrapperStack.push
aDEPRECATION_MESSAGE
aDeprecationWarning
startswith
T a__
check_deprecated
uCreate a `ConfigDict` instance from an existing dict, a class (e.g. old class-based config) or None.
Args:
config: The input config.
Returns:
A ConfigDict object created from config.
aV2_REMOVED_KEYS
aV2_RENAMED_KEYS
sorted
u*
u has been renamed to
u has been removed
w
uValid config keys have changed in V2:
aUserWarning
uCheck for deprecated config keys and warn the user.
Args:
config_dict: The input config.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
a_annotations
contextlib
T acontextmanager
contextmanager
re
T aPattern
aPattern
aTYPE_CHECKING
aAny
aCallable
core_schema
typing_extensions
T aLiteral
aSelf
aLiteral
aSelf
upydantic.aliases
aAliasGenerator
upydantic.config
aExtraValues
aJsonDict
aJsonEncoder
aJsonSchemaExtraCallable
upydantic.errors
upydantic.warnings
aPydanticDeprecatedSince20
uSupport for class-based `config` is deprecated, use ConfigDict instead.
