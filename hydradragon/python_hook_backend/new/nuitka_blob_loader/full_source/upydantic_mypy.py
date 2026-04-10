# Reconstructed from integrated Nuitka blob
# Module: upydantic.mypy

uThe Pydantic mypy plugin.
a__qualname__
D aoptions
return
aOptions
aNone
uPydanticPlugin.__init__
D afullname
return
str
uCallable[[ClassDefContext], None] | None
get_base_class_hook
uPydanticPlugin.get_base_class_hook
get_metaclass_hook
uPydanticPlugin.get_metaclass_hook
D afullname
return
str
uCallable[[MethodContext], Type] | None
get_method_hook
uPydanticPlugin.get_method_hook
D actx
return
aReportConfigContext
udict[str, Any]
report_config_data
uPydanticPlugin.report_config_data
D actx
return
aClassDefContext
aNone
uPydanticPlugin._pydantic_model_class_maker_callback
uPydanticPlugin._pydantic_model_metaclass_marker_callback
a__orig_bases__
uA Pydantic mypy plugin config holder.
Attributes:
init_forbid_extra: Whether to add a `**kwargs` at the end of the generated `__init__` signature.
init_typed: Whether to annotate fields in the generated `__init__`.
warn_required_dynamic_aliases: Whether to raise required dynamic aliases error.
debug_dataclass_transform: Whether to not reset `dataclass_transform_spec` attribute
of `ModelMetaclass` for testing purposes.
a__annotations__
T ainit_forbid_extra
init_typed
warn_required_dynamic_aliases
debug_dataclass_transform
bool
uPydanticPluginConfig.__init__
D areturn
udict[str, Any]
uPydanticPluginConfig.to_data
D actx
return
aMethodContext
aType
uBased on mypy.plugins.dataclasses.DataclassAttribute.
D
name
alias
is_frozen
has_dynamic_alias
has_default
strict
line
column
type
info
str
ustr | None
bool
ppubool | None
int
puType | None
aTypeInfo
uPydanticModelField.__init__
D	acurrent_info
typed
model_strict
force_optional
use_alias
api
force_typevars_invariant
is_root_model_root
return
aTypeInfo
bool
pppaSemanticAnalyzerPluginInterface
bool
paArgument
uPydanticModelField.to_argument
T FD acurrent_info
api
force_typevars_invariant
return
aTypeInfo
aSemanticAnalyzerPluginInterface
bool
uType | None
uPydanticModelField.expand_type
D acurrent_info
api
use_alias
force_typevars_invariant
return
aTypeInfo
aSemanticAnalyzerPluginInterface
bool
paVar
uPydanticModelField.to_var
D areturn
aJsonDict
uPydanticModelField.serialize
D ainfo
data
api
return
aTypeInfo
aJsonDict
aSemanticAnalyzerPluginInterface
aPydanticModelField
uPydanticModelField.deserialize
D asub_type
api
return
aTypeInfo
aSemanticAnalyzerPluginInterface
aNone
uPydanticModelField.expand_typevar_from_subtype
uBased on mypy.plugins.dataclasses.DataclassAttribute.
ClassVars are ignored by subclasses.
Attributes:
name: the ClassVar name
uPydanticModelClassVar.__init__
D adata
return
aJsonDict
aPydanticModelClassVar
uPydanticModelClassVar.deserialize
uPydanticModelClassVar.serialize
uTransform the BaseModel subclass according to the plugin settings.
Attributes:
tracked_config_fields: A set of field configs that the plugin has to track their value.
S astrict
populate_by_name
frozen
from_attributes
alias_generator
extra
uset[str]
D acls
reason
api
plugin_config
return
aClassDef
uExpression | Statement
aSemanticAnalyzerPluginInterface
aPydanticPluginConfig
aNone
uPydanticModelTransformer.__init__
D areturn
bool
uPydanticModelTransformer.transform
D areturn
aNone
uPydanticModelTransformer.adjust_decorator_signatures
D areturn
aModelConfigData
uPydanticModelTransformer.collect_config
D amodel_config
is_root_model
return
aModelConfigData
bool
utuple[list[PydanticModelField] | None, list[PydanticModelClassVar] | None]
uPydanticModelTransformer.collect_fields_and_class_vars
D astmt
return
aIfStmt
uIterator[AssignmentStmt]
D ablock
return
aBlock
uIterator[AssignmentStmt]
D astmt
model_config
class_vars
return
aAssignmentStmt
aModelConfigData
udict[str, PydanticModelClassVar]
uPydanticModelField | PydanticModelClassVar | None
uPydanticModelTransformer.collect_field_or_class_var_from_stmt
D asym
name
context
return
aSymbolTableNode
str
aContext
uType | None
uPydanticModelTransformer._infer_dataclass_attr_init_type
D afields
config
is_settings
is_root_model
return
ulist[PydanticModelField]
aModelConfigData
bool
paNone
uPydanticModelTransformer.add_initializer
uPydanticModelTransformer.add_model_construct_method
D afields
api
frozen
return
ulist[PydanticModelField]
aSemanticAnalyzerPluginInterface
bool
aNone
uPydanticModelTransformer.set_frozen
D aname
arg
lax_extra
return
str
aExpression
bool
uModelConfigData | None
uPydanticModelTransformer.get_config_update
D astmt
return
aAssignmentStmt
bool
uPydanticModelTransformer.get_has_default
D astmt
return
aAssignmentStmt
ubool | None
uPydanticModelTransformer.get_strict
D astmt
return
aAssignmentStmt
utuple[str | None, bool]
uPydanticModelTransformer.get_alias_info
uPydanticModelTransformer.is_field_frozen
D	afields
typed
model_strict
use_alias
requires_dynamic_aliases
is_settings
is_root_model
force_typevars_invariant
return
ulist[PydanticModelField]
bool
ppppppulist[Argument]
uPydanticModelTransformer.get_field_arguments
D afields
config
return
ulist[PydanticModelField]
aModelConfigData
bool
uPydanticModelTransformer.should_init_forbid_extra
D afields
has_alias_generator
return
ulist[PydanticModelField]
bool
puPydanticModelTransformer.is_dynamic_alias_present
uPydantic mypy plugin model config class.
T nnnnnnD aforbid_extra
frozen
from_attributes
populate_by_name
has_alias_generator
strict
ubool | None
ubool | None
ubool | None
ubool | None
ubool | None
ubool | None
uModelConfigData.__init__
uModelConfigData.get_values_dict
D aconfig
return
uModelConfigData | None
aNone
uModelConfigData.update
D akey
value
return
str
aAny
aNone
uModelConfigData.setdefault
T upydantic-orm
uInvalid from_attributes call
aPydantic
T upydantic-config
uInvalid config value
aPydantic
T upydantic-alias
uDynamic alias disallowed
aPydantic
T upydantic-unexpected
uUnexpected behavior
aPydantic
T upydantic-field
uUntyped field disallowed
aPydantic
T upydantic-field
uInvalid Field defaults
aPydantic
aERROR_FIELD_DEFAULTS
T upydantic-field
uExtra field on RootModel subclass
aPydantic
D amodel_name
api
context
return
str
aCheckerPluginInterface
aContext
aNone
D aname
api
context
return
str
aSemanticAnalyzerPluginInterface
aContext
aNone
D aapi
context
return
aSemanticAnalyzerPluginInterface
aContext
aNone
D adetail
api
context
return
str
uCheckerPluginInterface | SemanticAnalyzerPluginInterface
aContext
aNone
D aapi
context
return
aCheckerPluginInterface
aContext
aNone
T nnFD	aapi
cls
name
args
return_type
self_type
tvar_def
is_classmethod
return
uSemanticAnalyzerPluginInterface | CheckerPluginInterface
aClassDef
str
ulist[Argument]
aType
uType | None
uTypeVarType | None
bool
aNone
D aconfig_file
return
str
udict[str, Any] | None
upydantic\mypy.py
T a.0
wiaarg
first_dec
T a.0
base
u<module pydantic.mypy>
T a__class__
T aself
forbid_extra
frozen
from_attributes
populate_by_name
has_alias_generator
strict
T aself
name
T aself
name
alias
is_frozen
has_dynamic_alias
has_default
strict
line
column
type
info
T aself
cls
reason
api
plugin_config
T aself
options
a__class__
T aself
options
toml_config
config
key
setting
plugin_config
T aself
block
stmt
T aself
stmt
body
T	aself
sym
name
context
default
wtasetter
super_info
setter_type
T aself
ctx
transformer
T aself
ctx
info_metaclass
T aself
fields
config
is_settings
is_root_model
typed
model_strict
use_alias
requires_dynamic_aliases
args
base_settings_node
base_settings_init_node
func_type
arg_idx
arg_name
analyzed_variable_type
variable
var
T aapi
cls
name
args
return_type
self_type
tvar_def
is_classmethod
info
sym
function_type
first
arg_types
arg_names
arg_kinds
arg
signature
func
r_name
wvadec
T
self
fields
config
is_settings
is_root_model
set_str
optional_set_str
fields_set_argument
args
var
T aself
sym
first_dec
T aself
stmt
cls
config
has_config_kwargs
has_config_from_namespace
name
expr
config_data
lhs
arg_name
arg
key_expr
value_expr
substmt
info
value
T aself
stmt
model_config
class_vars
cls
lhs
sym
node
node_type
has_default
strict
typ
alias
has_dynamic_alias
is_frozen
init_type
T aself
model_config
is_root_model
found_fields
found_class_vars
current_field_names
current_class_vars_names
cls
info
name
data
field
sym_node
stmt
maybe_field
lhs
T acls
data
T acls
info
data
api
typ
T aapi
context
T amodel_name
api
context
T aname
api
context
T adetail
api
context
link
full_message
T aself
current_info
api
force_typevars_invariant
modified_type
filled_with_typevars
arg
T aself
sub_type
api
T actx
model_type
ctx_type
detail
pydantic_metadata
from_attributes
T astmt
expr
wiaarg_name
arg
T aself
fullname
sym
T aself
name
arg
lax_extra
forbid_extra
has_alias_generator
T aself
fields
typed
model_strict
use_alias
requires_dynamic_aliases
is_settings
is_root_model
force_typevars_invariant
info
arguments
T astmt
expr
arg
name
T aself
fullname
T aself
T afields
has_alias_generator
field
T aconfig_file
toml_
warnings
rf
T aversion
T aself
ctx
T
self
fields
api
frozen
info
field
sym_node
var
var_str
detail
T aself
key
value
T aself
fields
config
T aself
current_info
typed
model_strict
force_optional
use_alias
api
force_typevars_invariant
is_root_model_root
variable
strict
type_annotation
T aself
current_info
api
use_alias
force_typevars_invariant
name
T aself
info
is_root_model
config
fields
class_vars
field
is_settings
T aself
config
wkwva__spec__
.pydantic.networks
c
max_length
allowed_schemes
host_required
default_host
default_port
default_path
fields
name
uFetch a key / value mapping of constraints to values that are not None. Used for core schema updates.
type
ufunction-wrap
schema
T aurl
umulti-host-url
aPydanticUserError
u'UrlConstraints' cannot annotate '

u'.
D acode
uinvalid-annotated-type
defined_constraints
items
schema_to_mutate
a_build_type_adapter
validate_python
a_url
scheme
uThe scheme part of the URL.
e.g. `https` in `https://user:pass@host:port/path?query#fragment`
username
uThe username part of the URL, or `None`.
e.g. `user` in `https://user:pass@host:port/path?query#fragment`
password
uThe password part of the URL, or `None`.
e.g. `pass` in `https://user:pass@host:port/path?query#fragment`
host
uThe host part of the URL, or `None`.
If the URL must be punycode encoded, this is the encoded host, e.g if the input URL is `https://      .com`,
`host` will be `xn--9aaa.com`
unicode_host
uThe host part of the URL as a unicode string, or `None`.
e.g. `host` in `https://user:pass@host:port/path?query#fragment`
If the URL must be punycode encoded, this is the decoded host, e.g if the input URL is `https://      .com`,
`unicode_host()` will be `      .com`
port
uThe port part of the URL, or `None`.
e.g. `port` in `https://user:pass@host:port/path?query#fragment`
path
uThe path part of the URL, or `None`.
e.g. `/path` in `https://user:pass@host:port/path?query#fragment`
query
uThe query part of the URL, or `None`.
e.g. `query` in `https://user:pass@host:port/path?query#fragment`
query_params
uThe query part of the URL as a list of key-value pairs.
e.g. `[('foo', 'bar')]` in `https://user:pass@host:port/path?foo=bar#fragment`
fragment
uThe fragment part of the URL, or `None`.
e.g. `fragment` in `https://user:pass@host:port/path?query#fragment`
unicode_string
uThe URL as a unicode string, unlike `__str__()` this will not punycode encode the host.
If the URL must be punycode encoded, this is the decoded string, e.g if the input URL is `https://      .com`,
`unicode_string()` will be `https://      .com`
uThe URL as a string, this will punycode encode the host if required.
a__name__
w(w)a_CoreUrl
build
T ascheme
username
password
host
port
path
query
fragment
uBuild a new `Url` instance from its component parts.
Args:
scheme: The scheme part of the URL.
username: The username part of the URL, or omit for no username.
password: The password part of the URL, or omit for no password.
host: The host part of the URL.
port: The port part of the URL, or omit for no port.
path: The path part of the URL, or omit for no path.
query: The query part of the URL, or omit for no query.
fragment: The fragment part of the URL, or omit for no fragment.
Returns:
An instance of URL
aPydanticSerializationUnexpectedValue
uExpected `
u` but got `
u` with value `'
u'` - serialized value may not be as expected.
mode
json
wrap_val
u_BaseUrl.__get_pydantic_core_schema__.<locals>.wrap_val
upydantic_core.core_schema
no_info_wrap_validator_function
url_schema
a_constraints
plain_serializer_function_ser_schema
serialize_url
D ainfo_arg
when_used
taalways
T aschema
serialization
source
a_BaseUrl
a__new__
uThe scheme part of the URL.
e.g. `https` in `https://foo.com,bar.com/path?query#fragment`
uThe path part of the URL, or `None`.
e.g. `/path` in `https://foo.com,bar.com/path?query#fragment`
uThe query part of the URL, or `None`.
e.g. `query` in `https://foo.com,bar.com/path?query#fragment`
uThe query part of the URL as a list of key-value pairs.
e.g. `[('foo', 'bar')]` in `https://foo.com,bar.com/path?query#fragment`
uThe fragment part of the URL, or `None`.
e.g. `fragment` in `https://foo.com,bar.com/path?query#fragment`
hosts
uThe hosts of the `MultiHostUrl` as [`MultiHostHost`][pydantic_core.MultiHostHost] typed dicts.
```python
from pydantic_core import MultiHostUrl
mhu = MultiHostUrl('https://foo.com:123,foo:bar@bar.com/path')
print(mhu.hosts())
"""
[
{'username': None, 'password': None, 'host': 'foo.com', 'port': 123},
{'username': 'foo', 'password': 'bar', 'host': 'bar.com', 'port': 443}
]
```
Returns:
A list of dicts, each representing a host.
uThe URL as a unicode string, unlike `__str__()` this will not punycode encode the hosts.
a_CoreMultiHostUrl
T	ascheme
hosts
username
password
host
port
path
query
fragment
uBuild a new `MultiHostUrl` instance from its component parts.
This method takes either `hosts` - a list of `MultiHostHost` typed dicts, or the individual components
`username`, `password`, `host` and `port`.
Args:
scheme: The scheme part of the URL.
hosts: Multiple hosts to build the URL from.
username: The username part of the URL.
password: The password part of the URL.
host: The host part of the URL.
port: The port part of the URL.
path: The path part of the URL.
query: The query part of the URL, or omit for no query.
fragment: The fragment part of the URL, or omit for no fragment.
Returns:
An instance of `MultiHostUrl`
u_BaseMultiHostUrl.__get_pydantic_core_schema__.<locals>.wrap_val
multi_host_url_schema
a_BaseMultiHostUrl
aTypeAdapter
uThe required URL host.
email_validator
uemail-validator is not installed, run `pip install pydantic[email]`
uemail-validator
version
partition
T w.w2uemail-validator version >= 2.0 required, run pip install -U email-validator
import_email_validator
no_info_after_validator_function
a_validate
str_schema
update
T astring
email
T atype
format
validate_email
email
aNameEmail
T astring
uname-email
json_or_python_schema
union_schema
is_instance_schema
D acustom_error_type
custom_error_message
name_email_type
uInput is not a valid NameEmail
to_string_ser_schema
T ajson_schema
python_schema
serialization
w@w"u" <
w>u <
aIPv4Address
aIPv6Address
aPydanticCustomError
T aip_any_address
uvalue is not a valid IPv4 or IPv6 address
uValidate an IPv4 or IPv6 address.
string
format
ipvanyaddress
no_info_plain_validator_function
T aserialization
aIPv4Interface
aIPv6Interface
T aip_any_interface
uvalue is not a valid IPv4 or IPv6 interface
uValidate an IPv4 or IPv6 interface.
ipvanyinterface
aIPv4Network
aIPv6Network
T aip_any_network
uvalue is not a valid IPv4 or IPv6 network
uValidate an IPv4 or IPv6 network.
ipvanynetwork
re
compile
T u\s*(?:((?:[\w!#$%&\'*+\-/=?^_`{|}~]+\s+)*[\w!#$%&\'*+\-/=?^_`{|}~]+)|"((?:[^"]|\")+)")?\s*<(.+)>\s*
aMAX_EMAIL_LENGTH
value_error
uvalue is not a valid email address: {reason}
reason
uLength must not exceed
u characters
pretty_email_regex
fullmatch
groups
value
strip
D acheck_deliverability
FaEmailNotValidError
args
normalized
local_part
uEmail address validation using [email-validator](https://pypi.org/project/email-validator/).
Returns:
A tuple containing the local part of the email (or the name for "pretty" email addresses)
nd the normalized email.
Raises:
PydanticCustomError: If the email is invalid.
Note:
Note that:
* Raw IP address (literal) domain parts are not allowed.
* `"John Doe <local_part@domain.com>"` style "pretty" email addresses are processed.
* Spaces are striped from the beginning and end of addresses, but no error is raised.
uThe networks module contains types for common network-related fields.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
a_annotations
dataclasses
a_dataclasses
T afields
lru_cache
ipaddress
T aIPv4Address
aIPv4Interface
aIPv4Network
aIPv6Address
aIPv6Interface
aIPv6Network
aTYPE_CHECKING
aAny
aClassVar
pydantic_core
aMultiHostHost
aSchemaSerializer
core_schema
aMultiHostUrl
aUrl
typing_extensions
T aAnnotated
aSelf
aTypeAlias
aAnnotated
aSelf
aTypeAlias
upydantic.errors
a_internal
T a_repr
a_schema_generation_shared
a_repr
a_schema_generation_shared
a_migration
T agetattr_migration
getattr_migration
upydantic.annotated_handlers
aGetCoreSchemaHandler
upydantic.json_schema
aJsonSchemaValue
upydantic.type_adapter
L aAnyUrl
aAnyHttpUrl
aFileUrl
aFtpUrl
aHttpUrl
aWebsocketUrl
aAnyWebsocketUrl
aUrlConstraints
aEmailStr
aNameEmail
aIPvAnyAddress
aIPvAnyInterface
aIPvAnyNetwork
aPostgresDsn
aCockroachDsn
aAmqpDsn
aRedisDsn
aMongoDsn
aKafkaDsn
aNatsDsn
validate_email
aMySQLDsn
aMariaDBDsn
aClickHouseDsn
aSnowflakeDsn
a__all__
dataclass
