# Reconstructed from integrated Nuitka blob
# Module: a__base__

a__validators__
a__cls_kwargs__
nnnupydantic.main
nnD	amodel_name
a__config__
a__doc__
a__validators__
a__cls_kwargs__
field_definitions
return
str
uConfigDict | None
ustr | None
aNone
str
udict[str, Callable[..., Any]] | None
udict[str, Any] | None
aAny
utype[BaseModel]
create_model
D a__config__
a__validators__
a__cls_kwargs__
field_definitions
return
str
uConfigDict | None
ustr | None
utype[ModelT] | tuple[type[ModelT], ...]
str
udict[str, Callable[..., Any]] | None
udict[str, Any] | None
aAny
utype[ModelT]
D a__config__
a__doc__
a__validators__
a__cls_kwargs__
a__slots__
nnnnnnnD
model_name
a__config__
a__doc__
a__validators__
a__cls_kwargs__
a__slots__
field_definitions
return
str
uConfigDict | None
ustr | None
utype[ModelT] | tuple[type[ModelT], ...] | None
ustr | None
udict[str, Callable[..., Any]] | None
udict[str, Any] | None
utuple[str, ...] | None
aAny
utype[ModelT]
T upydantic.main
upydantic\main.py
T a.0
arg
typevars_map
T a.0
wkwvT a.0
wkwvaself
u<module pydantic.main>
T a__class__
T acls
typevar_values
typevars_map
cached
submodel
parent_args
args
origin
model_name
params
maybe_self_type
parent_ns
T aself
cls
wmT aself
memo
cls
wmT aself
item
attribute
exc
T aself
other
self_type
other_type
model_fields
getter
self_fields_proxy
other_fields_proxy
T aself
T acls
source
handler
schema
T acls
core_schema
handler
T aself
item
private_attributes
attribute
exc
pydantic_extra
a__class__
T aself
private
T aself
data
a__tracebackhide__
validated_self
T acls
kwargs
T aself
extra
T aself
changes
T aself
wkwvafield
pydantic_extra
T aself
name
value
attribute
attr
T aself
state
T aself
args
kwargs
copy_internals
T aself
name
value
error
typ
T acls
args
kwargs
copy_internals
T acls
a_fields_set
values
T aself
include
exclude
update
deep
extra
copy_internals
values
private
wkafields_set
T amodel_name
a__config__
a__doc__
a__validators__
a__cls_kwargs__
a__slots__
field_definitions
namespace
fields
annotations
f_name
f_def
f_annotation
f_value
wew_aFieldInfo
wfaresolved_bases
meta
ns
kwds
T amodel_name
a__config__
a__doc__
a__validators__
a__cls_kwargs__
field_definitions
T aself
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
T acls
obj
T
self
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
encoder
models_as_dict
dumps_kwargs
T acls
a_fields_set
values
fields_values
validation_aliases
a_extra
wmafields_set
name
field
alias
value
wkwvT aself
update
deep
copied
wkwvT aself
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
T aself
indent
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
T acls
by_alias
ref_template
schema_generator
mode
T acls
params
param_names
params_component
T aself
a_BaseModel__context
T	acls
force
raise_errors
a_parent_namespace_depth
a_types_namespace
rebuild_ns
parent_ns
ns_resolver
config
T acls
obj
strict
from_attributes
context
a__tracebackhide__
T acls
json_data
strict
context
a__tracebackhide__
T acls
obj
strict
context
a__tracebackhide__
T acls
path
content_type
encoding
proto
allow_pickle
parse
obj
T acls
wbacontent_type
encoding
proto
allow_pickle
error
parse
obj
exc
json
type_str
T acls
by_alias
ref_template
T acls
by_alias
ref_template
dumps_kwargs
json
pydantic_encoder
T acls
localns
T acls
value
a__spec__
.pydantic.mypy
+]
j aPydanticPlugin
u`version` is the mypy version string.
We might want to use this to print a warning if the mypy version being used is
newer, or especially older, than we expect (or need).
Args:
version: The mypy version string.
Return:
The Pydantic mypy plugin type.
aPydanticPluginConfig
plugin_config
to_data
a_plugin_data
a__class__
a__init__
lookup_fully_qualified
node
aTypeInfo
mro
a_pydantic_model_class_maker_callback
uUpdate Pydantic model class.
fullname
aBASEMODEL_FULLNAME
u<genexpr>
uPydanticPlugin.get_base_class_hook.<locals>.<genexpr>
aMODEL_METACLASS_FULLNAME
a_pydantic_model_metaclass_marker_callback
uUpdate Pydantic `ModelMetaclass` definition.
endswith
T u.from_orm
from_attributes_callback
uAdjust return type of `from_orm` method call.
uReturn all plugin config data.
Used by mypy to determine if cache needs to be discarded.
aPydanticModelTransformer
cls
reason
api
transform
debug_dataclass_transform
info
declared_metaclass
T ucallback not passed from 'get_metaclass_hook'
type
dataclass_transform_spec
uReset dataclass_transform_spec attribute of ModelMetaclass.
Let the plugin handle it. This behavior can be disabled
if 'debug_dataclass_transform' is set to True', for testing purposes.
config_file
parse_toml
get
tool
upydantic-mypy
a__slots__
config
uConfiguration value must be a boolean for key:

aConfigParser
read
getboolean
aCONFIGFILE_KEY
D afallback
FuReturns a dict of config names to their values.
aTypeType
item
aCallableType
ret_type
aInstance
uctx.type:
u (of type
a__name__
w)aerror_unexpected_behavior
context
default_return_type
metadata
aMETADATA_KEY
T afrom_attributes
error_from_attributes
name
uRaise an error if from_attributes is not enabled.
ufrom_attributes_callback.<locals>.<genexpr>
alias
is_frozen
has_dynamic_alias
has_default
strict
line
column
to_var
expand_type
aAnyType
aTypeOfAny
explicit
aArgument
aARG_OPT
aARG_NAMED_OPT
aARG_NAMED
T avariable
type_annotation
initializer
kind
uBased on mypy.plugins.dataclasses.DataclassAttribute.to_argument.
aTypeVarType
copy_modified
aINVARIANT
variance
self_type
state
strict_optional_set
options
strict_optional
a__enter__
a__exit__
fill_typevars
args
id
T nnnuBased on mypy.plugins.dataclasses.DataclassAttribute.expand_type.
aVar
uBased on mypy.plugins.dataclasses.DataclassAttribute.to_var.
serialize
uBased on mypy.plugins.dataclasses.DataclassAttribute.serialize.
copy
deserialize_and_fixup_type
pop
T atype
uBased on mypy.plugins.dataclasses.DataclassAttribute.deserialize.
map_type_from_supertype
uExpands type vars in the context of a subtype when an attribute is inherited
from a generic super type.
a_cls
a_reason
a_api
:nq nacollect_config
collect_fields_and_class_vars
add_initializer
add_model_construct_method
set_frozen
frozen
T afrozen
adjust_decorator_signatures
fields
class_vars
get_values_dict
uConfigures the BaseModel subclass according to the plugin settings.
In particular:
* determines the model config and fields,
* adds a fields-aware signature for the initializer and construct methods
* freezes the class if frozen = True
* stores the fields, config, and if the class is settings in the mypy metadata for access by subclasses
aROOT_MODEL_FULLNAME
uPydanticModelTransformer.transform.<locals>.<genexpr>
aBASESETTINGS_FULLNAME
names
values
aDecorator
original_decorators
aCallExpr
callee
aNameExpr
aDECORATOR_FULLNAMES
aMODEL_VALIDATOR_FULLNAME
func
is_class
uWhen we decorate a function `f` with `pydantic.validator(...)`, `pydantic.field_validator`
or `pydantic.serializer(...)`, mypy sees `f` as a regular method taking a `self` instance,
even though pydantic internally wraps `f` with `classmethod` if necessary.
Teach mypy this by marking any function whose outermost decorator is a `validator()`,
`field_validator()` or `serializer()` call as a `classmethod`.
first_dec
arg_names
mode
aStrExpr
value
after
uPydanticModelTransformer.adjust_decorator_signatures.<locals>.<genexpr>
aModelConfigData
keywords
items
self
get_config_update
update
defs
body
aAssignmentStmt
aClassDef
lvalues
model_config
rvalue
D alax_extra
taDictExpr
aConfig
has_config_kwargs
fail
uSpecifying config in two places is ambiguous, use either Config attribute or class kwargs
has_config_from_namespace
stmt
has_alias_generator
populate_by_name
warn_required_dynamic_aliases
error_required_dynamic_aliases
:l nnaadd_plugin_dependency
make_wildcard_trigger
setdefault
uCollects the values of the config attributes that are used by the plugin, accounting for parent classes.
:l q naPydanticModelField
deserialize
expand_typevar_from_subtype
found_fields
uBaseModel field may only be overridden by another field
aPydanticModelClassVar
found_class_vars
a_get_assignment_statements_from_block
collect_field_or_class_var_from_stmt
root
error_extra_fields_on_root_model
current_field_names
add
current_class_vars_names
uCollects the fields for the model, accounting for parent classes.
is_unreachable
else_body
a_get_assignment_statements_from_if_statement
uPydanticModelTransformer._get_assignment_statements_from_if_statement
block
aIfStmt
uPydanticModelTransformer._get_assignment_statements_from_block
a_fields
is_valid_field_name
new_syntax
error_untyped_fields
aPlaceholderNode
aTypeAlias
uType aliases inside BaseModel definitions are not supported at runtime
is_classvar
get_proper_type
udataclasses.InitVar
uInitVar is not supported in BaseModel
get_has_default
get_strict
is_final
is_inferred
analyze_simple_literal_type
D ais_final
tuNeed type argument for Final[...] with non-literal default in BaseModel
from_error
get_alias_info
is_field_frozen
a_infer_dataclass_attr_init_type
T
name
has_dynamic_alias
has_default
strict
alias
is_frozen
line
column
type
info
uGet pydantic model field from statement.
Args:
stmt: The statement.
model_config: Configuration settings for the model.
class_vars: ClassVars already known to be defined on the model.
Returns:
A pydantic model field if it could find the field in statement. Otherwise, `None`.
implicit
T a__set__
aFuncDef
get_containing_type_info
unannotated
arg_kinds
aARG_POS
expand_type_by_instance
arg_types
l uUnsupported signature for "__set__" in "
w"uUnsupported "__set__" in "
uInfer __init__ argument type for an attribute.
In particular, possibly use the signature of __set__.
plugin_generated
init_typed
get_field_arguments
T atyped
model_strict
requires_dynamic_aliases
use_alias
is_settings
is_root_model
force_typevars_invariant
startswith
T a__
T w_aanal_type
func_type
append
should_init_forbid_extra
T akwargs
aARG_STAR2
add_method
aNoneType
T aargs
return_type
uAdds a fields-aware `__init__` method to the class.
The added `__init__` will be annotated with types vs. all `Any` depending on the plugin settings.
named_type
aBUILTINS_NAME
u.set
u.str
aUnionType
a_fields_set
T atyped
model_strict
requires_dynamic_aliases
use_alias
is_settings
is_root_model
model_construct
T aargs
return_type
is_classmethod
uAdds a fully typed `model_construct` classmethod to the class.
Similar to the fields-aware __init__ method, but always uses the field names (not aliases),
nd does not treat settings fields as optional.
is_property
final_iteration
defer
usym_node.node:
D ause_alias
Fw.a_fullname
aSymbolTableNode
aMDEF
uMarks all fields as properties so that attempts to set them trigger mypy errors.
This is the same approach used by the attrs and dataclasses plugins.
tracked_config_fields
extra
forbid
aMemberExpr
error_invalid_config_value
T aforbid_extra
alias_generator
ubuiltins.None
T ahas_alias_generator
T ubuiltins.True
ubuiltins.False
ubuiltins.True
uDetermines the config update due to a single kwarg in the ConfigDict definition.
Warns if a tracked config attribute is set to a value the plugin doesn't know how to interpret (e.g., an int)
aTempNode
aRefExpr
aFIELD_FULLNAME
default
aEllipsisExpr
default_factory
uReturns a boolean indicating whether the field defined in `stmt` is a required field.
ubuiltins.False
uReturns a the `strict` value of a field if defined, otherwise `None`.
T nFT ntuReturns a pair (alias, has_dynamic_alias), extracted from the declaration of the field defined in `stmt`.
`has_dynamic_alias` is True if and only if an alias is provided, but not as a string literal.
If `has_dynamic_alias` is True, `alias` will be None.
uReturns whether the field is frozen, extracted from the declaration of the field defined in `stmt`.
Note that this is only whether the field was declared to be frozen in a `<field_name> = Field(frozen=True)`
sense; this does not determine whether the field is frozen because the entire model is frozen; that is
handled separately.
use_alias
to_argument
typed
model_strict
force_typevars_invariant
T atyped
model_strict
force_optional
use_alias
api
force_typevars_invariant
is_root_model_root
uHelper function used during the construction of the `__init__` and `model_construct` method signatures.
Returns a list of mypy Argument instances for use in the generated signatures.
is_dynamic_alias_present
forbid_extra
init_forbid_extra
uIndicates whether the generated `__init__` should get a `**kwargs` at the end of its signature.
We disallow arbitrary kwargs if the extra config setting is "forbid", or if the plugin config says to,
*unless* a required dynamic alias is present (since then we can't determine a valid signature).
uReturns whether any fields on the model have a "dynamic alias", i.e., an alias that cannot be
determined during static analysis.
from_attributes
uReturns a dict of Pydantic model config names to their values.
It includes the config if config value is not `None`.
uUpdate Pydantic model config values.
uSet default value for Pydantic model config if config value is `None`.
u" does not have from_attributes=True
aERROR_ORM
T acode
uEmits an error when the model does not have `from_attributes=True`.
uInvalid value for "Config.
aERROR_CONFIG
uEmits an error when the config value is invalid.
uRequired dynamic aliases disallowed
aERROR_ALIAS
uEmits required dynamic aliases error.
This will be called when `warn_required_dynamic_aliases=True`.
uThe pydantic mypy plugin ran into unexpected behavior:
w
uPlease consider reporting this bug at https://github.com/pydantic/pydantic/issues/new/choose so we can try to fix it!
aERROR_UNEXPECTED
uEmits unexpected behavior error.
uUntyped fields disallowed
aERROR_UNTYPED
uEmits an error when there is an untyped field in the model.
uOnly `root` is allowed as a field of a `RootModel`
aERROR_EXTRA_FIELD_ROOT_MODEL
uEmits an error when there is more than just a root field defined for a subclass of RootModel.
remove
aSemanticAnalyzerPluginInterface
T ubuiltins.function
named_generic_type
ubuiltins.function
T a_cls
T a__pydantic_self__
T L
ppatype_annotation
T uAll arguments must be fully typed.
variable
kind
variables
aBlock
aPassStmt
set_callable_name
get_unique_redefinition_name
is_decorated
is_classmethod
T aclassmethod
defn
uVery closely related to `mypy.plugins.common.add_method_to_class`, with a few pydantic-specific changes.
T u.toml
tomli
warnings
warn
T uNo TOML parser installed, cannot read configuration from `pyproject.toml`.
rb
load
uReturns a dict of config keys to values.
It reads configs from toml file and returns `None` if the file is not a toml file.
uThis module includes classes and functions designed specifically for use with the mypy plugin.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
sys
configparser
T aConfigParser
aAny
aCallable
aIterator
umypy.errorcodes
T aErrorCode
aErrorCode
umypy.expandtype
T aexpand_type
expand_type_by_instance
umypy.nodes
T aARG_NAMED
aARG_NAMED_OPT
aARG_OPT
aARG_POS
aARG_STAR2
aINVARIANT
aMDEF
aArgument
aAssignmentStmt
aBlock
aCallExpr
aClassDef
aContext
aDecorator
aDictExpr
aEllipsisExpr
aExpression
aFuncDef
aIfStmt
aJsonDict
aMemberExpr
aNameExpr
aPassStmt
aPlaceholderNode
aRefExpr
aStatement
aStrExpr
aSymbolTableNode
aTempNode
aTypeAlias
aTypeInfo
aVar
aContext
aExpression
aJsonDict
aStatement
umypy.options
T aOptions
aOptions
umypy.plugin
T aCheckerPluginInterface
aClassDefContext
aMethodContext
aPlugin
aReportConfigContext
aSemanticAnalyzerPluginInterface
aCheckerPluginInterface
aClassDefContext
aMethodContext
aPlugin
aReportConfigContext
umypy.plugins.common
T adeserialize_and_fixup_type
umypy.semanal
T aset_callable_name
umypy.server.trigger
T amake_wildcard_trigger
umypy.state
T astate
umypy.typeops
T amap_type_from_supertype
umypy.types
T
aAnyType
aCallableType
aInstance
aNoneType
aType
aTypeOfAny
aTypeType
aTypeVarType
aUnionType
get_proper_type
aType
umypy.typevars
T afill_typevars
umypy.util
T aget_unique_redefinition_name
umypy.version
T a__version__
a__version__
mypy_version
upydantic._internal
T a_fields
upydantic.version
T aparse_mypy_version
parse_mypy_version
upydantic-mypy-metadata
upydantic.main.BaseModel
upydantic_settings.main.BaseSettings
upydantic.root_model.RootModel
upydantic._internal._model_construction.ModelMetaclass
upydantic.fields.Field
upydantic.dataclasses.dataclass
aDATACLASS_FULLNAME
upydantic.functional_validators.model_validator
S upydantic.functional_validators.field_validator
upydantic.functional_serializers.model_serializer
upydantic.deprecated.class_validators.validator
upydantic.deprecated.class_validators.root_validator
upydantic.functional_serializers.serializer
upydantic.functional_validators.model_validator
aMYPY_VERSION_TUPLE
builtins
D aversion
return
str
utype[Plugin]
plugin
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
a__validators__
a__cls_kwargs__
nnupydantic.v1.main
nna__model_name
a__base__
T Ostr
aAnyClassMethod
a__cls_kwargs__
field_definitions
create_model
a__validators__
a__cls_kwargs__
a__slots__
nnupydantic.v1.main
nnnT Ostr
Q
model
aModelOrDc
upydantic\v1\main.py
T a.0
wkaself
T a.0
wiav_
value_exclude
value_include
cls
to_dict
by_alias
exclude_unset
exclude_defaults
exclude_none
T a.0
allowed_type
T a__class__
T wxT askip_on_failure_and_v
T wvu<module pydantic.v1.main>
T aself
other
T acls
T aself
private_attrs
T a__pydantic_self__
data
values
fields_set
validation_error
weT aself
instance
a__class__
T aself
T+amcs
name
bases
namespace
kwargs
fields
validators
private_attributes
base_private_attributes
slots
class_vars
hash_func
allowed_config_kwargs
config
pre_root_validators
post_root_validators
base
resolve_forward_refs
config_kwargs
config_from_namespace
vg
wfaextra_validators
untouched_types
is_untouched
annotations
ann_name
ann_type
value
allowed_types
var_name
can_be_changed
inferred
a_custom_root_type
json_encoder
pre_rv_new
post_rv_new
exclude_from_namespace
new_namespace
cls
obj
set_name
a__class__
T aself
name
value
new_values
validator
exc
known_field
dict_without_original_value
error_
errors
skip_on_failure
T aself
state
name
value
T acls
localns
T aself
include
exclude
exclude_unset
update
keys
T aself
values
fields_set
deep
cls
wmaname
value
T acls
obj
Tacls
wvato_dict
by_alias
include
exclude
exclude_unset
exclude_defaults
exclude_none
v_dict
value_exclude
value_include
seq_args
T aself
name
private_attr
default
T aself
to_dict
by_alias
include
exclude
exclude_unset
exclude_defaults
exclude_none
allowed_keys
value_exclude
value_include
field_key
wvamodel_field
dict_key
T acls
a_fields_set
values
fields_values
wmaname
field
T aself
include
exclude
update
deep
values
fields_set
T a__model_name
a__config__
a__validators__
a__cls_kwargs__
a__slots__
field_definitions
namespace
fields
annotations
f_name
f_def
f_annotation
f_value
wearesolved_bases
meta
ns
kwds
T a__model_name
a__config__
a__validators__
a__cls_kwargs__
field_definitions
T aself
include
exclude
by_alias
skip_defaults
exclude_unset
exclude_defaults
exclude_none
T acls
obj
wmavalues
fields_set
validation_error
T afrozen
hash_function
T aself_
T wvauntouched_types
T auntouched_types
T aself
include
exclude
by_alias
skip_defaults
exclude_unset
exclude_defaults
exclude_none
encoder
models_as_dict
dumps_kwargs
data
T acls
path
content_type
encoding
proto
allow_pickle
obj
T acls
obj
weaexc
T acls
wbacontent_type
encoding
proto
allow_pickle
obj
weT acls
by_alias
ref_template
cached
wsT acls
by_alias
ref_template
dumps_kwargs
pydantic_encoder
T acls
value
deep_copy
copy_on_model_validation
value_as_dict
weT afields
T amodel
input_data
cls
values
errors
names_used
fields_set
config
check_extra
cls_
validator
exc
name
field
value
using_name
v_
errors_
extra
wfaskip_on_failure
a__spec__
.pydantic.v1.networks
d a_url_regex_cache
re
compile
a_scheme_regex

a_user_info_regex
a_host_regex
a_path_regex
a_query_regex
a_fragment_regex
aIGNORECASE
a_multi_host_url_regex_cache
u(?P<hosts>([^/]*))

Compiled multi host url regex.
Additionally to `url_regex` it allows to match multiple hosts.
E.g. host1.db.net,host2.db.net
a_ascii_domain_regex_cache
u(?:[_0-9a-z](?:[-_0-9a-z]{0,61}[_0-9a-z])?\.)*?[_0-9a-z](?:[-_0-9a-z]{0,61}[_0-9a-z])?(?P<tld>\.[a-z]{2,63})?\.?
a_int_domain_regex_cache
u(?:[_0-9a-\U00040000](?:[-_0-9a-\U00040000]{0,61}[_0-9a-\U00040000])?\.)*?[_0-9a-\U00040000](?:[-_0-9a-\U00040000]{0,61}[_0-9a-\U00040000])?(?P<tld>(\.[^\W\d_]{2,63})|(\.(?:xn--)[_0-9a-z-]{2,63}))?\.?
a_host_regex_cache
a__new__
build
a__init__
scheme
user
password
host
tld
host_type
port
path
query
fragment
aParts
u://
w:w@ahidden_parts
get_default_parts
get
T aport
w?w#aupdate_not_none
min_length
max_length
uri
T aminLength
maxLength
format
cls
validate
a__get_validators__
uAnyUrl.__get_validators__
str_validator
strip_whitespace
strip
cast
constr_length_validator
a_match_url
T uURL regex failed unexpectedly
groupdict
apply_default_parts
validate_parts
end
errors
aUrlExtraError
T aextra
a_build_url
validate_host
T
scheme
user
password
host
tld
host_type
port
path
query
fragment

Validate hosts and build the AnyUrl object. Split from `validate` so this method
can be altered in `MultiHostDsn`.
url_regex
match
l   aUrlPortError
aUrlSchemeError
allowed_schemes
lower
aUrlSchemePermittedError
a_validate_port
user_required
aUrlUserInfoError

A method used to validate parts of a URL.
Could be overridden to set default values for parts if missing
T nnFT adomain
ipv4
ipv6
host_required
aUrlHostError
domain
ascii_domain_regex
fullmatch
int_domain_regex
group
T atld
:l nnatld_required
aUrlHostTldError
int_domain
encode
T aidna
decode
T aascii
items
parts
u,
a__slots__
a__name__
w(a__class__
a__repr__
w)aself
w=u<genexpr>
uAnyUrl.__repr__.<locals>.<genexpr>
http
u80
u443
hosts
multi_host_url_regex
D avalidate_port
Fahost_regex
split
T w,ahost_re
hosts_parts
rebuild
T ascheme
user
password
path
query
fragment
host_type
hosts
ipv4
ipv6
localhost
u6379
u/0
D aport
u27017
D adomain
port
localhost
u9092
aUrlValue
aAnyUrl
upydantic.v1.networks
email_validator
uemail-validator is not installed, run `pip install pydantic[email]`
update
T astring
email
T atype
format
import_email_validator
uEmailStr.__get_validators__
validate_email
name
email
aNameEmail
T astring
uname-email
uNameEmail.__get_validators__
u <
w>T astring
ipvanyaddress
uIPvAnyAddress.__get_validators__
aIPv4Address
aIPv6Address
aIPvAnyAddressError
T astring
ipvanyinterface
uIPvAnyInterface.__get_validators__
aIPv4Interface
aIPv6Interface
aIPvAnyInterfaceError
T astring
ipvanynetwork
uIPvAnyNetwork.__get_validators__
aIPv4Network
aIPv6Network
aIPvAnyNetworkError
aMAX_EMAIL_LENGTH
aEmailError
pretty_email_regex
groups
value
D acheck_deliverability
FaEmailNotValidError
normalized
local_part
index
T w@u
Email address validation using https://pypi.org/project/email-validator/
Notes:
* raw ip address (literal) domain parts are not allowed.
* "John Doe <local_part@domain.com>" style "pretty" email addresses are processed
* spaces are striped from the beginning and end of addresses but no error is raised
a__doc__
a__file__
origin
has_location
a__cached__
ipaddress
T aIPv4Address
aIPv4Interface
aIPv4Network
aIPv6Address
aIPv6Interface
aIPv6Network
a_BaseAddress
a_BaseNetwork
a_BaseAddress
a_BaseNetwork
aTYPE_CHECKING
aAny
aCollection
aDict
aGenerator
aList
aMatch
aOptional
aPattern
aSet
aTuple
aType
aUnion
no_type_check
upydantic.v1
T aerrors
upydantic.v1.utils
T aRepresentation
update_not_none
aRepresentation
upydantic.v1.validators
T aconstr_length_validator
str_validator
T Odict
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
