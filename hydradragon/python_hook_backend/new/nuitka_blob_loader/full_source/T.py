# Reconstructed from integrated Nuitka blob
# Module: T

T a__qualname__
T upydantic.main
aBaseModel
resolve_annotations
naitems
is_classvar
add
is_finalvar_with_default_val
namespace
aUndefined
is_valid_field
validate_field_name
bases
is_union
get_origin
get_args
aPyObject
aModelField
infer
T aname
value
annotation
class_validators
config
underscore_attrs_are_private
aPrivateAttr
private_attributes
aUNTOUCHED_TYPES
keep_untouched
aModelPrivateAttr
is_valid_private_name
uPrivate attributes "
u" must not be a valid field name; Use sunder or dunder names, e. g. "_
u" or "__
u__"
T adefault
annotations
lenient_issubclass
type_
uThe type of
w.u differs from the new default value; if you wish to change the type of this field, please use a type annotation
validate_custom_root_type
check_for_unused
json_encoders
partial
custom_pydantic_encoder
pydantic_encoder
extract_root_validators
hash_func
generate_hash_function
frozen
S a__slots__
a__exclude_fields__
field_info
exclude
a__include_fields__
include
unique_list
u<lambda>
uModelMetaclass.__new__.<locals>.<lambda>
T aname_factory
D a__schema_cache__
D
a__json_encoder__
a__custom_root_type__
a__slots__
a__class__
a__new__
aClassAttribute
a__signature__
generate_model_signature
a__init__
a__try_update_forward_refs__
a__set_name__
callable
cls
untouched_types
a__name__
cython_function_or_method
aType
u<genexpr>
uModelMetaclass.__new__.<locals>.<genexpr>
a__instancecheck__

Avoid calling ABC _abc_subclasscheck unless we're pretty sure.
See #3829 and python/cpython#92810
validate_model
object_setattr
a__dict__
uModel values must be a dict; you may not have returned a dictionary from a root validator
a__fields_set__
a_init_private_attributes

Create a new model by parsing and validating input data from keyword arguments.
Raises ValidationError if the input data cannot be parsed to form a valid model.
aDUNDER_ATTRIBUTES
extra
aExtra
allow
w"u" object has no field "
allow_mutation
u" is immutable and does not support item assignment
final
u" object "
u" field is final and does not support reassignment
validate_assignment
self
new_values
T EValueError
ETypeError
EAssertionError
aValidationError
aErrorWrapper
T aloc
u" has allow_mutation set to False and cannot be assigned
validate
T aloc
cls
errors
a__private_attribute_values__
uBaseModel.__getstate__.<locals>.<genexpr>
get_default
warnings
warn
u.dict(): "skip_defaults" is deprecated and replaced by "exclude_unset"
aDeprecationWarning
a_iter
T ato_dict
by_alias
include
exclude
exclude_unset
exclude_defaults
exclude_none

Generate a dictionary representation of the model, optionally specifying which fields to include or exclude.
u.json(): "skip_defaults" is deprecated and replaced by "exclude_unset"
cast
aCallable
json_dumps
default

Generate a JSON representation of the model, `include` and `exclude` arguments as per `dict()`.
`encoder` is an optional function to supply as `default` to json.dumps(), other arguments as per `json.dumps()`.
shape
aMAPPING_LIKE_SHAPES
a_enforce_dict_if_root
T ETypeError
EValueError
u expected dict not
load_str_bytes
json_loads
T aproto
content_type
encoding
allow_pickle
json_loads
T EValueError
ETypeError
EUnicodeDecodeError
parse_obj
load_file
orm_mode
aConfigError
T uYou must have the config attribute orm_mode=True to use from_orm
a_decompose_class
alt_alias
alias
fields_values
required

Creates a new model setting __dict__ and __fields_set__ from trusted or pre-validated data.
Default values are respected, but no other validation is performed.
Behaves as if `Config.extra = 'allow'` was set since it adds all passed values
deepcopy
wmT ato_dict
by_alias
include
exclude
exclude_unset
a_copy_and_set_values
T adeep

Duplicate a model, optionally choose which fields to include, exclude and change.
:param include: fields to include in new model
:param exclude: fields to exclude from new model, as with values this takes precedence over include
:param update: values to change/add in the new model. Note: the data is not validated before creating
the new model: you should trust this data
:param deep: set to `True` to make a deep copy of the model
:return: new model instance
a__schema_cache__
model_schema
T aby_alias
ref_template
upydantic.v1.json
T apydantic_encoder
schema
a__get_validators__
uBaseModel.__get_validators__
copy_on_model_validation
P ashallow
none
deep
u`copy_on_model_validation` should be a string: 'deep', 'shallow' or 'none'
shallow
deep
from_orm
aDictError
aGetterDict
getter_dict
dict
T aby_alias
exclude_unset
exclude_defaults
include
exclude
exclude_none
copy
T ainclude
exclude
aValueItems
value_exclude
is_excluded
value_include
is_included
a_get_value
to_dict
by_alias
exclude_unset
exclude_defaults
for_element
exclude_none
T ato_dict
by_alias
exclude_unset
exclude_defaults
include
exclude
exclude_none
sequence_like
is_namedtuple
aEnum
aConfig
use_enum_values
value
uBaseModel._get_value.<locals>.<genexpr>
update_model_forward_refs
T ENameError

Same as update_forward_refs but will not raise exception
when forward references are not defined.

Try to update ForwardRefs on fields based on this Model, globalns and localns.

so `dict(model)` works
a__iter__
uBaseModel.__iter__
merge
D aintersect
ta_calculate_keys
T ainclude
exclude
exclude_unset
a_missing
uBaseModel._iter
is_true
repr
u__slots__ should not be passed to create_model
aRuntimeWarning
T uto avoid confusion __config__ and __base__ cannot be used together
aModel
ufields may not start with an underscore, ignoring "
