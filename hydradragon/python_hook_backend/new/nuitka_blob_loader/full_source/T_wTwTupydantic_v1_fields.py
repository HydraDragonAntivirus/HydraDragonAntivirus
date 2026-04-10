# Reconstructed from integrated Nuitka blob
# Module: T wTwTupydantic.v1.fields

aUndefinedType
a__qualname__
D areturn
Ostr
aPydanticUndefined
a__repr__
uUndefinedType.__repr__
return
a__copy__
uUndefinedType.__copy__
a__reduce__
uUndefinedType.__reduce__
a__deepcopy__
uUndefinedType.__deepcopy__
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>

Captures extra information about a field.
T adefault
default_factory
alias
alias_priority
title
description
exclude
include
const
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_items
max_items
unique_items
min_length
max_length
allow_mutation
repr
regex
discriminator
extra
D amin_length
max_length
regex
gt
lt
ge
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_items
max_items
unique_items
allow_mutation
nnnnnnnnnnnnnntakwargs
a__init__
uFieldInfo.__init__
D areturn
aReprArgs
a__repr_args__
uFieldInfo.__repr_args__
str
get_constraints
uFieldInfo.get_constraints
from_config
uFieldInfo.update_from_config
D areturn
nuFieldInfo._validate
a__orig_bases__
D adefault_factory
alias
title
description
exclude
include
const
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_items
max_items
unique_items
min_length
max_length
allow_mutation
regex
discriminator
repr
nnnnnnnnnnnnnnnnnnnntnntaAbstractSetIntStr
aMappingIntStrAny
aField
l l l l l l l	l
l l ll uList[{}]
uSet[{}]
uTuple[{}, ...]
uSequence[{}]
uFrozenSet[{}]
uIterable[{}]
uDeque[{}]
uDict[{}]
uDefaultDict[{}]
uCounter[{}]
aModelField
T atype_
outer_type_
annotation
sub_fields
sub_fields_mapping
key_field
validators
pre_validators
post_validators
default
default_factory
required
final
model_config
name
alias
has_alias
field_info
discriminator_key
discriminator_alias
validate_always
allow_none
shape
class_validators
parse_json
aBaseConfig
aBoolUndefined
bool
uModelField.__init__
uModelField.get_default
staticmethod
field_name
value
config
uModelField._get_field_info
classmethod
infer
uModelField.infer
set_config
uModelField.set_config
property
uModelField.alt_alias
uModelField.prepare
uModelField._set_default_and_type
uModelField._type_analysis
uModelField.prepare_discriminated_union_sub_fields
D afor_keys
Fafor_keys
uModelField._create_sub_type
uModelField.populate_validators
D acls
naLocStr
aModelOrDc
aValidateReturn
uModelField.validate
uModelField._validate_sequence_like
uModelField._validate_iterable
uModelField._validate_tuple
uModelField._validate_mapping_like
original
converted
uModelField._get_mapping_value
uModelField._validate_singleton
uModelField._validate_discriminated_union
aValidatorsList
uModelField._apply_validators
is_complex
uModelField.is_complex
uModelField._type_display
uModelField.__repr_args__
T adefault
default_factory
D adefault_factory
nuModelPrivateAttr.__init__
uModelPrivateAttr.get_default
other
a__eq__
uModelPrivateAttr.__eq__
aPrivateAttr

Used to postpone field preparation, while creating recursive generic models.
val
is_finalvar_with_default_val
upydantic\v1\fields.py
T a.0
wsaself
T a.0
wfT a.0
wvu<module pydantic.v1.fields>
T adefault
default_factory
alias
title
description
exclude
include
const
gt
ge
lt
le
multiple_of
allow_inf_nan
max_digits
decimal_places
min_items
max_items
unique_items
min_length
max_length
allow_mutation
regex
discriminator
repr
extra
field_info
T a__class__
T aself
T aself
w_T aself
other
T aself
default
kwargs
T aself
name
type_
class_validators
model_config
default
default_factory
required
final
alias
field_info
T aself
default
default_factory
T aself
field_defaults_to_hide
attrs
T aself
args
T aself
wvavalues
loc
cls
validators
validator
exc
T aself
type_
name
for_keys
class_validators
field_info
w_T afield_name
annotation
value
config
field_info_from_config
field_info
field_infos
T aself
original
converted
original_cls
T aself
default_value
T aself
origin
types_
type_
args
get_validators
T aself
wtT aself
wvavalues
loc
cls
discriminator_value
sub_field
T aself
wvavalues
loc
cls
iterable
T aself
wvavalues
loc
cls
v_iter
exc
result
errors
wkav_
v_loc
key_result
key_errors
value_result
value_errors
T aself
wvavalues
loc
cls
weaerrors
converted
result
wiav_
v_loc
wraee
T	aself
wvavalues
loc
cls
errors
field
value
error
T aself
wvavalues
loc
cls
weaerrors
actual_length
expected_length
result
wiav_
field
v_loc
wraee
T	acls
name
value
annotation
class_validators
config
required
get_annotation_from_field_info
field_info
T aself
aBaseModel
T atype_
val
T aself
class_validators_
get_validators
v_funcs
T aself
sub_fields_mapping
all_aliases
sub_field
wtaalias
discriminator_values
discriminator_value
T aself
config
info_from_config
new_alias
new_alias_priority
new_exclude
new_include
T aself
from_config
attr_name
value
current_value
T aself
wvavalues
loc
cls
errors
a__spec__
.pydantic.v1.json
G
p
isoformat
as_tuple
exponent

Encodes a Decimal as int of there's no exponent, otherwise float
This is useful when we use ConstrainedDecimal to represent Numeric(x,0)
where a integer (but not int typed) is used. Encoding this as a float
results in failed round-tripping between encode and parse.
Our Id type is a prime example of this.
>>> decimal_encoder(Decimal("1.0"))
1.0
>>> decimal_encoder(Decimal("1"))
1
decode
total_seconds
value
pattern
dataclasses
T aasdict
is_dataclass
asdict
is_dataclass
upydantic.v1.main
T aBaseModel
aBaseModel
dict
a__mro__
:nq naENCODERS_BY_TYPE
uObject of type '
a__name__

u' is not JSON serializable
pydantic_encoder
seconds
l<adays
w-wPaDT
wdwHwMw.amicroseconds
u06d
wSu
ISO 8601 encoding for Python timedelta object.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
datetime
collections
T adeque
deque
decimal
T aDecimal
aDecimal
enum
T aEnum
aEnum
ipaddress
T aIPv4Address
aIPv4Interface
aIPv4Network
aIPv6Address
aIPv6Interface
aIPv6Network
aIPv4Address
aIPv4Interface
aIPv4Network
aIPv6Address
aIPv6Interface
aIPv6Network
pathlib
T aPath
aPath
re
T aPattern
aPattern
aGeneratorType
aAny
aCallable
aDict
aType
aUnion
uuid
T aUUID
aUUID
upydantic.v1.color
T aColor
aColor
upydantic.v1.networks
T aNameEmail
aNameEmail
upydantic.v1.types
T aSecretBytes
aSecretStr
aSecretBytes
aSecretStr
T apydantic_encoder
custom_pydantic_encoder
timedelta_isoformat
a__all__
woadate
time
return
dec_value
T Oint
Ofloat
decimal_encoder
u<lambda>
timedelta
obj
type_encoders
custom_pydantic_encoder
td
timedelta_isoformat
upydantic\v1\json.py
T woT atd
u<module pydantic.v1.json>
T atype_encoders
obj
base
encoder
T adec_value
T aobj
asdict
is_dataclass
aBaseModel
base
encoder
T atd
minutes
seconds
hours
a__spec__
.pydantic.v1.main
9
aROOT_KEY

u cannot be mixed with other fields
self_
aAny
return
hash_function
ugenerate_hash_function.<locals>.hash_function
values
aBaseConfig
T L
paget
T a__slots__
T
a_is_base_model_class_defined
aBaseModel
fields
smart_deepcopy
a__fields__
inherit_config
a__config__
config
inherit_validators
a__validators__
validators
pre_root_validators
a__pre_root_validators__
post_root_validators
a__post_root_validators__
base_private_attributes
a__private_attributes__
class_vars
update
a__class_vars__
a__hash__
a__resolve_forward_refs__
startswith
T a__
endswith
keys
kwargs
T aConfig
uSpecifying config in two places is ambiguous, use either Config attribute or class kwargs
extract_validators
aValidatorGroup
set_config
vg
get_validators
name
class_validators
populate_validators
prepare_config
aANNOTATED_FIELD_UNTOUCHED_TYPES
wvais_untouched
