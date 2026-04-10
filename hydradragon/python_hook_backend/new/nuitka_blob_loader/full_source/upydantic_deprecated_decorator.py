# Reconstructed from integrated Nuitka blob
# Module: upydantic.deprecated.decorator

uValidatedFunction.create_model.<locals>.DecoratorBaseModel
a__qualname__
field_validator
D acheck_fields
Faclassmethod
wvaOptional
check_args
uValidatedFunction.create_model.<locals>.DecoratorBaseModel.check_args
str
check_kwargs
uValidatedFunction.create_model.<locals>.DecoratorBaseModel.check_kwargs
check_positional_only
uValidatedFunction.create_model.<locals>.DecoratorBaseModel.check_positional_only
check_duplicate_kwargs
uValidatedFunction.create_model.<locals>.DecoratorBaseModel.check_duplicate_kwargs
config_wrapper
model_config
a__orig_bases__
to_pascal
a__base__
pos_args
u positional arguments expected but
u given
wsu,
repr
uunexpected keyword argument
u:
upositional-only argument
u passed as keyword argument
umultiple values for argument
a__doc__
a__file__
origin
has_location
a__cached__
aTYPE_CHECKING
aCallable
aMapping
aType
aTypeVar
aUnion
overload
typing_extensions
T adeprecated
deprecated
a_internal
T a_config
a_typing_extra
l aalias_generators
T ato_pascal
upydantic.errors
upydantic.functional_validators
upydantic.main
upydantic.warnings
aDeprecationWarning
T avalidate_arguments
a__all__
T nD aconfig
nafunc
aConfigType
T L aAnyCallableT
aAnyCallableT
D afunc
return
aAnyCallableT
aAnyCallableT
T uThe `validate_arguments` method is deprecated; use `validate_call` instead.
nT acategory
aAnyCallableT
v__args
v__kwargs
v__positional_only
v__duplicate_kwargs
D afunction
config
aAnyCallable
aConfigType
a__init__
uValidatedFunction.__init__
uValidatedFunction.init_model_instance
uValidatedFunction.call
uValidatedFunction.build_values
uValidatedFunction.execute
uValidatedFunction.create_model
upydantic\deprecated\decorator.py
u<module pydantic.deprecated.decorator>
T a__class__
self
config_wrapper
T a__class__
T aself
function
config
parameters
fields
aParameter
signature
type_hints
takes_args
takes_kwargs
wianame
wpaannotation
default
T aself
args
kwargs
values
var_kwargs
arg_iter
wiwaaarg_name
wrong_positional_args
duplicate_kwargs
fields_alias
non_var_fields
wkwvT aself
args
kwargs
wmT acls
wvatakes_args
pos_args
T apos_args
takes_args
T acls
wvaplural
keys
T acls
wvaplural
keys
takes_kwargs
T atakes_kwargs
T aself
fields
takes_args
takes_kwargs
config
pos_args
config_wrapper
aDecoratorBaseModel
T	aself
wmaargs_
wdavar_kwargs
in_kwargs
kwargs
name
value
T aself
args
kwargs
values
T a_func
vd
wrapper_function
config
T aconfig
T afunc
T afunc
config
T afunc
config
validate
T aargs
kwargs
vd
T avd
a__spec__
.pydantic.deprecated.json
isoformat
as_tuple
exponent
uEncodes a Decimal as int of there's no exponent, otherwise float.
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
warnings
warn
aPydanticDeprecatedSince20
l T u`pydantic_encoder` is deprecated, use `pydantic_core.to_jsonable_python` instead.
T acategory
stacklevel
dataclasses
T aasdict
is_dataclass
asdict
is_dataclass
import_cached_base_model
model_dump
a__mro__
:nq naENCODERS_BY_TYPE
uObject of type '
a__name__

u' is not JSON serializable
T u`custom_pydantic_encoder` is deprecated, use `BaseModel.model_dump` instead.
pydantic_encoder
T u`timedelta_isoformat` is deprecated.
seconds
l<adays
w-wPaDT
wdwHwMw.amicroseconds
u06d
wSuISO 8601 encoding for Python timedelta object.
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
aTYPE_CHECKING
aAny
aCallable
aDict
aType
aUnion
uuid
T aUUID
aUUID
typing_extensions
T adeprecated
deprecated
u_internal._import_utils
T aimport_cached_base_model
color
T aColor
aColor
upydantic.networks
aNameEmail
upydantic.types
aSecretBytes
aSecretStr
upydantic.warnings
aDeprecationWarning
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
T u`pydantic_encoder` is deprecated, use `pydantic_core.to_jsonable_python` instead.
nT acategory
obj
T u`custom_pydantic_encoder` is deprecated, use `BaseModel.model_dump` instead.
natype_encoders
custom_pydantic_encoder
T u`timedelta_isoformat` is deprecated.
natd
timedelta_isoformat
upydantic\deprecated\json.py
T woT atd
u<module pydantic.deprecated.json>
T atype_encoders
obj
base
encoder
T adec_value
exponent
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
.pydantic.deprecated.parse
I
warnings
warn
aPydanticDeprecatedSince20
l T u`load_str_bytes` is deprecated.
T acategory
stacklevel
endswith
T T ajson
javascript
T apickle
aProtocol
pickle
uUnknown content-type:

json
decode
uTrying to decode with pickle with allow_pickle=False
encode
loads
uUnknown protocol:
T u`load_file` is deprecated.
aPath
read_bytes
suffix
T u.js
u.json
u.pkl
load_str_bytes
T aproto
content_type
encoding
allow_pickle
json_loads
a__doc__
a__file__
origin
has_location
a__cached__
annotations
enum
T aEnum
aEnum
pathlib
T aPath
aTYPE_CHECKING
aAny
aCallable
typing_extensions
T adeprecated
deprecated
upydantic.warnings
aDeprecationWarning
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
