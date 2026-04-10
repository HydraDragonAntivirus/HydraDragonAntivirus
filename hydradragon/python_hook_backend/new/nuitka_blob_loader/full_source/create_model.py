# Reconstructed from integrated Nuitka blob
# Module: create_model

a__validators__
a__cls_kwargs__
D a__resolve_forward_refs__
Facached_property
items
a_is_field_cached_property
validate_model
T acls
update
a__fields__
get
validate
T aloc
cls
aValidationError
is_dataclass
issuperset
a__annotations__

Whether a class is a stdlib dataclass
(useful to discriminated a pydantic dataclass that is actually a wrapper around a stdlib dataclass)
we check that
- `_cls` is a dataclass
- `_cls` is not a processed pydantic dataclass (with a basemodel attached)
- `_cls` is not a pydantic dataclass inheriting directly from a stdlib dataclass
e.g.
```
@dataclasses.dataclass
class A:
x: int
@pydantic.dataclasses.dataclass
class B(A):
y: int
```
In this case, when we first check `B`, we make an extra check and look at the annotations ('y'),
which won't be a superset of all the dataclass fields (only the stdlib fields i.e. 'x')

Create a pydantic.dataclass from a builtin dataclass to add type validation
nd yield the validators
It retrieves the parameters of the dataclass and forwards them to the newly created dataclass
T aconfig
use_proxy
make_dataclass_validator

The main purpose is to enhance stdlib dataclasses by adding validation
A pydantic dataclass can be generated from scratch or from a stdlib one.
Behind the scene, a pydantic dataclass is just like a regular one on which we attach
a `BaseModel` and magic methods to trigger the validation of the data.
`__init__` and `__post_init__` are hence overridden and have extra logic to be
ble to validate input data.
When a pydantic dataclass is generated from scratch, it's just a plain dataclass
with validation triggered at initialization
The tricky part if for stdlib dataclasses that are converted after into pydantic ones e.g.
```py
@dataclasses.dataclass
class M:
x: int
ValidatedM = pydantic.dataclasses.dataclass(M)
```
We indeed still want to support equality, hashing, repr, ... as if it was the stdlib one!
```py
ssert isinstance(ValidatedM(x=1), M)
ssert ValidatedM(x=1) == M(x=1)
```
This means we **don't want to create a new dataclass that inherits from it**
The trick is to create a wrapper around `M` that will act as a proxy to trigger
validation without altering default `M` behaviour.
a__file__
origin
has_location
a__cached__
sys
contextlib
T acontextmanager
contextmanager
aTYPE_CHECKING
aCallable
aClassVar
aDict
aGenerator
aOptional
aTypeVar
aUnion
overload
typing_extensions
T adataclass_transform
dataclass_transform
upydantic.v1.class_validators
T agather_all_validators
upydantic.v1.config
T aBaseConfig
aConfigDict
aExtra
get_config
aBaseConfig
aConfigDict
upydantic.v1.error_wrappers
T aValidationError
upydantic.v1.errors
T aDataclassTypeError
upydantic.v1.fields
T aField
aFieldInfo
aRequired
aUndefined
upydantic.v1.main
T acreate_model
validate_model
upydantic.v1.utils
T aClassAttribute
L adataclass
set_validation
create_pydantic_model_from_dataclass
is_builtin_dataclass
make_dataclass_validator
a__all__
T a_T
a_T
field
T afield_specifiers
D
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
use_proxy
kw_only
tppFppnnnQ
a_cls
T nD
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
use_proxy
kw_only
tppFppnnnFaDataclassT
upydantic.v1.dataclasses
a__qualname__
a__slots__
uDataclassProxy.__init__
a__call__
uDataclassProxy.__call__
a__getattr__
uDataclassProxy.__getattr__
a_DataclassProxy__name
a_DataclassProxy__value
uDataclassProxy.__setattr__
instance
a__instancecheck__
uDataclassProxy.__instancecheck__
D areturn
aDataclassProxy
a__copy__
uDataclassProxy.__copy__
memo
a__deepcopy__
uDataclassProxy.__deepcopy__
dc_cls_doc
D acls
return
aDataclassClassOrWrapper
aCallableGenerator
wvaBaseModel
D aobj
wkareturn
aDataclass
Ostr
Obool
D aself
return
aDataclass
naCallableGenerator
upydantic\v1\dataclasses.py
u<module pydantic.v1.dataclasses>
T a__class__
T aself
args
kwargs
T aself
T aself
memo
T aself
name
T aself
dc_cls
T aself
instance
T aself
a_DataclassProxy__name
a_DataclassProxy__value
T	adc_cls
config
validate_on_init
dc_cls_doc
init
handle_extra_init
post_init
new_post_init
new_init
T aself
name
value
wdaknown_field
error_
T aself
input_data
wdw_avalidation_error
T aobj
wkT acls
wvT
dc_cls
config
dc_cls_doc
field_definitions
default
default_factory
field_info
model
field
validators
T a_cls
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
use_proxy
kw_only
Ta_cls
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
use_proxy
kw_only
the_config
wrap
T
init
repr
eq
order
unsafe_hash
frozen
config
validate_on_init
use_proxy
kw_only
T aself
args
kwargs
wkwvaconfig
init
T aconfig
init
T a_cls
T adc_cls
config
T aself
args
kwargs
initvars_and_values
wiwfahandle_extra_init
T ahandle_extra_init
T aself
args
kwargs
config
post_init
T aconfig
post_init
T acls
value
original_run_validation
T acls
should_use_proxy
dc_cls_doc
dc_cls
default_validate_on_init
should_validate_on_init
use_proxy
init
repr
eq
order
unsafe_hash
frozen
kw_only
validate_on_init
the_config
T
eq
frozen
init
kw_only
order
repr
the_config
unsafe_hash
use_proxy
validate_on_init
a__spec__
.pydantic.v1.datetime_parse
k
T Oint
Ofloat
uinvalid type; expected

u, string, bytes, int or float
aMAX_NUMBER
datetime
max
min
seconds
aMS_WATERSHED
l  aEPOCH
timedelta
T aseconds
replace
timezone
utc
T atzinfo
wZ:q nnl<:l l nw-T aminutes
date
get_numeric
from_unix_seconds
decode
date_re
match
value
errors
aDateError
groupdict
items

Parse a date/int/float/string and return a datetime.date.
Raise ValueError if the input is well formatted but not a valid date.
Raise ValueError if the input isn't well formatted.
time
l   aTimeError
time_re
microsecond
ljust
T l w0a_parse_timezone
pop
tzinfo

Parse a time/string and return a datetime.time.
Raise ValueError if the input is well formatted but not a valid time.
Raise ValueError if the input isn't well formatted, in particular if it contains an offset.
datetime_re
aDateTimeError

Parse a datetime/int/float/string and return a datetime.datetime.
This function supports time zone offsets. When the input contains one,
the output uses a timezone with a fixed offset from UTC.
Raise ValueError if the input is well formatted but not a valid datetime.
Raise ValueError if the input isn't well formatted.
wfastandard_duration_re
iso8601_duration_re
uinvalid type; expected timedelta, string, bytes, int or float
aDurationError
T asign
w+aget
T amicroseconds
microseconds
startswith
T w-u
Parse a duration int/float/string and return a datetime.timedelta.
The preferred format for durations in Django is '%d %H:%M:%S.%f'.
Also supports ISO 8601 representation.

Functions to parse datetime objects.
We're using regular expressions rather than time.strptime because:
- They provide both validation and parsing.
- They're more flexible for datetimes.
- The date/datetime/time constructors produce friendlier error messages.
Stolen from https://raw.githubusercontent.com/django/django/main/django/utils/dateparse.py at
9718fa2e8abe430c3526a9278dd976443d4ae3c6
Changed to:
* use standard python datetime types not django.utils.timezone
* raise ValueError when regex doesn't match rather than returning None
* support parsing unix timestamps for dates and datetimes
a__doc__
a__file__
origin
has_location
a__cached__
re
T adate
datetime
time
timedelta
timezone
aDict
aOptional
aType
aUnion
upydantic.v1
T aerrors
u(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})
date_expr
u(?P<hour>\d{1,2}):(?P<minute>\d{1,2})(?::(?P<second>\d{1,2})(?:\.(?P<microsecond>\d{1,6})\d{0,6})?)?(?P<tzinfo>Z|[+-]\d{2}(?::?\d{2})?)?$
time_expr
compile
w$u[T ]
T u^(?:(?P<days>-?\d+) (days?, )?)?((?:(?P<hours>-?\d+):)(?=\d+:\d+))?(?:(?P<minutes>-?\d+):)?(?P<seconds>-?\d+)(?:\.(?P<microseconds>\d{1,6})\d{0,6})?$
T u^(?P<sign>[-+]?)P(?:(?P<days>\d+(.\d+)?)D)?(?:T(?:(?P<hours>\d+(.\d+)?)H)?(?:(?P<minutes>\d+(.\d+)?)M)?(?:(?P<seconds>\d+(.\d+)?)S)?)?$
T l  l pg 	     g A   5     T Ostr
Obytes
Oint
Ofloat
aStrBytesIntFloat
native_expected_type
return
T nOint
Ofloat
error
parse_date
parse_time
parse_datetime
parse_duration
upydantic\v1\datetime_parse.py
u<module pydantic.v1.datetime_parse>
T avalue
error
offset_mins
offset
T aseconds
dt
T avalue
native_expected_type
T avalue
number
match
kw
T avalue
kw_
number
match
kw
tzinfo
T avalue
match
kw
sign
kw_
a__spec__
.pydantic.v1.decorator
D a_func
return
aAnyCallable
aAnyCallable
validate
uvalidate_arguments.<locals>.validate

Decorator to validate the arguments passed to a function.
aValidatedFunction
config
wraps
args
aAny
kwargs
return
wrapper_function
uvalidate_arguments.<locals>.validate.<locals>.wrapper_function
vd
init_model_instance
raw_function
model
call
inspect
T aParameter
signature
aParameter
signature
parameters
keys
aALT_V_ARGS
aALT_V_KWARGS
aV_POSITIONAL_ONLY_NAME
aV_DUPLICATE_KWARGS
aConfigError
w"u
u", "
u" and "
u" are not permitted as argument names when using the "
validate_arguments
a__name__
u" decorator
arg_mapping
positional_only_args
v_args_name
v_kwargs_name
get_all_type_hints
items
annotation
empty
default
kind
aPOSITIONAL_ONLY
self
fields
aList
add
aPOSITIONAL_OR_KEYWORD
aKEYWORD_ONLY
aVAR_POSITIONAL
aTuple
aVAR_KEYWORD
aDict
takes_args
takes_kwargs
create_model
build_values
execute
get
values
a__fields__
alias
wrong_positional_args
duplicate_kwargs
var_kwargs
a_iter
wma__fields_set__
default_factory
pop
in_kwargs
args_
