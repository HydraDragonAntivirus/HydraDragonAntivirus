# Reconstructed from integrated Nuitka blob
# Module: a__name__


w.aname
u<stdout>
usys.stdout
u<stdin>
usys.stdin
u<stderr>
usys.stderr
aDecimal
T amax_digits
decimal_places

!!! warning "Discouraged"
This function is **discouraged** in favor of using
[`Annotated`](https://docs.python.org/3/library/typing.html#typing.Annotated) with
[`Field`][pydantic.fields.Field] instead.
This function will be **deprecated** in Pydantic 3.0.
The reason is that `condecimal` returns a type, which doesn't play well with static analysis tools.
=== ":x: Don't do this"
```python
from pydantic import BaseModel, condecimal
class Foo(BaseModel):
bar: condecimal(strict=True, allow_inf_nan=True)
```
=== ":white_check_mark: Do this"
```python
from decimal import Decimal
from typing_extensions import Annotated
from pydantic import BaseModel, Field
class Foo(BaseModel):
bar: Annotated[Decimal, Field(strict=True, allow_inf_nan=True)]
```
A wrapper around Decimal that adds validation.
Args:
strict: Whether to validate the value in strict mode. Defaults to `None`.
gt: The value must be greater than this. Defaults to `None`.
ge: The value must be greater than or equal to this. Defaults to `None`.
lt: The value must be less than this. Defaults to `None`.
le: The value must be less than or equal to this. Defaults to `None`.
multiple_of: The value must be a multiple of this. Defaults to `None`.
max_digits: The maximum number of digits. Defaults to `None`.
decimal_places: The number of decimal places. Defaults to `None`.
llow_inf_nan: Whether to allow infinity and NaN. Defaults to `None`.
```python
from decimal import Decimal
from pydantic import BaseModel, ValidationError, condecimal
class ConstrainedExample(BaseModel):
constrained_decimal: condecimal(gt=Decimal('1.0'))
m = ConstrainedExample(constrained_decimal=Decimal('1.1'))
print(repr(m))
#> ConstrainedExample(constrained_decimal=Decimal('1.1'))
try:
ConstrainedExample(constrained_decimal=Decimal('0.9'))
except ValidationError as e:
print(e.errors())
'''
[
{
'type': 'greater_than',
'loc': ('constrained_decimal',),
'msg': 'Input should be greater than 1.0',
'input': Decimal('0.9'),
'ctx': {'gt': Decimal('1.0')},
'url': 'https://errors.pydantic.dev/2/v/greater_than',
}
]
'''
```
pop
T aanyOf
naupdate
string
uuid
uuid_version
T atype
format
uuid_schema
T aversion
a_check_annotated_type
type
version
D afile
dir
ufile-path
udirectory-path
path_type
path
T aformat
type
file
cast
aWithInfoValidatorFunction
validate_file
dir
validate_directory
new
validate_new
socket
validate_socket
with_info_after_validator_function
is_file
aPydanticCustomError
T apath_not_file
uPath does not point to a file
is_socket
T apath_not_socket
uPath does not point to a socket
is_dir
T apath_not_directory
uPath does not point to a directory
exists
T apath_exists
uPath already exists
parent
T aparent_does_not_exist
uParent directory does not exist
json_schema
T na_secret_value
uGet the secret value.
Returns:
The secret value.
get_secret_value
a_display
w(w)amode
json
u**********
get_origin
get_args
a__orig_bases__
a__bases__
aSecret
inner_type
uCan't get secret type from
u. Please use Secret[<type>], or subclass from Secret[<type>] instead.
generate_schema
D areturn
uSecret[SecretType]
validate_secret_value
uSecret.__get_pydantic_core_schema__.<locals>.validate_secret_value
json_or_python_schema
no_info_wrap_validator_function
no_info_after_validator_function
u<lambda>
uSecret.__get_pydantic_core_schema__.<locals>.<lambda>
a_serialize_secret
D ainfo_arg
when_used
taalways
T apython_schema
json_schema
serialization
cls
a_secret_display
D a_core_schema
handler
return
ucore_schema.CoreSchema
aGetJsonSchemaHandler
aJsonSchemaValue
get_json_schema
u_SecretField.__get_pydantic_core_schema__.<locals>.get_json_schema
a_inner_schema
D astrict
return
bool
aCoreSchema
get_secret_schema
u_SecretField.__get_pydantic_core_schema__.<locals>.get_secret_schema
lax_or_strict_schema
T FT astrict
T tapydantic_js_functions
T alax_schema
strict_schema
metadata
a_utils
update_not_none
D atype
writeOnly
format
string
tapassword
union_schema
is_instance_schema
source
a_error_kind
T acustom_error_type
strict
a_serialize_secret_field
encode
value
validate_digits
validate_luhn_check_digit
:nl nabin
:q nnalast4
validate_brand
brand
validate
T amin_length
max_length
strip_whitespace
uValidate the card number and return a `PaymentCardNumber` instance.
w*uMask all but the last 4 digits of the card number.
Returns:
A masked card number string.
isdigit
T apayment_card_number_digits
uCard number is not all digits
uValidate that the card number is all digits.
l l	asum_
l
T apayment_card_number_luhn
uCard number is not luhn valid
uBased on: https://en.wikipedia.org/wiki/Luhn_algorithm.
w4aPaymentCardBrand
visa
:nl nl3l7amastercard
P u34
u37
amex
other
l u13, 16 or 19
P l l ll apayment_card_number_brand
uLength for a {brand} card must be {required_length}
required_length
uValidate length based on BIN for major brands:
https://en.wikipedia.org/wiki/Payment_card_number#Issuer_identification_number_(IIN).
a_validate
byte_string_pattern
T apattern
int_schema
T l
T age
D acustom_error_type
custom_error_message
byte_size
ucould not parse value and unit from byte string
T Oint
T areturn_schema
byte_string_re
match
T abyte_size
ucould not parse value and unit from byte string
groups
wbabyte_sizes
lower
byte_size_unit
ucould not interpret byte unit: {unit}
unit
l  T wBaKB
aMB
aGB
aTB
aPB
aEB
l  T wBaKiB
aMiB
aGiB
aTiB
aPiB
aEiB
num
divisor
wBu0.0f
u0.1f
uConverts a byte size to a human readable string.
Args:
decimal: If True, use decimal units (e.g. 1000 bytes per KB). If False, use binary units
(e.g. 1024 bytes per KiB).
separator: A string used to split the value and unit. Defaults to an empty string ('').
Returns:
A human readable string representation of the byte size.
uCould not interpret byte unit: {unit}
uConverts a byte size to another unit, including both byte and bit units.
Args:
unit: The unit to convert to. Must be one of the following: B, KB, MB, GB, TB, PB, EB,
KiB, MiB, GiB, TiB, PiB, EiB (byte units) and
bit, kbit, mbit, gbit, tbit, pbit, ebit,
kibit, mibit, gibit, tibit, pibit, eibit (bit units).
Returns:
The byte size in the new unit.
w'u' cannot annotate '
u'.
D acode
uinvalid-annotated-type
date_schema
T apast
T anow_op
date
past
now_op
T afuture
future
uA wrapper for date that adds constraints.
Args:
strict: Whether to validate the date value in strict mode. Defaults to `None`.
gt: The value must be greater than this. Defaults to `None`.
ge: The value must be greater than or equal to this. Defaults to `None`.
lt: The value must be less than this. Defaults to `None`.
le: The value must be less than or equal to this. Defaults to `None`.
Returns:
A date type with the specified constraints.
datetime_schema
T aaware
T atz_constraint
datetime
aware
tz_constraint
T anaive
naive
base64
b64decode
base64_decode
uBase64 decoding error: '{error}'
error
uDecode the data from base64 encoded bytes to original bytes data.
Args:
data: The data to decode.
Returns:
The decoded data.
b64encode
uEncode the data from bytes to a base64 encoded bytes.
Args:
value: The data to encode.
Returns:
The encoded data.
urlsafe_b64decode
urlsafe_b64encode
encoder
get_json_format
bytes
decode
T afunction
uDecode the data using the specified encoder.
Args:
data: The data to decode.
Returns:
The decoded data.
uEncode the data using the specified encoder.
Args:
value: The data to encode.
Returns:
The encoded data.
str
decode_str
encode_str
a__get_pydantic_core_schema__
get_pydantic_core_schema
a__get_pydantic_json_schema__
get_pydantic_json_schema
a__getattribute__
uUse this rather than defining `__get_pydantic_core_schema__` etc. to reduce the number of nested calls.
setdefault
metadata
tag
a_core_utils
aTAGGED_UNION_TAG_KEY
a_typing_extra
origin_is_union
u must be used with a Union type, not
discriminator
upydantic.fields
aField
T adiscriminator
a_convert_schema
union
choices
get
T ametadata
u`Tag` not provided for choice
u used with `Discriminator`
D acode
ucallable-discriminator-no-tag
tagged_union_choices
custom_error_type
T acustom_error_type
custom_error_message
T acustom_error_message
custom_error_context
T acustom_error_context
tagged_union_schema
T aref
T aserialization
T acustom_error_type
custom_error_message
custom_error_context
strict
ref
metadata
serialization
a_JSON_TYPES
int
float
list
dict
u<no type name>
any_schema
T ajson_schema
python_schema
with_default_schema
omit
T aschema
on_error
uThe types module contains custom types used by pydantic.
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
re
T adate
datetime
decimal
T aDecimal
enum
T aEnum
aEnum
pathlib
T aPath
aPath
aTYPE_CHECKING
aAny
aCallable
aClassVar
aDict
aGeneric
aHashable
aIterator
aPattern
aTypeVar
aUnion
T aUUID
aUUID
T aBaseMetadata
aMaxLen
aMinLen
aBaseMetadata
pydantic_core
aCoreSchema
aSchemaSerializer
core_schema
typing_extensions
T aAnnotated
aLiteral
aProtocol
aTypeAlias
aTypeAliasType
deprecated
aLiteral
aProtocol
aTypeAlias
aTypeAliasType
deprecated
a_internal
T a_core_utils
a_fields
a_internal_dataclass
a_typing_extra
a_utils
a_validators
a_internal_dataclass
a_migration
T agetattr_migration
getattr_migration
upydantic.annotated_handlers
aGetCoreSchemaHandler
aGetJsonSchemaHandler
upydantic.errors
upydantic.json_schema
aJsonSchemaValue
upydantic.warnings
aPydanticDeprecatedSince20
T=aStrict
aStrictStr
aSocketPath
conbytes
conlist
conset
confrozenset
constr
aImportString
conint
aPositiveInt
aNegativeInt
aNonNegativeInt
aNonPositiveInt
confloat
aPositiveFloat
aNegativeFloat
aNonNegativeFloat
aNonPositiveFloat
aFiniteFloat
condecimal
aUUID1
aUUID3
aUUID4
aUUID5
aFilePath
aDirectoryPath
aNewPath
aJson
aSecret
aSecretStr
aSecretBytes
aStrictBool
aStrictBytes
aStrictInt
aStrictFloat
aPaymentCardNumber
aByteSize
aPastDate
aFutureDate
aPastDatetime
aFutureDatetime
condate
aAwareDatetime
aNaiveDatetime
aAllowInfNan
aEncoderProtocol
aEncodedBytes
aEncodedStr
aBase64Encoder
aBase64Bytes
aBase64Str
aBase64UrlBytes
aBase64UrlStr
aGetPydanticSchema
aStringConstraints
aTag
aDiscriminator
aJsonValue
aOnErrorOmit
aFailFast
a__all__
T wTwTaPydanticMetadata
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
dataclass
upydantic.types
uUsage docs: https://docs.pydantic.dev/2.10/concepts/strict_mode/#strict-mode-with-annotated-strict
A field metadata class to indicate that a field should be validated in strict mode.
Use this class as an annotation via [`Annotated`](https://docs.python.org/3/library/typing.html#typing.Annotated), as seen below.
Attributes:
strict: Whether to validate the field in strict mode.
Example:
```python
from typing_extensions import Annotated
from pydantic.types import Strict
StrictBool = Annotated[bool, Strict()]
```
a__qualname__
bool
D areturn
int
a__hash__
uStrict.__hash__
aStrictBool
D astrict
gt
ge
lt
le
multiple_of
nnnnnnD astrict
gt
ge
lt
le
multiple_of
return
ubool | None
uint | None
uint | None
uint | None
uint | None
uint | None
utype[int]
conint
aGt
aPositiveInt
aLt
aNegativeInt
aLe
aNonPositiveInt
aGe
aNonNegativeInt
aStrictInt
uA field metadata class to indicate that a field should allow `-inf`, `inf`, and `nan`.
Use this class as an annotation via [`Annotated`](https://docs.python.org/3/library/typing.html#typing.Annotated), as seen below.
Attributes:
llow_inf_nan: Whether to allow `-inf`, `inf`, and `nan`. Defaults to `True`.
Example:
```python
from typing_extensions import Annotated
from pydantic.types import AllowInfNan
LaxFloat = Annotated[float, AllowInfNan()]
uAllowInfNan.__hash__
D astrict
gt
ge
lt
le
multiple_of
allow_inf_nan
nnnnnnnD astrict
gt
ge
lt
le
multiple_of
allow_inf_nan
return
ubool | None
ufloat | None
ufloat | None
ufloat | None
ufloat | None
ufloat | None
ubool | None
utype[float]
confloat
aPositiveFloat
aNegativeFloat
aNonPositiveFloat
aNonNegativeFloat
aStrictFloat
aFiniteFloat
D amin_length
max_length
strict
nnnD amin_length
max_length
strict
return
uint | None
uint | None
ubool | None
utype[bytes]
conbytes
aStrictBytes
aGroupedMetadata
T afrozen
uUsage docs: https://docs.pydantic.dev/2.10/concepts/fields/#string-constraints
A field metadata class to apply constraints to `str` types.
Use this class as an annotation via [`Annotated`](https://docs.python.org/3/library/typing.html#typing.Annotated), as seen below.
Attributes:
strip_whitespace: Whether to remove leading and trailing whitespace.
to_upper: Whether to convert the string to uppercase.
to_lower: Whether to convert the string to lowercase.
strict: Whether to validate the string in strict mode.
min_length: The minimum length of the string.
max_length: The maximum length of the string.
pattern: A regex pattern that the string must match.
Example:
```python
from typing_extensions import Annotated
from pydantic.types import StringConstraints
ConstrainedStr = Annotated[str, StringConstraints(min_length=1, max_length=10)]
```
ubool | None
uint | None
ustr | Pattern[str] | None
D areturn
uIterator[BaseMetadata]
D astrip_whitespace
to_upper
to_lower
strict
min_length
max_length
pattern
nnnnnnnD astrip_whitespace
to_upper
to_lower
strict
min_length
max_length
pattern
return
ubool | None
ubool | None
ubool | None
ubool | None
uint | None
uint | None
ustr | Pattern[str] | None
utype[str]
constr
aStrictStr
T aHashableItemType
T abound
aHashableItemType
D amin_length
max_length
nnD aitem_type
min_length
max_length
return
utype[HashableItemType]
uint | None
uint | None
utype[set[HashableItemType]]
conset
D aitem_type
min_length
max_length
return
utype[HashableItemType]
uint | None
uint | None
utype[frozenset[HashableItemType]]
confrozenset
T aAnyItemType
aAnyItemType
D amin_length
max_length
unique_items
nnnD aitem_type
min_length
max_length
unique_items
return
utype[AnyItemType]
uint | None
uint | None
ubool | None
utype[list[AnyItemType]]
conlist
T aAnyType
aAnyType
uA type that can be used to import a Python object from a string.
`ImportString` expects a string and loads the Python object importable at that dotted path.
Attributes of modules may be separated from the module by `:` or `.`, e.g. if `'math:cos'` is provided,
the resulting field value would be the function `cos`. If a `.` is used and both an attribute and submodule
re present at the same path, the module will be preferred.
On model instantiation, pointers will be evaluated and imported. There is
some nuance to this behavior, demonstrated in the examples below.
```python
import math
from pydantic import BaseModel, Field, ImportString, ValidationError
class ImportThings(BaseModel):
obj: ImportString
# A string value will cause an automatic import
my_cos = ImportThings(obj='math.cos')
# You can use the imported function as you would expect
cos_of_0 = my_cos.obj(0)
ssert cos_of_0 == 1
# A string whose value cannot be imported will raise an error
try:
ImportThings(obj='foo.bar')
except ValidationError as e:
print(e)
'''
1 validation error for ImportThings
obj
Invalid python path: No module named 'foo.bar' [type=import_error, input_value='foo.bar', input_type=str]
'''
# Actual python objects can be assigned as well
my_cos = ImportThings(obj=math.cos)
my_cos_2 = ImportThings(obj='math.cos')
my_cos_3 = ImportThings(obj='math:cos')
ssert my_cos == my_cos_2 == my_cos_3
# You can set default field value either as Python object:
class ImportThingsDefaultPyObj(BaseModel):
obj: ImportString = math.cos
# or as a string value (but only if used with `validate_default=True`)
class ImportThingsDefaultString(BaseModel):
obj: ImportString = Field(default='math.cos', validate_default=True)
my_cos_default1 = ImportThingsDefaultPyObj()
my_cos_default2 = ImportThingsDefaultString()
ssert my_cos_default1.obj == my_cos_default2.obj == math.cos
# note: this will not work!
class ImportThingsMissingValidateDefault(BaseModel):
obj: ImportString = 'math.cos'
my_cos_default3 = ImportThingsMissingValidateDefault()
ssert my_cos_default3.obj == 'math.cos'  # just string, not evaluated
```
Serializing an `ImportString` type to json is also possible.
```python
from pydantic import BaseModel, ImportString
class ImportThings(BaseModel):
obj: ImportString
# Create an instance
m = ImportThings(obj='math.cos')
print(m)
#> obj=<built-in function cos>
print(m.model_dump_json())
#> {"obj":"math.cos"}
```
aImportString
D aitem
return
aAnyType
pa__class_getitem__
uImportString.__class_getitem__
D asource
handler
return
utype[Any]
aGetCoreSchemaHandler
ucore_schema.CoreSchema
uImportString.__get_pydantic_core_schema__
D acs
handler
return
aCoreSchema
aGetJsonSchemaHandler
aJsonSchemaValue
uImportString.__get_pydantic_json_schema__
D wvareturn
aAny
str
uImportString._serialize
D areturn
str
a__repr__
uImportString.__repr__
D	astrict
gt
ge
lt
le
multiple_of
max_digits
decimal_places
allow_inf_nan
nnnnnnnnnD
strict
gt
ge
lt
le
multiple_of
max_digits
decimal_places
allow_inf_nan
return
ubool | None
uint | Decimal | None
uint | Decimal | None
uint | Decimal | None
uint | Decimal | None
uint | Decimal | None
uint | None
uint | None
ubool | None
utype[Decimal]
condecimal
slots_true
uA field metadata class to indicate a [UUID](https://docs.python.org/3/library/uuid.html) version.
Use this class as an annotation via [`Annotated`](https://docs.python.org/3/library/typing.html#typing.Annotated), as seen below.
Attributes:
uuid_version: The version of the UUID. Must be one of 1, 3, 4, or 5.
Example:
```python
from uuid import UUID
from typing_extensions import Annotated
from pydantic.types import UuidVersion
UUID1 = Annotated[UUID, UuidVersion(1)]
```
aUuidVersion
uLiteral[1, 3, 4, 5]
D acore_schema
handler
return
ucore_schema.CoreSchema
aGetJsonSchemaHandler
aJsonSchemaValue
uUuidVersion.__get_pydantic_json_schema__
D asource
handler
return
aAny
aGetCoreSchemaHandler
ucore_schema.CoreSchema
uUuidVersion.__get_pydantic_core_schema__
uUuidVersion.__hash__
T l aUUID1
T l aUUID3
T l aUUID4
T l aUUID5
aPathType
uLiteral['file', 'dir', 'new', 'socket']
uPathType.__get_pydantic_json_schema__
uPathType.__get_pydantic_core_schema__
D apath
w_areturn
aPath
ucore_schema.ValidationInfo
aPath
uPathType.validate_file
uPathType.validate_socket
uPathType.validate_directory
uPathType.validate_new
uPathType.__hash__
T afile
aFilePath
T adir
aDirectoryPath
T anew
aNewPath
T asocket
aSocketPath
uA special type wrapper which loads JSON before parsing.
You can use the `Json` data type to make Pydantic first load a raw JSON string before
validating the loaded data into the parametrized type:
```python
from typing import Any, List
from pydantic import BaseModel, Json, ValidationError
class AnyJsonModel(BaseModel):
json_obj: Json[Any]
class ConstrainedJsonModel(BaseModel):
json_obj: Json[List[int]]
print(AnyJsonModel(json_obj='{"b": 1}'))
#> json_obj={'b': 1}
print(ConstrainedJsonModel(json_obj='[1, 2, 3]'))
#> json_obj=[1, 2, 3]
try:
ConstrainedJsonModel(json_obj=12)
except ValidationError as e:
print(e)
'''
1 validation error for ConstrainedJsonModel
json_obj
JSON input should be string, bytes or bytearray [type=json_type, input_value=12, input_type=int]
'''
try:
ConstrainedJsonModel(json_obj='[a, b]')
except ValidationError as e:
print(e)
'''
1 validation error for ConstrainedJsonModel
json_obj
Invalid JSON: expected value at line 1 column 2 [type=json_invalid, input_value='[a, b]', input_type=str]
'''
try:
ConstrainedJsonModel(json_obj='["a", "b"]')
except ValidationError as e:
print(e)
'''
2 validation errors for ConstrainedJsonModel
json_obj.0
Input should be a valid integer, unable to parse string as an integer [type=int_parsing, input_value='a', input_type=str]
json_obj.1
Input should be a valid integer, unable to parse string as an integer [type=int_parsing, input_value='b', input_type=str]
'''
```
When you dump the model using `model_dump` or `model_dump_json`, the dumped value will be the result of validation,
not the original JSON string. However, you can use the argument `round_trip=True` to get the original JSON string back:
```python
from typing import List
from pydantic import BaseModel, Json
class ConstrainedJsonModel(BaseModel):
json_obj: Json[List[int]]
print(ConstrainedJsonModel(json_obj='[1, 2, 3]').model_dump_json())
#> {"json_obj":[1,2,3]}
print(
ConstrainedJsonModel(json_obj='[1, 2, 3]').model_dump_json(round_trip=True)
)
#> {"json_obj":"[1,2,3]"}
```
aJson
uJson.__class_getitem__
uJson.__get_pydantic_core_schema__
uJson.__repr__
uJson.__hash__
D aother
return
aAny
bool
a__eq__
uJson.__eq__
T aSecretType
aSecretType
a_SecretBase
D asecret_value
return
aSecretType
aNone
a__init__
u_SecretBase.__init__
D areturn
aSecretType
u_SecretBase.get_secret_value
u_SecretBase.__eq__
u_SecretBase.__hash__
a__str__
u_SecretBase.__str__
u_SecretBase.__repr__
D areturn
ustr | bytes
u_SecretBase._display
D avalue
info
return
uSecret[SecretType]
ucore_schema.SerializationInfo
ustr | Secret[SecretType]
uA generic base class used for defining a field with sensitive information that you do not want to be visible in logging or tracebacks.
You may either directly parametrize `Secret` with a type, or subclass from `Secret` with a parametrized type. The benefit of subclassing
is that you can define a custom `_display` method, which will be used for `repr()` and `str()` methods. The examples below demonstrate both
ways of using `Secret` to create a new secret type.
1. Directly parametrizing `Secret` with a type:
```python
from pydantic import BaseModel, Secret
SecretBool = Secret[bool]
class Model(BaseModel):
secret_bool: SecretBool
m = Model(secret_bool=True)
print(m.model_dump())
#> {'secret_bool': Secret('**********')}
print(m.model_dump_json())
#> {"secret_bool":"**********"}
print(m.secret_bool.get_secret_value())
#> True
```
2. Subclassing from parametrized `Secret`:
```python
from datetime import date
from pydantic import BaseModel, Secret
class SecretDate(Secret[date]):
def _display(self) -> str:
return '****/**/**'
class Model(BaseModel):
secret_date: SecretDate
m = Model(secret_date=date(2022, 1, 1))
print(m.model_dump())
#> {'secret_date': SecretDate('****/**/**')}
print(m.model_dump_json())
#> {"secret_date":"****/**/**"}
print(m.secret_date.get_secret_value())
#> 2022-01-01
```
The value returned by the `_display` method will be used for `repr()` and `str()`.
You can enforce constraints on the underlying type through annotations:
For example:
```python
from typing_extensions import Annotated
from pydantic import BaseModel, Field, Secret, ValidationError
SecretPosInt = Secret[Annotated[int, Field(gt=0, strict=True)]]
class Model(BaseModel):
sensitive_int: SecretPosInt
m = Model(sensitive_int=42)
print(m.model_dump())
#> {'sensitive_int': Secret('**********')}
try:
m = Model(sensitive_int=-42)  # (1)!
except ValidationError as exc_info:
print(exc_info.errors(include_url=False, include_input=False))
'''
[
{
'type': 'greater_than',
'loc': ('sensitive_int',),
'msg': 'Input should be greater than 0',
'ctx': {'gt': 0},
}
]
'''
try:
m = Model(sensitive_int='42')  # (2)!
except ValidationError as exc_info:
print(exc_info.errors(include_url=False, include_input=False))
'''
[
{
'type': 'int_type',
'loc': ('sensitive_int',),
'msg': 'Input should be a valid integer',
}
]
'''
```
1. The input value is not greater than 0, so it raises a validation error.
2. The input value is not an integer, so it raises a validation error because the `SecretPosInt` type has strict mode enabled.
uSecret._display
classmethod
uSecret.__get_pydantic_core_schema__
a__pydantic_serializer__
D avalue
return
aSecretType
str
D avalue
info
return
u_SecretField[SecretType]
ucore_schema.SerializationInfo
ustr | _SecretField[SecretType]
a_SecretField
uClassVar[CoreSchema]
uClassVar[str]
u_SecretField.__get_pydantic_core_schema__
aSecretStr
uA string used for storing sensitive information that you do not want to be visible in logging or tracebacks.
When the secret value is nonempty, it is displayed as `'**********'` instead of the underlying value in
calls to `repr()` and `str()`. If the value _is_ empty, it is displayed as `''`.
```python
from pydantic import BaseModel, SecretStr
class User(BaseModel):
username: str
password: SecretStr
user = User(username='scolvin', password='password1')
print(user)
#> username='scolvin' password=SecretStr('**********')
print(user.password.get_secret_value())
#> password1
print((SecretStr('password'), SecretStr('')))
#> (SecretStr('**********'), SecretStr(''))
```
As seen above, by default, [`SecretStr`][pydantic.types.SecretStr] (and [`SecretBytes`][pydantic.types.SecretBytes])
will be serialized as `**********` when serializing to json.
You can use the [`field_serializer`][pydantic.functional_serializers.field_serializer] to dump the
secret as plain-text when serializing to json.
```python
from pydantic import BaseModel, SecretBytes, SecretStr, field_serializer
class Model(BaseModel):
password: SecretStr
password_bytes: SecretBytes
@field_serializer('password', 'password_bytes', when_used='json')
def dump_secret(self, v):
return v.get_secret_value()
model = Model(password='IAmSensitive', password_bytes=b'IAmSensitiveBytes')
print(model)
#> password=SecretStr('**********') password_bytes=SecretBytes(b'**********')
print(model.password)
#> **********
print(model.model_dump())
'''
{
'password': SecretStr('**********'),
'password_bytes': SecretBytes(b'**********'),
}
'''
print(model.model_dump_json())
#> {"password":"IAmSensitive","password_bytes":"IAmSensitiveBytes"}
```
string_type
a__len__
uSecretStr.__len__
uSecretStr._display
aSecretBytes
uA bytes used for storing sensitive information that you do not want to be visible in logging or tracebacks.
It displays `b'**********'` instead of the string value on `repr()` and `str()` calls.
When the secret value is nonempty, it is displayed as `b'**********'` instead of the underlying value in
calls to `repr()` and `str()`. If the value _is_ empty, it is displayed as `b''`.
```python
from pydantic import BaseModel, SecretBytes
class User(BaseModel):
username: str
password: SecretBytes
user = User(username='scolvin', password=b'password1')
#> username='scolvin' password=SecretBytes(b'**********')
print(user.password.get_secret_value())
#> b'password1'
print((SecretBytes(b'password'), SecretBytes(b'')))
#> (SecretBytes(b'**********'), SecretBytes(b''))
```
bytes_schema
bytes_type
uSecretBytes.__len__
D areturn
bytes
uSecretBytes._display
uAmerican Express
aMastercard
aVisa
uPaymentCardBrand.__str__
T Ostr
aPaymentCardNumber
T uThe `PaymentCardNumber` class is deprecated, use `pydantic_extra_types` instead. See https://docs.pydantic.dev/latest/api/pydantic_extra_types_payment/#pydantic_extra_types.payment.PaymentCardNumber.
T acategory
uBased on: https://en.wikipedia.org/wiki/Payment_card_number.
uClassVar[bool]
l uClassVar[int]
l D acard_number
str
uPaymentCardNumber.__init__
uPaymentCardNumber.__get_pydantic_core_schema__
D ainput_value
w_areturn
str
ucore_schema.ValidationInfo
aPaymentCardNumber
uPaymentCardNumber.validate
property
masked
uPaymentCardNumber.masked
D acard_number
return
str
aNone
uPaymentCardNumber.validate_digits
D acard_number
return
str
puPaymentCardNumber.validate_luhn_check_digit
staticmethod
D acard_number
return
str
aPaymentCardBrand
uPaymentCardNumber.validate_brand
aByteSize
uConverts a string representing a number of bytes with units (such as `'1KB'` or `'11.5MiB'`) into an integer.
You can use the `ByteSize` data type to (case-insensitively) convert a string representation of a number of bytes into
n integer, and also to print out human-readable strings representing a number of bytes.
In conformance with [IEC 80000-13 Standard](https://en.wikipedia.org/wiki/ISO/IEC_80000) we interpret `'1KB'` to mean 1000 bytes,
nd `'1KiB'` to mean 1024 bytes. In general, including a middle `'i'` will cause the unit to be interpreted as a power of 2,
rather than a power of 10 (so, for example, `'1 MB'` is treated as `1_000_000` bytes, whereas `'1 MiB'` is treated as `1_048_576` bytes).
!!! info
Note that `1b` will be parsed as "1 byte" and not "1 bit".
```python
from pydantic import BaseModel, ByteSize
class MyModel(BaseModel):
size: ByteSize
print(MyModel(size=52000).size)
#> 52000
print(MyModel(size='3000 KiB').size)
#> 3072000
m = MyModel(size='50 PB')
print(m.size.human_readable())
#> 44.4PiB
print(m.size.human_readable(decimal=True))
#> 50.0PB
print(m.size.human_readable(separator=' '))
#> 44.4 PiB
print(m.size.to('TiB'))
#> 45474.73508864641
```
D wbakb
mb
gb
tb
pb
eb
kib
mib
gib
tib
pib
eib
bit
kbit
mbit
gbit
tbit
pbit
ebit
kibit
mibit
gibit
tibit
pibit
eibit
l l  l  =l     g        g         g           l  l  @l     g
g
g
f
?f
@_@f
@f
e  Af
=Bf
4& k Bf
Ngm {Cf
`@f
Af
Af
@Bf
Bf
Caitems
wiu^\s*(\d*\.?\d+)\s*(\w+)?
compile
aIGNORECASE
uByteSize.__get_pydantic_core_schema__
D ainput_value
w_areturn
aAny
ucore_schema.ValidationInfo
aByteSize
uByteSize._validate
T Fu
D adecimal
separator
return
bool
str
pahuman_readable
uByteSize.human_readable
D aunit
return
str
float
to
uByteSize.to
D aannotated_type
expected_type
annotation
return
str
ppaNone
uA date in the past.
aPastDate
uPastDate.__get_pydantic_core_schema__
uPastDate.__repr__
uA date in the future.
aFutureDate
uFutureDate.__get_pydantic_core_schema__
uFutureDate.__repr__
D astrict
gt
ge
lt
le
nnnnnD astrict
gt
ge
lt
le
return
ubool | None
udate | None
udate | None
udate | None
udate | None
utype[date]
condate
uA datetime that requires timezone info.
aAwareDatetime
uAwareDatetime.__get_pydantic_core_schema__
uAwareDatetime.__repr__
uA datetime that doesn't require timezone info.
aNaiveDatetime
uNaiveDatetime.__get_pydantic_core_schema__
uNaiveDatetime.__repr__
uA datetime that must be in the past.
aPastDatetime
uPastDatetime.__get_pydantic_core_schema__
uPastDatetime.__repr__
uA datetime that must be in the future.
aFutureDatetime
uFutureDatetime.__get_pydantic_core_schema__
uFutureDatetime.__repr__
aEncoderProtocol
uProtocol for encoding and decoding data to and from bytes.
D adata
return
bytes
puDecode the data using the encoder.
Args:
data: The data to decode.
Returns:
The decoded data.
uEncoderProtocol.decode
D avalue
return
bytes
puEncode the data using the encoder.
Args:
value: The data to encode.
Returns:
The encoded data.
uEncoderProtocol.encode
uGet the JSON format for the encoded data.
Returns:
The JSON format for the encoded data.
uEncoderProtocol.get_json_format
aBase64Encoder
uStandard (non-URL-safe) Base64 encoder.
uBase64Encoder.decode
uBase64Encoder.encode
D areturn
uLiteral['base64']
uBase64Encoder.get_json_format
aBase64UrlEncoder
uURL-safe Base64 encoder.
uBase64UrlEncoder.decode
uBase64UrlEncoder.encode
D areturn
uLiteral['base64url']
base64url
uBase64UrlEncoder.get_json_format
uA bytes type that is encoded and decoded using the specified encoder.
`EncodedBytes` needs an encoder that implements `EncoderProtocol` to operate.
```python
from typing_extensions import Annotated
from pydantic import BaseModel, EncodedBytes, EncoderProtocol, ValidationError
class MyEncoder(EncoderProtocol):
@classmethod
def decode(cls, data: bytes) -> bytes:
if data == b'**undecodable**':
raise ValueError('Cannot decode data')
return data[13:]
@classmethod
def encode(cls, value: bytes) -> bytes:
return b'**encoded**: ' + value
@classmethod
def get_json_format(cls) -> str:
return 'my-encoder'
MyEncodedBytes = Annotated[bytes, EncodedBytes(encoder=MyEncoder)]
class Model(BaseModel):
my_encoded_bytes: MyEncodedBytes
# Initialize the model with encoded data
m = Model(my_encoded_bytes=b'**encoded**: some bytes')
# Access decoded value
print(m.my_encoded_bytes)
#> b'some bytes'
# Serialize into the encoded form
print(m.model_dump())
#> {'my_encoded_bytes': b'**encoded**: some bytes'}
# Validate encoded data
try:
Model(my_encoded_bytes=b'**undecodable**')
except ValidationError as e:
print(e)
'''
1 validation error for Model
my_encoded_bytes
Value error, Cannot decode data [type=value_error, input_value=b'**undecodable**', input_type=bytes]
'''
```
aEncodedBytes
utype[EncoderProtocol]
uEncodedBytes.__get_pydantic_json_schema__
uEncodedBytes.__get_pydantic_core_schema__
D adata
w_areturn
bytes
ucore_schema.ValidationInfo
bytes
uEncodedBytes.decode
uEncodedBytes.encode
uEncodedBytes.__hash__
uA str type that is encoded and decoded using the specified encoder.
`EncodedStr` needs an encoder that implements `EncoderProtocol` to operate.
```python
from typing_extensions import Annotated
from pydantic import BaseModel, EncodedStr, EncoderProtocol, ValidationError
class MyEncoder(EncoderProtocol):
@classmethod
def decode(cls, data: bytes) -> bytes:
if data == b'**undecodable**':
raise ValueError('Cannot decode data')
return data[13:]
@classmethod
def encode(cls, value: bytes) -> bytes:
return b'**encoded**: ' + value
@classmethod
def get_json_format(cls) -> str:
return 'my-encoder'
MyEncodedStr = Annotated[str, EncodedStr(encoder=MyEncoder)]
class Model(BaseModel):
my_encoded_str: MyEncodedStr
# Initialize the model with encoded data
m = Model(my_encoded_str='**encoded**: some str')
# Access decoded value
print(m.my_encoded_str)
#> some str
# Serialize into the encoded form
print(m.model_dump())
#> {'my_encoded_str': '**encoded**: some str'}
# Validate encoded data
try:
Model(my_encoded_str='**undecodable**')
except ValidationError as e:
print(e)
'''
1 validation error for Model
my_encoded_str
Value error, Cannot decode data [type=value_error, input_value='**undecodable**', input_type=str]
'''
```
aEncodedStr
uEncodedStr.__get_pydantic_json_schema__
uEncodedStr.__get_pydantic_core_schema__
D adata
w_areturn
str
ucore_schema.ValidationInfo
str
uEncodedStr.decode_str
D avalue
return
str
puEncodedStr.encode_str
uEncodedStr.__hash__
T aencoder
aBase64Bytes
aBase64Str
aBase64UrlBytes
aBase64UrlStr
T upydantic.types
a__getattr__
uUsage docs: https://docs.pydantic.dev/2.10/concepts/types/#using-getpydanticschema-to-reduce-boilerplate
A convenience class for creating an annotation that provides pydantic custom type hooks.
This class is intended to eliminate the need to create a custom "marker" which defines the
`__get_pydantic_core_schema__` and `__get_pydantic_json_schema__` custom hook methods.
For example, to have a field treated by type checkers as `int`, but by pydantic as `Any`, you can do:
```python
from typing import Any
from typing_extensions import Annotated
from pydantic import BaseModel, GetPydanticSchema
HandleAsAny = GetPydanticSchema(lambda _s, h: h(Any))
class Model(BaseModel):
x: Annotated[int, HandleAsAny]  # pydantic sees `x: Any`
print(repr(Model(x='abc').x))
#> 'abc'
```
aGetPydanticSchema
uCallable[[Any, GetCoreSchemaHandler], CoreSchema] | None
uCallable[[Any, GetJsonSchemaHandler], JsonSchemaValue] | None
D aitem
return
str
aAny
uGetPydanticSchema.__getattr__
D afrozen
tuProvides a way to specify the expected tag to use for a case of a (callable) discriminated union.
Also provides a way to label a union case in error messages.
When using a callable `Discriminator`, attach a `Tag` to each case in the `Union` to specify the tag that
should be used to identify that case. For example, in the below example, the `Tag` is used to specify that
if `get_discriminator_value` returns `'apple'`, the input should be validated as an `ApplePie`, and if it
returns `'pumpkin'`, the input should be validated as a `PumpkinPie`.
The primary role of the `Tag` here is to map the return value from the callable `Discriminator` function to
the appropriate member of the `Union` in question.
```python
from typing import Any, Union
from typing_extensions import Annotated, Literal
from pydantic import BaseModel, Discriminator, Tag
class Pie(BaseModel):
time_to_cook: int
num_ingredients: int
class ApplePie(Pie):
fruit: Literal['apple'] = 'apple'
class PumpkinPie(Pie):
filling: Literal['pumpkin'] = 'pumpkin'
def get_discriminator_value(v: Any) -> str:
if isinstance(v, dict):
return v.get('fruit', v.get('filling'))
return getattr(v, 'fruit', getattr(v, 'filling', None))
class ThanksgivingDinner(BaseModel):
dessert: Annotated[
Union[
Annotated[ApplePie, Tag('apple')],
Annotated[PumpkinPie, Tag('pumpkin')],
],
Discriminator(get_discriminator_value),
]
pple_variation = ThanksgivingDinner.model_validate(
{'dessert': {'fruit': 'apple', 'time_to_cook': 60, 'num_ingredients': 8}}
)
print(repr(apple_variation))
'''
ThanksgivingDinner(dessert=ApplePie(time_to_cook=60, num_ingredients=8, fruit='apple'))
'''
pumpkin_variation = ThanksgivingDinner.model_validate(
{
'dessert': {
'filling': 'pumpkin',
'time_to_cook': 40,
'num_ingredients': 6,
}
}
)
print(repr(pumpkin_variation))
'''
ThanksgivingDinner(dessert=PumpkinPie(time_to_cook=40, num_ingredients=6, filling='pumpkin'))
'''
```
!!! note
You must specify a `Tag` for every case in a `Tag` that is associated with a
callable `Discriminator`. Failing to do so will result in a `PydanticUserError` with code
[`callable-discriminator-no-tag`](../errors/usage_errors.md#callable-discriminator-no-tag).
See the [Discriminated Unions] concepts docs for more details on how to use `Tag`s.
[Discriminated Unions]: ../concepts/unions.md#discriminated-unions
aTag
D asource_type
handler
return
aAny
aGetCoreSchemaHandler
aCoreSchema
uTag.__get_pydantic_core_schema__
uUsage docs: https://docs.pydantic.dev/2.10/concepts/unions/#discriminated-unions-with-callable-discriminator
Provides a way to use a custom callable as the way to extract the value of a union discriminator.
This allows you to get validation behavior like you'd get from `Field(discriminator=<field_name>)`,
but without needing to have a single shared field across all the union choices. This also makes it
possible to handle unions of models and primitive types with discriminated-union-style validation errors.
Finally, this allows you to use a custom callable as the way to identify which member of a union a value
belongs to, while still seeing all the performance benefits of a discriminated union.
Consider this example, which is much more performant with the use of `Discriminator` and thus a `TaggedUnion`
than it would be as a normal `Union`.
```python
from typing import Any, Union
from typing_extensions import Annotated, Literal
from pydantic import BaseModel, Discriminator, Tag
class Pie(BaseModel):
time_to_cook: int
num_ingredients: int
class ApplePie(Pie):
fruit: Literal['apple'] = 'apple'
class PumpkinPie(Pie):
filling: Literal['pumpkin'] = 'pumpkin'
def get_discriminator_value(v: Any) -> str:
if isinstance(v, dict):
return v.get('fruit', v.get('filling'))
return getattr(v, 'fruit', getattr(v, 'filling', None))
class ThanksgivingDinner(BaseModel):
dessert: Annotated[
Union[
Annotated[ApplePie, Tag('apple')],
Annotated[PumpkinPie, Tag('pumpkin')],
],
Discriminator(get_discriminator_value),
]
pple_variation = ThanksgivingDinner.model_validate(
{'dessert': {'fruit': 'apple', 'time_to_cook': 60, 'num_ingredients': 8}}
)
print(repr(apple_variation))
'''
ThanksgivingDinner(dessert=ApplePie(time_to_cook=60, num_ingredients=8, fruit='apple'))
'''
pumpkin_variation = ThanksgivingDinner.model_validate(
{
'dessert': {
'filling': 'pumpkin',
'time_to_cook': 40,
'num_ingredients': 6,
}
}
)
print(repr(pumpkin_variation))
'''
ThanksgivingDinner(dessert=PumpkinPie(time_to_cook=40, num_ingredients=6, filling='pumpkin'))
'''
```
See the [Discriminated Unions] concepts docs for more details on how to use `Discriminator`s.
[Discriminated Unions]: ../concepts/unions.md#discriminated-unions
aDiscriminator
ustr | Callable[[Any], Hashable]
ustr | None
udict[str, int | str | float] | None
uDiscriminator.__get_pydantic_core_schema__
D aoriginal_schema
return
ucore_schema.CoreSchema
ucore_schema.TaggedUnionSchema
uDiscriminator._convert_schema
S Olist
Ostr
Ofloat
Obool
Oint
Odict
M
D wxareturn
aAny
str
a_get_type_name
a_AllowAnyJson
u_AllowAnyJson.__get_pydantic_core_schema__
aJsonValue
T alist
T Ostr
aJsonValue
T adict
T astr
T abool
T aint
T afloat
T aNoneType
D acustom_error_type
custom_error_message
uinvalid-json-value
uinput was not a valid JSON value
a_OnErrorOmit
u_OnErrorOmit.__get_pydantic_core_schema__
aOnErrorOmit
aFailFast
uA `FailFast` annotation can be used to specify that validation should stop at the first error.
This can be useful when you want to validate a large amount of data and you only need to know if it's valid or not.
You might want to enable this setting if you want to validate your data faster (basically, if you use this,
validation will be more performant with the caveat that you get less information).
```python
from typing import List
from typing_extensions import Annotated
from pydantic import BaseModel, FailFast, ValidationError
class Model(BaseModel):
x: Annotated[List[int], FailFast()]
# This will raise a single error for the first invalid value and stop validation
try:
obj = Model(x=[1, 2, 'a', 4, 5, 'b', 7, 8, 9, 'c'])
except ValidationError as e:
print(e)
'''
1 validation error for Model
x.2
Input should be a valid integer, unable to parse string as an integer [type=int_parsing, input_value='a', input_type=str]
'''
```
fail_fast
upydantic\types.py
T wxacls
T acls
u<module pydantic.types>
T a__class__
T acls
item
T aself
other
T acls
source
handler
schema
T acls
source
handler
T aself
source_type
handler
origin
aField
original_schema
T aself
source
handler
schema
T acls
source
handler
serializer
T aself
source
handler
function_lookup
T	acls
source
handler
inner_type
origin_type
bases
base
inner_schema
validate_secret_value
T aself
source_type
handler
schema
metadata
T acls
source_type
handler
python_schema
T acls
source_type
handler
T acls
source
handler
get_json_schema
json_schema
get_secret_schema
T aself
core_schema
handler
field_schema
T acls
cs
handler
T aself
core_schema
handler
field_schema
format_conversion
T aself
item
T aself
T aself
card_number
T aself
secret_value
T aannotated_type
expected_type
annotation
T
self
original_schema
tagged_union_choices
choice
tag
metadata
metadata_tag
custom_error_type
custom_error_message
custom_error_context
T wxatype_
T avalue
T wvT avalue
info
T acls
input_value
w_astr_match
scalar
unit
unit_mult
T amin_length
max_length
strict
T astrict
gt
ge
lt
le
T	astrict
gt
ge
lt
le
multiple_of
max_digits
decimal_places
allow_inf_nan
T astrict
gt
ge
lt
le
multiple_of
allow_inf_nan
T aitem_type
min_length
max_length
T astrict
gt
ge
lt
le
multiple_of
T aitem_type
min_length
max_length
unique_items
T acls
data
weT aself
data
w_T acls
data
T acls
value
T aself
value
T a_core_schema
handler
json_schema
cls
T astrict
source
json_schema
cls
T acls
json_schema
source
T aself
decimal
separator
divisor
units
final_unit
num
unit
T aself
num_masked
T aself
unit
unit_div
T acls
input_value
w_T acard_number
required_length
brand
valid
T acls
card_number
T apath
w_T acls
card_number
sum_
length
parity
wiadigit
valid
T avalue
handler
validated_inner
cls
a__spec__
.pydantic.typing
u`typing` module is a backport module from V1.
a__doc__
a__file__
origin
has_location
a__cached__
a_migration
T agetattr_migration
getattr_migration
T upydantic.typing
a__getattr__
upydantic\typing.py
u<module pydantic.typing>

a__spec__
.pydantic.utils
uThe `utils` module is a backport module from V1.
a__doc__
a__file__
origin
has_location
a__cached__
a_migration
T agetattr_migration
getattr_migration
T upydantic.utils
a__getattr__
upydantic\utils.py
u<module pydantic.utils>

a__spec__
.pydantic.v1.annotated_types
5
