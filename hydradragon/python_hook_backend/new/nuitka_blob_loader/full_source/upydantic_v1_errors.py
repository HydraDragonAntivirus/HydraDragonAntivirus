# Reconstructed from integrated Nuitka blob
# Module: upydantic.v1.errors

a__qualname__
a__annotations__
code
uPydanticErrorMixin.__init__
D areturn
Ostr
a__str__
uPydanticErrorMixin.__str__
T Q
aPydanticErrorMixin
a__reduce__
uPydanticErrorMixin.__reduce__
a__prepare__
aPydanticTypeError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
a__orig_bases__
aPydanticValueError
T ERuntimeError
aConfigError
aMissingError
ufield required
aExtraError
uextra fields not permitted
aNoneIsNotAllowedError
unone.not_allowed
unone is not an allowed value
aNoneIsAllowedError
unone.allowed
uvalue is not none
aWrongConstantError
const
str
uWrongConstantError.__str__
aNotNoneError
not_none
uvalue is not None
aBoolError
uvalue could not be parsed to a boolean
aBytesError
ubyte type expected
aDictError
uvalue is not a valid dict
aEmailError
uvalue is not a valid email address
aUrlError
url
aUrlSchemeError
uurl.scheme
uinvalid or missing URL scheme
aUrlSchemePermittedError
uURL scheme not permitted
allowed_schemes
uUrlSchemePermittedError.__init__
aUrlUserInfoError
uurl.userinfo
uuserinfo required in URL but missing
aUrlHostError
uurl.host
uURL host invalid
aUrlHostTldError
uURL host invalid, top level domain required
aUrlPortError
uurl.port
uURL port invalid, port cannot exceed 65535
aUrlExtraError
uurl.extra
uURL invalid, extra characters found after valid URL: {extra!r}
aEnumMemberError
enum
uEnumMemberError.__str__
aIntegerError
uvalue is not a valid integer
aFloatError
uvalue is not a valid float
aPathError
uvalue is not a valid path
a_PathValueError
path
u_PathValueError.__init__
aPathNotExistsError
upath.not_exists
ufile or directory at path "{path}" does not exist
aPathNotAFileError
upath.not_a_file
upath "{path}" does not point to a file
aPathNotADirectoryError
upath.not_a_directory
upath "{path}" does not point to a directory
aPyObjectError
uensure this value contains valid import path or valid callable: {error_message}
aSequenceError
uvalue is not a valid sequence
aIterableError
uvalue is not a valid iterable
aListError
uvalue is not a valid list
aSetError
uvalue is not a valid set
aFrozenSetError
uvalue is not a valid frozenset
aDequeError
uvalue is not a valid deque
aTupleError
uvalue is not a valid tuple
aTupleLengthError
utuple.length
uwrong tuple length {actual_length}, expected {expected_length}
actual_length
int
expected_length
uTupleLengthError.__init__
aListMinLengthError
ulist.min_items
uensure this value has at least {limit_value} items
limit_value
uListMinLengthError.__init__
aListMaxLengthError
ulist.max_items
uensure this value has at most {limit_value} items
uListMaxLengthError.__init__
aListUniqueItemsError
ulist.unique_items
uthe list has duplicated items
aSetMinLengthError
uset.min_items
uSetMinLengthError.__init__
aSetMaxLengthError
uset.max_items
uSetMaxLengthError.__init__
aFrozenSetMinLengthError
ufrozenset.min_items
uFrozenSetMinLengthError.__init__
aFrozenSetMaxLengthError
ufrozenset.max_items
uFrozenSetMaxLengthError.__init__
aAnyStrMinLengthError
uany_str.min_length
uensure this value has at least {limit_value} characters
uAnyStrMinLengthError.__init__
aAnyStrMaxLengthError
uany_str.max_length
uensure this value has at most {limit_value} characters
uAnyStrMaxLengthError.__init__
aStrError
ustr type expected
aStrRegexError
ustr.regex
ustring does not match regex "{pattern}"
pattern
uStrRegexError.__init__
a_NumberBoundError
float
u_NumberBoundError.__init__
aNumberNotGtError
unumber.not_gt
uensure this value is greater than {limit_value}
aNumberNotGeError
unumber.not_ge
uensure this value is greater than or equal to {limit_value}
aNumberNotLtError
unumber.not_lt
uensure this value is less than {limit_value}
aNumberNotLeError
unumber.not_le
uensure this value is less than or equal to {limit_value}
aNumberNotFiniteError
unumber.not_finite_number
uensure this value is a finite number
aNumberNotMultipleError
unumber.not_multiple
uensure this value is a multiple of {multiple_of}
multiple_of
uNumberNotMultipleError.__init__
aDecimalError
uvalue is not a valid decimal
aDecimalIsNotFiniteError
udecimal.not_finite
aDecimalMaxDigitsError
udecimal.max_digits
uensure that there are no more than {max_digits} digits in total
max_digits
uDecimalMaxDigitsError.__init__
aDecimalMaxPlacesError
udecimal.max_places
uensure that there are no more than {decimal_places} decimal places
decimal_places
uDecimalMaxPlacesError.__init__
aDecimalWholeDigitsError
udecimal.whole_digits
uensure that there are no more than {whole_digits} digits before the decimal point
whole_digits
uDecimalWholeDigitsError.__init__
aDateTimeError
uinvalid datetime format
aDateError
uinvalid date format
aDateNotInThePastError
udate.not_in_the_past
udate is not in the past
aDateNotInTheFutureError
udate.not_in_the_future
udate is not in the future
aTimeError
uinvalid time format
aDurationError
uinvalid duration format
aHashableError
uvalue is not a valid hashable
aUUIDError
uvalue is not a valid uuid
aUUIDVersionError
uuuid.version
uuuid version {required_version} expected
required_version
uUUIDVersionError.__init__
aArbitraryTypeError
arbitrary_type
uinstance of {expected_arbitrary_type} expected
expected_arbitrary_type
uArbitraryTypeError.__init__
aClassError
class
ua class is expected
aSubclassError
subclass
usubclass of {expected_class} expected
expected_class
uSubclassError.__init__
aJsonError
uInvalid JSON
aJsonTypeError
json
uJSON object must be str, bytes or bytearray
aPatternError
regex_pattern
uInvalid regular expression
aDataclassTypeError
dataclass
uinstance of {class_name}, tuple or dict expected
aCallableError
u{value} is not callable
aEnumError
enum_instance
u{value} is not a valid Enum instance
aIntEnumError
int_enum_instance
u{value} is not a valid IntEnum instance
aIPvAnyAddressError
uvalue is not a valid IPv4 or IPv6 address
aIPvAnyInterfaceError
uvalue is not a valid IPv4 or IPv6 interface
aIPvAnyNetworkError
uvalue is not a valid IPv4 or IPv6 network
aIPv4AddressError
uvalue is not a valid IPv4 address
aIPv6AddressError
uvalue is not a valid IPv6 address
aIPv4NetworkError
uvalue is not a valid IPv4 network
aIPv6NetworkError
uvalue is not a valid IPv6 network
aIPv4InterfaceError
uvalue is not a valid IPv4 interface
aIPv6InterfaceError
uvalue is not a valid IPv6 interface
aColorError
uvalue is not a valid color: {reason}
aStrictBoolError
uvalue is not a valid boolean
aNotDigitError
upayment_card_number.digits
ucard number is not all digits
aLuhnValidationError
upayment_card_number.luhn_check
ucard number is not luhn valid
aInvalidLengthForBrand
upayment_card_number.invalid_length_for_brand
uLength for a {brand} card must be {required_length}
aInvalidByteSize
ucould not parse value and unit from byte string
aInvalidByteSizeUnit
ucould not interpret byte unit: {unit}
aMissingDiscriminator
udiscriminated_union.missing_discriminator
uDiscriminator {discriminator_key!r} is missing in value
aInvalidDiscriminator
udiscriminated_union.invalid_discriminator
uNo match for discriminator {discriminator_key!r} and value {discriminator_value!r} (allowed values: {allowed_values})
discriminator_key
discriminator_value
allowed_values
uInvalidDiscriminator.__init__
upydantic\v1\errors.py
T a.0
wvu<module pydantic.v1.errors>
T a__class__
T aself
limit_value
a__class__
T aself
expected_arbitrary_type
a__class__
T aself
max_digits
a__class__
T aself
decimal_places
a__class__
T aself
whole_digits
a__class__
T aself
discriminator_key
discriminator_value
allowed_values
a__class__
T aself
multiple_of
a__class__
T aself
ctx
T aself
pattern
a__class__
T aself
expected_class
a__class__
T aself
actual_length
expected_length
a__class__
T aself
required_version
a__class__
T aself
allowed_schemes
a__class__
T aself
path
a__class__
T aself
T aself
permitted
T acls
ctx
a__spec__
.pydantic.v1.fields
D
default
default_factory
pop
T aalias
naalias
alias_priority
l T atitle
natitle
T adescription
nadescription
T aexclude
naexclude
T ainclude
nainclude
T aconst
naconst
T agt
nagt
T age
nage
T alt
nalt
T ale
nale
T amultiple_of
namultiple_of
T aallow_inf_nan
naallow_inf_nan
T amax_digits
namax_digits
T adecimal_places
nadecimal_places
T amin_items
namin_items
T amax_items
namax_items
T aunique_items
naunique_items
T amin_length
namin_length
T amax_length
namax_length
T aallow_mutation
taallow_mutation
T aregex
naregex
T adiscriminator
nadiscriminator
T arepr
tarepr
extra
D arepr
ta__field_constraints__
a__slots__
field_defaults_to_hide
get
self
u<genexpr>
uFieldInfo.__repr_args__.<locals>.<genexpr>
items

Gets the constraints set on the field by comparing the constraint value with its default value
:return: the constraints set on field_info
setdefault
current_value
aValueItems
merge
D aintersect
tu
Update this FieldInfo based on a dict from get_field_info, only fields which have not been set are dated.
aUndefined
ucannot specify both default and default_factory
aFieldInfo
a_validate

Used to provide extra information about a field, either for the model schema or complex validation. Some arguments
pply only to number fields (``int``, ``float``, ``Decimal``) and some apply only to ``str``.
:param default: since this is replacing the field   s default, its first argument is used
to set the default, use ellipsis (``...``) to indicate the field is required
:param default_factory: callable that will be called when a default value is needed for this field
If both `default` and `default_factory` are set, an error is raised.
:param alias: the public name of the field
:param title: can be any string, used in the schema
:param description: can be any string, used in the schema
:param exclude: exclude this field while dumping.
Takes same values as the ``include`` and ``exclude`` arguments on the ``.dict`` method.
:param include: include this field while dumping.
Takes same values as the ``include`` and ``exclude`` arguments on the ``.dict`` method.
:param const: this field is required and *must* take it's default value
:param gt: only applies to numbers, requires the field to be "greater than". The schema
will have an ``exclusiveMinimum`` validation keyword
:param ge: only applies to numbers, requires the field to be "greater than or equal to". The
schema will have a ``minimum`` validation keyword
:param lt: only applies to numbers, requires the field to be "less than". The schema
will have an ``exclusiveMaximum`` validation keyword
:param le: only applies to numbers, requires the field to be "less than or equal to". The
schema will have a ``maximum`` validation keyword
:param multiple_of: only applies to numbers, requires the field to be "a multiple of". The
schema will have a ``multipleOf`` validation keyword
:param allow_inf_nan: only applies to numbers, allows the field to be NaN or infinity (+inf or -inf),
which is a valid Python float. Default True, set to False for compatibility with JSON.
:param max_digits: only applies to Decimals, requires the field to have a maximum number
of digits within the decimal. It does not include a zero before the decimal point or trailing decimal zeroes.
:param decimal_places: only applies to Decimals, requires the field to have at most a number of decimal places
llowed. It does not include trailing decimal zeroes.
:param min_items: only applies to lists, requires the field to have a minimum number of
elements. The schema will have a ``minItems`` validation keyword
:param max_items: only applies to lists, requires the field to have a maximum number of
elements. The schema will have a ``maxItems`` validation keyword
:param unique_items: only applies to lists, requires the field not to have duplicated
elements. The schema will have a ``uniqueItems`` validation keyword
:param min_length: only applies to strings, requires the field to have a minimum length. The
schema will have a ``minLength`` validation keyword
:param max_length: only applies to strings, requires the field to have a maximum length. The
schema will have a ``maxLength`` validation keyword
:param allow_mutation: a boolean which defaults to True. When False, the field raises a TypeError if the field is
ssigned on an instance.  The BaseModel Config must set validate_assignment to True
:param regex: only applies to strings, requires the field match against a regular expression
pattern string. The schema will have a ``pattern`` validation keyword
:param discriminator: only useful with a (discriminated a.k.a. tagged) `Union` of sub models with a common field.
The `discriminator` is the name of this common field to shorten validation and improve generated schema
:param repr: show this field in the representation
:param **extra: any additional keyword arguments will be added as is to the schema
name
has_alias
annotation
convert_generics
type_
outer_type_
class_validators
required
final
model_config
field_info
discriminator_key
discriminator_alias
allow_none
validate_always
sub_fields
sub_fields_mapping
key_field
validators
pre_validators
post_validators
parse_json
aSHAPE_SINGLETON
shape
prepare_field
prepare
smart_deepcopy
get_field_info
get_origin
aAnnotated
get_args
:l nnucannot specify multiple `Annotated` `Field`s for

copy
update_from_config
aRequired
u`Field` default cannot be set in `Annotated` for
ucannot specify `Annotated` and value `Field`s together for

Get a FieldInfo from a root typing.Annotated annotation, value, or config default.
The FieldInfo may be set in typing.Annotated or the value, but not both. If neither contain
a FieldInfo, a new one will be created using the config.
:param field_name: name of the field for use in error messages
:param annotation: a type hint such as `str` or `Annotated[str, Field(..., min_length=5)]`
:param value: the field's assigned value
:param config: the model's config object
:return: the FieldInfo contained in the `annotation`, the value, or a new one from the config.
upydantic.v1.schema
T aget_annotation_from_field_info
get_annotation_from_field_info
a_get_field_info
validate_assignment
T	aname
type_
alias
class_validators
default
default_factory
required
model_config
field_info
T aalias
T aalias_priority
T aexclude
T ainclude
a_set_default_and_type
aForwardRef
aDeferredType
a_type_analysis
populate_validators

Prepare the field but inspecting self.default, self.type_ etc.
Note: this method is **not** idempotent (because _type_analysis is not idempotent),
e.g. calling it it multiple times may modify the field and configure it incorrectly.
errors_
aConfigError
uyou need to set the type of field
u when using `default_factory`
get_default
uunable to infer type for attribute "
w"u
Set the default value, infer the type if needed and check if `None` value is valid.
lenient_issubclass
aJsonWrapper
inner_type
aJson
aAny
aTypeVar
a__bound__
a__constraints__
aUnion
is_new_type
new_type_supertype
aPattern
re
is_literal_type
is_typeddict
is_finalvar
aFinal
is_typeddict_special
is_union
u`discriminator` can only be used with `Union` type with more than one variant
aCollectionsHashable
aCallable
is_none_type
types_
a_create_sub_type
w_adisplay_as_type
prepare_discriminated_union_sub_fields
aTuple
aSHAPE_TUPLE_ELLIPSIS
aEllipsis
a_0
T T
aSHAPE_TUPLE
aList
a__get_validators__
update
list_
aValidator
D apre
taSHAPE_LIST
aSet
set_
aSHAPE_SET
aFrozenSet
frozenset_
aSHAPE_FROZENSET
aDeque
aSHAPE_DEQUE
aSequence
aSHAPE_SEQUENCE
aDict
key_
D afor_keys
taSHAPE_DICT
aDefaultDict
aSHAPE_DEFAULTDICT
aCounter
aSHAPE_COUNTER
aMapping
aSHAPE_MAPPING
aIterable
aCollectionsIterable
aSHAPE_ITERABLE
a_type
aType
arbitrary_types_allowed
aSHAPE_GENERIC
uFields of type "
u" are not supported.
get_discriminator_alias_and_values
all_aliases
add
get_unique_discriminator_alias

Prepare the mapping <discriminator key> -> <ModelField> and update `sub_fields`
Note that this process can be aborted if a `ForwardRef` is encountered
each_item
func
pre
always
check_fields
skip_on_failure
T afunc
pre
each_item
always
check_fields
skip_on_failure
T atype_
name
class_validators
model_config
field_info
values
find_validators
prep_validators
append
make_generic_validator
constant_validator
validate_json

Prepare self.pre_validators, self.validators, and self.post_validators based on self.type_'s  __get_validators__
nd class validators. This method should be idempotent, e.g. it should be safe to call multiple times
without mis-configuring the field.
uModelField.populate_validators.<locals>.<genexpr>
ufield "
u" not yet prepared so type is still a ForwardRef, you might need to call
a__name__
u.update_forward_refs().
a_apply_validators
T nnaErrorWrapper
aNoneIsNotAllowedError
a_validate_singleton
aMAPPING_LIKE_SHAPES
a_validate_mapping_like
a_validate_tuple
a_validate_iterable
a_validate_sequence_like
sequence_like
aListError
aTupleError
aSetError
aFrozenSetError
aSequenceError
loc
cls
errors
result
deque
maxlen
T amaxlen
aGenerator

Validate sequence-like containers: lists, tuples, sets and generators
Note that large if-else blocks are necessary to enable Cython
optimization, which is why we disable the complexity check above.
aIterableError

Validate Iterables.
This intentionally doesn't validate values to allow infinite generators.
aTupleLengthError
T aactual_length
expected_length
validate
T aloc
cls
dict_validator
T D
L
T a__key__
defaultdict
aCollectionCounter
a_get_mapping_value
uCould not convert dictionary to

When type is `Mapping[KT, KV]` (or another unsupported mapping), we try to avoid
coercing to `dict` unwillingly.
a_validate_discriminated_union
smart_union
wvalenient_isinstance
allow_population_by_field_name
aMissingDiscriminator
T adiscriminator_key
T EAttributeError
ETypeError
T EKeyError
ETypeError
aInvalidDiscriminator
T adiscriminator_key
discriminator_value
allowed_values
T EValueError
ETypeError
EAssertionError
upydantic.v1.main
T aBaseModel
aBaseModel
a__pydantic_model__

Whether the field is "complex" eg. env variables should be parsed as JSON.
uMapping[
u,
w]uTuple[{}]
u{}[{}]
aSHAPE_NAME_LOOKUP
format
uOptional[
aPyObjectStr
uModelField._type_display.<locals>.<genexpr>
type
a_type_display
u<function
w>aalt_alias
args
aModelPrivateAttr
T adefault_factory

Indicates that attribute is only used internally and never mixed with regular fields.
Types or values of private attrs are not checked by pydantic and it's up to you to keep them relevant.
Private attrs are stored in model __slots__.
:param default: the attribute   s default value
:param default_factory: callable that will be called when a default value is needed for this attribute
If both `default` and `default_factory` are set, an error is raised.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
collections
T aCounter
defaultdict
deque
ucollections.abc
T aCallable
aHashable
aIterable
aHashable
aTYPE_CHECKING
aIterator
aOptional
typing_extensions
T aAnnotated
aFinal
upydantic.v1
T aerrors
upydantic.v1.class_validators
T aValidator
make_generic_validator
prep_validators
upydantic.v1.error_wrappers
T aErrorWrapper
upydantic.v1.errors
T aConfigError
aInvalidDiscriminator
aMissingDiscriminator
aNoneIsNotAllowedError
upydantic.v1.types
T aJson
aJsonWrapper
upydantic.v1.typing
TaNoArgAnyCallable
convert_generics
display_as_type
get_args
get_origin
is_finalvar
is_literal_type
is_new_type
is_none_type
is_typeddict
is_typeddict_special
is_union
new_type_supertype
aNoArgAnyCallable
upydantic.v1.utils
T	aPyObjectStr
aRepresentation
aValueItems
get_discriminator_alias_and_values
get_unique_discriminator_alias
lenient_isinstance
lenient_issubclass
sequence_like
smart_deepcopy
aRepresentation
upydantic.v1.validators
T aconstant_validator
dict_validator
find_validators
validate_json
