# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._utils

uClass for more convenient calculation of excluded or included fields on values.
a__qualname__
T a_items
a_type
a__slots__
D avalue
items
return
aAny
uAbstractSetIntStr | MappingIntStrAny
aNone
a__init__
uValueItems.__init__
D aitem
return
aAny
bool
is_excluded
uValueItems.is_excluded
is_included
uValueItems.is_included
D weareturn
uint | str
uAbstractSetIntStr | MappingIntStrAny | None
for_element
uValueItems.for_element
D aitems
v_length
return
aMappingIntStrAny
int
udict[int | str, Any]
uValueItems._normalize_indexes
classmethod
T FD abase
override
intersect
return
aAny
pabool
aAny
uValueItems.merge
staticmethod
D aitems
return
uAbstractSetIntStr | MappingIntStrAny
aMappingIntStrAny
uValueItems._coerce_items
D avalue
return
aAny
puValueItems._coerce_value
uValueItems.is_true
D areturn
u_repr.ReprArgs
a__repr_args__
uValueItems.__repr_args__
a__orig_bases__
uA descriptor exposing an attribute only accessible on a class (hidden from instances).
The attribute is lazily computed and cached during the first access.
aLazyClassAttribute
D aname
get_value
return
str
uCallable[[], Any]
aNone
uLazyClassAttribute.__init__
D areturn
aAny
uLazyClassAttribute.value
D ainstance
owner
return
aAny
utype[Any]
aNone
a__get__
uLazyClassAttribute.__get__
T aObj
aObj
D aobj
return
aObj
pasmart_deepcopy
D aleft
right
return
utyping.Iterable[Any]
utyping.Iterable[Any]
bool
all_identical
dataclass
T tT afrozen
uWrapper redirecting `__getitem__` to `get` with a sentinel value as default
This makes is safe to use in `operator.itemgetter` when some keys may be missing
aSafeGetItemProxy
T awrapped
uMapping[str, Any]
D akey
return
str
aAny
uSafeGetItemProxy.__getitem__
upydantic\_internal\_utils.py
u<module pydantic._internal._utils>
T a__class__
T aself
instance
owner
T aself
key
T aself
name
get_value
T aself
value
items
T aself
T aitems
class_name
T acls
value
T	aself
items
v_length
normalized_items
all_items
wiwvanormalized_i
normalized_item
T aleft
right
left_item
right_item
T aparam
T amapping
updating_mappings
updated_mapping
updating_mapping
wkwvT aself
weaitem
T aself
item
T acls
aBaseModel
T wvT aidentifier
T woaclass_or_tuple
T acls
class_or_tuple
T acls
base
override
intersect
merged
merge_keys
wkamerged_item
T aobj
obj_type
T ainput_list
name_factory
result
result_names
wvav_name
T amapping
update
a__spec__
.pydantic._internal._validators
T Ostr
Obytes
aPydanticCustomError
sequence_str
u'{type_name}' instances are not allowed as a Sequence value
type_name
a__name__
uValidator for `Sequence` types, isinstance(v, Sequence) has already been called.
a_import_string_logic
import_error
uInvalid python path: {error}
error
import_module
strip
split
T w:uImport strings should have at most one ':'; received

uImport strings should have a nonempty module name; received
w.arsplit
T w.l w:uNo module named
ucannot import name
u from
uInspired by uvicorn     dotted paths should include a colon before the final item if that item is not a module.
(This is necessary to distinguish between a submodule and an attribute when there is a conflict.).
If the dotted path does not include a colon and the final item is not a valid module, importing as an attribute
rather than a submodule will be attempted automatically.
So, for example, the following values of `dotted_path` result in the following returned values:
* 'collections': <module 'collections'>
* 'collections.abc': <module 'collections.abc'>
* 'collections.abc:Mapping': <class 'collections.abc.Mapping'>
* `collections.abc.Mapping`: <class 'collections.abc.Mapping'> (though this is a bit slower than the previous line)
An error will be raised under any of the following scenarios:
* `dotted_path` contains more than one colon (e.g., 'collections:abc:Mapping')
* the substring of `dotted_path` before the colon is not a valid module in the environment (e.g., '123:Mapping')
* the substring of `dotted_path` after the colon is not an attribute of the module (e.g., 'collections:abc123')
aPattern
compile_pattern
T apattern_type
uInput should be a valid pattern
pattern
T apattern_str_type
uInput should be a string pattern
T apattern_bytes_type
uInput should be a bytes pattern
re
compile
T apattern_regex
uInput should be a valid regular expression
aIPv4Address
T aip_v4_address
uInput is not a valid IPv4 address
aIPv6Address
T aip_v6_address
uInput is not a valid IPv6 address
aIPv4Network
T aip_v4_network
uInput is not a valid IPv4 network
uAssume IPv4Network initialised with a default `strict` argument.
See more:
https://docs.python.org/library/ipaddress.html#ipaddress.IPv4Network
aIPv6Network
T aip_v6_network
uInput is not a valid IPv6 network
uAssume IPv6Network initialised with a default `strict` argument.
See more:
https://docs.python.org/library/ipaddress.html#ipaddress.IPv6Network
aIPv4Interface
T aip_v4_interface
uInput is not a valid IPv4 interface
aIPv6Interface
T aip_v6_interface
uInput is not a valid IPv6 interface
aFraction
T afraction_parsing
uInput is not a valid fraction
math
isfinite
aPydanticKnownError
T afinite_number
T Oint
Ofloat
Ostr
uThe context argument for `PydanticKnownError` requires a number or str type, so we do a simple repr() coercion for types like timedelta.
See tests/test_types.py::test_annotated_metadata_any_order for some context.
greater_than
gt
a_safe_repr
uUnable to apply constraint 'gt' to supplied value
greater_than_equal
ge
uUnable to apply constraint 'ge' to supplied value
less_than
lt
uUnable to apply constraint 'lt' to supplied value
less_than_equal
le
uUnable to apply constraint 'le' to supplied value
multiple_of
uUnable to apply constraint 'multiple_of' to supplied value
too_short
field_type
aValue
min_length
actual_length
uUnable to apply constraint 'min_length' to supplied value
too_long
max_length
uUnable to apply constraint 'max_length' to supplied value
as_tuple
exponent
uUnable to extract decimal digits info from supplied value
digits
max
uCompute the total number of digits and decimal places for a given [`Decimal`][decimal.Decimal] instance.
This function handles both normalized and non-normalized Decimal instances.
Example: Decimal('1.230') -> 4 digits, 3 decimal places
Args:
decimal (Decimal): The decimal number to analyze.
Returns:
tuple[int, int]: A tuple containing the number of decimal places and total digits.
Though this could be divided into two separate functions, the logic is easier to follow if we couple the computation
of the number of decimals and digits together.
a_extract_decimal_digits_info
normalize
decimal_max_digits
max_digits
uUnable to apply constraint 'max_digits' to supplied value
decimal_max_places
decimal_places
uUnable to apply constraint 'decimal_places' to supplied value
uValidator functions for standard library types.
Import of this module is deferred since it contains imports of many standard library modules.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
a_annotations
typing
decimal
T aDecimal
aDecimal
fractions
T aFraction
ipaddress
T aIPv4Address
aIPv4Interface
aIPv4Network
aIPv6Address
aIPv6Interface
aIPv6Network
aAny
aCallable
aUnion
pydantic_core
upydantic_core.core_schema
core_schema
upydantic_core._pydantic_core
T aPydanticKnownError
D ainput_value
validator
return
utyping.Sequence[Any]
ucore_schema.ValidatorFunctionWrapHandler
utyping.Sequence[Any]
sequence_validator
D avalue
return
aAny
paimport_string
D adotted_path
return
str
aAny
D ainput_value
return
aAny
utyping.Pattern[Any]
pattern_either_validator
D ainput_value
return
aAny
utyping.Pattern[str]
pattern_str_validator
D ainput_value
return
aAny
utyping.Pattern[bytes]
pattern_bytes_validator
aTypeVar
T aPatternType
Ostr
Obytes
aPatternType
D apattern
return
aPatternType
utyping.Pattern[PatternType]
D ainput_value
return
aAny
aIPv4Address
ip_v4_address_validator
D ainput_value
return
aAny
aIPv6Address
ip_v6_address_validator
D ainput_value
return
aAny
aIPv4Network
ip_v4_network_validator
D ainput_value
return
aAny
aIPv6Network
ip_v6_network_validator
D ainput_value
return
aAny
aIPv4Interface
ip_v4_interface_validator
D ainput_value
return
aAny
aIPv6Interface
ip_v6_interface_validator
D ainput_value
return
aAny
aFraction
fraction_validator
D wxareturn
aAny
paforbid_inf_nan_check
D wvareturn
aAny
uint | float | str
D wxagt
return
aAny
ppagreater_than_validator
D wxage
return
aAny
ppagreater_than_or_equal_validator
D wxalt
return
aAny
ppaless_than_validator
D wxale
return
aAny
ppaless_than_or_equal_validator
D wxamultiple_of
return
aAny
ppamultiple_of_validator
D wxamin_length
return
aAny
ppamin_length_validator
D wxamax_length
return
aAny
ppamax_length_validator
D adecimal
return
aDecimal
utuple[int, int]
D wxamax_digits
return
aAny
ppamax_digits_validator
D wxadecimal_places
return
aAny
ppadecimal_places_validator
aNUMERIC_VALIDATOR_LOOKUP
udict[str, Callable]
aIpType
aIP_VALIDATOR_LOOKUP
udict[type[IpType], Callable]
upydantic\_internal\_validators.py
u<module pydantic._internal._validators>
T adecimal
decimal_tuple
exponent
num_digits
decimal_places
T	adotted_path
import_module
components
module_path
module
weamaybe_module_path
maybe_attribute
attribute
T wvT apattern
T wxadecimal_places
decimal_places_
w_anormalized_decimal_places
T wxT ainput_value
T wxage
T wxagt
T avalue
weT wxale
T wxalt
T wxamax_digits
w_anum_digits
normalized_num_digits
T wxamax_length
T wxamin_length
T wxamultiple_of
T ainput_value
validator
value_type
v_list
a__spec__
.pydantic._internal
3
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_pydantic
u\not_existing
a_internal
T aNUITKA_PACKAGE_pydantic__internal
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
upydantic\_internal\__init__.py
u<module pydantic._internal>

a__spec__
.pydantic._migration
$
;
upydantic.errors
aPydanticImportError
D aname
return
Ostr
Oobject
uRaise an error if the object is not found, or warn if it was moved.
In case it was moved, it still returns the object.
Args:
name: The object name.
Returns:
The object.
wrapper
ugetattr_migration.<locals>.wrapper
uImplement PEP 562 for objects that were either moved or removed on the migration
to V2.
Args:
module: The module name.
Returns:
A callable that will raise an error if the object is not found.
a__path__
umodule
module

u has no attribute
warnings
u_internal._validators
T aimport_string
import_string
w:aMOVED_IN_V2
keys
warn
w`u` has been moved to `
u`.
aDEPRECATED_MOVED_IN_V2
aREDIRECT_TO_V1
u` has been removed. We are importing from `
u` instead.See the migration guide for more details: https://docs.pydantic.dev/latest/migration/
upydantic:BaseSettings
u`BaseSettings` has been moved to the `pydantic-settings` package. See https://docs.pydantic.dev/
version_short
u/migration/#basesettings-has-moved-to-pydantic-settings for more details.
aREMOVED_IN_V2
u` has been removed in V2.
modules
a__doc__
a__file__
origin
has_location
a__cached__
sys
aAny
aCallable
aDict
version
T aversion_short
D upydantic.utils:version_info
upydantic.error_wrappers:ValidationError
upydantic.utils:to_camel
upydantic.utils:to_lower_camel
upydantic:PyObject
upydantic.types:PyObject
upydantic.generics:GenericModel
upydantic.version:version_info
upydantic:ValidationError
upydantic.alias_generators:to_pascal
upydantic.alias_generators:to_camel
upydantic.types:ImportString
upydantic.types:ImportString
upydantic.BaseModel
D upydantic.tools:schema_of
upydantic.tools:parse_obj_as
upydantic.tools:schema_json_of
upydantic.json:pydantic_encoder
upydantic:validate_arguments
upydantic.json:custom_pydantic_encoder
upydantic.json:timedelta_isoformat
upydantic.decorator:validate_arguments
upydantic.class_validators:validator
upydantic.class_validators:root_validator
upydantic.config:BaseConfig
upydantic.config:Extra
upydantic.deprecated.tools:schema_of
upydantic.deprecated.tools:parse_obj_as
upydantic.deprecated.tools:schema_json_of
upydantic.deprecated.json:pydantic_encoder
upydantic.deprecated.decorator:validate_arguments
upydantic.deprecated.json:custom_pydantic_encoder
upydantic.deprecated.json:timedelta_isoformat
upydantic.deprecated.decorator:validate_arguments
upydantic.deprecated.class_validators:validator
upydantic.deprecated.class_validators:root_validator
upydantic.deprecated.config:BaseConfig
upydantic.deprecated.config:Extra
T adeep_update
aGetterDict
lenient_issubclass
lenient_isinstance
is_valid_field
update_not_none
import_string
aRepresentation
aROOT_KEY
smart_deepcopy
sequence_like
upydantic.utils:
upydantic.v1.utils:
S  upydantic.error_wrappers:ErrorWrapper
upydantic.errors:DecimalMaxPlacesError
upydantic.typing:resolve_annotations
upydantic.errors:IPvAnyNetworkError
upydantic.errors:ColorError
upydantic.typing:all_literal_values
upydantic.datetime_parse:parse_time
upydantic.errors:DictError
upydantic.errors:BoolError
upydantic.errors:FrozenSetMaxLengthError
upydantic.types:ConstrainedDate
upydantic.typing:display_as_type
upydantic.types:ConstrainedList
upydantic:create_model_from_namedtuple
upydantic.tools:parse_file_as
upydantic:JsonWrapper
upydantic.typing:SetStr
upydantic.typing:get_args
upydantic.typing:get_all_type_hints
upydantic.typing:get_origin
upydantic:ConstrainedInt
upydantic.errors:DateTimeError
upydantic.utils:almost_equal_floats
upydantic.errors:SetMinLengthError
upydantic.errors:NotDigitError
upydantic.errors:ListMinLengthError
upydantic.errors:StrError
upydantic.typing:DictIntStrAny
upydantic.utils:path_type
upydantic.config:prepare_config
upydantic:ConstrainedFrozenSet
upydantic.errors:SetError
upydantic.errors:PatternError
upydantic.errors:EmailError
upydantic.config:inherit_config
upydantic.typing:DictStrAny
upydantic.errors:ExtraError
upydantic.types:JsonWrapper
upydantic.typing:ReprArgs
upydantic.errors:NoneIsNotAllowedError
upydantic.errors:StrictBoolError
upydantic.typing:AnyCallable
upydantic.typing:is_classvar
upydantic:StrBytes
upydantic.errors:PathNotExistsError
upydantic.errors:PydanticValueError
upydantic.errors:CallableError
upydantic:ConstrainedFloat
upydantic.types:ConstrainedDecimal
upydantic.errors:UrlPortError
upydantic.errors:DateError
upydantic:Protocol
upydantic.utils:in_ipython
upydantic.errors:UrlExtraError
upydantic:parse_raw_as
upydantic:ConstrainedDate
upydantic.errors:IPv6InterfaceError
upydantic.typing:is_typeddict_special
upydantic.errors:MissingError
upydantic.typing:evaluate_forwardref
upydantic.typing:is_union
upydantic.utils:ValueItems
upydantic.types:ConstrainedFloat
upydantic.dataclasses:create_pydantic_model_from_dataclass
upydantic.errors:IPvAnyAddressError
upydantic.errors:NumberNotMultipleError
upydantic.typing:is_new_type
upydantic.types:ConstrainedStr
upydantic.utils:get_model
upydantic.errors:AnyStrMaxLengthError
upydantic.typing:is_finalvar
upydantic.errors:UUIDVersionError
upydantic.errors:WrongConstantError
upydantic.errors:PathError
upydantic.typing:is_callable_type
upydantic:NoneStrBytes
upydantic.errors:ListUniqueItemsError
upydantic.errors:EnumError
upydantic:NoneBytes
upydantic.datetime_parse:parse_duration
upydantic.errors:InvalidLengthForBrand
upydantic:parse_file_as
upydantic.types:ConstrainedSet
upydantic.errors:ListMaxLengthError
upydantic.errors:MissingDiscriminator
upydantic.errors:DecimalWholeDigitsError
upydantic:NoneStr
upydantic.errors:PydanticTypeError
upydantic.typing:is_literal_type
upydantic.dataclasses:set_validation
upydantic.errors:DecimalMaxDigitsError
upydantic.errors:PathNotADirectoryError
upydantic.errors:SubclassError
upydantic.errors:DurationError
upydantic.errors:SequenceError
upydantic:compiled
upydantic.errors:JsonTypeError
upydantic.errors:FrozenSetMinLengthError
upydantic.errors:PyObjectError
upydantic.typing:StrPath
upydantic.errors:DecimalIsNotFiniteError
upydantic.errors:HashableError
upydantic.errors:UrlSchemeError
upydantic.typing:get_sub_types
upydantic.typing:is_typeddict
upydantic.utils:is_valid_identifier
upydantic.errors:ArbitraryTypeError
upydantic.types:ConstrainedFrozenSet
upydantic.typing:TupleGenerator
upydantic.typing:is_none_type
upydantic.datetime_parse:parse_datetime
upydantic.errors:DateNotInThePastError
upydantic.errors:NoneIsAllowedError
upydantic.typing:AnyClassMethod
upydantic:ConstrainedList
upydantic.types:NoneStr
upydantic.errors:EnumMemberError
upydantic.errors:IPv6NetworkError
upydantic.typing:NoneType
upydantic.typing:AbstractSetIntStr
upydantic.errors:TimeError
upydantic.typing:typing_base
upydantic:create_model_from_typeddict
upydantic.errors:FrozenSetError
upydantic.errors:ConfigError
upydantic:validate_model
upydantic.errors:UrlSchemePermittedError
upydantic:ConstrainedDecimal
upydantic.utils:DUNDER_ATTRIBUTES
upydantic.utils:get_unique_discriminator_alias
upydantic.errors:SetMaxLengthError
upydantic.typing:MappingIntStrAny
upydantic.errors:FloatError
upydantic.errors:BytesError
upydantic.errors:IntEnumError
upydantic.main:validate_model
upydantic.typing:NoArgAnyCallable
upydantic.errors:InvalidByteSizeUnit
upydantic.errors:NumberNotLeError
upydantic.errors:IntegerError
upydantic.errors:DecimalError
upydantic.errors:UrlUserInfoError
upydantic.errors:DataclassTypeError
upydantic.typing:CallableGenerator
upydantic.types:ConstrainedBytes
upydantic.errors:NotNoneError
upydantic.errors:ListError
upydantic.utils:ClassAttribute
upydantic.errors:IPv6AddressError
upydantic.errors:NumberNotLtError
upydantic:ConstrainedSet
upydantic.config:get_config
upydantic:ConstrainedBytes
upydantic.errors:IPv4InterfaceError
upydantic.typing:IntStr
upydantic.errors:NumberNotGtError
upydantic:ConstrainedStr
upydantic.errors:AnyStrMinLengthError
upydantic.errors:InvalidDiscriminator
upydantic.tools:parse_raw_as
upydantic.errors:DateNotInTheFutureError
upydantic.errors:UUIDError
upydantic.typing:update_model_forward_refs
upydantic.utils:PyObjectStr
upydantic.errors:NumberNotGeError
upydantic.typing:ListStr
upydantic.errors:UrlHostTldError
upydantic.types:NoneBytes
upydantic.errors:InvalidByteSize
upydantic.dataclasses:make_dataclass_validator
upydantic.types:StrBytes
upydantic.errors:JsonError
upydantic.errors:PathNotAFileError
upydantic.typing:WithArgsTypes
upydantic.errors:IPv4AddressError
upydantic.utils:get_discriminator_alias_and_values
upydantic:Required
upydantic.errors:ClassError
upydantic.errors:LuhnValidationError
upydantic.typing:update_field_forward_refs
upydantic.networks:stricturl
upydantic.errors:UrlHostError
upydantic:stricturl
upydantic.typing:is_namedtuple
upydantic.errors:TupleLengthError
upydantic.errors:IPv4NetworkError
upydantic.types:ConstrainedInt
upydantic.types:NoneStrBytes
upydantic.typing:new_type_supertype
upydantic.datetime_parse:parse_date
upydantic.errors:IPvAnyInterfaceError
upydantic.errors:StrRegexError
upydantic.errors:TupleError
upydantic.errors:UrlError
upydantic.typing:DictAny
upydantic.utils:validate_field_name
return
getattr_migration
upydantic\_migration.py
u<module pydantic._migration>
T amodule
aPydanticImportError
wrapper
T aname
globals
warnings
import_string
import_path
new_location
module
aPydanticImportError
T aPydanticImportError
module
a__spec__
.pydantic.alias_generators
~
/
title
re
sub
u([0-9A-Za-z])_(?=[0-9A-Z])
u<lambda>
uto_pascal.<locals>.<lambda>
uConvert a snake_case string to PascalCase.
Args:
snake: The string to convert.
Returns:
The PascalCase string.
group
T l amatch
u^[a-z]+[A-Za-z0-9]*$
search
u\d[a-z]
to_pascal
u(^_*[A-Z])
uto_camel.<locals>.<lambda>
uConvert a snake_case string to camelCase.
Args:
snake: The string to convert.
Returns:
The converted camelCase string.
lower
u([A-Z]+)([A-Z][a-z])
uto_snake.<locals>.<lambda>
u([a-z])([A-Z])
u([0-9])([A-Z])
u([a-z])([0-9])
replace
T w-w_uConvert a PascalCase, camelCase, or kebab-case string to snake_case.
Args:
camel: The string to convert.
Returns:
The converted string in snake_case.

w_T l uAlias generators for converting between different capitalization conventions.
a__doc__
a__file__
origin
has_location
a__cached__
T ato_pascal
to_camel
to_snake
a__all__
D asnake
return
Ostr
pato_camel
D acamel
return
Ostr
pato_snake
upydantic\alias_generators.py
T wmu<module pydantic.alias_generators>
T asnake
camel
T acamel
snake
a__spec__
.pydantic.aliases
S
path
uConverts arguments to a list of string or integer aliases.
Returns:
The list of aliases.
wvaPydanticUndefined
T EKeyError
EIndexError
ETypeError
uSearches a dictionary for the path specified by the alias.
Returns:
The value at the specified path, or `PydanticUndefined` if the path is not found.
choices
aAliasPath
aliases
convert_to_aliases
uConverts arguments to a list of lists containing string or integer aliases.
Returns:
The list of aliases.
uInvalid `

u` type. `
u` generator must produce one of `
w`uGenerate an alias of the specified kind. Returns None if the alias generator is None.
Raises:
TypeError: If the alias generator produces an invalid type.
a_generate_alias
alias
T Ostr
validation_alias
aAliasChoices
serialization_alias
uGenerate `alias`, `validation_alias`, and `serialization_alias` for a field.
Returns:
A tuple of three aliases - validation, alias, and serialization.
uSupport for alias configurations.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
dataclasses
aAny
aCallable
aLiteral
pydantic_core
a_internal
T a_internal_dataclass
a_internal_dataclass
T aAliasGenerator
aAliasPath
aAliasChoices
a__all__
dataclass
slots_true
