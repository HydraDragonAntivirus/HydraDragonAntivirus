# Reconstructed from integrated Nuitka blob
# Module: upydantic.v1.error_wrappers

a__qualname__
T aexc
a_loc
a__slots__
aException
str
aLoc
return
a__init__
uErrorWrapper.__init__
D areturn
aLoc
uErrorWrapper.loc_tuple
D areturn
aReprArgs
a__repr_args__
uErrorWrapper.__repr_args__
a__orig_bases__
aErrorList
T araw_errors
model
a_error_cache
aModelOrDc
uValidationError.__init__
aErrorDict
uValidationError.errors
D aindent
l aindent
int
uValidationError.json
a__str__
uValidationError.__str__
uValidationError.__repr_args__
D aerror
return
aErrorDict
Ostr
T naBaseConfig
T aErrorDict
nnacls
upydantic\v1\error_wrappers.py
T a.0
weT a.0
wkwvu<module pydantic.v1.error_wrappers>
T a__class__
T aself
exc
loc
T aself
errors
model
T aself
T aself
errors
no_errors
T aerror
T aerror
wtactx
T acls
base_name
code
T aerrors
T aexc
config
loc
wdatype_
msg_template
ctx
msg
T aself
config
T aerrors
config
loc
error
error_loc
T acls
wrT aself
indent
a__spec__
.pydantic.v1.errors
)
x u
For built-in exceptions like ValueError or TypeError, we need to implement
__reduce__ to override the default behaviour (instead of __getstate__/__setstate__)
By default pickle protocol 2 calls `cls.__new__(cls, *args)`.
Since we only use kwargs, we need a little constructor to change that.
Note: the callable can't be a lambda as pickle looks in the namespace to find it
msg_template
format
cls_kwargs
u,
permitted
uunexpected value; permitted:

u<genexpr>
uWrongConstantError.__str__.<locals>.<genexpr>
a__class__
a__init__
T aallowed_schemes
enum_values
uvalue is not a valid enumeration member; permitted:
value
uEnumMemberError.__str__.<locals>.<genexpr>
T apath
T aactual_length
expected_length
T alimit_value
T apattern
T amultiple_of
T amax_digits
T adecimal_places
T awhole_digits
T arequired_version
display_as_type
T aexpected_arbitrary_type
T aexpected_class
repr
T adiscriminator_key
discriminator_value
allowed_values
a__doc__
a__file__
origin
has_location
a__cached__
decimal
T aDecimal
aDecimal
pathlib
T aPath
aPath
aTYPE_CHECKING
aAny
aCallable
aSequence
aSet
aTuple
aType
aUnion
upydantic.v1.typing
T adisplay_as_type
T]aPydanticTypeError
aPydanticValueError
aConfigError
aMissingError
aExtraError
aNoneIsNotAllowedError
aNoneIsAllowedError
aWrongConstantError
aNotNoneError
aBoolError
aBytesError
aDictError
aEmailError
aUrlError
aUrlSchemeError
aUrlSchemePermittedError
aUrlUserInfoError
aUrlHostError
aUrlHostTldError
aUrlPortError
aUrlExtraError
aEnumError
aIntEnumError
aEnumMemberError
aIntegerError
aFloatError
aPathError
aPathNotExistsError
aPathNotAFileError
aPathNotADirectoryError
aPyObjectError
aSequenceError
aListError
aSetError
aFrozenSetError
aTupleError
aTupleLengthError
aListMinLengthError
aListMaxLengthError
aListUniqueItemsError
aSetMinLengthError
aSetMaxLengthError
aFrozenSetMinLengthError
aFrozenSetMaxLengthError
aAnyStrMinLengthError
aAnyStrMaxLengthError
aStrError
aStrRegexError
aNumberNotGtError
aNumberNotGeError
aNumberNotLtError
aNumberNotLeError
aNumberNotMultipleError
aDecimalError
aDecimalIsNotFiniteError
aDecimalMaxDigitsError
aDecimalMaxPlacesError
aDecimalWholeDigitsError
aDateTimeError
aDateError
aDateNotInThePastError
aDateNotInTheFutureError
aTimeError
aDurationError
aHashableError
aUUIDError
aUUIDVersionError
aArbitraryTypeError
aClassError
aSubclassError
aJsonError
aJsonTypeError
aPatternError
aDataclassTypeError
aCallableError
aIPvAnyAddressError
aIPvAnyInterfaceError
aIPvAnyNetworkError
aIPv4AddressError
aIPv6AddressError
aIPv4NetworkError
aIPv6NetworkError
aIPv4InterfaceError
aIPv6InterfaceError
aColorError
aStrictBoolError
aNotDigitError
aLuhnValidationError
aInvalidLengthForBrand
aInvalidByteSize
aInvalidByteSizeUnit
aMissingDiscriminator
aInvalidDiscriminator
a__all__
cls
aPydanticErrorMixin
ctx
aDictStrAny
return
