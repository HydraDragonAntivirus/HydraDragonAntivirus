# Reconstructed from integrated Nuitka blob
# Module: is_typeddict

typing
a__required_keys__
uYou should use `typing_extensions.TypedDict` instead of `typing.TypedDict` with Python < 3.9.2. Without it, there is no way to differentiate required and optional fields when subclassed.
is_legacy_typeddict
a__annotations__
values
uYou should use `typing_extensions.TypedDict` instead of `typing.TypedDict` with Python < 3.11. Without it, there is no way to reflect Required/NotRequired keys.
items
aRequired
create_model
a__name__

Create a `BaseModel` based on the fields of a `TypedDict`.
Since `typing.TypedDict` in Python 3.8 does not store runtime information about optional keys,
we raise an error if this happens (see https://bugs.python.org/issue38834).
is_typeddict_special
u<genexpr>
ucreate_model_from_typeddict.<locals>.<genexpr>
a_fields
aAny

Create a `BaseModel` based on the fields of a named tuple.
A named tuple can be created with `typing.NamedTuple` and declared annotations
but also with `collections.namedtuple`, in this case we consider all fields
to have type `Any`.
a__doc__
a__file__
origin
has_location
a__cached__
sys
aTYPE_CHECKING
aDict
aFrozenSet
aNamedTuple
aType
upydantic.v1.fields
T aRequired
upydantic.v1.main
T aBaseModel
create_model
aBaseModel
upydantic.v1.typing
T ais_typeddict
is_typeddict_special
typeddict_cls
aTypedDict
return
kwargs
create_model_from_typeddict
namedtuple_cls
create_model_from_namedtuple
upydantic\v1\annotated_types.py
T a.0
wtu<module pydantic.v1.annotated_types>
T anamedtuple_cls
kwargs
namedtuple_annotations
field_definitions
T atypeddict_cls
kwargs
field_definitions
required_keys
T atypeddict_cls

a__spec__
.pydantic.v1.class_validators
func
pre
each_item
always
check_fields
skip_on_failure
aConfigError
T uvalidator with no fields specified
aFunctionType
T uvalidators should be used with fields and keyword arguments, not bare. E.g. usage should be `@validator('<field_name>', ...)`
T uvalidator fields should be passed as separate string args. E.g. usage should be `@validator('<field_name_1>', '<field_name_2>', ...)`
warnings
warn
uThe "whole" keyword argument is deprecated, use "each_item" (inverse meaning, default False) instead
aDeprecationWarning
T u"each_item" and "whole" conflict, remove "whole"
wfaAnyCallable
return
aAnyClassMethod
dec
uvalidator.<locals>.dec

Decorate methods on the class indicating that they should be used to validate fields
:param fields: which field(s) the method should be called on
:param pre: whether or not this validator should be called before the standard validators (else after)
:param each_item: for complex objects (sets, lists etc.) whether to validate individual elements rather than the
whole object
:param always: whether this method and other validators should be called even if the value is missing
:param check_fields: whether to check that the fields actually exist on the model
:param allow_reuse: whether to track and raise an error if another validator refers to the decorated function
u<genexpr>
uvalidator.<locals>.<genexpr>
a_prepare_validator
allow_reuse
aVALIDATOR_CONFIG_KEY
fields
aValidator
a__func__
T afunc
pre
each_item
always
check_fields
aROOT_VALIDATOR_CONFIG_KEY
T afunc
pre
skip_on_failure
uroot_validator.<locals>.dec

Decorate methods on a model indicating that they should be used to validate (and perhaps modify) data either
before or after standard model parsing/validation is performed.
