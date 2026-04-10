# Reconstructed from integrated Nuitka blob
# Module: upydantic.errors

uA mixin class for common functionality shared by all Pydantic-specific errors.
Attributes:
message: A message describing the error.
code: An optional error code from PydanticErrorCodes enum.
aPydanticErrorMixin
a__qualname__
D amessage
code
return
str
uPydanticErrorCodes | None
aNone
uPydanticErrorMixin.__init__
D areturn
str
a__str__
uPydanticErrorMixin.__str__
a__prepare__
aPydanticUserError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uAn error raised due to incorrect use of Pydantic.
a__orig_bases__
aPydanticUndefinedAnnotation
uA subclass of `NameError` raised when handling undefined annotations during `CoreSchema` generation.
Attributes:
name: Name of the error.
message: Description of the error.
D aname
message
return
str
paNone
uPydanticUndefinedAnnotation.__init__
classmethod
D aname_error
return
aNameError
aSelf
from_name_error
uPydanticUndefinedAnnotation.from_name_error
aPydanticImportError
uAn error raised when an import fails due to module changes between V1 and V2.
Attributes:
message: Description of the error.
D amessage
return
str
aNone
uPydanticImportError.__init__
aPydanticSchemaGenerationError
uAn error raised during failures to generate a `CoreSchema` for some type.
Attributes:
message: Description of the error.
uPydanticSchemaGenerationError.__init__
aPydanticInvalidForJsonSchema
uAn error raised during failures to generate a JSON schema for some `CoreSchema`.
Attributes:
message: Description of the error.
uPydanticInvalidForJsonSchema.__init__
T upydantic.errors
a__getattr__
upydantic\errors.py
u<module pydantic.errors>
T a__class__
T aself
message
code
T aself
message
a__class__
T aself
name
message
a__class__
T aself
T acls
name_error
name
a__spec__
.pydantic.fields
i
a_Unset
a_attributes_set
a_DefaultValues
get
a_extract_metadata
T aannotation
annotation
evaluated
pop
default
aPydanticUndefined
aEllipsis
T adefault
nT adefault_factory
nadefault_factory
ucannot specify both default and default_factory
T aalias
naalias
T avalidation_alias
navalidation_alias
T aserialization_alias
naserialization_alias
T aalias_priority
nl aalias_priority
T atitle
natitle
T afield_title_generator
nafield_title_generator
T adescription
nadescription
T aexamples
naexamples
T aexclude
naexclude
T adiscriminator
nadiscriminator
deprecated
T arepr
tarepr
T ajson_schema_extra
najson_schema_extra
T avalidate_default
navalidate_default
T afrozen
nafrozen
T ainit
nainit
T ainit_var
nainit_var
T akw_only
nakw_only
a_collect_metadata
metadata
uThis class should generally not be initialized directly; instead, use the `pydantic.fields.Field` function
or one of the constructor classmethods.
See the signature of `pydantic.fields.Field` for more details about the expected arguments.
u<genexpr>
uFieldInfo.__init__.<locals>.<genexpr>
u"annotation" is not permitted as a Field keyword argument
aFieldInfo
uCreate a new `FieldInfo` object with the `Field` function.
Args:
default: The default value for the field. Defaults to Undefined.
**kwargs: Additional arguments dictionary.
Raises:
TypeError: If 'annotation' is passed as a keyword argument.
Returns:
A new FieldInfo object with the given parameters.
Example:
This is how you can create a field with default value like this:
```python
import pydantic
class MyModel(pydantic.BaseModel):
foo: int = pydantic.Field(4)
```
a_typing_extra
is_finalvar
typing_extensions
aFinal
get_args
is_annotated
unot enough values to unpack (expected at least 1, got %d)
merge_field_infos
copy
is_deprecated_instance
message
new_field_info
T aannotation
frozen
uCreates a `FieldInfo` instance from a bare annotation.
This function is used internally to create a `FieldInfo` from a bare annotation like this:
```python
import pydantic
class MyModel(pydantic.BaseModel):
foo: int  # <-- like this
```
We also account for the case where the annotation can be an instance of `Annotated` and where
one of the (not first) arguments in `Annotated` is an instance of `FieldInfo`, e.g.:
```python
import annotated_types
from typing_extensions import Annotated
import pydantic
class MyModel(pydantic.BaseModel):
foo: Annotated[int, annotated_types.Gt(42)]
bar: Annotated[int, pydantic.Field(gt=42)]
```
Args:
nnotation: An annotation object.
Returns:
An instance of the field metadata.
aPydanticUserError
T uError when building FieldInfo from annotated attribute. Make sure you don't have any field name clashing with a type annotation
uunevaluable-type-annotation
T acode
dataclasses
aField
aInitVar
cast
aAny
type
a_from_dataclass_field
field_info
T aannotation
default
frozen
uCreate `FieldInfo` from an annotation with a default value.
This is used in cases like the following:
```python
import annotated_types
from typing_extensions import Annotated
import pydantic
class MyModel(pydantic.BaseModel):
foo: int = 4  # <-- like this
bar: Annotated[int, annotated_types.Gt(4)] = 4  # <-- or this
spam: Annotated[int, pydantic.Field(gt=4)] = 4  # <-- or this
```
Args:
nnotation: The type annotation of the field.
default: The default value of the field.
Returns:
A field object with the passed values.
update
items
T ajson_schema_extra
merged_field_info_kwargs
callable
warn
uComposing `dict` and `callable` type `json_schema_extra` is not supported.The `callable` type is being ignored.If you'd like support for this behavior, please open an issue on pydantic.
aPydanticJsonSchemaWarning
uMerge `FieldInfo` instances keeping only explicitly set attributes.
Later `FieldInfo` instances override earlier ones.
Returns:
FieldInfo: A merged FieldInfo instance.
aMISSING
a_FIELD_ARG_NAMES
uReturn a new `FieldInfo` instance from a `dataclasses.Field` instance.
Args:
dc_field: The `dataclasses.Field` instance to convert.
Returns:
The corresponding `FieldInfo` instance.
Raises:
TypeError: If any of the `FieldInfo` kwargs does not match the `dataclass.Field` kwargs.
uTries to extract metadata/constraints from an annotation if it uses `Annotated`.
Args:
nnotation: The type hint annotation for which metadata has to be extracted.
Returns:
A tuple containing the extracted metadata type and the list of extra arguments.
metadata_lookup
general_metadata
a_fields
pydantic_general_metadata
uCollect annotations from kwargs.
Args:
kwargs: Keyword arguments passed to the function.
Returns:
A list of metadata objects - a combination of `annotated_types.BaseMetadata` and
`PydanticMetadata`.
uThe deprecation message to be emitted, or `None` if not set.
takes_validated_data_argument
uWhether the provided default factory callable has a validated data parameter.
Returns `None` if no default factory is set.
a_utils
smart_deepcopy
default_factory_takes_validated_data
uCallable[[dict[str, Any]], Any]
uThe default factory requires the 'validated_data' argument, which was not provided when calling 'get_default'.
uCallable[[], Any]
uGet the default value.
We expose an option for whether to call the default_factory (if present), as calling it may
result in side effects that we want to avoid. However, there are times when it really should
be called (namely, when instantiating a model via `model_construct`).
Args:
call_default_factory: Whether to call the default factory or not.
validated_data: The already validated data to be passed to the default factory.
Returns:
The default value, calling the default factory if requested or `None` if not set.
uCheck if the field is required (i.e., does not have a default value or factory).
Returns:
`True` if the field is required, `False` otherwise.
aAnnotated
uAttempts to rebuild the original annotation for use in function signatures.
If metadata is present, it adds it to the original annotation using
`Annotated`. Otherwise, it returns the original annotation as-is.
Note that because the metadata has been flattened, the original annotation
may not be reconstructed exactly as originally provided, e.g. if the original
type had unrecognized annotations, or was annotated with a call to `pydantic.Field`.
Returns:
The rebuilt annotation.
try_eval_type
a_generics
replace_types
uApply a `typevars_map` to the annotation.
This method is used when analyzing parametrized generic types to replace typevars with their concrete types.
This method applies the `typevars_map` to the annotation in place.
Args:
typevars_map: A dictionary mapping type variables to their concrete types.
globalns: The globals namespace to use during type annotation evaluation.
localns: The locals namespace to use during type annotation evaluation.
See Also:
pydantic._internal._generics.replace_types is used for replacing the typevars with
their concrete types.
a_repr
aPlainRepr
display_as_type
self
required
is_required
a__slots__
T a_attributes_set
annotation
evaluated
a__repr_args__
uFieldInfo.__repr_args__
const
T u`const` is removed, use `Literal` instead
uremoved-kwargs
T amin_items
nu`min_items` is deprecated and will be removed, use `min_length` instead
aDeprecationWarning
T amax_items
nu`max_items` is deprecated and will be removed, use `max_length` instead
T aunique_items
nT u`unique_items` is removed, use `Set` instead(this feature is discussed in https://github.com/pydantic/pydantic-core/issues/296)
uremoved-kwargs
T aallow_mutation
nu`allow_mutation` is deprecated and will be removed. use `frozen` instead
T aregex
nT u`regex` is removed. use `pattern` instead
uremoved-kwargs
uUsing extra keyword arguments on `Field` is deprecated and will be removed. Use `json_schema_extra` instead. (Extra keys:
u,
keys
w)u
aAliasChoices
aAliasPath
uInvalid `validation_alias` type. it should be `str`, `AliasChoices`, or `AliasPath`
T ainclude
nu`include` is deprecated and does nothing. It will be removed, use `exclude` instead
from_field
T"adefault_factory
alias
alias_priority
validation_alias
serialization_alias
title
field_title_generator
description
examples
exclude
discriminator
deprecated
json_schema_extra
frozen
pattern
validate_default
repr
init
init_var
kw_only
coerce_numbers_to_str
strict
gt
ge
lt
le
multiple_of
min_length
max_length
allow_inf_nan
max_digits
decimal_places
union_mode
fail_fast
uUsage docs: https://docs.pydantic.dev/2.10/concepts/fields
Create a field for objects that can be configured.
Used to provide extra information about a field, either for the model schema or complex validation. Some arguments
pply only to number fields (`int`, `float`, `Decimal`) and some apply only to `str`.
Note:
- Any `_Unset` objects will be replaced by the corresponding value defined in the `_DefaultValues` dictionary. If a key for the `_Unset` object is not found in the `_DefaultValues` dictionary, it will default to `None`
Args:
default: Default value if the field is not set.
default_factory: A callable to generate the default value. The callable can either take 0 arguments
(in which case it is called as is) or a single argument containing the already validated data.
lias: The name to use for the attribute when validating or serializing by alias.
This is often used for things like converting between snake and camel case.
lias_priority: Priority of the alias. This affects whether an alias generator is used.
validation_alias: Like `alias`, but only affects validation, not serialization.
serialization_alias: Like `alias`, but only affects serialization, not validation.
title: Human-readable title.
field_title_generator: A callable that takes a field name and returns title for it.
description: Human-readable description.
examples: Example values for this field.
exclude: Whether to exclude the field from the model serialization.
discriminator: Field name or Discriminator for discriminating the type in a tagged union.
deprecated: A deprecation message, an instance of `warnings.deprecated` or the `typing_extensions.deprecated` backport,
or a boolean. If `True`, a default deprecation message will be emitted when accessing the field.
json_schema_extra: A dict or callable to provide extra JSON schema properties.
frozen: Whether the field is frozen. If true, attempts to change the value on an instance will raise an error.
validate_default: If `True`, apply validation to the default value every time you create an instance.
Otherwise, for performance reasons, the default value of the field is trusted and not validated.
repr: A boolean indicating whether to include the field in the `__repr__` output.
init: Whether the field should be included in the constructor of the dataclass.
(Only applies to dataclasses.)
init_var: Whether the field should _only_ be included in the constructor of the dataclass.
(Only applies to dataclasses.)
kw_only: Whether the field should be a keyword-only argument in the constructor of the dataclass.
(Only applies to dataclasses.)
coerce_numbers_to_str: Whether to enable coercion of any `Number` type to `str` (not applicable in `strict` mode).
strict: If `True`, strict validation is applied to the field.
See [Strict Mode](../concepts/strict_mode.md) for details.
gt: Greater than. If set, value must be greater than this. Only applicable to numbers.
ge: Greater than or equal. If set, value must be greater than or equal to this. Only applicable to numbers.
lt: Less than. If set, value must be less than this. Only applicable to numbers.
le: Less than or equal. If set, value must be less than or equal to this. Only applicable to numbers.
multiple_of: Value must be a multiple of this. Only applicable to numbers.
min_length: Minimum length for iterables.
max_length: Maximum length for iterables.
pattern: Pattern for strings (a regular expression).
llow_inf_nan: Allow `inf`, `-inf`, `nan`. Only applicable to numbers.
max_digits: Maximum number of allow digits for strings.
decimal_places: Maximum number of decimal places allowed for numbers.
union_mode: The strategy to apply when validating a union. Can be `smart` (the default), or `left_to_right`.
See [Union Mode](../concepts/unions.md#union-modes) for details.
fail_fast: If `True`, validation will stop on the first error. If `False`, all validation errors will be collected.
This option can be applied only to iterable types (list, tuple, set, and frozenset).
extra: (Deprecated) Extra fields that will be included in the JSON schema.
!!! warning Deprecated
The `extra` kwargs is deprecated. Use `json_schema_extra` instead.
Returns:
A new [`FieldInfo`][pydantic.fields.FieldInfo]. The return annotation is `Any` so `Field` can be used on
type-annotated fields without causing a type error.
a__repr__
uField.<locals>.<genexpr>
P a__get__
a__delete__
a__set__
a__name__
u object has no attribute
uThis function improves compatibility with custom descriptors by ensuring delegation happens
s expected when the default value of a private attribute is a descriptor.
a__set_name__
uPreserve `__set_name__` protocol defined in https://peps.python.org/pep-0487.
uRetrieve the default value of the object.
If `self.default_factory` is `None`, the method will return a deep copy of the `self.default` object.
If `self.default_factory` is not `None`, it will call `self.default_factory` and return the value returned.
Returns:
The default value of the object.
aModelPrivateAttr
T adefault_factory
uUsage docs: https://docs.pydantic.dev/2.10/concepts/models/#private-model-attributes
Indicates that an attribute is intended for private use and not handled during normal validation/serialization.
Private attributes are not validated by Pydantic, so it's up to you to ensure they are used in a type-safe manner.
Private attributes are stored in `__private_attributes__` on the model.
Args:
default: The attribute's default value. Defaults to Undefined.
default_factory: Callable that will be
called when a default value is needed for this attribute.
If both `default` and `default_factory` are set, an error will be raised.
init: Whether the attribute should be included in the constructor of the dataclass. Always `False`.
Returns:
An instance of [`ModelPrivateAttr`][pydantic.fields.ModelPrivateAttr] class.
Raises:
ValueError: If both `default` and `default_factory` are set.
fget
cached_property
func
startswith
T w_T a__
uReturns true if provided property is private, False otherwise.
D wfareturn
aAny
padec
ucomputed_field.<locals>.dec
uUsage docs: https://docs.pydantic.dev/2.10/concepts/fields#the-computed_field-decorator
Decorator to include `property` and `cached_property` when serializing models or dataclasses.
This is useful for fields that are computed from other fields, or for fields that are expensive to compute and should be cached.
```python
from pydantic import BaseModel, computed_field
class Rectangle(BaseModel):
width: int
length: int
@computed_field
@property
def area(self) -> int:
return self.width * self.length
print(Rectangle(width=3, length=2).model_dump())
#> {'width': 3, 'length': 2, 'area': 6}
```
If applied to functions not yet decorated with `@property` or `@cached_property`, the function is
utomatically wrapped with `property`. Although this is more concise, you will lose IntelliSense in your IDE,
nd confuse static type checkers, thus explicit use of `@property` is recommended.
!!! warning "Mypy Warning"
Even with the `@property` or `@cached_property` applied to your function before `@computed_field`,
mypy may throw a `Decorated property not supported` error.
See [mypy issue #1362](https://github.com/python/mypy/issues/1362), for more information.
To avoid this error message, add `# type: ignore[misc]` to the `@computed_field` line.
[pyright](https://github.com/microsoft/pyright) supports `@computed_field` without error.
```python
import random
from pydantic import BaseModel, computed_field
class Square(BaseModel):
width: float
@computed_field
def area(self) -> float:  # converted to a `property` by `computed_field`
return round(self.width**2, 2)
@area.setter
def area(self, new_area: float) -> None:
self.width = new_area**0.5
@computed_field(alias='the magic number', repr=False)
def random_number(self) -> int:
return random.randint(0, 1_000)
square = Square(width=1.3)
# `random_number` does not appear in representation
print(repr(square))
#> Square(width=1.3, area=1.69)
print(square.random_number)
#> 3
square.area = 4
print(square.model_dump_json(by_alias=True))
#> {"width":2.0,"area":4.0,"the magic number":3}
```
!!! warning "Overriding with `computed_field`"
You can't override a field from a parent class with a `computed_field` in the child class.
`mypy` complains about this behavior if allowed, and `dataclasses` doesn't allow this pattern either.
See the example below:
```python
from pydantic import BaseModel, computed_field
class Parent(BaseModel):
a: str
try:
class Child(Parent):
@computed_field
@property
def a(self) -> str:
return 'new a'
except ValueError as e:
print(repr(e))
#> ValueError("you can't override a field with a computed field")
```
Private properties decorated with `@computed_field` have `repr=False` by default.
```python
from functools import cached_property
from pydantic import BaseModel, computed_field
class Model(BaseModel):
foo: int
@computed_field
@cached_property
def _private_cached_property(self) -> int:
return -self.foo
@computed_field
@property
def _private_property(self) -> int:
return -self.foo
m = Model(foo=1)
print(repr(m))
#> Model(foo=1)
```
Args:
func: the function to wrap.
lias: alias to use when serializing this computed field, only used when `by_alias=True`
lias_priority: priority of the alias. This affects whether an alias generator is used
title: Title to use when including this computed field in JSON Schema
field_title_generator: A callable that takes a field name and returns title for it.
description: Description to use when including this computed field in JSON Schema, defaults to the function's
docstring
deprecated: A deprecation message (or an instance of `warnings.deprecated` or the `typing_extensions.deprecated` backport).
to be emitted when accessing the field. Or a boolean. This will automatically be set if the property is decorated with the
`deprecated` decorator.
examples: Example values to use when including this computed field in JSON Schema
json_schema_extra: A dict or callable to provide extra JSON schema properties.
repr: whether to include this computed field in model repr.
Default is `False` for private properties and `True` for public properties.
return_type: optional return for serialization logic to expect when serializing to JSON, if included
this must be correct, otherwise a `TypeError` is raised.
If you don't include a return type Any is used, which does runtime introspection to handle arbitrary
objects.
Returns:
A proxy wrapper for the property.
a_decorators
unwrap_wrapped_function
a__doc__
inspect
cleandoc
a__deprecated__
ensure_property
a_wrapped_property_is_private
T aproperty_
aComputedFieldInfo
return_type
aPydanticDescriptorProxy
uDefining fields on models.
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
a_annotations
sys
typing
T acopy
T aField
aDataclassField
aCallable
aClassVar
aTypeVar
overload
warnings
T awarn
annotated_types
pydantic_core
T aLiteral
aTypeAlias
aUnpack
deprecated
aLiteral
aTypeAlias
aUnpack
T atypes
types
a_internal
T a_decorators
a_fields
a_generics
a_internal_dataclass
a_repr
a_typing_extra
a_utils
a_internal_dataclass
u_internal._namespace_utils
T aGlobalsNamespace
aMappingNamespace
aGlobalsNamespace
aMappingNamespace
upydantic.aliases
upydantic.config
aJsonDict
upydantic.errors
upydantic.json_schema
upydantic.warnings
aPydanticDeprecatedSince20
T aField
aPrivateAttr
computed_field
a__all__
aDeprecated
aTypedDict
D atotal
Fa__prepare__
a_FromFieldInfoInputs
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
