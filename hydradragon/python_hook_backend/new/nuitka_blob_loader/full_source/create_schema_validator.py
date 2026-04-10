# Reconstructed from integrated Nuitka blob
# Module: create_schema_validator

dataclass
plugin_settings
a__pydantic_validator__
aSchemaSerializer
a__pydantic_serializer__
validate_assignment
wraps
a__setattr__
D ainstance
field
value
return
aAny
str
paNone
validated_setattr
ucomplete_dataclass.<locals>.validated_setattr
a__get__
a__pydantic_complete__
uFinish building a pydantic dataclass.
This logic is called on a class which has already been wrapped in `dataclasses.dataclass()`.
This is somewhat analogous to `pydantic._internal._model_construction.complete_model_class`.
Args:
cls: The class.
config_wrapper: The config wrapper instance.
raise_errors: Whether to raise errors, defaults to `True`.
ns_resolver: The namespace resolver instance to use when collecting dataclass fields
nd during schema building.
_force_build: Whether to force building the dataclass, no matter if
[`defer_build`][pydantic.config.ConfigDict.defer_build] is set.
Returns:
`True` if building a pydantic dataclass is successfully completed, `False` otherwise.
Raises:
PydanticUndefinedAnnotation: If `raise_error` is `True` and there is an undefined annotations.
validate_python
aArgsKwargs
T aself_instance
validator
dataclasses
is_dataclass
a__dataclass_fields__
issuperset
a__annotations__
uReturns True if a class is a stdlib dataclass and *not* a pydantic dataclass.
We check that
- `_cls` is a dataclass
- `_cls` does not inherit from a processed pydantic dataclass (and thus have a `__pydantic_validator__`)
- `_cls` does not have any annotations that are not dataclass fields
e.g.
```python
import dataclasses
import pydantic.dataclasses
@dataclasses.dataclass
class A:
x: int
@pydantic.dataclasses.dataclass
class B(A):
y: int
```
In this case, when we first check `B`, we make an extra check and look at the annotations ('y'),
which won't be a superset of all the dataclass fields (only the stdlib fields i.e. 'x')
Args:
cls: The class.
Returns:
`True` if the class is a stdlib dataclass, `False` otherwise.
uPrivate logic for creating pydantic dataclasses.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
a_annotations
typing
aAny
aClassVar
pydantic_core
aSchemaValidator
upydantic_core.core_schema
core_schema
typing_extensions
T aTypeGuard
aTypeGuard
upydantic.errors
uplugin._schema_validator
T aPluggableSchemaValidator
create_schema_validator
l aPluggableSchemaValidator
upydantic.warnings
aPydanticDeprecatedSince20
T a_config
a_decorators
a_config
a_decorators
a_fields
T acollect_dataclass_fields
upydantic._internal._generate_schema
a_generics
T aget_standard_typevars_map
a_mock_val_ser
T aset_dataclass_mocks
a_namespace_utils
T aNsResolver
aNsResolver
a_schema_generation_shared
T aCallbackGetCoreSchemaHandler
a_signature
T agenerate_pydantic_signature
a_utils
T aLazyClassAttribute
T nnD acls
ns_resolver
config_wrapper
return
utype[StandardDataclass]
uNsResolver | None
u_config.ConfigWrapper | None
aNone
D araise_errors
ns_resolver
a_force_build
tnFD acls
config_wrapper
raise_errors
ns_resolver
a_force_build
return
utype[Any]
u_config.ConfigWrapper
bool
uNsResolver | None
bool
pacomplete_dataclass
D a_cls
return
utype[Any]
uTypeGuard[type[StandardDataclass]]
is_builtin_dataclass
upydantic\_internal\_dataclasses.py
u<module pydantic._internal._dataclasses>
T a__dataclass_self__
args
kwargs
a__tracebackhide__
wsT acls
config_wrapper
raise_errors
ns_resolver
a_force_build
original_init
a__init__
typevars_map
gen_schema
get_core_schema
schema
weacore_config
validator
validated_setattr
T a_cls
T acls
ns_resolver
config_wrapper
typevars_map
fields
T ainstance
field
value
validator
T avalidator
a__spec__
.pydantic._internal._decorators
G
K T asetter
deleter
self
wrapped
partial
a_call_wrapped_attr
T aname
upydantic.fields
aComputedFieldInfo
decorator_info
wrapped_property
a__get__
a__set_name__
uForward checks for __isabstractmethod__ and such.
get_attribute_from_bases
unwrap_wrapped_function
D aunwrap_partial
Facallable
get_attribute_from_base_dicts
aPydanticDescriptorProxy
aDecorator
get_type_ref
T acls_ref
cls_var_name
func
shim
info
uBuild a new decorator.
Args:
cls_: The class.
cls_var_name: The decorated function name.
shim: A wrapper function to wrap V1 style function.
info: The decorator info.
Returns:
The new decorator instance.
build
cls_var_name
shim
info
T acls_var_name
shim
info
uBind the decorator to a class.
Args:
cls: the class.
Returns:
The new decorator instance.
is_typeddict
a__orig_bases__
a__bases__
uGet the base classes of a class or typeddict.
Args:
tp: The type or class to get the bases.
Returns:
The base classes.
a__mro__
get_bases
mro_for_bases
uCalculate the Method Resolution Order of bases using the C3 algorithm.
See https://www.python.org/download/releases/2.3/mro/
D aseqs
return
ulist[deque[type[Any]]]
uIterable[type[Any]]
merge_seqs
umro_for_bases.<locals>.merge_seqs
deque
mro
seqs
non_empty
islice
candidate
uInconsistent hierarchy, no C3 MRO is possible
popleft
get
name
a_sentinel

u not found in
uGet the attribute from the next class in the MRO that has it,
iming to simulate calling the method on the actual class.
The reason for iterating over the mro instead of just getting
the attribute (which would do that for us) is to support TypedDict,
which lacks a real __mro__, but can have a virtual one constructed
from its bases (as done here).
Args:
tp: The type or class to search for the attribute. If a tuple, this is treated as a set of base classes.
name: The name of the attribute to retrieve.
Returns:
Any: The attribute value, if found.
Raises:
AttributeError: If the attribute is not found in any class in the MRO.
uGet an attribute out of the `__dict__` following the MRO.
This prevents the call to `__get__` on the descriptor, and allows
us to get the original function for classmethod properties.
Args:
tp: The type or class to search for the attribute.
name: The name of the attribute to retrieve.
Returns:
Any: The attribute value, if found.
Raises:
KeyError: If the attribute is not found in any class's `__dict__` in the MRO.
aDecoratorInfos
:l nnT a__pydantic_decorators__
res
validators
update
items
bind_to_cls
model_dc
field_validators
root_validators
field_serializers
model_serializers
model_validators
computed_fields
aValidatorDecoratorInfo
aFieldValidatorDecoratorInfo
aRootValidatorDecoratorInfo
aFieldSerializerDecoratorInfo
values
fields
field_serializer_decorator
aPydanticUserError
uMultiple field serializer functions were defined for field
u, this is not allowed.
D acode
umultiple-field-serializers
aModelValidatorDecoratorInfo
aModelSerializerDecoratorInfo
to_replace
var_name
a__pydantic_decorators__
uWe want to collect all DecFunc instances that exist as
ttributes in the namespace of the class (a BaseModel or dataclass)
that called us
But we want to collect these in the order of the bases
So instead of getting them all from the leaf class (the class that called us),
we traverse the bases from root (the oldest ancestor class) to leaf
nd collect all of the instances as we go, taking care to replace
ny duplicate ones with the last one we see to mimic how function overriding
works with inheritance.
If we do replace any functions we put the replacement into the position
the replaced function was in; that is, we maintain the order.
signature
T EValueError
ETypeError
count_positional_required_params
wrap
l l P aplain
after
before
uinvalid mode:
u, expected 'before', 'after' or 'plain
uUnrecognized field_validator function signature for
u with `mode=
u`:
D acode
uvalidator-signature
uLook at a field or model validator function and determine whether it takes an info argument.
An error is raised if the function has an invalid signature.
Args:
validator: The validator function to inspect.
mode: The proposed validator mode.
Returns:
Whether the validator takes an info argument.
T Fpaparameters
a_serializer_info_arg
uUnrecognized field_serializer function signature for
mode
D acode
ufield-serializer-signature
uLook at a field serializer function and determine if it is a field serializer,
nd whether it takes an info argument.
An error is raised if the function has an invalid signature.
Args:
serializer: The serializer function to inspect.
mode: The serializer mode, either 'plain' or 'wrap'.
Returns:
Tuple of (is_field_serializer, info_arg).
uLook at a serializer function used via `Annotated` and determine whether it takes an info argument.
An error is raised if the function has an invalid signature.
Args:
serializer: The serializer function to check.
mode: The serializer mode, either 'plain' or 'wrap'.
Returns:
info_arg
T Ostaticmethod
Oclassmethod
is_instance_method_from_sig
T u`@model_serializer` must be applied to instance methods
umodel-serializer-instance-method
T acode
uUnrecognized model_serializer function signature for
D acode
umodel-serializer-signature
uLook at a model serializer function and determine whether it takes an info argument.
An error is raised if the function has an invalid signature.
Args:
serializer: The serializer function to check.
mode: The serializer mode, either 'plain' or 'wrap'.
Returns:
`info_arg` - whether the function expects an info argument.
plain
u, expected 'plain' or 'wrap'
uWhether the function is an instance method.
It will consider a function as instance method if the first parameter of
function is `self`.
Args:
function: The function to check.
Returns:
`True` if the function is an instance method, `False` otherwise.
D aunwrap_class_static_method
Fa_is_classmethod_from_sig
uApply the `@classmethod` decorator on the function.
Args:
function: The function to apply the decorator on.
Return:
The `@classmethod` decorator applied function.
cls
cached_property
partialmethod
func
T Oclassmethod
Ostaticmethod
a__func__
fget
uRecursively unwraps a wrapped function until the underlying function is reached.
This handles property, functools.partial, functools.partialmethod, staticmethod, and classmethod.
Args:
func: The function to unwrap.
unwrap_partial: If True (default), unwrap partial and partialmethod decorators.
unwrap_class_static_method: If True (default), also unwrap classmethod and staticmethod
decorators. If False, only unwrap partial and partialmethod decorators.
Returns:
The underlying function of the wrapped function.
aPydanticUndefined
get_function_type_hints
S areturn
T ainclude_keys
globalns
localns
return
uGet the function return type.
It gets the return type from the type annotation if `explicit_return_type` is `None`.
Otherwise, it returns `explicit_return_type`.
Args:
func: The function to get its return type.
explicit_return_type: The explicit return type.
globalns: The globals namespace to use during type annotation evaluation.
localns: The locals namespace to use during type annotation evaluation.
Returns:
The function return type.
uGet the number of positional (required) arguments of a signature.
This function should only be used to inspect signatures of validation and serialization functions.
The first argument (the value being serialized or validated) is counted as a required argument
even if a default value exists.
Returns:
The number of positional arguments of a signature.
can_be_positional
default
aParameter
empty
u<genexpr>
ucount_positional_required_params.<locals>.<genexpr>
ismethoddescriptor
isdatadescriptor
uEnsure that a function is a `property` or `cached_property`, or is a valid descriptor.
Args:
f: The function to check.
Returns:
The function, or a `property` or `cached_property` instance wrapping the function.
uLogic related to validators applied to models etc. via the `@field_validator` and `@model_validator` decorators.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
a_annotations
collections
T adeque
dataclasses
T adataclass
field
dataclass
field
inspect
T aParameter
aSignature
isdatadescriptor
ismethoddescriptor
signature
aSignature
itertools
T aislice
aTYPE_CHECKING
aAny
aCallable
aClassVar
aGeneric
aIterable
aTypeVar
aUnion
pydantic_core
upydantic_core.core_schema
core_schema
typing_extensions
T aLiteral
aTypeAlias
is_typeddict
aLiteral
aTypeAlias
upydantic.errors
a_core_utils
T aget_type_ref
a_internal_dataclass
T aslots_true
slots_true
a_namespace_utils
T aGlobalsNamespace
aMappingNamespace
aGlobalsNamespace
aMappingNamespace
a_typing_extra
T aget_function_type_hints
a_utils
T acan_be_positional
