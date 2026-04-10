# Reconstructed from integrated Nuitka blob
# Module: upydantic.type_adapter

uUsage docs: https://docs.pydantic.dev/2.10/concepts/type_adapter/
Type adapters provide a flexible way to perform validation and serialization based on a Python type.
A `TypeAdapter` instance exposes some of the functionality from `BaseModel` instance methods
for types that do not have such methods (such as dataclasses, primitive types, and more).
**Note:** `TypeAdapter` instances are not types, and cannot be used as type annotations for fields.
Args:
type: The type associated with the `TypeAdapter`.
config: Configuration for the `TypeAdapter`, should be a dictionary conforming to
[`ConfigDict`][pydantic.config.ConfigDict].
!!! note
You cannot provide a configuration when instantiating a `TypeAdapter` if the type you're using
has its own config that cannot be overridden (ex: `BaseModel`, `TypedDict`, and `dataclass`). A
[`type-adapter-config-unused`](../errors/usage_errors.md#type-adapter-config-unused) error will
be raised in this case.
_parent_depth: Depth at which to search for the [parent frame][frame-objects]. This frame is used when
resolving forward annotations during schema building, by looking for the globals and locals of this
frame. Defaults to 2, which will result in the frame where the `TypeAdapter` was instantiated.
!!! note
This parameter is named with an underscore to suggest its private nature and discourage use.
It may be deprecated in a minor version, so we only recommend using it if you're comfortable
with potential change in behavior/support. It's default value is 2 because internally,
the `TypeAdapter` class makes another call to fetch the frame.
module: The module that passes to plugin if provided.
Attributes:
core_schema: The core schema for the type.
validator: The schema validator for the type.
serializer: The schema serializer for the type.
pydantic_complete: Whether the core schema for the type is successfully built.
??? tip "Compatibility with `mypy`"
Depending on the type used, `mypy` might raise an error when instantiating a `TypeAdapter`. As a workaround, you can explicitly
nnotate your variable:
```py
from typing import Union
from pydantic import TypeAdapter
ta: TypeAdapter[Union[str, int]] = TypeAdapter(Union[str, int])  # type: ignore[arg-type]
```
??? info "Namespace management nuances and implementation details"
Here, we collect some notes on namespace management, and subtle differences from `BaseModel`:
`BaseModel` uses its own `__module__` to find out where it was defined
nd then looks for symbols to resolve forward references in those globals.
On the other hand, `TypeAdapter` can be initialized with arbitrary objects,
which may not be types and thus do not have a `__module__` available.
So instead we look at the globals in our parent stack frame.
It is expected that the `ns_resolver` passed to this function will have the correct
namespace for the type we're adapting. See the source code for `TypeAdapter.__init__`
nd `TypeAdapter.rebuild` for various ways to construct this namespace.
This works for the case where this function is called in a module that
has the target of forward references in its scope, but
does not always work for more complex cases.
For example, take the following:
```python {title="a.py"}
from typing import Dict, List
IntList = List[int]
OuterDict = Dict[str, 'IntList']
```
```python {test="skip" title="b.py"}
from a import OuterDict
from pydantic import TypeAdapter
IntList = int  # replaces the symbol the forward reference is looking for
v = TypeAdapter(OuterDict)
v({'x': 1})  # should fail but doesn't
```
If `OuterDict` were a `BaseModel`, this would work because it would resolve
the forward reference within the `a.py` namespace.
But `TypeAdapter(OuterDict)` can't determine what module `OuterDict` came from.
In other words, the assumption that _all_ forward references exist in the
module we are being called from is not technically always true.
Although most of the time it is and it works fine for recursive models and such,
`BaseModel`'s behavior isn't perfect either and _can_ break in similar ways,
so there is no right or wrong between the two.
But at the very least this behavior is _subtly_ different from `BaseModel`'s.
a__qualname__
a__annotations__
uSchemaValidator | PluggableSchemaValidator
bool
D aconfig
a_parent_depth
module
Q
Q
Q
D atype
config
a_parent_depth
module
return
utype[T]
uConfigDict | None
int
ustr | None
aNone
a__init__
uTypeAdapter.__init__
D atype
config
a_parent_depth
module
return
aAny
uConfigDict | None
int
ustr | None
aNone
D aconfig
a_parent_depth
module
nl nD areturn
uFrameType | None
uTypeAdapter._fetch_parent_frame
T FD ans_resolver
force
raise_errors
return
u_namespace_utils.NsResolver
bool
ppuTypeAdapter._init_core_attrs
property
D areturn
bool
uTypeAdapter._defer_build
D areturn
uConfigDict | None
uTypeAdapter._model_config
D areturn
str
a__repr__
uTypeAdapter.__repr__
D aforce
raise_errors
a_parent_namespace_depth
a_types_namespace
Ftl nD aforce
raise_errors
a_parent_namespace_depth
a_types_namespace
return
bool
paint
u_namespace_utils.MappingNamespace | None
ubool | None
uTypeAdapter.rebuild
D astrict
from_attributes
context
experimental_allow_partial
nnnFD aobject
strict
from_attributes
context
experimental_allow_partial
return
aAny
ubool | None
ubool | None
udict[str, Any] | None
ubool | Literal['off', 'on', 'trailing-strings']
wTuTypeAdapter.validate_python
D astrict
context
experimental_allow_partial
nnFD adata
strict
context
experimental_allow_partial
return
ustr | bytes | bytearray
ubool | None
udict[str, Any] | None
ubool | Literal['off', 'on', 'trailing-strings']
wTuTypeAdapter.validate_json
D aobj
strict
context
experimental_allow_partial
return
aAny
ubool | None
udict[str, Any] | None
ubool | Literal['off', 'on', 'trailing-strings']
wTuTypeAdapter.validate_strings
D astrict
context
nnD astrict
context
return
ubool | None
udict[str, Any] | None
uSome[T] | None
uTypeAdapter.get_default_value
D amode
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
context
python
nnFpppptFnDainstance
mode
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
context
return
wTuLiteral['json', 'python']
uIncEx | None
uIncEx | None
bool
ppppubool | Literal['none', 'warn', 'error']
bool
udict[str, Any] | None
aAny
dump_python
uTypeAdapter.dump_python
D aindent
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
context
nnnFpppptFnDainstance
indent
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
context
return
wTuint | None
uIncEx | None
uIncEx | None
bool
ppppubool | Literal['none', 'warn', 'error']
bool
udict[str, Any] | None
bytes
dump_json
uTypeAdapter.dump_json
by_alias
ref_template
schema_generator
mode
validation
D aby_alias
ref_template
schema_generator
mode
return
bool
str
utype[GenerateJsonSchema]
aJsonSchemaMode
udict[str, Any]
json_schema
uTypeAdapter.json_schema
staticmethod
D ainputs
by_alias
title
description
ref_template
schema_generator
return
uIterable[tuple[JsonSchemaKeyT, JsonSchemaMode, TypeAdapter[Any]]]
bool
ustr | None
ustr | None
str
utype[GenerateJsonSchema]
utuple[dict[tuple[JsonSchemaKeyT, JsonSchemaMode], JsonSchemaValue], JsonSchemaValue]
json_schemas
uTypeAdapter.json_schemas
a__orig_bases__
upydantic\type_adapter.py
u<module pydantic.type_adapter>
T a__class__
T aself
type
config
a_parent_depth
module
T aself
type
config
a_parent_depth
module
parent_frame
globalns
localns
T aself
T aself
config
T aself
frame
T aobj
attribute
slots
T aself
ns_resolver
force
raise_errors
config_wrapper
schema_generator
core_schema
core_config
T aself
type_
T atype_
Taself
instance
indent
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
context
Taself
instance
mode
include
exclude
by_alias
exclude_unset
exclude_defaults
exclude_none
round_trip
warnings
serialize_as_any
context
T aself
strict
context
T aself
by_alias
ref_template
schema_generator
mode
schema_generator_instance
T ainputs
by_alias
title
description
ref_template
schema_generator
json_schema
schema_generator_instance
inputs_
key
mode
adapter
json_schemas_map
definitions
T aself
force
raise_errors
a_parent_namespace_depth
a_types_namespace
rebuild_ns
globalns
ns_resolver
T aself
data
strict
context
experimental_allow_partial
T aself
object
strict
from_attributes
context
experimental_allow_partial
T aself
obj
strict
context
experimental_allow_partial
a__spec__
.pydantic.types
strict
aAnnotated
aStrict
annotated_types
aInterval
T agt
ge
lt
le
aMultipleOf

!!! warning "Discouraged"
This function is **discouraged** in favor of using
[`Annotated`](https://docs.python.org/3/library/typing.html#typing.Annotated) with
[`Field`][pydantic.fields.Field] instead.
This function will be **deprecated** in Pydantic 3.0.
The reason is that `conint` returns a type, which doesn't play well with static analysis tools.
=== ":x: Don't do this"
```python
from pydantic import BaseModel, conint
class Foo(BaseModel):
bar: conint(strict=True, gt=0)
```
=== ":white_check_mark: Do this"
```python
from typing_extensions import Annotated
from pydantic import BaseModel, Field
class Foo(BaseModel):
bar: Annotated[int, Field(strict=True, gt=0)]
```
A wrapper around `int` that allows for additional constraints.
Args:
strict: Whether to validate the integer in strict mode. Defaults to `None`.
gt: The value must be greater than this.
ge: The value must be greater than or equal to this.
lt: The value must be less than this.
le: The value must be less than or equal to this.
multiple_of: The value must be a multiple of this.
Returns:
The wrapped integer type.
```python
from pydantic import BaseModel, ValidationError, conint
class ConstrainedExample(BaseModel):
constrained_int: conint(gt=1)
m = ConstrainedExample(constrained_int=2)
print(repr(m))
#> ConstrainedExample(constrained_int=2)
try:
ConstrainedExample(constrained_int=0)
except ValidationError as e:
print(e.errors())
'''
[
{
'type': 'greater_than',
'loc': ('constrained_int',),
'msg': 'Input should be greater than 1',
'input': 0,
'ctx': {'gt': 1},
'url': 'https://errors.pydantic.dev/2/v/greater_than',
}
]
'''
```
allow_inf_nan
aAllowInfNan

!!! warning "Discouraged"
This function is **discouraged** in favor of using
[`Annotated`](https://docs.python.org/3/library/typing.html#typing.Annotated) with
[`Field`][pydantic.fields.Field] instead.
This function will be **deprecated** in Pydantic 3.0.
The reason is that `confloat` returns a type, which doesn't play well with static analysis tools.
=== ":x: Don't do this"
```python
from pydantic import BaseModel, confloat
class Foo(BaseModel):
bar: confloat(strict=True, gt=0)
```
=== ":white_check_mark: Do this"
```python
from typing_extensions import Annotated
from pydantic import BaseModel, Field
class Foo(BaseModel):
bar: Annotated[float, Field(strict=True, gt=0)]
```
A wrapper around `float` that allows for additional constraints.
Args:
strict: Whether to validate the float in strict mode.
gt: The value must be greater than this.
ge: The value must be greater than or equal to this.
lt: The value must be less than this.
le: The value must be less than or equal to this.
multiple_of: The value must be a multiple of this.
llow_inf_nan: Whether to allow `-inf`, `inf`, and `nan`.
Returns:
The wrapped float type.
```python
from pydantic import BaseModel, ValidationError, confloat
class ConstrainedExample(BaseModel):
constrained_float: confloat(gt=1.0)
m = ConstrainedExample(constrained_float=1.1)
print(repr(m))
#> ConstrainedExample(constrained_float=1.1)
try:
ConstrainedExample(constrained_float=0.9)
except ValidationError as e:
print(e.errors())
'''
[
{
'type': 'greater_than',
'loc': ('constrained_float',),
'msg': 'Input should be greater than 1',
'input': 0.9,
'ctx': {'gt': 1.0},
'url': 'https://errors.pydantic.dev/2/v/greater_than',
}
]
'''
```
aLen
uA wrapper around `bytes` that allows for additional constraints.
Args:
min_length: The minimum length of the bytes.
max_length: The maximum length of the bytes.
strict: Whether to validate the bytes in strict mode.
Returns:
The wrapped bytes type.
self
min_length
aMinLen
max_length
aMaxLen
strip_whitespace
pattern
to_lower
to_upper
a_fields
pydantic_general_metadata
T astrip_whitespace
to_upper
to_lower
pattern
a__iter__
uStringConstraints.__iter__
aStringConstraints
T astrip_whitespace
to_upper
to_lower
strict
min_length
max_length
pattern

!!! warning "Discouraged"
This function is **discouraged** in favor of using
[`Annotated`](https://docs.python.org/3/library/typing.html#typing.Annotated) with
[`StringConstraints`][pydantic.types.StringConstraints] instead.
This function will be **deprecated** in Pydantic 3.0.
The reason is that `constr` returns a type, which doesn't play well with static analysis tools.
=== ":x: Don't do this"
```python
from pydantic import BaseModel, constr
class Foo(BaseModel):
bar: constr(strip_whitespace=True, to_upper=True, pattern=r'^[A-Z]+$')
```
=== ":white_check_mark: Do this"
```python
from typing_extensions import Annotated
from pydantic import BaseModel, StringConstraints
class Foo(BaseModel):
bar: Annotated[
str,
StringConstraints(
strip_whitespace=True, to_upper=True, pattern=r'^[A-Z]+$'
),
]
```
A wrapper around `str` that allows for additional constraints.
```python
from pydantic import BaseModel, constr
class Foo(BaseModel):
bar: constr(strip_whitespace=True, to_upper=True)
foo = Foo(bar='  hello  ')
print(foo)
#> bar='HELLO'
```
Args:
strip_whitespace: Whether to remove leading and trailing whitespace.
to_upper: Whether to turn all characters to uppercase.
to_lower: Whether to turn all characters to lowercase.
strict: Whether to validate the string in strict mode.
min_length: The minimum length of the string.
max_length: The maximum length of the string.
pattern: A regex pattern to validate the string against.
Returns:
The wrapped string type.
aSet
uA wrapper around `typing.Set` that allows for additional constraints.
Args:
item_type: The type of the items in the set.
min_length: The minimum length of the set.
max_length: The maximum length of the set.
Returns:
The wrapped set type.
aFrozenSet
uA wrapper around `typing.FrozenSet` that allows for additional constraints.
Args:
item_type: The type of the items in the frozenset.
min_length: The minimum length of the frozenset.
max_length: The maximum length of the frozenset.
Returns:
The wrapped frozenset type.
aPydanticUserError
T u`unique_items` is removed, use `Set` instead(this feature is discussed in https://github.com/pydantic/pydantic-core/issues/296)
uremoved-kwargs
T acode
aList
uA wrapper around typing.List that adds validation.
Args:
item_type: The type of the items in the list.
min_length: The minimum length of the list. Defaults to None.
max_length: The maximum length of the list. Defaults to None.
unique_items: Whether the items in the list must be unique. Defaults to None.
!!! warning Deprecated
The `unique_items` parameter is deprecated, use `Set` instead.
See [this issue](https://github.com/pydantic/pydantic-core/issues/296) for more details.
Returns:
The wrapped list type.
upydantic_core.core_schema
plain_serializer_function_ser_schema
a_serialize
D awhen_used
json
no_info_plain_validator_function
a_validators
import_string
T afunction
serialization
no_info_before_validator_function
T afunction
schema
serialization
str_schema
aModuleType
