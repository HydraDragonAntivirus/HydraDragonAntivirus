# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._std_types_schema

uUse a fixed CoreSchema, avoiding interference from outward annotations.
a__qualname__
uJsonSchemaValue | None
uCoreSchema | None
D a_schema
handler
return
aCoreSchema
aGetJsonSchemaHandler
aJsonSchemaValue
a__get_pydantic_json_schema__
uInnerSchemaValidator.__get_pydantic_json_schema__
D a_source_type
a_handler
return
aAny
aGetCoreSchemaHandler
aCoreSchema
a__get_pydantic_core_schema__
uInnerSchemaValidator.__get_pydantic_core_schema__
D asource_type
annotations
return
aAny
uIterable[Any]
utuple[Any, list[Any]] | None
path_schema_prepare_pydantic_annotations
D ainput_value
handler
maxlen
return
aAny
ucore_schema.ValidatorFunctionWrapHandler
uNone | int
ucollections.deque[Any]
utype[Any]
udict[str, Any]
D asource_type
handler
return
aAny
aGetCoreSchemaHandler
aCoreSchema
uDequeValidator.__get_pydantic_core_schema__
deque_schema_prepare_pydantic_annotations
aDefaultDict
aOrderedDict
aDict
udict[Any, Any]
D ainput_value
handler
default_default_factory
return
aAny
ucore_schema.ValidatorFunctionWrapHandler
uCallable[[], Any]
ucollections.defaultdict[Any, Any]
D avalues_source_type
return
aAny
uCallable[[], Any]
uint | None
bool
D wvahandler
return
aAny
ucore_schema.SerializerFunctionWrapHandler
aAny
uMappingValidator.serialize_mapping_via_dict
uMappingValidator.__get_pydantic_core_schema__
mapping_like_prepare_pydantic_annotations
upydantic\_internal\_std_types_schema.py
T a.0
wvu<module pydantic._internal._std_types_schema>
T a__class__
T aself
source_type
handler
items_schema
coerce_instance_wrap
metadata_with_strict_override
constrained_schema
check_instance
serialization
strict
schema
lax
T aself
a_source_type
a_handler
T aself
source_type
handler
keys_schema
values_schema
metadata
schema
constrained_schema
check_instance
default_default_factory
coerce_instance_wrap
serialization
strict
lax
T aself
a_schema
handler
js_schema
T ainput_value
handler
default_default_factory
default_factory
T asource_type
annotations
args
item_source_type
metadata
remaining_annotations
T ainput_value
handler
maxlen
maxlens
T avalues_source_type
infer_default
field_info
default_default_factory
T aallowed_default_types
values_type_origin
instructions
type_var_default_factory
allowed_msg
values_source_type
T avalues_source_type
T	asource_type
annotations
origin
mapped_origin
args
keys_source_type
values_source_type
metadata
remaining_annotations
T asource_type
annotations
orig_source_type
strict
pathlib
source_type_args
metadata
remaining_annotations
is_first_arg_byte
construct_path
constrained_schema
path_validator
instance_schema
annotation
schema
T ainput_value
weais_first_arg_byte
construct_path
T aconstruct_path
is_first_arg_byte
T aself
wvahandler
T ainstructions
a__spec__
.pydantic._internal._typing_extra
b8
typing_extensions
uNeither `typing` nor `typing_extensions` has an object called

uGet the member named `name` from both `typing` and `typing-extensions` (if it exists).
name
u<genexpr>
u_get_typing_objects_by_name_of.<locals>.<genexpr>
a_get_typing_objects_by_name_of
uReturn whether `obj` is the member of the typing modules (includes the `typing-extensions` one) named `name`.
a_is_typing_name
D aname
aAny
uReturn whether the provided argument is the `Any` special form.
```python {test="skip" lint="skip"}
is_any(Any)
#> True
```
get_origin
D aname
aUnion
uReturn whether the provided argument is a `Union` special form.
```python {test="skip" lint="skip"}
is_union(Union[int, str])
#> True
is_union(int | str)
#> False
```
D aname
aLiteral
uReturn whether the provided argument is a `Literal` special form.
```python {test="skip" lint="skip"}
is_literal(Literal[42])
#> True
```
is_literal
get_args
literal_values
uReturn the values contained in the provided `Literal` special form.
D aname
aAnnotated
uReturn whether the provided argument is a `Annotated` special form.
```python {test="skip" lint="skip"}
is_annotated(Annotated[int, ...])
#> True
```
is_annotated
uReturn the type of the `Annotated` special form, or `None`.
D aname
aUnpack
uReturn whether the provided argument is a `Unpack` special form.
```python {test="skip" lint="skip"}
is_unpack(Unpack[Ts])
#> True
```
is_unpack
uReturn the type wrapped by the `Unpack` special form, or `None`.
D aname
aSelf
uReturn whether the provided argument is the `Self` special form.
```python {test="skip" lint="skip"}
is_self(Self)
#> True
```
D aname
aNewType
uReturn whether the provided argument is a `NewType`.
```python {test="skip" lint="skip"}
is_new_type(NewType('MyInt', int))
#> True
```
collections
abc
aHashable
uReturn whether the provided argument is the `Hashable` class.
```python {test="skip" lint="skip"}
is_hashable(Hashable)
#> True
```
aCallable
uReturn whether the provided argument is a `Callable`, parametrized or not.
```python {test="skip" lint="skip"}
is_callable(Callable[[int], str])
#> True
is_callable(typing.Callable)
#> True
is_callable(collections.abc.Callable)
#> True
```
a_PARAMSPEC_TYPES
uReturn whether the provided argument is a `ParamSpec`.
```python {test="skip" lint="skip"}
P = ParamSpec('P')
is_paramspec(P)
#> True
```
a_TYPE_ALIAS_TYPES
uReturn whether the provided argument is an instance of `TypeAliasType`.
```python {test="skip" lint="skip"}
type Int = int
is_type_alias_type(Int)
#> True
Str = TypeAliasType('Str', str)
is_type_alias_type(Str)
#> True
```
D aname
aClassVar
uReturn whether the provided argument is a `ClassVar` special form, parametrized or not.
Note that in most cases, you will want to use the `is_classvar_annotation` function,
which is used to check if an annotation (in the context of a Pydantic model or dataclass)
should be treated as being a class variable.
```python {test="skip" lint="skip"}
is_classvar(ClassVar[int])
#> True
is_classvar(ClassVar)
#> True
is_classvar
annotated_type
aForwardRef
a__forward_arg__
a_classvar_re
match
uReturn whether the provided argument represents a class variable annotation.
Although not explicitly stated by the typing specification, `ClassVar` can be used
inside `Annotated` and as such, this function checks for this specific scenario.
Because this function is used to detect class variables before evaluating forward references
(or because evaluation failed), we also implement a naive regex match implementation. This is
required because class variables are inspected before fields are collected, so we try to be
s accurate as possible.
D aname
aFinal
uReturn whether the provided argument is a `Final` special form, parametrized or not.
```python {test="skip" lint="skip"}
is_finalvar(Final[int])
#> True
is_finalvar(Final)
#> True
D aname
aRequired
uReturn whether the provided argument is a `Required` special form.
```python {test="skip" lint="skip"}
is_required(Required[int])
#> True
D aname
aNotRequired
uReturn whether the provided argument is a `NotRequired` special form.
```python {test="skip" lint="skip"}
is_required(Required[int])
#> True
D aname
aNoReturn
uReturn whether the provided argument is the `NoReturn` special form.
```python {test="skip" lint="skip"}
is_no_return(NoReturn)
#> True
```
D aname
aNever
uReturn whether the provided argument is the `Never` special form.
```python {test="skip" lint="skip"}
is_never(Never)
#> True
```
a_DEPRECATED_TYPES
uReturn whether the argument is an instance of the `warnings.deprecated` class or the `typing_extensions` backport.
a_NONE_TYPES
uReturn whether the argument represents the `None` type as part of an annotation.
```python {test="skip" lint="skip"}
is_none_type(None)
#> True
is_none_type(NoneType)
#> True
is_none_type(Literal[None])
#> True
is_none_type(type[None])
#> False
a_utils
T alenient_issubclass
lenient_issubclass
a_fields
uReturn whether the provided argument is a named tuple class.
The class can be created using `typing.NamedTuple` or `collections.namedtuple`.
Parametrized generic classes are *not* assumed to be named tuples.
aZoneInfo
uReturn whether the provided argument is the `zoneinfo.ZoneInfo` type.
aUnionType
uReturn whether the provided argument is the `Union` special form or the `UnionType`.
aGenericAlias
a_GenericAlias
a_getframe
f_locals
f_back
f_code
co_name
u<module>
uWe allow use of items in parent namespace to get around the issue with `get_type_hints` only looking in the
global module namespace. See https://github.com/pydantic/pydantic/issues/2678#issuecomment-1008139014 -> Scope
nd suggestion at the end of the next comment by @gvanrossum.
WARNING 1: it matters exactly where this is called. By default, this function will build a namespace from the
parent of where it is called.
WARNING 2: this only looks in the parent namespace, not other parents since (AFAIK) there's no way to collect a
dict of exactly what's in scope. Using `f_back` would work sometimes but would be very wrong and confusing in many
other cases. See https://discuss.python.org/t/is-there-a-way-to-access-parent-nested-namespaces/20659.
There are some cases where we want to force fetching the parent namespace, ex: during a `model_rebuild` call.
In this case, we want both the namespace of the class' module, if applicable, and the parent namespace of the
module where the rebuild is called.
In other cases, like during initial schema build, if a class is defined at the top module level, we don't need to
fetch that module's namespace, because the class' __module__ attribute can be used to access the parent namespace.
This is done in `_namespace_utils.get_module_ns_of`. Thus, there's no need to cache the parent frame namespace in this case.
aNoneType
a_make_forward_ref
D ais_argument
is_class
FtuConvert `None` to `NoneType` and strings to `ForwardRef` instances.
This is a backport of the private `typing._type_convert` function. When
evaluating a type, `ForwardRef._evaluate` ends up being called, and is
responsible for making this conversion. However, we still have to apply
it for the first argument passed to our type evaluation functions, similarly
to the `typing.get_type_hints` function.
aNsResolver
a__mro__
get
T a__annotations__
aGetSetDescriptorType
ns_resolver
push
a__enter__
a__exit__
types_namespace
items
startswith
T w_atry_eval_type
globalns
localns
hints
T nnnuCollect annotations from a Pydantic model class, including those from parent classes.
Args:
obj: The Pydantic model to inspect.
ns_resolver: A namespace resolver instance to use. Defaults to an empty instance.
Returns:
A dictionary mapping annotation names to a two-tuple: the first element is the evaluated
type or the original annotation if a `NameError` occurred, the second element is a boolean
indicating if whether the evaluation succeeded.
eval_type
uCollect annotations from a class, including those from parent classes.
Args:
obj: The class to inspect.
ns_resolver: A namespace resolver instance to use. Defaults to an empty instance.
a_type_convert
eval_type_backport
uTry evaluating the annotation using the provided namespaces.
Args:
value: The value to evaluate. If `None`, it will be replaced by `type[None]`. If an instance
of `str`, it will be converted to a `ForwardRef`.
localns: The global namespace to use during annotation evaluation.
globalns: The local namespace to use during annotation evaluation.
Returns:
A two-tuple containing the possibly evaluated type and a boolean indicating
whether the evaluation succeeded or not.
uEvaluate the annotation using the provided namespaces.
Args:
value: The value to evaluate. If `None`, it will be replaced by `type[None]`. If an instance
of `str`, it will be converted to a `ForwardRef`.
localns: The global namespace to use during annotation evaluation.
globalns: The local namespace to use during annotation evaluation.
a_eval_type_backport
uUnable to evaluate type annotation
uUnable to evaluate type annotation
w.uAn enhanced version of `typing._eval_type` which will fall back to using the `eval_type_backport`
package if it's installed to let older Python versions use newer typing constructs.
Specifically, this transforms `X | Y` into `typing.Union[X, Y]` and `list[X]` into `typing.List[X]`
(as well as all the types made generic in PEP 585) if the original syntax is not supported in the
current Python version.
This function will also display a helpful error if the value passed fails to evaluate.
a_eval_type
is_backport_fixable_error
T aeval_type_backport
u. If you are making use of the new typing syntax (unions using `|` since Python 3.10 or builtins subscripting since Python 3.9), you should either replace the use of new syntax with the existing `typing` constructs or install the `eval_type_backport` package.
D atry_default
Fapartial
func
a__annotations__
get_type_hints
function
setdefault
return
get_module_ns_of
a__type_params__
type_params
type_hints
uReturn type hints for a function.
This is similar to the `typing.get_type_hints` function, with a few differences:
- Support `functools.partial` by using the underlying `func` attribute.
- If `function` happens to be a built-in type (e.g. `int`), assume it doesn't have annotations
but specify the `return` key as being the actual type.
- Do not wrap type annotation of a parameter with `Optional` if it has a default value of `None`
(related bug: https://github.com/python/cpython/issues/90353, only fixed in 3.11+).
uLogic for interacting with type annotations, mostly extensions, shims and hacks to wrap Python's typing module.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
ucollections.abc
re
sys
types
typing
warnings
lru_cache
aTYPE_CHECKING
aAny
T aTypeIs
deprecated
get_args
get_origin
aTypeIs
deprecated
a_namespace_utils
T aGlobalsNamespace
aMappingNamespace
aNsResolver
get_module_ns_of
aGlobalsNamespace
aMappingNamespace
aEllipsisType
T nT amaxsize
D aname
return
str
utuple[Any, ...]
D aobj
name
return
object
str
bool
D atp
return
aAny
bool
is_any
is_union
D atp
return
aAny
ulist[Any]
D atp
return
aAny
uAny | None
unpack_type
is_self
is_new_type
is_hashable
is_callable
aParamSpec
utuple[type[typing_extensions.ParamSpec], ...]
is_paramspec
aTypeAliasType
utuple[type[typing_extensions.TypeAliasType], ...]
D atp
return
aAny
uTypeIs[typing_extensions.TypeAliasType]
is_type_alias_type
compile
T u((\w+\.)?Annotated\[)?(\w+\.)?ClassVar\[
is_classvar_annotation
is_finalvar
is_required
is_not_required
is_no_return
is_never
utuple[type[typing_extensions.deprecated], ...]
D aobj
return
aAny
uTypeIs[deprecated]
is_deprecated_instance
aLiteral
utuple[Any, ...]
is_none_type
is_namedtuple
zoneinfo
T aZoneInfo
D atp
return
aAny
uTypeIs[type[ZoneInfo]]
is_zoneinfo_type
origin_is_union
is_generic_alias
aWithArgsTypes
a_Final
typing_base
D aparent_depth
force
l FD aparent_depth
force
return
int
bool
udict[str, Any] | None
parent_frame_namespace
D aarg
return
aAny
pD ans_resolver
nD aobj
ns_resolver
return
utype[BaseModel]
uNsResolver | None
udict[str, tuple[Any, bool]]
get_model_type_hints
D aobj
ns_resolver
return
utype[Any]
uNsResolver | None
udict[str, Any]
get_cls_type_hints
T nnD avalue
globalns
localns
return
aAny
uGlobalsNamespace | None
uMappingNamespace | None
utuple[Any, bool]
D avalue
globalns
localns
return
aAny
uGlobalsNamespace | None
uMappingNamespace | None
aAny
T u`eval_type_lenient` is deprecated, use `try_eval_type` instead.
nT acategory
eval_type_lenient
D avalue
globalns
localns
type_params
return
aAny
uGlobalsNamespace | None
uMappingNamespace | None
utuple[Any, ...] | None
aAny
D weareturn
aTypeError
bool
D ainclude_keys
globalns
localns
nnnD afunction
include_keys
globalns
localns
return
uCallable[..., Any]
uset[str] | None
uGlobalsNamespace | None
uMappingNamespace | None
udict[str, Any]
get_function_type_hints
upydantic\_internal\_typing_extra.py
T a.0
module
name
u<module pydantic._internal._typing_extra>
T avalue
globalns
localns
type_params
T avalue
globalns
localns
type_params
weaeval_type_backport
T aname
result
T aobj
name
thing
T aarg
T atp
T avalue
globalns
localns
T avalue
globalns
localns
type_params
weamessage
T avalue
globalns
localns
ev
w_T	aobj
ns_resolver
hints
ann
base
globalns
localns
name
value
T	afunction
include_keys
globalns
localns
type_params
annotations
type_hints
name
value
T weamsg
T atp
str_ann
anntp
T aobj
T atp
lenient_issubclass
T atp
values
T aparent_depth
force
frame
a__spec__
.pydantic._internal._utils
kind
aParameter
aPOSITIONAL_ONLY
aPOSITIONAL_OR_KEYWORD
uReturn whether the parameter accepts a positional argument.
```python {test="skip" lint="skip"}
def func(a, /, b, *, c):
pass
params = inspect.signature(func).parameters
can_be_positional(params['a'])
#> True
can_be_positional(params['b'])
#> True
can_be_positional(params['c'])
#> False
```
aGeneratorType
deque
a_typing_extra
aWithArgsTypes
import_cached_base_model
lenient_issubclass
uReturns true if cls is a _proper_ subclass of BaseModel, and provides proper type-checking,
unlike raw calls to lenient_issubclass.
isidentifier
keyword
iskeyword
uChecks that a string is a valid identifier and not a Python keyword.
:param identifier: The identifier to test.
:return: True if the identifier is valid.
copy
items
updated_mapping
deep_update
update
name_factory
result_names
result
uMake a list unique while maintaining order.
We update the list if another one with the same name is set
(e.g. model validator overridden in subclass).
a_coerce_items
T Olist
Otuple
a_normalize_indexes
a_items
is_true
get
uCheck if item is fully excluded.
:param item: key or index of a value
uCheck if value is contained in self._items.
:param item: key or index of value
u:param e: key or index of element on value
:return: raw values for element if self._items is dict and contain needed element
aMapping
aAbstractSet
self
uUnexpected type of exclude value for index "

u"
a__all__
a_coerce_value
uExcluding fields from a sequence of sub-models or dicts must be performed index-wise: expected integer keys or keyword "__all__"
v_length
merge
normalized_items
all_items
u:param items: dict or set of indexes which will be normalized
:param v_length: length of sequence indexes of which will be
>>> self._normalize_indexes({0: True, -2: True, -1: True}, 4)
{0: True, 2: True, 3: True}
>>> self._normalize_indexes({'__all__': True}, 4)
{0: True, 1: True, 2: True, 3: True}
cls
base
override
intersect
T aintersect
merged
uMerge a `base` item with an `override` item.
Both `base` and `override` are converted to dictionaries if possible.
Sets are converted to dictionaries with the sets entries as keys and
Ellipsis as values.
Each key-value pair existing in `base` is merged with `override`,
while the rest of the key-value pairs are updated recursively with this function.
Merging takes place based on the "union" of keys if `intersect` is
set to `False` (default) and on the intersection of keys if
`intersect` is set to `True`.
a__class__
u???
uUnexpected type of exclude value
name
get_value
value
u attribute of
a__name__
u is class-only
aIMMUTABLE_NON_COLLECTIONS_TYPES
aBUILTIN_COLLECTIONS
T ETypeError
EValueError
ERuntimeError
deepcopy
uReturn type as is for immutable built-in types
Use obj.copy() for built-in empty collections
Use copy.deepcopy() for non-empty collections and unknown objects.
zip_longest
a_SENTINEL
T afillvalue
uCheck that the items of `left` are the same objects as those in `right`.
>>> a, b = object(), object()
>>> all_identical([a, b, a], [a, b, a])
True
>>> all_identical([a, b, [a]], [a, b, [a]])  # new list object, while "equal" is not "identical"
False
wrapped
uBucket of reusable internal utilities.
This should be reduced as much as possible with functions only used in one place, moved to that place.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
a_annotations
dataclasses
typing
weakref
collections
T aOrderedDict
defaultdict
deque
aOrderedDict
defaultdict
T adeepcopy
cached_property
inspect
T aParameter
itertools
T azip_longest
aBuiltinFunctionType
aCodeType
aFunctionType
aLambdaType
aModuleType
aAny
aCallable
aTypeVar
typing_extensions
T aTypeAlias
aTypeGuard
aTypeAlias
aTypeGuard
T a_repr
a_typing_extra
a_repr
a_import_utils
T aimport_cached_base_model
aNoneType
ref
uset[type[Any]]
D aparam
return
aParameter
bool
can_be_positional
D wvareturn
aAny
bool
sequence_like
D woaclass_or_tuple
return
aAny
utype[Any] | tuple[type[Any], ...] | None
bool
lenient_isinstance
D acls
class_or_tuple
return
aAny
pabool
D acls
return
aAny
uTypeGuard[type[BaseModel]]
is_model_class
D aidentifier
return
str
bool
is_valid_identifier
T aKeyType
aKeyType
D amapping
updating_mappings
return
udict[KeyType, Any]
udict[KeyType, Any]
udict[KeyType, Any]
D amapping
update
return
udict[Any, Any]
aAny
aNone
update_not_none
T wTwTD aname_factory
Ostr
D ainput_list
name_factory
return
ulist[T] | tuple[T, ...]
utyping.Callable[[T], str]
ulist[T]
unique_list
aRepresentation
a__prepare__
aValueItems
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
