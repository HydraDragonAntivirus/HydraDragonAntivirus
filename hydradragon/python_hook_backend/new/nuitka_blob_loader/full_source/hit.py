# Reconstructed from integrated Nuitka blob
# Module: hit

prepare_class
a__pydantic_generic_metadata__
origin
args
parameters
a__pydantic_reset_parent_namespace__
a_get_caller_frame_info
T l T adepth
modules
object_by_reference
created_model
reference_module_globals
setdefault
reference_name
w_uDynamically create a submodel of a provided (generic) BaseModel.
This is used when producing concrete parametrizations of generic models. This function
only *creates* the new subclass; the schema/validators/serialization must be updated to
reflect a concrete parametrization elsewhere.
Args:
model_name: The name of the newly created model.
origin: The base class for the new model to inherit from.
rgs: A tuple of generic metadata arguments.
params: A tuple of generic metadata parameters.
Returns:
The created submodel.
a_getframe
uThis function must be used inside another function
T nFaf_globals
get
T a__name__
f_locals
uUsed inside a function to check whether it was called globally.
Args:
depth: The depth to get the frame.
Returns:
A tuple contains `module_name` and `called_globally`.
Raises:
RuntimeError: If the function is not called inside a function.
uRecursively iterate through all subtypes and type args of `v` and yield any typevars that are found.
This is inspired as an alternative to directly accessing the `__parameters__` attribute of a GenericAlias,
since __parameters__ of (nested) generic BaseModel subclasses won't show up in that list.
wvaTypeVar
is_model_class
aDictValues
iter_contained_typevars
get_args
T aargs
typing_extensions
T aorigin
get_origin
a__parameters__
a__args__
uPackage a generic type's typevars and parametrization (if present) into a dictionary compatible with the
`replace_types` function. Specifically, this works with standard typing generics and typing._GenericAlias.
uPackage a generic BaseModel's typevars and concrete parametrization (if present) into a dictionary compatible
with the `replace_types` function.
Since BaseModel.__class_getitem__ does not produce a typing._GenericAlias, and the BaseModel generic info is
stored in the __pydantic_generic_metadata__ attribute, we need special handling here.
a_typing_extra
is_annotated
unot enough values to unpack (expected at least 1, got %d)
replace_types
aAnnotated
annotated
all_identical
typing_base
a_name
origin_is_union
aAny
resolved_type_args
aUnionType
a_UnionGenericAlias
type_map
uReturn type with all occurrences of `type_map` keys recursively replaced with their values.
Args:
type_: The class or generic alias.
type_map: Mapping from `TypeVar` instance to concrete types.
Returns:
A new type representing the basic structure of `type_` with all
`typevar_map` keys recursively replaced.
Example:
```python
from typing import List, Tuple, Union
from pydantic._internal._generics import replace_types
replace_types(Tuple[str, Union[List[str], float]], {str: int})
#> Tuple[int, Union[List[int], float]]
```
u<genexpr>
ureplace_types.<locals>.<genexpr>
is_any
is_no_return
is_never
has_instance_in_type
a__origin__
is_literal
isinstance_target
aParamSpec
uChecks if the type, or any of its arbitrary nested args, satisfy
`isinstance(<type>, isinstance_target)`.
many
few
uToo
u parameters for

u; actual
u, expected
uCheck the generic model parameters count is equal.
Args:
cls: The generic model.
parameters: A tuple of passed parameters to the generic model.
Raises:
TypeError: If the passed parameters count is not equal to generic model parameters count.
uThis contextmanager should be placed around the recursive calls used to build a generic type,
nd accept as arguments the generic origin type and the type arguments being passed to it.
If the same origin and arguments are observed twice, it implies that a self-reference placeholder
can be used while building the core schema, and will produce a schema_ref that will be valid in the
final parent schema.
a_generic_recursion_cache
set
get_type_ref
T aargs_override
previously_seen_type_refs
aPydanticRecursiveRef
T atype_ref
add
remove
reset
generic_recursion_self_type
copy
a_GENERIC_TYPES_CACHE
a_early_cache_key
uThe use of a two-stage cache lookup approach was necessary to have the highest performance possible for
repeated calls to `__class_getitem__` on generic types (which may happen in tighter loops during runtime),
while still ensuring that certain alternative parametrizations ultimately resolve to the same type.
As a concrete example, this approach was necessary to make Model[List[T]][int] equal to Model[List[int]].
The approach could be modified to not use two different cache keys at different points, but the
_early_cache_key is optimized to be as quick to compute as possible (for repeated-access speed), and the
_late_cache_key is optimized to be as "correct" as possible, so that two types that will ultimately be the
same after resolving the type arguments will always produce cache hits.
If we wanted to move to only using a single cache key per type, we would either need to always use the
slower/more computationally intensive logic associated with _late_cache_key, or would need to accept
that Model[List[T]][int] is a different type than Model[List[T]][int]. Because we rely on subclass relationships
during validation, I think it is worthwhile to ensure that types that are functionally equivalent are actually
equal.
a_late_cache_key
set_cached_generic_type
uSee the docstring of `get_cached_generic_type_early` for more information about the two-stage cache lookup.
uSee the docstring of `get_cached_generic_type_early` for more information about why items are cached with
two different keys.
args_data
a_union_orderings_key
is_union
uThis is intended to help differentiate between Union types with the same arguments in different order.
Thanks to caching internal to the `typing` module, it is not possible to distinguish between
List[Union[int, float]] and List[Union[float, int]] (and similarly for other "parent" origins besides List)
because `typing` considers Union[int, float] to be equal to Union[float, int].
However, you _can_ distinguish between (top-level) Union[int, float] vs. Union[float, int].
Because we parse items as the first Union type that is successful, we get slightly more consistent behavior
if we make an effort to distinguish the ordering of items in a union. It would be best if we could _always_
get the exact-correct order of items in the union, but that would require a change to the `typing` module itself.
(See https://github.com/python/cpython/issues/86483 for reference.)
uThis is intended for minimal computational overhead during lookups of cached types.
Note that this is overly simplistic, and it's possible that two different cls/typevar_values
inputs would ultimately result in the same type being created in BaseModel.__class_getitem__.
To handle this, we have a fallback _late_cache_key that is checked later if the _early_cache_key
lookup fails, and should result in a cache hit _precisely_ when the inputs to __class_getitem__
would result in the same type.
uThis is intended for use later in the process of creating a new type, when we have more information
bout the exact args that will be passed. If it turns out that a different set of inputs to
__class_getitem__ resulted in the same inputs to the generic type creation process, we can still
return the cached type, and update the cache with the _early_cache_key as well.
a__doc__
a__file__
has_location
a__cached__
a__annotations__
annotations
sys
types
typing
collections
T aChainMap
aChainMap
contextlib
T acontextmanager
contextmanager
contextvars
T aContextVar
aContextVar
aTYPE_CHECKING
aIterator
aMapping
aMutableMapping
aTuple
weakref
T aWeakValueDictionary
aWeakValueDictionary
T a_typing_extra
a_core_utils
T aget_type_ref
a_forward_ref
T aPydanticRecursiveRef
a_utils
T aall_identical
is_model_class
aGenericTypesCacheKey
T aKT
aKT
T aVT
aVT
lda_LIMITED_DICT_SIZE
T Odict
a__prepare__
aLimitedDict
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
upydantic._internal._generics
uLimit the size/length of a dict used for caching to avoid unlimited increase in memory usage.
Since the dict is ordered, and we always remove elements from the beginning, this is effectively a FIFO cache.
a__qualname__
D asize_limit
int
uLimitedDict.__init__
D akey
value
return
aAny
paNone
uLimitedDict.__setitem__
a__orig_bases__
utype[BaseModel]
aGenericTypesCache
aDeepChainMap
uVariant of ChainMap that allows direct updates to inner scopes.
Taken from https://docs.python.org/3/library/collections.html#collections.ChainMap,
with some light modifications for this use case.
D areturn
aNone
uDeepChainMap.clear
D akey
value
return
aKT
aVT
aNone
uDeepChainMap.__setitem__
D akey
return
aKT
aNone
a__delitem__
uDeepChainMap.__delitem__
aTypedDict
aPydanticGenericMetadata
utype[BaseModel] | None
utuple[Any, ...]
utuple[TypeVar, ...]
D amodel_name
origin
args
params
return
str
utype[BaseModel]
utuple[Any, ...]
utuple[Any, ...]
utype[BaseModel]
create_generic_submodel
T l D adepth
return
int
utuple[str | None, bool]
utype[Any]
D wvareturn
aAny
uIterator[TypeVar]
D wvareturn
aAny
pD acls
return
aAny
udict[TypeVar, Any] | None
get_standard_typevars_map
D acls
return
utype[BaseModel]
udict[TypeVar, Any] | None
get_model_typevars_map
D atype_
type_map
return
aAny
uMapping[Any, Any] | None
aAny
D atype_
isinstance_target
return
aAny
pabool
D acls
parameters
return
utype[BaseModel]
utuple[Any, ...]
aNone
check_parameters_count
T a_generic_recursion_cache
nT adefault
uContextVar[set[str] | None]
D aorigin
args
return
utype[BaseModel]
utuple[Any, ...]
uIterator[PydanticRecursiveRef | None]
D areturn
uset[str]
recursively_defined_type_refs
D aparent
typevar_values
return
utype[BaseModel]
aAny
utype[BaseModel] | None
get_cached_generic_type_early
D aparent
typevar_values
origin
args
return
utype[BaseModel]
aAny
utype[BaseModel]
utuple[Any, ...]
utype[BaseModel] | None
get_cached_generic_type_late
T nnD aparent
typevar_values
type_
origin
args
return
utype[BaseModel]
utuple[Any, ...]
utype[BaseModel]
utype[BaseModel] | None
utuple[Any, ...] | None
aNone
D atypevar_values
return
aAny
pD acls
typevar_values
return
utype[BaseModel]
aAny
aGenericTypesCacheKey
D aorigin
args
typevar_values
return
utype[BaseModel]
utuple[Any, ...]
aAny
aGenericTypesCacheKey
upydantic\_internal\_generics.py
T a.0
arg
T a.0
arg
type_map
T a.0
wtatype_map
u<module pydantic._internal._generics>
T a__class__
T aself
key
hit
mapping
T aself
size_limit
a__class__
T aself
key
value
mapping
T aself
key
value
excess
to_remove
wka__class__
T acls
typevar_values
T adepth
previous_caller_frame
weaframe_globals
T aorigin
args
typevar_values
T atypevar_values
args_data
value
T acls
parameters
actual
expected
description
T aself
mapping
T amodel_name
origin
args
params
namespace
bases
meta
ns
kwds
created_model
model_module
called_globally
object_by_reference
reference_name
reference_module_globals
T aorigin
args
previously_seen_type_refs
token
type_ref
self_type
T wvapydantic_generic_metadata
T aparent
typevar_values
T aparent
typevar_values
origin
args
cached
T acls
generic_metadata
origin
args
T acls
args
parameters
origin
T atype_
isinstance_target
type_args
arg
element
T wvavar
args
arg
T avisited
T atype_
type_map
type_args
annotated_type
annotations
annotated
annotation
origin_type
resolved_type_args
parameters
resolved_list
T aparent
typevar_values
type_
origin
args
a__spec__
.pydantic._internal._git
x
"
join
u.git
uIs the given directory version-controlled with git?
subprocess
check_output
git
u--help
aCalledProcessError
uCan we run the git executable?
T L agit
urev-parse
u--short
aHEAD
T acwd
decode
T uutf-8
strip
uGet the SHA-1 of the HEAD of a git repository.
uGit utilities, adopted from mypy's git utilities (https://github.com/python/mypy/blob/master/mypy/git.py).
a__doc__
a__file__
origin
has_location
a__cached__
annotations
os
D adir
return
str
bool
is_git_repo
D areturn
bool
have_git
D adir
return
str
pagit_revision
upydantic\_internal\_git.py
u<module pydantic._internal._git>
T adir

a__spec__
.pydantic._internal._import_utils
N
upydantic.main
aBaseModel
upydantic.fields
aFieldInfo
a__doc__
a__file__
origin
has_location
a__cached__
lru_cache
aTYPE_CHECKING
aType
T nT amaxsize
return
import_cached_base_model
import_cached_field_info
upydantic\_internal\_import_utils.py
u<module pydantic._internal._import_utils>
T aBaseModel
T aFieldInfo

a__spec__
.pydantic._internal._internal_dataclass
a__doc__
a__file__
origin
has_location
a__cached__
sys
D aslots
taslots_true
upydantic\_internal\_internal_dataclass.py
u<module pydantic._internal._internal_dataclass>

a__spec__
.pydantic._internal._known_annotated_metadata
T Oint
Ostr
Ofloat
Obytes
Obool
M
to_jsonable_python
uExpand the annotations.
Args:
nnotations: An iterable of annotations.
Returns:
An iterable of expanded annotations.
Example:
```python
from annotated_types import Ge, Len
from pydantic._internal._known_annotated_metadata import expand_grouped_metadata
print(list(expand_grouped_metadata([Ge(4), Len(5)])))
#> [Ge(ge=4), MinLen(min_length=5)]
```
annotated_types
import_cached_field_info
annotations
at
aGroupedMetadata
metadata
copy
expand_grouped_metadata
aGt
gt
aGe
ge
aLt
lt
aLe
le
aMultipleOf
multiple_of
aMinLen
min_length
aMaxLen
max_length
uReturn a mapping of annotated types to constraints.
Normally, we would define a mapping like this in the module scope, but we can't do that
because we don't permit module level imports of `annotated_types`, in an attempt to speed up
the import time of `pydantic`. We still only want to have this dictionary defined in one place,
so we use this function to cache the result.
a_validators
T aNUMERIC_VALIDATOR_LOOKUP
forbid_inf_nan_check
aNUMERIC_VALIDATOR_LOOKUP
forbid_inf_nan_check
collect_known_metadata
type
S astrip_whitespace
to_upper
coerce_numbers_to_str
to_lower
pattern
items
aCONSTRAINTS_TO_ALLOWED_SCHEMAS
uUnknown constraint

schema_type
P ufunction-before
ufunction-after
ufunction-wrap
strict
apply_known_metadata
annotation
schema
union_mode
union
mode
D avalue
handler
return
aAny
ucs.ValidatorFunctionWrapHandler
aAny
a_apply_constraint_with_incompatibility_info
uapply_known_metadata.<locals>._apply_constraint_with_incompatibility_info
chain_schema_steps
upydantic_core.core_schema
no_info_wrap_validator_function
str_schema
aLENGTH_CONSTRAINTS
inner_schema
list
ujson-or-python
json_schema
minItems
maxItems
minLength
maxLength
no_info_after_validator_function
partial
get
T apydantic_js_updates
as_jsonable_value
pydantic_js_updates
allow_inf_nan
uUnable to apply constraint '
u' to schema of type '
w'a_get_at_to_constraint_map
aPredicate
aNot
func
a__qualname__
D wvareturn
aAny
paval_func
uapply_known_metadata.<locals>.val_func
chain_schema
uApply `annotation` to `schema` if it is an annotation we know about (Gt, Le, etc.).
Otherwise return `None`.
This does not handle all known annotations. If / when it does, it can always
return a CoreSchema and return the unmodified schema if the annotation should be ignored.
Assumes that GroupedMetadata has already been expanded via `expand_grouped_metadata`.
Args:
nnotation: The annotation.
schema: The schema.
Returns:
An updated schema with annotation if it is an annotation we know about, `None` otherwise.
Raises:
PydanticCustomError: If `Predicate` fails.
aValidationError
errors
constraint
u' to supplied value
u for schema of type '
aPydanticCustomError
predicate_failed
uPredicate
predicate_name
u failed
not_operation_failed
uNot of
aPydanticMetadata
res
startswith
T w_aremaining
uSplit `annotations` into known metadata and unknown annotations.
Args:
nnotations: An iterable of annotations.
Returns:
A tuple contains a dict of known metadata and a list of unknown annotations.
Example:
```python
from annotated_types import Gt, Len
from pydantic._internal._known_annotated_metadata import collect_known_metadata
print(collect_known_metadata([Gt(1), Len(42), ...]))
#> ({'gt': 1, 'min_length': 42}, [Ellipsis])
```
keys
uThe following constraints cannot be applied to
u:
u,
uA small utility function to validate that the given metadata can be applied to the target.
More than saving lines of code, this gives us a consistent error message for all of our internal implementations.
Args:
metadata: A dict of metadata.
llowed: An iterable of allowed metadata.
source_type: The source type.
Raises:
TypeError: If there is metadatas that can't be applied on source type.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
collections
T adefaultdict
defaultdict
T acopy
lru_cache
aTYPE_CHECKING
aAny
aIterable
pydantic_core
aCoreSchema
cs
a_fields
T aPydanticMetadata
a_import_utils
T aimport_cached_field_info
S astrict
aSTRICT
S afail_fast
aFAIL_FAST
S amax_length
min_length
S agt
ge
le
lt
aINEQUALITY
T amultiple_of
aNUMERIC_CONSTRAINTS
S aallow_inf_nan
aALLOW_INF_NAN
T astrip_whitespace
T ato_lower
T ato_upper
T apattern
T acoerce_numbers_to_str
aSTR_CONSTRAINTS
aBYTES_CONSTRAINTS
aLIST_CONSTRAINTS
aTUPLE_CONSTRAINTS
aSET_CONSTRAINTS
aDICT_CONSTRAINTS
aGENERATOR_CONSTRAINTS
aSEQUENCE_CONSTRAINTS
aFLOAT_CONSTRAINTS
T amax_digits
T adecimal_places
aDECIMAL_CONSTRAINTS
aINT_CONSTRAINTS
aBOOL_CONSTRAINTS
aUUID_CONSTRAINTS
aDATE_TIME_CONSTRAINTS
aTIMEDELTA_CONSTRAINTS
aTIME_CONSTRAINTS
aLAX_OR_STRICT_CONSTRAINTS
aENUM_CONSTRAINTS
aCOMPLEX_CONSTRAINTS
S aunion_mode
aUNION_CONSTRAINTS
S adefault_port
default_host
allowed_schemes
default_path
max_length
host_required
aURL_CONSTRAINTS
T astr
bytes
url
umulti-host-url
aTEXT_SCHEMA_TYPES
T alist
T atuple
T aset
T afrozenset
T agenerator
aSEQUENCE_SCHEMA_TYPES
T afloat
int
date
time
timedelta
datetime
aNUMERIC_SCHEMA_TYPES
T Oset
udict[str, set[str]]
T abytes
T aset
frozenset
T adict
T afloat
T aint
T adate
time
datetime
timedelta
T utyped-dict
T amodel
T aunion
T aurl
umulti-host-url
T abool
T auuid
T ulax-or-strict
T aenum
T adecimal
T acomplex
constraint_schema_pairings
ulist[tuple[set[str], tuple[str, ...]]]
constraints
schemas
wcaupdate
D aannotations
return
uIterable[Any]
uIterable[Any]
D areturn
udict[type, str]
D aannotation
schema
return
aAny
aCoreSchema
uCoreSchema | None
D aannotations
return
uIterable[Any]
utuple[dict[str, Any], list[Any]]
D ametadata
allowed
source_type
return
udict[str, Any]
uIterable[str]
aAny
aNone
check_metadata
upydantic\_internal\_known_annotated_metadata.py
u<module pydantic._internal._known_annotated_metadata>
T avalue
handler
wxave
constraint
schema_type
T aconstraint
schema_type
T aat
T aannotation
schema
chain_schema_constraints
chain_schema_steps
at
aNUMERIC_VALIDATOR_LOOKUP
forbid_inf_nan_check
schema_update
other_metadata
schema_type
constraint
value
allowed_schemas
a_apply_constraint_with_incompatibility_info
inner_schema
inner_schema_type
js_constraint_key
metadata
existing_json_schema_updates
annotation_type
at_to_constraint_map
validator
predicate_name
val_func
T wvT ametadata
allowed
source_type
unknown
T aannotations
res
remaining
annotation
annotation_type
at_to_constraint_map
constraint
T aannotations
at
aFieldInfo
annotation
T wvapredicate_satisfied
annotation
at
predicate_name
T aannotation
at
predicate_name
a__spec__
.pydantic._internal._mock_val_ser
a_error_message
a_code
a_attempt_rebuild
a_built_memo
a_get_built
a__getitem__
a__len__
a__iter__
aPydanticUserError
T acode
validator
aSchemaValidator
aSchemaSerializer
a_val_or_ser
u`TypeAdapter[

u]` is not fully defined; you should define `
u` and all referenced types, then call `.rebuild()` on the instance.
D aattr_fn
return
uCallable[[TypeAdapter], T]
uCallable[[], T | None]
attempt_rebuild_fn
uset_type_adapter_mocks.<locals>.attempt_rebuild_fn
aMockCoreSchema
uclass-not-fully-defined
u<lambda>
uset_type_adapter_mocks.<locals>.<lambda>
T acode
attempt_rebuild
core_schema
aMockValSer
T acode
val_or_ser
attempt_rebuild
serializer
uSet `core_schema`, `validator` and `serializer` to mock core types on a type adapter instance.
Args:
dapter: The type adapter instance to set the mocks on
type_repr: Name of the type used in the adapter, used in error messages
D areturn
uT | None
handler
uset_type_adapter_mocks.<locals>.attempt_rebuild_fn.<locals>.handler
adapter
rebuild
T Fl T araise_errors
a_parent_namespace_depth
attr_fn
w`u` is not fully defined; you should define
u, then call `
u.model_rebuild()`.
D aattr_fn
return
uCallable[[type[BaseModel]], T]
uCallable[[], T | None]
uset_model_mocks.<locals>.attempt_rebuild_fn
uset_model_mocks.<locals>.<lambda>
a__pydantic_core_schema__
a__pydantic_validator__
a__pydantic_serializer__
uSet `__pydantic_core_schema__`, `__pydantic_validator__` and `__pydantic_serializer__` to mock core types on a model.
Args:
cls: The model class to set the mocks on
cls_name: Name of the model class, used in error messages
undefined_name: Name of the undefined thing, used in error messages
uset_model_mocks.<locals>.attempt_rebuild_fn.<locals>.handler
cls
model_rebuild
dataclasses
T arebuild_dataclass
l arebuild_dataclass
u, then call `pydantic.dataclasses.rebuild_dataclass(
u)`.
D aattr_fn
return
uCallable[[type[PydanticDataclass]], T]
uCallable[[], T | None]
uset_dataclass_mocks.<locals>.attempt_rebuild_fn
uset_dataclass_mocks.<locals>.<lambda>
uSet `__pydantic_validator__` and `__pydantic_serializer__` to `MockValSer`s on a dataclass.
Args:
cls: The model class to set the mocks on
cls_name: Name of the model class, used in error messages
undefined_name: Name of the undefined thing, used in error messages
uset_dataclass_mocks.<locals>.attempt_rebuild_fn.<locals>.handler
D araise_errors
a_parent_namespace_depth
Fl a__doc__
a__file__
origin
has_location
a__cached__
annotations
aTYPE_CHECKING
aAny
aCallable
aGeneric
aIterator
aMapping
aTypeVar
aUnion
pydantic_core
aCoreSchema
typing_extensions
T aLiteral
aLiteral
upydantic.errors
aPydanticErrorCodes
uplugin._schema_validator
T aPluggableSchemaValidator
aPluggableSchemaValidator
T aValSer
T abound
aValSer
T wTwTa__prepare__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
