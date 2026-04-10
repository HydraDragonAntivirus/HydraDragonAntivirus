# Reconstructed from integrated Nuitka blob
# Module: p

modules
uGet the namespace of the module where the object is defined.
Caution: this function does not return a copy of the module namespace, so the result
should not be mutated. The burden of enforcing this is on the caller.
a_namespaces
items
data
a__type_params__
get
T a__type_params__
T
a__name__
get_module_ns_of
aNamespacesTuple
aLazyLocalNamespace
uReturn the global and local namespaces to be used when evaluating annotations for the provided function.
The global namespace will be the `__dict__` attribute of the module the function was defined in.
The local namespace will contain the `__type_params__` introduced by PEP 695.
Args:
obj: The object to use when building namespaces.
parent_namespace: Optional namespace to be added with the lowest priority in the local namespace.
If the passed function is a method, the `parent_namespace` will be the namespace of the class
the method is defined in. Thus, we also fetch type `__type_params__` from there (i.e. the
class-scoped type variables).
a_base_ns_tuple
a_parent_ns
a_types_stack
a__dict__
uThe current global and local namespaces to be used for annotations evaluation.
uPush a type to the stack.
self
append
typ
pop
T atypes_namespace
napush
uNsResolver.push
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
sys
ucollections.abc
T aGenerator
aGenerator
contextlib
T acontextmanager
contextmanager
cached_property
aAny
aCallable
aIterator
aMapping
aNamedTuple
aTypeVar
typing_extensions
T aParamSpec
aTypeAlias
aTypeAliasType
aTypeVarTuple
aParamSpec
aTypeAlias
aTypeAliasType
aTypeVarTuple
udict[str, Any]
aGlobalsNamespace
aMappingNamespace
uTypeVar | ParamSpec | TypeVarTuple
a_TypeVarLike
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
upydantic._internal._namespace_utils
uA tuple of globals and locals to be used during annotations evaluation.
This datastructure is defined as a named tuple so that it can easily be unpacked:
```python {lint="skip" test="skip"}
def eval_type(typ: type[Any], ns: NamespacesTuple) -> None:
return eval(typ, *ns)
```
a__qualname__
globals
locals
a__orig_bases__
D aobj
return
aAny
udict[str, Any]
uA lazily evaluated mapping, to be used as the `locals` argument during annotations evaluation.
While the [`eval`][eval] function expects a mapping as the `locals` argument, it only
performs `__getitem__` calls. The [`Mapping`][collections.abc.Mapping] abstract base class
is fully implemented only for type checking purposes.
Args:
*namespaces: The namespaces to consider, in ascending order of priority.
Example:
```python {lint="skip" test="skip"}
ns = LazyLocalNamespace({'a': 1, 'b': 2}, {'a': 3})
ns['a']
#> 3
ns['b']
#> 2
```
D anamespaces
return
aMappingNamespace
aNone
a__init__
uLazyLocalNamespace.__init__
D areturn
udict[str, Any]
uLazyLocalNamespace.data
D areturn
int
a__len__
uLazyLocalNamespace.__len__
D akey
return
str
aAny
uLazyLocalNamespace.__getitem__
D akey
return
object
bool
a__contains__
uLazyLocalNamespace.__contains__
D areturn
uIterator[str]
a__iter__
uLazyLocalNamespace.__iter__
T nD aobj
parent_namespace
return
uCallable[..., Any]
uMappingNamespace | None
aNamespacesTuple
ns_for_function
uA class responsible for the namespaces resolving logic for annotations evaluation.
This class handles the namespace logic when evaluating annotations mainly for class objects.
It holds a stack of classes that are being inspected during the core schema building,
nd the `types_namespace` property exposes the globals and locals to be used for
type annotation evaluation. Additionally -- if no class is present in the stack -- a
fallback globals and locals can be provided using the `namespaces_tuple` argument
(this is useful when generating a schema for a simple annotation, e.g. when using
`TypeAdapter`).
The namespace creation logic is unfortunately flawed in some cases, for backwards
compatibility reasons and to better support valid edge cases. See the description
for the `parent_namespace` argument and the example for more details.
Args:
namespaces_tuple: The default globals and locals to use if no class is present
on the stack. This can be useful when using the `GenerateSchema` class
with `TypeAdapter`, where the "type" being analyzed is a simple annotation.
parent_namespace: An optional parent namespace that will be added to the locals
with the lowest priority. For a given class defined in a function, the locals
of this function are usually used as the parent namespace:
```python {lint="skip" test="skip"}
from pydantic import BaseModel
def func() -> None:
SomeType = int
class Model(BaseModel):
f: 'SomeType'
# when collecting fields, an namespace resolver instance will be created
# this way:
# ns_resolver = NsResolver(parent_namespace={'SomeType': SomeType})
```
For backwards compatibility reasons and to support valid edge cases, this parent
namespace will be used for *every* type being pushed to the stack. In the future,
we might want to be smarter by only doing so when the type being pushed is defined
in the same module as the parent namespace.
Example:
```python {lint="skip" test="skip"}
ns_resolver = NsResolver(
parent_namespace={'fallback': 1},
)
class Sub:
m: 'Model'
class Model:
some_local = 1
sub: Sub
ns_resolver = NsResolver()
# This is roughly what happens when we build a core schema for `Model`:
with ns_resolver.push(Model):
ns_resolver.types_namespace
#> NamespacesTuple({'Sub': Sub}, {'Model': Model, 'some_local': 1})
# First thing to notice here, the model being pushed is added to the locals.
# Because `NsResolver` is being used during the model definition, it is not
# yet added to the globals. This is useful when resolving self-referencing annotations.
with ns_resolver.push(Sub):
ns_resolver.types_namespace
#> NamespacesTuple({'Sub': Sub}, {'Sub': Sub, 'Model': Model})
# Second thing to notice: `Sub` is present in both the globals and locals.
# This is not an issue, just that as described above, the model being pushed
# is added to the locals, but it happens to be present in the globals as well
# because it is already defined.
# Third thing to notice: `Model` is also added in locals. This is a backwards
# compatibility workaround that allows for `Sub` to be able to resolve `'Model'`
# correctly (as otherwise models would have to be rebuilt even though this
# doesn't look necessary).
```
aNsResolver
T nnD anamespaces_tuple
parent_namespace
return
uNamespacesTuple | None
uMappingNamespace | None
aNone
uNsResolver.__init__
D areturn
aNamespacesTuple
types_namespace
uNsResolver.types_namespace
D atyp
return
utype[Any] | TypeAliasType
uGenerator[None]
upydantic\_internal\_namespace_utils.py
u<module pydantic._internal._namespace_utils>
T a__class__
T aself
key
T aself
namespaces
T aself
namespaces_tuple
parent_namespace
T aself
T aobj
module_name
T aobj
parent_namespace
locals_list
type_params
globalns
T aself
typ
T aself
locals_list
typ
globalns
first_type

a__spec__
.pydantic._internal._repr
W
o
a__slots__
a__dict__
keys
self
a__repr_recursion__
uReturns the attributes to show in __str__, __repr__, and __pretty__ this is generally overridden.
Can either return:
* name - value pairs, e.g.: `[('foo_name', 'foo'), ('bar_name', ['b', 'a', 'r'])]`
* or, just values, e.g.: `[(None, 'foo'), (None, ['b', 'a', 'r'])]`
u<genexpr>
uRepresentation.__repr_args__.<locals>.<genexpr>
a__name__
uName of the instance's class, used in __repr__.
u<Recursion on

u with id=
w>uReturns the string representation of a recursive object.
join
a__repr_args__
w=uRepresentation.__repr_str__.<locals>.<genexpr>
uUsed by devtools (https://python-devtools.helpmanual.io/) to pretty print objects.
a__repr_name__
w(afmt
w,w)a__pretty__
uRepresentation.__pretty__
uUsed by Rich (https://rich.readthedocs.io/en/stable/pretty.html) to pretty print objects.
a__rich_repr__
uRepresentation.__rich_repr__
a__repr_str__
T w T u,
aFunctionType
aBuiltinFunctionType
u...
aRepresentation
aForwardRef
a_typing_extra
is_type_alias_type
typing_base
aWithArgsTypes
origin_is_union
typing_extensions
get_origin
obj
u,
display_as_type
get_args
uUnion[
w]ais_literal
repr
a__qualname__
w[areplace
T utyping.

T utyping_extensions.

uPretty representation of a type, should be as close as possible to the original type definition string.
Takes some logic from `typing._type_repr`.
uTools to provide pretty/human-readable display of objects.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
a_annotations
types
typing
aAny
T a_typing_extra
T Ostr
a__prepare__
aPlainRepr
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
