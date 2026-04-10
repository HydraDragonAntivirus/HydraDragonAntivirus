# Reconstructed from integrated Nuitka blob
# Module: uattr._compat


Extract type annotations from a callable, returning None whenever there
is none.
a_AnnotationExtractor
a__qualname__
a__slots__
a__init__
u_AnnotationExtractor.__init__
get_first_param_type
u_AnnotationExtractor.get_first_param_type
get_return_type
u_AnnotationExtractor.get_return_type
local
repr_context
get_generic_base
uattr\_compat.py
u<module attr._compat>
T aself
callable
T acls
T aself
params
T acl
T aself

a__spec__
.attr._config
u'run' must be bool.
a_run_validators

Set whether or not validators are run.  By default, they are run.
.. deprecated:: 21.3.0 It will not be removed, but it also will not be
moved to new ``attrs`` namespace. Use `attrs.validators.set_disabled()`
instead.

Return whether or not validators are run.
.. deprecated:: 21.3.0 It will not be removed, but it also will not be
moved to new ``attrs`` namespace. Use `attrs.validators.get_disabled()`
instead.
a__doc__
a__file__
origin
has_location
a__cached__
get_run_validators
set_run_validators
a__all__
uattr\_config.py
u<module attr._config>
T arun
msg

a__spec__
.attr._funcs
)
L
fields
inst
name
filter
value_serializer
has
wvaasdict
dict_factory
retain_collection_types
T arecurse
filter
dict_factory
retain_collection_types
value_serializer
rv
T Otuple
Olist
Oset
Ofrozenset
a_asdict_anything
T ais_key
filter
dict_factory
retain_collection_types
value_serializer
items

Return the *attrs* attribute values of *inst* as a dict.
Optionally recurse into other *attrs*-decorated classes.
Args:
inst: Instance of an *attrs*-decorated class.
recurse (bool): Recurse into classes that are also *attrs*-decorated.
filter (~typing.Callable):
A callable whose return code determines whether an attribute or
element is included (`True`) or dropped (`False`).  Is called with
the `attrs.Attribute` as the first argument and the value as the
second argument.
dict_factory (~typing.Callable):
A callable to produce dictionaries from.  For example, to produce
ordered dictionaries instead of normal Python dictionaries, pass in
``collections.OrderedDict``.
retain_collection_types (bool):
Do not convert to `list` when encountering an attribute whose type
is `tuple` or `set`.  Only meaningful if *recurse* is `True`.
value_serializer (typing.Callable | None):
A hook that is called for every attribute or dict key/value.  It
receives the current instance, field and value and must return the
(updated) value.  The hook is run *after* the optional *filter* has
been applied.
Returns:
Return type of *dict_factory*.
Raises:
ttrs.exceptions.NotAnAttrsClassError:
If *cls* is not an *attrs* class.
..  versionadded:: 16.0.0 *dict_factory*
..  versionadded:: 16.1.0 *retain_collection_types*
..  versionadded:: 20.3.0 *value_serializer*
..  versionadded:: 21.3.0
If a dict has a collection for a key, it is serialized as a tuple.
df
u<genexpr>
uasdict.<locals>.<genexpr>
a__attrs_attrs__

``asdict`` only works on attrs instances, this works on anything.
u_asdict_anything.<locals>.<genexpr>
astuple
tuple_factory
retain
T arecurse
filter
tuple_factory
retain_collection_types

Return the *attrs* attribute values of *inst* as a tuple.
Optionally recurse into other *attrs*-decorated classes.
Args:
inst: Instance of an *attrs*-decorated class.
recurse (bool):
Recurse into classes that are also *attrs*-decorated.
filter (~typing.Callable):
A callable whose return code determines whether an attribute or
element is included (`True`) or dropped (`False`).  Is called with
the `attrs.Attribute` as the first argument and the value as the
second argument.
tuple_factory (~typing.Callable):
A callable to produce tuples from. For example, to produce lists
instead of tuples.
retain_collection_types (bool):
Do not convert to `list` or `dict` when encountering an attribute
which type is `tuple`, `dict` or `set`. Only meaningful if
*recurse* is `True`.
Returns:
Return type of *tuple_factory*
Raises:
ttrs.exceptions.NotAnAttrsClassError:
If *cls* is not an *attrs* class.
..  versionadded:: 16.2.0
T atuple_factory
retain_collection_types
uastuple.<locals>.<genexpr>
get_generic_base

Check whether *cls* is a class with *attrs* attributes.
Args:
cls (type): Class to introspect.
Raises:
TypeError: If *cls* is not a class.
Returns:
bool:
copy
aNOTHING

u is not an attrs attribute on
new
w.aAttrsAttributeNotFoundError
a_OBJ_SETATTR

Copy *inst* and apply *changes*.
This is different from `evolve` that applies the changes to the arguments
that create the new instance.
`evolve`'s behavior is preferable, but there are `edge cases`_ where it
doesn't work. Therefore `assoc` is deprecated, but will not be removed.
.. _`edge cases`: https://github.com/python-attrs/attrs/issues/251
Args:
inst: Instance of a class with *attrs* attributes.
changes: Keyword changes in the new copy.
Returns:
A copy of inst with *changes* incorporated.
Raises:
ttrs.exceptions.AttrsAttributeNotFoundError:
If *attr_name* couldn't be found on *cls*.
ttrs.exceptions.NotAnAttrsClassError:
If *cls* is not an *attrs* class.
..  deprecated:: 17.1.0
Use `attrs.evolve` instead if you can. This function will not be
removed du to the slightly different approach compared to
`attrs.evolve`, though.
a__attrs_types_resolved__
globalns
localns
aPY_3_9_PLUS
include_extras
get_type_hints
type

Resolve any strings and forward annotations in type annotations.
This is only required if you need concrete types in :class:`Attribute`'s
*type* field. In other words, you don't need to resolve your types if you
only use them for static type checking.
With no arguments, names will be looked up in the module in which the class
was created. If this is not what you want, for example, if the name only
exists inside a method, you may pass *globalns* or *localns* to specify
other dictionaries in which to look up these names. See the docs of
`typing.get_type_hints` for more details.
Args:
cls (type): Class to resolve.
globalns (dict | None): Dictionary containing global variables.
localns (dict | None): Dictionary containing local variables.
ttribs (list | None):
List of attribs for the given class. This is necessary when calling
from inside a ``field_transformer`` since *cls* is not an *attrs*
class yet.
include_extras (bool):
Resolve more accurately, if possible. Pass ``include_extras`` to
``typing.get_hints``, if supported by the typing module. On
supported Python versions (3.9+), this resolves the types more
ccurately.
Raises:
TypeError: If *cls* is not a class.
ttrs.exceptions.NotAnAttrsClassError:
If *cls* is not an *attrs* class and you didn't pass any attribs.
NameError: If types cannot be resolved because of missing variables.
Returns:
*cls* so you can use this function also as a class decorator. Please
note that you have to apply it **after** `attrs.define`. That means the
decorator has to come in the line **before** `attrs.define`.
..  versionadded:: 20.1.0
..  versionadded:: 21.1.0 *attribs*
..  versionadded:: 23.1.0 *include_extras*
a__doc__
a__file__
origin
has_location
a__cached__
a_compat
T aPY_3_9_PLUS
get_generic_base
a_make
T a_OBJ_SETATTR
aNOTHING
fields
exceptions
T aAttrsAttributeNotFoundError
T tnOdict
FnT tnOtuple
Faassoc
T nnntaresolve_types
uattr\_funcs.py
T a.0
kk
vv
filter
df
retain_collection_types
value_serializer
T a.0
kk
vv
tuple_factory
retain
u<module attr._funcs>
T	aval
is_key
filter
dict_factory
retain_collection_types
value_serializer
rv
cf
df
Tainst
recurse
filter
dict_factory
retain_collection_types
value_serializer
attrs
rv
wawvacf
items
df
T ainst
changes
new
attrs
wkwvwaamsg
Tainst
recurse
filter
tuple_factory
retain_collection_types
attrs
rv
retain
wawvacf
items
df
T acls
attrs
generic_base
generic_attrs
T	acls
globalns
localns
attribs
include_extras
typing
kwargs
hints
field
a__spec__
.attr._make
n
; a_determine_attrib_eq_order
uInvalid value for hash.  Must be True, False, or None.
aNOTHING
uThe `default` and `factory` arguments are mutually exclusive.
callable
uThe `factory` argument must be a callable.
aFactory
T Olist
Otuple
setters
pipe
and_
a_CountingAttr
T adefault
validator
repr
cmp
hash
init
converter
metadata
type
kw_only
eq
eq_key
order
order_key
on_setattr
alias

Create a new field / attribute on a class.
Identical to `attrs.field`, except it's not keyword-only.
Consider using `attrs.field` in new code (``attr.ib`` will *never* go away,
though).
..  warning::
Does **nothing** unless the class is also decorated with
`attr.s` (or similar)!
.. versionadded:: 15.2.0 *convert*
.. versionadded:: 16.3.0 *metadata*
.. versionchanged:: 17.1.0 *validator* can be a ``list`` now.
.. versionchanged:: 17.1.0
*hash* is `None` and therefore mirrors *eq* by default.
.. versionadded:: 17.3.0 *type*
.. deprecated:: 17.4.0 *convert*
.. versionadded:: 17.4.0
*converter* as a replacement for the deprecated *convert* to achieve
consistency with other noun-based arguments.
.. versionadded:: 18.1.0
``factory=f`` is syntactic sugar for ``default=attr.Factory(f)``.
.. versionadded:: 18.2.0 *kw_only*
.. versionchanged:: 19.2.0 *convert* keyword argument removed.
.. versionchanged:: 19.2.0 *repr* also accepts a custom callable.
.. deprecated:: 19.2.0 *cmp* Removal on or after 2021-06-01.
.. versionadded:: 19.2.0 *eq* and *order*
.. versionadded:: 20.1.0 *on_setattr*
.. versionchanged:: 20.3.0 *kw_only* backported to Python 2
.. versionchanged:: 21.1.0
*eq*, *order*, and *cmp* also accept a custom callable
.. versionchanged:: 21.1.0 *cmp* undeprecated
.. versionadded:: 22.2.0 *alias*
exec
script
globs
locs
filename
bytecode
T M Omemoryview
strip
T c
T u
u<string>
eval

Evaluate the script with the given global (globs) and local (locs)
variables.
splitlines
T talinecache
cache
setdefault
:nq nu
w-acount
w>a_compile_and_eval

Create the method with the script given and return the method object.
aAttributes
uclass
u(tuple):
u    __slots__ = ()
attr_class_template

u = _attrs_property(_attrs_itemgetter(
u))
u    pass
a_attrs_itemgetter
itemgetter
a_attrs_property
w

Create a tuple subclass to hold `Attribute`s for an `attrs` class.
The subclass is a bare tuple with properties for names.
class MyClassAttributes(tuple):
__slots__ = ()
x = property(itemgetter(0))
startswith
T T w'w"aendswith
:l q naannot
a_CLASSVAR_PREFIXES

Check whether *annot* is a typing.ClassVar.
The string comparison hack is used to avoid evaluating all string
nnotations which would put attrs-based classes at a performance
disadvantage compared to plain old classes.

Check whether *cls* defines *attrib_name* (and doesn't just inherit it).
a__mro__
a__attrs_attrs__
inherited
name
evolve
T ainherited
base_attrs
base_attr_map
seen
filtered
add

Collect attr.ibs from base classes of *cls*, except *taken_attr_names*.
taken_attr_names

Collect attr.ibs from base classes of *cls*, except *taken_attr_names*.
N.B. *taken_attr_names* will be mutated.
Adhere to the old incorrect behavior.
Notably it collects from the front and considers inherited attributes which
leads to the buggy behavior reported in #428.
a_get_annotations
items
a_is_class_var
annot_names
cd
get
attrib
T adefault
ca_list
aUnannotatedAttributeError
uThe following `attr.ib`s lack a type annotation:
u,
sorted
u<lambda>
u_transform_attrs.<locals>.<lambda>
T akey
w.aAttribute
from_counting_attr
anns
T aname
ca
type
a_collect_base_attrs
a_collect_base_attrs_broken
own_attrs
T akw_only
had_default
default
uNo mandatory attributes allowed after an attribute with a default value or factory.  Attribute in question:
attrs
alias
a_default_init_alias_for
T aalias
a_make_attr_tuple_class
a__name__
a_Attributes

Transform all `_CountingAttr`s on a class into `Attribute`s.
If *these* is passed, use that and don't look for them on the class.
If *collect_by_mro* is True, collect them in the correct MRO order,
otherwise use the old -- incorrect -- order.  See #428.
Return an `_Attributes`.
counter
u<genexpr>
u_transform_attrs.<locals>.<genexpr>
init
kw_only
L	udef wrapper(_cls):
u    __class__ = _cls
u    def __getattr__(self, item, cached_properties=cached_properties, original_getattr=original_getattr, _cached_setattr_get=_cached_setattr_get):
u         func = cached_properties.get(item)
u         if func is not None:
u              result = func(self)
u              _setter = _cached_setattr_get(self)
u              _setter(item, result)
u              return result
u         return original_getattr(self, item)
L u         try:
u             return super().__getattribute__(item)
u         except AttributeError:
u             if not hasattr(super(), '__getattr__'):
u                 raise
u             return super().__getattr__(item)
u         original_error = f"'{self.__class__.__name__}' object has no attribute '{item}'"
u         raise AttributeError(original_error)
lines
u    return __getattr__
u__getattr__ = wrapper(_cls)
a_generate_unique_filename
getattr
cached_properties
a_cached_setattr_get
a_OBJ_SETATTR
a__get__
original_getattr
a_make_method
a__getattr__
a_cls
T alocals
T a__cause__
a__context__
a__traceback__
a__suppress_context__
a__notes__
a__setattr__
aFrozenInstanceError

Attached to frozen classes as __setattr__.
T a__notes__
a__delattr__

Attached to frozen classes as __delattr__.
uevolve() takes 1 positional argument, but
u were given
fields
changes

Create a new instance, based on the first positional argument with
*changes* applied.
.. tip::
On Python 3.13 and later, you can also use `copy.replace` instead.
Args:
inst:
Instance of a class with *attrs* attributes. *inst* must be passed
s a positional argument.
changes:
Keyword changes in the new copy.
Returns:
A copy of inst with *changes* incorporated.
Raises:
TypeError:
If *attr_name* couldn't be found in the class ``__init__``.
ttrs.exceptions.NotAnAttrsClassError:
If *cls* is not an *attrs* class.
.. versionadded:: 17.1.0
.. deprecated:: 23.1.0
It is now deprecated to pass the instance using the keyword argument
*inst*. It will raise a warning until at least April 2024, after which
it will become an error. Always pass the instance as a positional
rgument.
.. versionchanged:: 24.1.0
*inst* can't be passed as a keyword argument anymore.
a_transform_attrs
a_cls_dict
a_attrs
a_base_names
a_base_attr_map
a_attr_names
a_slots
a_frozen
a_weakref_slot
a_cache_hash
a__attrs_pre_init__
a_has_pre_init
a_pre_init_has_args
inspect
signature
parameters
a__attrs_post_init__
a_has_post_init
a_delete_attribs
a_is_exc
a_on_setattr
a_has_custom_setattr
a_wrote_own_setattr
a_frozen_setattrs
a_frozen_delattrs
a_DEFAULT_ON_SETATTR
validate
convert
validator
converter
has_validator
has_converter
a_make_getstate_setstate
a__getstate__
a__setstate__
u_ClassBuilder.__init__.<locals>.<genexpr>
u<_ClassBuilder(cls=
u)>
a_create_slots_class
a_patch_original_class
aPY_3_10_PLUS
abc
update_abstractmethods
a__attrs_init_subclass__

Finalize class based on the accumulated configuration.
Builder cannot be used after calling this method.
a_SENTINEL
contextlib
suppress
T EAttributeError
a__enter__
a__exit__
delattr
T nnna__attrs_own_setattr__

Apply accumulated methods and return the class.
self
T a__dict__
T a__weakref__
a__bases__
T a__attrs_own_setattr__
FT a__weakref__
naexisting_slots
a__slots__
a__weakref__
weakref_inherited
cached_property
func
names
additional_closure_functions_to_update
return_annotation
aParameter
empty
class_annotations
T a__getattr__
a_make_cached_property_getattr
update
append
a_HASH_CACHE_FIELD
a__qualname__
itertools
chain
values
T Oclassmethod
Ostaticmethod
a__func__
a__closure__
fget
cell_contents
match
cls

Build and return a new class with a `__slots__` attribute.
a_add_method_dunders
a_make_repr
a__repr__
T a__repr__
u__str__ can only be generated if a __repr__ exists.
a__str__
u_ClassBuilder.add_str.<locals>.__str__

Automatically created by attrs.
slots_getstate
u_ClassBuilder._make_getstate_setstate.<locals>.slots_getstate
slots_setstate
u_ClassBuilder._make_getstate_setstate.<locals>.slots_setstate

Create custom __setstate__ and __getstate__ methods.
u_ClassBuilder._make_getstate_setstate.<locals>.<genexpr>
state_attr_names
a_ClassBuilder__bound_setattr
hash_caching_enabled
a__hash__
a_make_hash
T afrozen
cache_hash
a_make_init
D aattrs_init
Fa__init__
u_ClassBuilder.add_replace.<locals>.<lambda>
a__replace__
a__match_args__
u_ClassBuilder.add_match_args.<locals>.<genexpr>
D aattrs_init
ta__attrs_init__
a_make_eq
a__eq__
a_make_ne
a__ne__
a_make_order
a__lt__
a__le__
a__gt__
a__ge__
u_ClassBuilder.add_order.<locals>.<genexpr>
on_setattr
aNO_OP
sa_attrs
uCan't combine custom __setattr__ with on_setattr hooks.
u_ClassBuilder.add_setattr.<locals>.__setattr__
hook
