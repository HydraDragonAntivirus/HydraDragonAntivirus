# Reconstructed from integrated Nuitka blob
# Module: async_timeout

a__qualname__
a__orig_bases__
T a_deadline
a_loop
a_state
a_timeout_handler
a_task
a__slots__
loop
aAbstractEventLoop
a__init__
uTimeout.__init__
D areturn
aTimeout
exc_val
exc_tb
D areturn
Obool
expired
uTimeout.expired
uTimeout.deadline
D areturn
nareject
uTimeout.reject
uTimeout._reject
D adelay
return
Ofloat
nashift
uTimeout.shift
D adeadline
return
Ofloat
nuTimeout.update
uTimeout._reschedule
uTimeout._do_enter
uTimeout._do_exit
uTimeout._on_timeout
uasync_timeout\__init__.py
u<module async_timeout>
T a__class__
T aself
T aself
exc_type
exc_val
exc_tb
T aself
deadline
loop
T aself
exc_type
T aself
deadline
now
T aself
delay
deadline
T adelay
loop
deadline
T adeadline
loop
T aself
deadline
a__spec__
.attr._cmp
K
a__slots__
value
a__init__
a_make_init
a_requirements
a_is_comparable_to
a_make_operator
eq
a__eq__
a_make_ne
a__ne__
lt
a__lt__
le
a__le__
gt
a__gt__
ge
a__ge__
new_class
T Oobject
u<lambda>
ucmp_using.<locals>.<lambda>
append
a_check_same_type
ueq must be define is order to complete ordering from lt, le, gt, ge.
total_ordering
type_

Create a class that can be passed into `attrs.field`'s ``eq``, ``order``,
nd ``cmp`` arguments to customize field comparison.
The resulting class will have a full set of ordering methods if at least
one of ``{lt, le, gt, ge}`` and ``eq``  are provided.
Args:
eq (typing.Callable | None):
Callable used to evaluate equality of two objects.
lt (typing.Callable | None):
Callable used to evaluate whether one object is less than another
object.
le (typing.Callable | None):
Callable used to evaluate whether one object is less than or equal
to another object.
gt (typing.Callable | None):
Callable used to evaluate whether one object is greater than
nother object.
ge (typing.Callable | None):
Callable used to evaluate whether one object is greater than or
equal to another object.
require_same_type (bool):
When `True`, equality and ordering methods will return
`NotImplemented` if objects are not of the same type.
class_name (str | None): Name of class. Defaults to "Comparable".
See `comparison` for more details.
.. versionadded:: 21.1.0
update
body

Initialize object with *value*.
u_make_init.<locals>.__init__

Create __init__ method.
method
u_make_operator.<locals>.method
a__

a__name__
uReturn a
a_operation_names
u b.  Computed by attrs.
a__doc__

Create operator method.
func

Check whether `other` is comparable to `self`.
self
other
u<genexpr>
u_is_comparable_to.<locals>.<genexpr>

Return True if *self* and *other* are of the same type, False otherwise.
a__file__
origin
has_location
a__cached__
functools
types
a_make
T a_make_ne
D aeq
lt
le
gt
ge
u==
w<u<=
w>u>=
T nnnnntaComparable
cmp_using
uattr\_cmp.py
T a.0
func
self
other
T ans
body
T abody
u<module attr._cmp>
T aself
value
T aself
other
T a__init__
T aname
func
method
T aeq
lt
le
gt
ge
require_same_type
class_name
body
num_order_functions
has_eq_function
type_
msg
T aself
other
result
func
T afunc
a__spec__
.attr._compat
A
get
a__annotations__

Get annotations for *cls*.
inspect
signature
sig
T EValueError
ETypeError
parameters
values
annotation
aParameter
empty

Return the type annotation of the first argument if it's not empty.
return_annotation
aSignature

Return the return type if it's not empty.
a_GenericAlias
a__origin__
uIf this is a generic class (A[str]), return the generic base for it.
a__doc__
a__file__
origin
has_location
a__cached__
platform
sys
threading
ucollections.abc
T aMapping
aSequence
aMapping
aSequence
python_implementation
aPyPy
aPYPY
aPY_3_9_PLUS
aPY_3_10_PLUS
aPY_3_11_PLUS
aPY_3_12_PLUS
aPY_3_13_PLUS
aPY_3_14_PLUS
a_get_annotations
