# Reconstructed from integrated Nuitka blob
# Module: unumpy._pytesttester

aPytestTester
a__qualname__
a__init__
uPytestTester.__init__
unumpy\_pytesttester.py
u<module numpy._pytesttester>
T aself
name

.numpy._typing._add_docstring
0
a_docstrings_list
append
utoo many values to unpack (expected 3)
textwrap
dedent
replace
T w

split
T w

re
match
u^(\s+)[-=]+\s*$
new_lines
aExamples
group
T l u.. rubric::

u.. admonition::
T u
indent
w
u.. data::

:value:

type_list_ret
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
l
a_array_like
T aNDArray
l aNDArray
add_newdoc
a_parse_docstrings
T aArrayLike
utyping.Union[...]

A `~typing.Union` representing objects that can be coerced
into an `~numpy.ndarray`.
Among others this includes the likes of:
* Scalars.
* (Nested) sequences.
* Objects implementing the `~class.__array__` protocol.
.. versionadded:: 1.20
See Also
--------
:term:`array_like`:
Any scalar or sequence that can be interpreted as an ndarray.
Examples
--------
.. code-block:: python
>>> import numpy as np
>>> import numpy.typing as npt
>>> def as_array(a: npt.ArrayLike) -> np.ndarray:
...     return np.array(a)
T aDTypeLike
utyping.Union[...]

A `~typing.Union` representing objects that can be coerced
into a `~numpy.dtype`.
Among others this includes the likes of:
* :class:`type` objects.
* Character codes or the names of :class:`type` objects.
* Objects with the ``.dtype`` attribute.
.. versionadded:: 1.20
See Also
--------
:ref:`Specifying and constructing data types <arrays.dtypes.constructing>`
A comprehensive overview of all objects that can be coerced
into data types.
Examples
--------
.. code-block:: python
>>> import numpy as np
>>> import numpy.typing as npt
>>> def as_dtype(d: npt.DTypeLike) -> np.dtype:
...     return np.dtype(d)

A `np.ndarray[tuple[int, ...], np.dtype[+ScalarType]] <numpy.ndarray>`
type alias :term:`generic <generic type>` w.r.t. its
`dtype.type <numpy.dtype.type>`.
Can be used during runtime for typing arrays with a given dtype
nd unspecified shape.
.. versionadded:: 1.21
Examples
--------
.. code-block:: python
>>> import numpy as np
>>> import numpy.typing as npt
>>> print(npt.NDArray)
numpy.ndarray[tuple[int, ...], numpy.dtype[+_ScalarType_co]]
>>> print(npt.NDArray[np.float64])
numpy.ndarray[tuple[int, ...], numpy.dtype[numpy.float64]]
>>> NDArrayInt = npt.NDArray[np.int_]
>>> a: NDArrayInt = np.arange(10)
>>> def func(a: npt.ArrayLike) -> npt.NDArray[Any]:
...     return np.array(a)
a_docstrings
unumpy\_typing\_add_docstring.py
u<module numpy._typing._add_docstring>
T atype_list_ret
name
value
doc
wsalines
new_lines
indent
line
wmaprev
s_block
T aname
value
doc
.numpy._typing._array_like
|
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
annotations
sys
ucollections.abc
T aCollection
aCallable
aSequence
l
aCollection
aCallable
aSequence
aAny
aProtocol
aTypeAlias
aTypeVar
runtime_checkable
aTYPE_CHECKING
numpy
np
T andarray
dtype
generic
unsignedinteger
integer
floating
complexfloating
number
timedelta64
datetime64
object_
void
str_
bytes_
ndarray
dtype
generic
unsignedinteger
integer
floating
complexfloating
number
timedelta64
datetime64
object_
void
str_
bytes_
a_nbit_base
T a_32Bit
a_64Bit
l a_32Bit
a_64Bit
a_nested_sequence
T a_NestedSequence
a_NestedSequence
a_shape
T a_Shape
a_Shape
unumpy._core.multiarray
T aStringDType
aStringDType
T a_T
a_T
T a_ScalarType
T abound
a_ScalarType
T a_ScalarType_co
T abound
covariant
a_ScalarType_co
T a_DType
a_DType
T a_DType_co
T acovariant
bound
a_DType_co
aNDArray
a__prepare__
a_SupportsArray
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
