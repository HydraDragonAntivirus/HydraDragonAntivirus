# Reconstructed from integrated Nuitka blob
# Module: uattr.exceptions


A frozen/immutable instance or attribute have been attempted to be
modified.
It mirrors the behavior of ``namedtuples`` by using the same error message
nd subclassing `AttributeError`.
.. versionadded:: 20.1.0
a__qualname__
a__annotations__
ucan't set attribute
args
uClassVar[tuple[str]]
a__orig_bases__
aFrozenInstanceError

A frozen instance has been attempted to be modified.
.. versionadded:: 16.1.0
aFrozenAttributeError

A frozen attribute has been attempted to be modified.
.. versionadded:: 20.1.0
T EValueError
aAttrsAttributeNotFoundError

An *attrs* function couldn't find an attribute that the user asked for.
.. versionadded:: 16.2.0
aNotAnAttrsClassError

A non-*attrs* class has been passed into an *attrs* function.
.. versionadded:: 16.2.0
T ERuntimeError
aDefaultAlreadySetError

A default has been set when defining the field and is attempted to be reset
using the decorator.
.. versionadded:: 17.1.0
aUnannotatedAttributeError

A class with ``auto_attribs=True`` has a field without a type annotation.
.. versionadded:: 17.3.0
aPythonTooOldError

It was attempted to use an *attrs* feature that requires a newer Python
version.
.. versionadded:: 18.2.0
T ETypeError
aNotCallableError

A field requiring a callable has been set with a value that is not
callable.
.. versionadded:: 19.2.0
uNotCallableError.__init__
a__str__
uNotCallableError.__str__
uattr\exceptions.py
u<module attr.exceptions>
T a__class__
T aself
msg
value
a__class__
T aself

a__spec__
.attr.filters
}
#

Returns a tuple of `frozenset`s of classes and attributes.
u<genexpr>
u_split_what.<locals>.<genexpr>
aAttribute
a_split_what
include_
uinclude.<locals>.include_

Create a filter that only allows *what*.
Args:
what (list[type, str, attrs.Attribute]):
What to include. Can be a type, a name, or an attribute.
Returns:
Callable:
A callable that can be passed to `attrs.asdict`'s and
`attrs.astuple`'s *filter* argument.
.. versionchanged:: 23.1.0 Accept strings with field names.
cls
name
names
attrs
exclude_
uexclude.<locals>.exclude_

Create a filter that does **not** allow *what*.
Args:
what (list[type, str, attrs.Attribute]):
What to exclude. Can be a type, a name, or an attribute.
Returns:
Callable:
A callable that can be passed to `attrs.asdict`'s and
`attrs.astuple`'s *filter* argument.
.. versionchanged:: 23.3.0 Accept field name string as input argument

Commonly useful filters for `attrs.asdict` and `attrs.astuple`.
a__doc__
a__file__
origin
has_location
a__cached__
a_make
T aAttribute
include
exclude
uattr\filters.py
T a.0
cls
u<module attr.filters>
T awhat
T awhat
cls
names
attrs
exclude_
T aattribute
value
cls
names
attrs
T aattrs
cls
names
T awhat
cls
names
attrs
include_

a__spec__
.attr.setters
*
wrapped_pipe
upipe.<locals>.wrapped_pipe

Run all *setters* and return the return value of the last one.
.. versionadded:: 20.1.0
setters
instance
attrib
rv
aFrozenAttributeError

Prevent an attribute to be modified.
.. versionadded:: 20.1.0
a_config
a_run_validators
validator

Run *attrib*'s validator on *new_value* if it has one.
.. versionadded:: 20.1.0
converter
a_make
T aConverter
aConverter

Run *attrib*'s converter -- if it has one -- on *new_value* and return the
result.
.. versionadded:: 20.1.0

Commonly used hooks for on_setattr.
a__doc__
a__file__
origin
has_location
a__cached__

T a_config
exceptions
T aFrozenAttributeError
pipe
frozen
validate
convert
aNO_OP
uattr\setters.py
u<module attr.setters>
T ainstance
attrib
new_value
wcaConverter
T w_a__
a___
T asetters
wrapped_pipe
T ainstance
attrib
new_value
wvT ainstance
attrib
new_value
rv
setter
setters
T asetters
a__spec__
.attr.validators
/
set_run_validators

Globally disable or enable running validators.
By default, they are run.
Args:
disabled (bool): If `True`, disable running all validators.
.. warning::
This function is not thread-safe!
.. versionadded:: 21.3.0
get_run_validators

Return a bool indicating whether validators are currently disabled or not.
Returns:
bool:`True` if validators are currently disabled.
.. versionadded:: 21.3.0

Context manager that disables running validators within its context.
.. warning::
This context manager is not thread-safe!
.. versionadded:: 21.3.0
T FT tadisabled
type
w'aname

u' must be
u (got
u that is a
u).

We use a callable class to be able to change the ``__repr__``.
u<instance_of validator for type
w>a_InstanceOfValidator

A validator that raises a `TypeError` if the initializer is called with a
wrong type for this particular attribute (checks are performed using
`isinstance` therefore it's also valid to pass a tuple of types).
Args:
type (type | tuple[type]): The type to check for.
Raises:
TypeError:
With a human readable error message, the attribute (of type
`attrs.Attribute`), the expected type, and the value it got.
match_func
u' must match regex
pattern
u (
u doesn't)
u<matches_re validator for pattern
re
fullmatch
search
match
u'func' must be one of {}.
u,
sorted
aPattern
u'flags' can only be used with a string pattern; pass flags to re.compile() instead
compile
a_MatchesReValidator

A validator that raises `ValueError` if the initializer is called with a
string that doesn't match *regex*.
Args:
regex (str, re.Pattern):
A regex string or precompiled pattern to match against
flags (int):
Flags that will be passed to the underlying re function (default 0)
func (typing.Callable):
Which underlying `re` function to call. Valid options are
`re.fullmatch`, `re.search`, and `re.match`; the default `None`
means `re.fullmatch`. For performance reasons, the pattern is
lways precompiled using `re.compile`.
.. versionadded:: 19.2.0
.. versionchanged:: 21.3.0 *regex* can be a pre-compiled pattern.
a__name__
aNone
u<genexpr>
umatches_re.<locals>.<genexpr>
validator
u<optional validator for
u or None>
T Olist
Otuple
a_OptionalValidator
a_AndValidator

A validator that makes an attribute optional.  An optional attribute is one
which can be set to `None` in addition to satisfying the requirements of
the sub-validator.
Args:
validator
(typing.Callable | tuple[typing.Callable] | list[typing.Callable]):
A validator (or validators) that is used for non-`None` values.
.. versionadded:: 15.1.0
.. versionchanged:: 17.1.0 *validator* can be a list of validators.
.. versionchanged:: 23.1.0 *validator* can also be a tuple of validators.
options
u' must be in
a_original_options
w)u<in_ validator with options
T Olist
Odict
Oset
a_InValidator

A validator that raises a `ValueError` if the initializer is called with a
value that does not belong in the *options* provided.
The check is performed using ``value in options``, so *options* has to
support that operation.
To keep the validator hashable, dicts, lists, and sets are transparently
transformed into a `tuple`.
Args:
options: Allowed options.
Raises:
ValueError:
With a human readable error message, the attribute (of type
`attrs.Attribute`), the expected options, and the value it got.
.. versionadded:: 17.1.0
.. versionchanged:: 22.1.0
The ValueError was incomplete until now and only contained the human
readable error message. Now it contains all the information that has
been promised since 17.1.0.
.. versionchanged:: 24.1.0
*options* that are a list, dict, or a set are now transformed into a
tuple to keep the validator hashable.
callable
aNotCallableError
u'{name}' must be callable (got {value!r} that is a {actual!r}).
T aname
value
actual
T amsg
value
a_IsCallableValidator

A validator that raises a `attrs.exceptions.NotCallableError` if the
initializer is called with a value for this particular attribute that is
not callable.
.. versionadded:: 19.1.0
Raises:
ttrs.exceptions.NotCallableError:
With a human readable error message containing the attribute
(`attrs.Attribute`) name, and the value it got.
iterable_validator
self
member_validator
inst
attr
w u<deep_iterable validator for
u iterables of
and_
a_DeepIterable

A validator that performs deep validation of an iterable.
Args:
member_validator: Validator to apply to iterable members.
iterable_validator:
Validator to apply to iterable itself (optional).
Raises
TypeError: if any sub-validators fail
.. versionadded:: 19.1.0
mapping_validator
key_validator
value_validator
u<deep_mapping validator for objects mapping
u to
a_DeepMapping

A validator that performs deep validation of a dictionary.
Args:
key_validator: Validator to apply to dictionary keys.
value_validator: Validator to apply to dictionary values.
mapping_validator:
Validator to apply to top-level mapping attribute (optional).
.. versionadded:: 19.1.0
Raises:
TypeError: if any sub-validators fail
compare_func
bound
compare_op
u:
u<Validator for x
a_NumberValidator
w<aoperator
lt

A validator that raises `ValueError` if the initializer is called with a
number larger or equal to *val*.
The validator uses `operator.lt` to compare the values.
Args:
val: Exclusive upper bound for values.
.. versionadded:: 21.3.0
u<=
le

A validator that raises `ValueError` if the initializer is called with a
number greater than *val*.
The validator uses `operator.le` to compare the values.
Args:
val: Inclusive upper bound for values.
.. versionadded:: 21.3.0
u>=
ge

A validator that raises `ValueError` if the initializer is called with a
number smaller than *val*.
The validator uses `operator.ge` to compare the values.
Args:
val: Inclusive lower bound for values
.. versionadded:: 21.3.0
gt

A validator that raises `ValueError` if the initializer is called with a
number smaller or equal to *val*.
The validator uses `operator.ge` to compare the values.
Args:
val: Exclusive lower bound for values
.. versionadded:: 21.3.0
max_length
uLength of '
u' must be <=
u<max_len validator for
a_MaxLengthValidator

A validator that raises `ValueError` if the initializer is called
with a string or iterable that is longer than *length*.
Args:
length (int): Maximum length of the string or iterable
.. versionadded:: 21.3.0
min_length
u' must be >=
u<min_len validator for
a_MinLengthValidator

A validator that raises `ValueError` if the initializer is called
with a string or iterable that is shorter than *length*.
Args:
length (int): Minimum length of the string or iterable
.. versionadded:: 22.1.0
u' must be a subclass of
u<subclass_of validator for type
a_SubclassOfValidator

A validator that raises a `TypeError` if the initializer is called with a
wrong type for this particular attribute (checks are performed using
`issubclass` therefore it's also valid to pass a tuple of types).
Args:
type (type | tuple[type, ...]): The type(s) to check for.
Raises:
TypeError:
With a human readable error message, the attribute (of type
`attrs.Attribute`), the expected type, and the value it got.
exc_types
msg
format
T avalidator
exc_types
u<not_ validator wrapping
u, capturing
a_NotValidator

A validator that wraps and logically 'inverts' the validator passed to it.
It will raise a `ValueError` if the provided validator *doesn't* raise a
`ValueError` or `TypeError` (by default), and will suppress the exception
if the provided validator *does*.
Intended to be used with existing validators to compose logic without
needing to create inverted variants, for example, ``not_(in_(...))``.
Args:
validator: A validator to be logically inverted.
msg (str):
Message to raise if validator fails. Formatted with keys
``exc_types`` and ``validator``.
exc_types (tuple[type, ...]):
Exception type(s) to capture. Other types raised by child
validators will not be intercepted and pass through.
Raises:
ValueError:
With a human readable error message, the attribute (of type
`attrs.Attribute`), the validator that failed to raise an
exception, the value it got, and the expected exception types.
.. versionadded:: 22.2.0
validators
value
uNone of
u satisfied for value
u<or validator wrapping
vals
a_OrValidator

A validator that composes multiple validators into one.
When called on a value, it runs all wrapped validators until one of them is
satisfied.
Args:
validators (~collections.abc.Iterable[typing.Callable]):
Arbitrary number of validators.
Raises:
ValueError:
If no validator is satisfied. Raised with a human-readable error
message listing all the wrapped validators and the value that
failed all of them.
.. versionadded:: 24.1.0

Commonly useful validators.
a__doc__
a__file__
origin
has_location
a__cached__
contextlib
T acontextmanager
contextmanager
T aPattern
a_config
T aget_run_validators
set_run_validators
a_make
T a_AndValidator
and_
attrib
attrs
attrib
attrs
converters
T adefault_if_none
default_if_none
exceptions
T aNotCallableError
L aand_
deep_iterable
deep_mapping
disabled
ge
get_disabled
gt
in_
instance_of
is_callable
le
lt
matches_re
max_len
min_len
not_
optional
or_
set_disabled
a__all__
set_disabled
get_disabled
T FtpT arepr
slots
unsafe_hash
