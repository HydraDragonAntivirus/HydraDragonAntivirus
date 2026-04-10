# Reconstructed from integrated Nuitka blob
# Module: annotated_types

a_SupportsGt__other
return
bool
a__gt__
uSupportsGt.__gt__
a__orig_bases__
aSupportsGe
a_SupportsGe__other
a__ge__
uSupportsGe.__ge__
aSupportsLt
a_SupportsLt__other
a__lt__
uSupportsLt.__lt__
aSupportsLe
a_SupportsLe__other
a__le__
uSupportsLe.__le__
aSupportsMod
a_SupportsMod__other
a__mod__
uSupportsMod.__mod__
aSupportsDiv
a_SupportsDiv__other
a__div__
uSupportsDiv.__div__
uBase class for all metadata.
This exists mainly so that implementers
can do `isinstance(..., BaseMetadata)` while traversing field annotations.
aBaseMetadata
a__slots__
D afrozen
tuGt(gt=x) implies that the value must be greater than x.
It can be used with any type that supports the ``>`` operator,
including numbers, dates and times, strings, sets, and so on.
a__annotations__
uGe(ge=x) implies that the value must be greater than or equal to x.
It can be used with any type that supports the ``>=`` operator,
including numbers, dates and times, strings, sets, and so on.
uLt(lt=x) implies that the value must be less than x.
It can be used with any type that supports the ``<`` operator,
including numbers, dates and times, strings, sets, and so on.
uLe(le=x) implies that the value must be less than or equal to x.
It can be used with any type that supports the ``<=`` operator,
including numbers, dates and times, strings, sets, and so on.
uA grouping of multiple objects, like typing.Unpack.
`GroupedMetadata` on its own is not metadata and has no meaning.
All of the constraints and metadata should be fully expressable
in terms of the `BaseMetadata`'s returned by `GroupedMetadata.__iter__()`.
Concrete implementations should override `GroupedMetadata.__iter__()`
to add their own metadata.
For example:
>>> @dataclass
>>> class Field(GroupedMetadata):
>>>     gt: float | None = None
>>>     description: str | None = None
...
>>>     def __iter__(self) -> Iterable[object]:
>>>         if self.gt is not None:
>>>             yield Gt(self.gt)
>>>         if self.description is not None:
>>>             yield Description(self.gt)
Also see the implementation of `Interval` below for an example.
Parsers should recognize this and unpack it so that it can be used
both with and without unpacking:
- `Annotated[int, Field(...)]` (parser must unpack Field)
- `Annotated[int, *Field(...)]` (PEP-646)
property
a__is_annotated_types_grouped_metadata__
uGroupedMetadata.__is_annotated_types_grouped_metadata__
object
uGroupedMetadata.__iter__
args
kwargs
uGroupedMetadata.__init_subclass__
aInterval
uInterval can express inclusive or exclusive bounds with a single object.
It accepts keyword arguments ``gt``, ``ge``, ``lt``, and/or ``le``, which
re interpreted the same way as the single-bound constraints.
aMultipleOf
uMultipleOf(multiple_of=x) might be interpreted in two ways:
1. Python semantics, implying ``value % multiple_of == 0``, or
2. JSONschema semantics, where ``int(value / multiple_of) == value / multiple_of``
We encourage users to be aware of these two common interpretations,
nd libraries to carefully document which they implement.
multiple_of

MinLen() implies minimum inclusive length,
e.g. ``len(value) >= min_length``.
int
T l

MaxLen() implies maximum inclusive length,
e.g. ``len(value) <= max_length``.
aLen

Len() implies that ``min_length <= len(value) <= max_length``.
Upper bound may be omitted or ``None`` to indicate no upper length bound.
aTimezone
uTimezone(tz=...) requires a datetime to be aware (or ``tz=None``, naive).
``Annotated[datetime, Timezone(None)]`` must be a naive datetime.
``Timezone[...]`` (the ellipsis literal) expresses that the datetime must be
tz-aware but any timezone is allowed.
You may also pass a specific timezone string or tzinfo object such as
``Timezone(timezone.utc)`` or ``Timezone("Africa/Abidjan")`` to express that
you only allow a specific timezone, though we note that this is often
a symptom of poor design.
str
tz
aUnit
uIndicates that the value is a physical quantity with the specified unit.
It is intended for usage with numeric types, where the value represents the
magnitude of the quantity. For example, ``distance: Annotated[float, Unit('m')]``
or ``speed: Annotated[float, Unit('m/s')]``.
Interpretation of the unit string is left to the discretion of the consumer.
It is suggested to follow conventions established by python libraries that work
with physical quantities, such as
- ``pint`` : <https://pint.readthedocs.io/en/stable/>
- ``astropy.units``: <https://docs.astropy.org/en/stable/units/>
For indicating a quantity with a certain dimensionality but without a specific unit
it is recommended to use square brackets, e.g. `Annotated[float, Unit('[time]')]`.
Note, however, ``annotated_types`` itself makes no use of the unit string.
unit
aPredicate
u``Predicate(func: Callable)`` implies `func(value)` is truthy for valid values.
Users should prefer statically inspectable metadata, but if you need the full
power and flexibility of arbitrary runtime predicates... here it is.
We provide a few predefined predicates for common string constraints:
``IsLower = Predicate(str.islower)``, ``IsUpper = Predicate(str.isupper)``, and
``IsDigits = Predicate(str.isdigit)``. Users are encouraged to use methods which
can be given special handling, and avoid indirection like ``lambda s: s.lower()``.
Some libraries might have special logic to handle certain predicates, e.g. by
checking for `str.isdigit` and using its presence to both call custom logic to
enforce digit-only strings, and customise some generated external schema.
We do not specify what behaviour should be expected for predicates that raise
n exception.  For example `Annotated[int, Predicate(str.isdigit)]` might silently
skip invalid constraints, or statically raise an error; or it might try calling it
nd then propagate or discard the resulting exception.
a__repr__
uPredicate.__repr__
aNot
a_Not__v
a__call__
uNot.__call__
T a_StrType
Ostr
T abound
a_StrType
islower
aLowerCase
isupper
aUpperCase
isdigit
aIsDigit
aIsDigits
aIsAscii
T a_NumericType
a_NumericType
isfinite
aIsFinite
aIsNotFinite
isnan
aIsNan
aIsNotNan
isinf
aIsInfinite
aIsNotInfinite
typing_extensions
T aDocInfo
doc
doc
u "
The return value of doc(), mainly to be used by tools that want to extract the
Annotated documentation at runtime.
documentation
uannotated_types\__init__.py
u<module annotated_types>
T a__class__
T aself
a_Not__v
T aself
a_SupportsDiv__other
T aself
a_SupportsGe__other
T aself
a_SupportsGt__other
T acls
args
kwargs
a__class__
T aself
T aself
a_SupportsLe__other
T aself
a_SupportsLt__other
T aself
a_SupportsMod__other
T aself
namespace
T adocumentation
a__spec__
.anyio-preLoad
a__doc__
a__file__
origin
has_location
a__cached__
sys
os
argv
argv0
endswith
T u.exe
u.exe
a__nuitka_binary_exe
executable
a_base_executable
uanyio-preLoad.py
u<module anyio-preLoad>

a__spec__
.anyio._backends._asyncio

a_State
aCREATED
a_state
a_debug
a_loop_factory
a_loop
a_context
a_interrupt_count
a_set_event_loop
a_lazy_init
close
aINITIALIZED
a_cancel_all_tasks
run_until_complete
shutdown_asyncgens
shutdown_default_executor
a_shutdown_default_executor
events
set_event_loop
T naloop
aCLOSED
uShutdown and close event loop.
uReturn embedded event loop.
coroutines
iscoroutine
ua coroutine was expected, got

a_get_running_loop
uRunner.run() cannot be called from a running event loop
run
create_task
threading
current_thread
main_thread
signal
getsignal
aSIGINT
default_int_handler
partial
a_on_sigint
T amain_task
exceptions
aCancelledError
uncancel
sigint_handler
uRun a coroutine inside the embedded event loop.
uRunner is closed
new_event_loop
set_debug
contextvars
copy_context
done
cancel
call_soon_threadsafe
u<lambda>
uRunner._on_sigint.<locals>.<lambda>
tasks
all_tasks
gather
D areturn_exceptions
tacancelled
exception
call_exception_handler
message
uunhandled exception during asyncio.run() shutdown
task
uSchedule the shutdown of the default executor.
D afuture
return
uasyncio.futures.Future
aNone
a_do_shutdown
u_shutdown_default_executor.<locals>._do_shutdown
a_executor_shutdown_called
a_default_executor
create_future
aThread
T atarget
args
start
join
shutdown
T tT await
set_result
set_exception
a_root_task
get
a_callbacks
