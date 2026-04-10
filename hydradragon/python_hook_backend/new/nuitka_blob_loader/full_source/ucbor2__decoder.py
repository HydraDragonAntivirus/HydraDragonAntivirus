# Reconstructed from integrated Nuitka blob
# Module: ucbor2._decoder


The CBORDecoder class implements a fully featured `CBOR`_ decoder with
several extensions for handling shared references, big integers, rational
numbers and so on. Typically the class is not used directly, but the
:func:`load` and :func:`loads` functions are called to indirectly construct
nd use the class.
When the class is constructed manually, the main entry points are
:meth:`decode` and :meth:`decode_from_bytes`.
.. _CBOR: https://cbor.io/
a__qualname__
T	a_tag_hook
a_object_hook
a_share_index
a_shareables
a_fp
a_fp_read
a_immutable
a_str_errors
a_stringref_namespace
a__slots__
uIO[bytes]
uCallable[[int], bytes]
T nnastrict
D afp
tag_hook
object_hook
str_errors
uIO[bytes]
uCallable[[CBORDecoder, CBORTag], Any] | None
uCallable[[CBORDecoder, dict[Any, Any]], Any] | None
uLiteral['strict', 'error', 'replace']
a__init__
uCBORDecoder.__init__
D areturn
bool
immutable
uCBORDecoder.immutable
D areturn
uIO[bytes]
uCBORDecoder.fp
setter
D avalue
return
uIO[bytes]
aNone
D areturn
uCallable[[CBORDecoder, CBORTag], Any] | None
uCBORDecoder.tag_hook
D avalue
return
uCallable[[CBORDecoder, CBORTag], Any] | None
aNone
D areturn
uCallable[[CBORDecoder, dict[Any, Any]], Any] | None
uCBORDecoder.object_hook
D avalue
return
uCallable[[CBORDecoder, Mapping[Any, Any]], Any] | None
aNone
D areturn
uLiteral['strict', 'error', 'replace']
uCBORDecoder.str_errors
D avalue
return
uLiteral['strict', 'error', 'replace']
aNone
D avalue
return
wTpuCBORDecoder.set_shareable
D astring
length
return
ustr | bytes
int
aNone
uCBORDecoder._stringref_namespace_add
D aamount
return
int
bytes
uCBORDecoder.read
T FpD aimmutable
unshared
return
bool
paAny
uCBORDecoder._decode
D areturn
object
uCBORDecoder.decode
D abuf
return
bytes
object
decode_from_bytes
uCBORDecoder.decode_from_bytes
D asubtype
return
int
puCBORDecoder._decode_length
D asubtype
allow_indefinite
return
int
uLiteral[True]
uint | None
T FD asubtype
allow_indefinite
return
int
bool
uint | None
decode_uint
uCBORDecoder.decode_uint
decode_negint
uCBORDecoder.decode_negint
D asubtype
return
int
bytes
decode_bytestring
uCBORDecoder.decode_bytestring
D asubtype
return
int
str
decode_string
uCBORDecoder.decode_string
D asubtype
return
int
uSequence[Any]
decode_array
uCBORDecoder.decode_array
D asubtype
return
int
uMapping[Any, Any]
decode_map
uCBORDecoder.decode_map
D asubtype
return
int
aAny
decode_semantic
uCBORDecoder.decode_semantic
decode_special
uCBORDecoder.decode_special
D areturn
date
decode_epoch_date
uCBORDecoder.decode_epoch_date
decode_date_string
uCBORDecoder.decode_date_string
D areturn
datetime
decode_datetime_string
uCBORDecoder.decode_datetime_string
decode_epoch_datetime
uCBORDecoder.decode_epoch_datetime
D areturn
int
uCBORDecoder.decode_positive_bignum
decode_negative_bignum
uCBORDecoder.decode_negative_bignum
D areturn
aDecimal
decode_fraction
uCBORDecoder.decode_fraction
decode_bigfloat
uCBORDecoder.decode_bigfloat
D areturn
ustr | bytes
decode_stringref
uCBORDecoder.decode_stringref
decode_shareable
uCBORDecoder.decode_shareable
D areturn
aAny
decode_sharedref
uCBORDecoder.decode_sharedref
D areturn
aFraction
decode_rational
uCBORDecoder.decode_rational
D areturn
ure.Pattern[str]
decode_regexp
uCBORDecoder.decode_regexp
D areturn
aMessage
decode_mime
uCBORDecoder.decode_mime
D areturn
aUUID
decode_uuid
uCBORDecoder.decode_uuid
decode_stringref_namespace
uCBORDecoder.decode_stringref_namespace
D areturn
uset[Any] | frozenset[Any]
decode_set
uCBORDecoder.decode_set
D areturn
uIPv4Address | IPv6Address | CBORTag
decode_ipaddress
uCBORDecoder.decode_ipaddress
D areturn
uIPv4Network | IPv6Network
decode_ipnetwork
uCBORDecoder.decode_ipnetwork
decode_self_describe_cbor
uCBORDecoder.decode_self_describe_cbor
D areturn
aCBORSimpleValue
decode_simple_value
uCBORDecoder.decode_simple_value
D areturn
float
decode_float16
uCBORDecoder.decode_float16
decode_float32
uCBORDecoder.decode_float32
decode_float64
uCBORDecoder.decode_float64
l udict[int, Callable[[CBORDecoder, int], Any]]
u<lambda>
l l l udict[int, Callable[[CBORDecoder], Any]]
l l l l#l$l%ldl  l  l  l  l   D wsatag_hook
object_hook
str_errors
return
ubytes | bytearray | memoryview
uCallable[[CBORDecoder, CBORTag], Any] | None
uCallable[[CBORDecoder, dict[Any, Any]], Any] | None
uLiteral['strict', 'error', 'replace']
aAny
loads
D afp
tag_hook
object_hook
str_errors
return
uIO[bytes]
uCallable[[CBORDecoder, CBORTag], Any] | None
uCallable[[CBORDecoder, dict[Any, Any]], Any] | None
uLiteral['strict', 'error', 'replace']
aAny
load
ucbor2\_decoder.py
T aself
u<module cbor2._decoder>
T a__class__
T aself
fp
tag_hook
object_hook
str_errors
T	aself
immutable
unshared
old_immutable
old_index
initial_byte
major_type
subtype
decoder
T aself
subtype
T aself
subtype
allow_indefinite
T aself
string
length
next_index
is_referenced
T aself
subtype
items
length
value
index
items_tuple
T aself
aDecimal
exp
sig
weT
self
subtype
buf
length
initial_byte
result
value
left
buffer
chunk_size
T aself
value
T aself
value
match
year
month
day
hour
minute
second
secfrac
offset_sign
offset_h
offset_m
microsecond
sign
hours
minutes
tz
T aself
value
tmp
exc
T aself
aDecimal
exp
sig
weatmp
T aself
buf
fp
old_fp
retval
T aself
ip_address
buf
T aself
ip_network
net_map
net
T aself
subtype
dictionary
length
key
w_afrozen_dict
T aself
aParser
value
exc
T aself
hexlify
value
T aself
aFraction
inputval
value
exc
T aself
value
exc
T aself
subtype
tagnum
semantic_decoder
tag
T aself
old_index
T aself
value
shared
T aself
subtype
weT aself
subtype
buf
length
initial_byte
result
value
exc
codec
left
chunk_size
final
T aself
index
value
T aself
old_namespace
value
T aself
aUUID
value
exc
T afp
tag_hook
object_hook
str_errors
T wsatag_hook
object_hook
str_errors
fp
T aself
amount
data
a__spec__
.cbor2._encoder
A
wraps
D aencoder
value
return
aCBOREncoder
aAny
aNone
wrapper
ushareable_encoder.<locals>.wrapper

Wrap the given encoder function to gracefully handle cyclic data
structures.
If value sharing is enabled, this marks the given value shared in the
datastream on the first call. If the value has already been passed to this
method, a reference marker is instead written to the data stream and the
wrapped function is not called.
If value sharing is disabled, only infinite recursion protection is done.
:rtype: Callable[[cbor2.CBOREncoder, Any], None]
encode_shared
func
ucontainer_encoder.<locals>.wrapper

The given encoder is a container with child values. Handle cyclic or
duplicate references to the value and strings within the value
efficiently.
Containers may contain cyclic data structures or may contain values
or themselves by referenced multiple times throughout the greater
encoded value and could thus be more efficiently encoded with shared
value references and string references where duplication occurs.
If value sharing is enabled, this marks the given value shared in the
datastream on the first call. If the value has already been passed to this
method, a reference marker is instead written to the data stream and the
wrapped function is not called.
If value sharing is disabled, only infinite recursion protection is done.
If string referencing is enabled and this is the first use of this
method in encoding a value, all repeated references to long strings
nd bytearrays will be replaced with references to the first
occurrence of those arrays.
If string referencing is disabled, all strings and bytearrays will
be encoded directly.
encode_container
fp
datetime_as_timestamp
date_as_datetime
timezone
value_sharing
string_referencing
string_namespacing
default
a_canonical
a_shared_containers
a_string_references
default_encoders
copy
a_encoders
update
canonical_encoders

:param fp:
the file to write to (any file-like object opened for writing in binary
mode)
:param datetime_as_timestamp:
set to ``True`` to serialize datetimes as UNIX timestamps (this makes
datetimes more concise on the wire, but loses the timezone information)
:param timezone:
the default timezone to use for serializing naive datetimes; if this is not
specified naive datetimes will throw a :exc:`ValueError` when encoding is
ttempted
:param value_sharing:
set to ``True`` to allow more efficient serializing of repeated values and,
more importantly, cyclic data structures, at the cost of extra line overhead
:param default:
a callable that is called by the encoder with two arguments (the encoder
instance and the value being encoded) when no suitable encoder has been
found, and should use the methods on the encoder to encode any objects it
wants to add to the data stream
:param canonical:
when ``True``, use "canonical" CBOR representation; this typically involves
sorting maps, sets, etc. into a pre-determined order ensuring that
serializations are comparable without decoding
:param date_as_datetime:
set to ``True`` to serialize date objects as datetimes (CBOR tag 0), which
was the default behavior in previous releases (cbor2 <= 4.1.2).
:param string_referencing:
set to ``True`` to allow more efficient serializing of repeated string
values
items
T ETypeError
EValueError
aCBOREncodeValueError
uinvalid deferred encoder type

u (must be a 2-tuple of module name and type name, e.g. ('collections', 'defaultdict'))
modules
get
self
a_fp
callable
write
ufp.write is not callable
ufp object has no write method
a_fp_write
a_timezone
tzinfo
utimezone must be None or a tzinfo instance
a_default
udefault must be None or a callable

Disable value sharing in the encoder for the duration of the context
block.
disable_value_sharing
uCBOREncoder.disable_value_sharing

Disable tracking of string references for the duration of the
context block.
disable_string_referencing
uCBOREncoder.disable_string_referencing

Disable generation of new string namespaces for the duration of the
context block.
disable_string_namespacing
uCBOREncoder.disable_string_namespacing

Write bytes to the data stream.
:param bytes data:
the bytes to write
a_find_encoder
aCBOREncodeTypeError
ucannot serialize type
a__name__

Encode the given object using CBOR.
:param obj:
the object to encode
aBytesIO
a__enter__
a__exit__
encode
getvalue
T nnnu
Encode the given object to a byte buffer and return its value as bytes.
This method was intended to be used from the ``default`` hook when an
object needs to be encoded separately from the rest but while still
taking advantage of the shared value registry.
encode_length
T l l  T l l T l l aencode_int
cast
index
T ucyclic data structure detected but value sharing is disabled
encode_semantic
aCBORTag
l g

Try to encode the string or bytestring as a reference.
Returns True if a reference was generated, False if the string
must still be emitted.
l l astruct
pack
u>B
l  u>BB
l   u>BH
u>BL
l u>BQ
l g
G
l l ato_bytes
bit_length
l l abig
a_stringref
encode_bytestring
T uutf-8
l aencode_to_bytes

Takes a key and calculates the length of its optimal byte
representation, along with the representation itself. This is used as
the sorting key in CBOR's canonical representations.
sorted
uReorder keys according to Canonical CBOR specification
encode_sortable_key
u<genexpr>
uCBOREncoder.encode_canonical_map.<locals>.<genexpr>
tag
l avalue
replace
T atzinfo
unaive datetime
u encountered and no default timezone has been set
calendar
T atimegm
timegm
microsecond
utctimetuple
l  =aisoformat
T u+00:00
wZadatetime
combine
time
encode_datetime
toordinal
l  +ldl  ais_nan
T b  ~
is_infinite
b  |
b
as_tuple
digits
sig
l
sign
exponent
l anumerator
denominator
l#apattern
l$aas_string
l%abytes
l  uCBOREncoder.encode_canonical_set.<locals>.<genexpr>
l  apacked
l  anetwork_address
prefixlen
l  l  amath
isnan
isinf
u>Bd
l  T T u>Bf
l  T u>Be
l  aunpack
encoded
d d T d T d aCBOREncoder
T adatetime_as_timestamp
timezone
value_sharing
default
canonical
date_as_datetime
string_referencing

Serialize an object to a bytestring.
:param obj:
the object to serialize
:param datetime_as_timestamp:
set to ``True`` to serialize datetimes as UNIX timestamps (this makes datetimes
more concise on the wire, but loses the timezone information)
:param timezone:
the default timezone to use for serializing naive datetimes; if this is not
specified naive datetimes will throw a :exc:`ValueError` when encoding is
ttempted
:param value_sharing:
set to ``True`` to allow more efficient serializing of repeated values
nd, more importantly, cyclic data structures, at the cost of extra
line overhead
:param default:
a callable that is called by the encoder with two arguments (the encoder
instance and the value being encoded) when no suitable encoder has been found,
nd should use the methods on the encoder to encode any objects it wants to add
to the data stream
:param canonical:
when ``True``, use "canonical" CBOR representation; this typically involves
sorting maps, sets, etc. into a pre-determined order ensuring that
serializations are comparable without decoding
:param date_as_datetime:
set to ``True`` to serialize date objects as datetimes (CBOR tag 0), which was
the default behavior in previous releases (cbor2 <= 4.1.2).
:param string_referencing:
set to ``True`` to allow more efficient serializing of repeated string values
:return: the serialized output

Serialize an object to a file.
:param obj:
the object to serialize
:param fp:
the file to write to (any file-like object opened for writing in binary mode)
:param datetime_as_timestamp:
set to ``True`` to serialize datetimes as UNIX timestamps (this makes datetimes
more concise on the wire, but loses the timezone information)
:param timezone:
the default timezone to use for serializing naive datetimes; if this is not
specified naive datetimes will throw a :exc:`ValueError` when encoding is
ttempted
:param value_sharing:
set to ``True`` to allow more efficient serializing of repeated values
nd, more importantly, cyclic data structures, at the cost of extra
line overhead
:param default:
a callable that is called by the encoder with two arguments (the encoder
instance and the value being encoded) when no suitable encoder has been found,
nd should use the methods on the encoder to encode any objects it wants to add
to the data stream
:param canonical:
when ``True``, use "canonical" CBOR representation; this typically involves
sorting maps, sets, etc. into a pre-determined order ensuring that
serializations are comparable without decoding
:param date_as_datetime:
set to ``True`` to serialize date objects as datetimes (CBOR tag 0), which was
the default behavior in previous releases (cbor2 <= 4.1.2).
:param string_referencing:
set to ``True`` to allow more efficient serializing of repeated string values
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
re
sys
collections
T aOrderedDict
defaultdict
aOrderedDict
defaultdict
ucollections.abc
T aCallable
aGenerator
aMapping
aSequence
aSet
aCallable
aGenerator
aMapping
aSequence
aSet
contextlib
T acontextmanager
contextmanager
T adate
datetime
time
tzinfo
date
aIO
aTYPE_CHECKING
aAny
a_types
T aCBOREncodeTypeError
aCBOREncodeValueError
aCBORSimpleValue
aCBORTag
aFrozenDict
aUndefinedType
undefined
aCBORSimpleValue
aFrozenDict
aUndefinedType
undefined
D afunc
return
uCallable[[CBOREncoder, Any], None]
uCallable[[CBOREncoder, Any], None]
shareable_encoder
D afunc
return
uCallable[[CBOREncoder, Any], Any]
uCallable[[CBOREncoder, Any], Any]
container_encoder
