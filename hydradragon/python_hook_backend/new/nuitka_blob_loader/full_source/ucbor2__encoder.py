# Reconstructed from integrated Nuitka blob
# Module: ucbor2._encoder


The CBOREncoder class implements a fully featured `CBOR`_ encoder with
several extensions for handling shared references, big integers, rational
numbers and so on. Typically the class is not used directly, but the
:func:`dump` and :func:`dumps` functions are called to indirectly construct
nd use the class.
When the class is constructed manually, the main entry points are
:meth:`encode` and :meth:`encode_to_bytes`.
.. _CBOR: https://cbor.io/
a__qualname__
Tadatetime_as_timestamp
date_as_datetime
a_timezone
a_default
value_sharing
a_fp
a_fp_write
a_shared_containers
a_encoders
a_canonical
string_referencing
string_namespacing
a_string_references
a__slots__
uIO[bytes]
uCallable[[Buffer], int]
T FnFnFppD afp
datetime_as_timestamp
timezone
value_sharing
default
canonical
date_as_datetime
string_referencing
uIO[bytes]
bool
utzinfo | None
bool
uCallable[[CBOREncoder, Any], Any] | None
bool
ppa__init__
uCBOREncoder.__init__
D aobj_type
return
type
uCallable[[CBOREncoder, Any], None] | None
uCBOREncoder._find_encoder
D areturn
uIO[bytes]
uCBOREncoder.fp
setter
D avalue
return
uIO[bytes]
aNone
D areturn
utzinfo | None
uCBOREncoder.timezone
D avalue
return
utzinfo | None
aNone
D areturn
uCallable[[CBOREncoder, Any], Any] | None
uCBOREncoder.default
D avalue
return
uCallable[[CBOREncoder, Any], Any] | None
aNone
D areturn
bool
canonical
uCBOREncoder.canonical
D areturn
uGenerator[None, None, None]
D adata
return
bytes
aNone
uCBOREncoder.write
D aobj
return
aAny
aNone
uCBOREncoder.encode
D aobj
return
aAny
bytes
uCBOREncoder.encode_to_bytes
D aencoder
value
return
uCallable[[CBOREncoder, Any], Any]
aAny
aNone
uCBOREncoder.encode_container
uCBOREncoder.encode_shared
D avalue
return
ustr | bytes
bool
uCBOREncoder._stringref
D amajor_tag
length
return
int
paNone
uCBOREncoder.encode_length
D avalue
return
int
aNone
uCBOREncoder.encode_int
D avalue
return
bytes
aNone
uCBOREncoder.encode_bytestring
D avalue
return
bytearray
aNone
encode_bytearray
uCBOREncoder.encode_bytearray
D avalue
return
str
aNone
encode_string
uCBOREncoder.encode_string
D avalue
return
uSequence[Any]
aNone
encode_array
uCBOREncoder.encode_array
D avalue
return
uMapping[Any, Any]
aNone
encode_map
uCBOREncoder.encode_map
D avalue
return
aAny
utuple[int, bytes]
uCBOREncoder.encode_sortable_key
encode_canonical_map
uCBOREncoder.encode_canonical_map
D avalue
return
aCBORTag
aNone
uCBOREncoder.encode_semantic
D avalue
return
datetime
aNone
uCBOREncoder.encode_datetime
D avalue
return
date
aNone
encode_date
uCBOREncoder.encode_date
D avalue
return
aDecimal
aNone
encode_decimal
uCBOREncoder.encode_decimal
D avalue
return
ustr | bytes
aNone
encode_stringref
uCBOREncoder.encode_stringref
D avalue
return
aFraction
aNone
encode_rational
uCBOREncoder.encode_rational
D avalue
return
ure.Pattern[str]
aNone
encode_regexp
uCBOREncoder.encode_regexp
D avalue
return
aMessage
aNone
encode_mime
uCBOREncoder.encode_mime
D avalue
return
aUUID
aNone
encode_uuid
uCBOREncoder.encode_uuid
D avalue
return
aAny
aNone
encode_stringref_namespace
uCBOREncoder.encode_stringref_namespace
D avalue
return
uSet[Any]
aNone
encode_set
uCBOREncoder.encode_set
encode_canonical_set
uCBOREncoder.encode_canonical_set
D avalue
return
uIPv4Address | IPv6Address
aNone
encode_ipaddress
uCBOREncoder.encode_ipaddress
D avalue
return
uIPv4Network | IPv6Network
aNone
encode_ipnetwork
uCBOREncoder.encode_ipnetwork
D avalue
return
aCBORSimpleValue
aNone
encode_simple_value
uCBOREncoder.encode_simple_value
D avalue
return
float
aNone
encode_float
uCBOREncoder.encode_float
encode_minimal_float
uCBOREncoder.encode_minimal_float
D avalue
return
bool
aNone
encode_boolean
uCBOREncoder.encode_boolean
D avalue
return
aNone
paencode_none
uCBOREncoder.encode_none
D avalue
return
aUndefinedType
aNone
encode_undefined
uCBOREncoder.encode_undefined
T adecimal
aDecimal
aPattern
T afractions
aFraction
T uemail.message
aMessage
T auuid
aUUID
T aipaddress
aIPv4Address
T aipaddress
aIPv6Address
T aipaddress
aIPv4Network
T aipaddress
aIPv6Network
udict[type | tuple[str, str], Callable[[CBOREncoder, Any], None]]
D	aobj
datetime_as_timestamp
timezone
value_sharing
default
canonical
date_as_datetime
string_referencing
return
object
bool
utzinfo | None
bool
uCallable[[CBOREncoder, Any], None] | None
bool
ppabytes
dumps
D
obj
fp
datetime_as_timestamp
timezone
value_sharing
default
canonical
date_as_datetime
string_referencing
return
object
uIO[bytes]
bool
utzinfo | None
bool
uCallable[[CBOREncoder, Any], None] | None
bool
ppaNone
dump
ucbor2\_encoder.py
T a.0
key
value
self
T a.0
key
self
u<module cbor2._encoder>
T a__class__
T	aself
fp
datetime_as_timestamp
timezone
value_sharing
default
canonical
date_as_datetime
string_referencing
T aself
obj_type
type_or_tuple
enc
modname
typename
imported_type
type_
T aself
value
index
length
next_index
is_referenced
T aself
T afunc
wrapper
T aself
value
T aself
old_string_namespacing
T aself
old_string_referencing
T aself
old_value_sharing
T	aobj
fp
datetime_as_timestamp
timezone
value_sharing
default
canonical
date_as_datetime
string_referencing
T	aobj
datetime_as_timestamp
timezone
value_sharing
default
canonical
date_as_datetime
string_referencing
fp
T aself
obj
obj_type
encoder
T aself
value
item
T aself
value
keyed_keys
sortkey
realkey
T aself
value
values
T aself
encoder
value
T aself
value
days_since_epoch
datestring
T aself
value
timestamp
timegm
datestring
T aself
value
dt
sig
digit
T aself
value
major_type
payload
T aself
major_tag
length
T aself
value
key
val
T aself
value
encoded
format
tag
new_encoded
T aself
value
old_string_referencing
old_string_references
T aself
encoder
value
value_id
index
T aself
value
encoded
T aself
obj
fp
old_fp
T aencoder
value
func
T afunc
T aself
data
a__spec__
.cbor2._types
;l
g
l uCBORTag tags must be positive integers less than 2**64
tag
value
aCBORTag
uCBORTag(

u,
w)athread_locals
running_hashes
uThis CBORTag is not hashable because it contains a reference to itself
add
remove
l  l l usimple value out of range (0..23, 32..255)
a__class__
a__new__
aCBORSimpleValue
a_d
a_hash
a__name__
w(avalues
undefined
break_marker
a__doc__
a__file__
origin
has_location
a__cached__
annotations
threading
collections
T anamedtuple
namedtuple
ucollections.abc
T aIterable
aIterator
aIterable
aIterator
total_ordering
reprlib
T arecursive_repr
recursive_repr
aAny
aMapping
aTypeVar
T aKT
aKT
T aVT_co
tT acovariant
aVT_co
local
T EException
a__prepare__
aCBORError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
