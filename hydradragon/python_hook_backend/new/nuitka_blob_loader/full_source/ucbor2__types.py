# Reconstructed from integrated Nuitka blob
# Module: ucbor2._types

uBase class for errors that occur during CBOR encoding or decoding.
a__qualname__
a__orig_bases__
aCBOREncodeError
uRaised for exceptions occurring during CBOR encoding.
aCBOREncodeTypeError
uRaised when attempting to encode a type that cannot be serialized.
aCBOREncodeValueError
uRaised when the CBOR encoder encounters an invalid value.
aCBORDecodeError
uRaised for exceptions occurring during CBOR decoding.
aCBORDecodeValueError
uRaised when the CBOR stream being decoded contains an invalid value.
aCBORDecodeEOF
uRaised when decoding unexpectedly reaches EOF.

Represents a CBOR semantic tag.
:param int tag: tag number
:param value: encapsulated value (any object)
T atag
value
a__slots__
D atag
value
return
ustr | int
aAny
aNone
a__init__
uCBORTag.__init__
D aother
return
object
bool
a__eq__
uCBORTag.__eq__
a__le__
uCBORTag.__le__
D areturn
str
a__repr__
uCBORTag.__repr__
D areturn
int
a__hash__
uCBORTag.__hash__

Represents a CBOR "simple value".
:param int value: the value (0-255)
a__annotations__
int
uCBORSimpleValue.__hash__
D avalue
return
int
aCBORSimpleValue
uCBORSimpleValue.__new__
uCBORSimpleValue.__eq__
a__ne__
uCBORSimpleValue.__ne__
a__lt__
uCBORSimpleValue.__lt__
uCBORSimpleValue.__le__
a__ge__
uCBORSimpleValue.__ge__
a__gt__
uCBORSimpleValue.__gt__
aFrozenDict

A hashable, immutable mapping type.
The arguments to ``FrozenDict`` are processed just like those to ``dict``.
D aargs
return
uMapping[KT, VT_co] | Iterable[tuple[KT, VT_co]]
aNone
uFrozenDict.__init__
D areturn
uIterator[KT]
a__iter__
uFrozenDict.__iter__
a__len__
uFrozenDict.__len__
D akey
return
aKT
aVT_co
uFrozenDict.__getitem__
uFrozenDict.__repr__
uFrozenDict.__hash__
aUndefinedType
D acls
return
utype[UndefinedType]
aUndefinedType
uUndefinedType.__new__
uUndefinedType.__repr__
D areturn
bool
a__bool__
uUndefinedType.__bool__
aBreakMarkerType
D acls
return
utype[BreakMarkerType]
aBreakMarkerType
uBreakMarkerType.__new__
uBreakMarkerType.__repr__
uBreakMarkerType.__bool__
ucbor2\_types.py
u<module cbor2._types>
T a__class__
T aself
T aself
other
T aself
key
T aself
self_id
running_hashes
T aself
tag
value
T aself
args
T acls
a__class__
T acls
value
a__class__
a__spec__
.cbor2
S
collections
T aOrderedDict
aOrderedDict
a_cbor2
a_encoder
T acanonical_encoders
default_encoders
canonical_encoders
default_encoders
a_types
T aCBORSimpleValue
aCBORTag
undefined
aCBORSimpleValue
aCBORTag
undefined
items
type
getattr
aCBOREncoder
a__name__
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_cbor2
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
a__annotations__
aAny
a_decoder
T aCBORDecoder
aCBORDecoder
T aload
load
T aloads
loads
T aCBOREncoder
T adump
dump
T adumps
dumps
T ashareable_encoder
shareable_encoder
T aCBORDecodeEOF
aCBORDecodeEOF
T aCBORDecodeError
aCBORDecodeError
T aCBORDecodeValueError
aCBORDecodeValueError
T aCBOREncodeError
aCBOREncodeError
T aCBOREncodeTypeError
aCBOREncodeTypeError
T aCBOREncodeValueError
aCBOREncodeValueError
T aCBORError
aCBORError
T aCBORSimpleValue
T aCBORTag
T aFrozenDict
aFrozenDict
T aundefined
T w*aImportError
str
key
value
list
