# Reconstructed from integrated Nuitka blob
# Module: ueth_abi.encoding


Base class for all encoder classes.  Subclass this if you want to define a
custom encoder class.  Subclasses must also implement
:any:`BaseCoder.from_type_str`.
a__qualname__
abstractmethod
value
return
bytes

Encodes the given value as a sequence of bytes.  Should raise
:any:`exceptions.EncodingError` if ``value`` cannot be encoded.
uBaseEncoder.encode

Checks whether or not the given value can be encoded by this encoder.
If the given value cannot be encoded, must raise
:any:`exceptions.EncodingError`.
uBaseEncoder.validate_value
classmethod
exc
aException
msg
str
uBaseEncoder.invalidate_value
a__call__
uBaseEncoder.__call__
a__orig_bases__
aTupleEncoder
uTupleEncoder.__init__
uTupleEncoder.validate
uTupleEncoder.validate_value
uTupleEncoder.encode
from_type_str
uTupleEncoder.from_type_str
aFixedSizeEncoder
uFixedSizeEncoder.validate
uFixedSizeEncoder.validate_value
uFixedSizeEncoder.encode
aFixed32ByteSizeEncoder
aBooleanEncoder
uBooleanEncoder.validate_value
uBooleanEncoder.encode_fn
T abool
uBooleanEncoder.from_type_str
aPackedBooleanEncoder
aNumberEncoder
uNumberEncoder.validate
uNumberEncoder.validate_value
aUnsignedIntegerEncoder
staticmethod
T auint
uUnsignedIntegerEncoder.from_type_str
T l  l aPackedUnsignedIntegerEncoder
uPackedUnsignedIntegerEncoder.from_type_str
aSignedIntegerEncoder
uSignedIntegerEncoder.encode_fn
uSignedIntegerEncoder.encode
T aint
uSignedIntegerEncoder.from_type_str
aPackedSignedIntegerEncoder
uPackedSignedIntegerEncoder.from_type_str
aBaseFixedEncoder
uBaseFixedEncoder.type_check_fn
uBaseFixedEncoder.illegal_value_fn
uBaseFixedEncoder.validate_value
uBaseFixedEncoder.validate
aUnsignedFixedEncoder
uUnsignedFixedEncoder.bounds_fn
uUnsignedFixedEncoder.encode_fn
T aufixed
uUnsignedFixedEncoder.from_type_str
aPackedUnsignedFixedEncoder
uPackedUnsignedFixedEncoder.from_type_str
aSignedFixedEncoder
uSignedFixedEncoder.bounds_fn
uSignedFixedEncoder.encode_fn
uSignedFixedEncoder.encode
T afixed
uSignedFixedEncoder.from_type_str
aPackedSignedFixedEncoder
uPackedSignedFixedEncoder.from_type_str
aAddressEncoder
uAddressEncoder.validate_value
uAddressEncoder.validate
T aaddress
uAddressEncoder.from_type_str
aPackedAddressEncoder
l aBytesEncoder
uBytesEncoder.validate_value
uBytesEncoder.encode_fn
T abytes
uBytesEncoder.from_type_str
aPackedBytesEncoder
uPackedBytesEncoder.from_type_str
aByteStringEncoder
uByteStringEncoder.validate_value
uByteStringEncoder.encode
uByteStringEncoder.from_type_str
aPackedByteStringEncoder
uPackedByteStringEncoder.encode
aTextStringEncoder
uTextStringEncoder.validate_value
uTextStringEncoder.encode
T astring
uTextStringEncoder.from_type_str
aPackedTextStringEncoder
uPackedTextStringEncoder.encode
aBaseArrayEncoder
uBaseArrayEncoder.validate
uBaseArrayEncoder.validate_value
uBaseArrayEncoder.encode_elements
T tT awith_arrlist
uBaseArrayEncoder.from_type_str
aPackedArrayEncoder
uPackedArrayEncoder.validate_value
uPackedArrayEncoder.encode
uPackedArrayEncoder.from_type_str
uSizedArrayEncoder.__init__
uSizedArrayEncoder.validate
uSizedArrayEncoder.validate_value
uSizedArrayEncoder.encode
uDynamicArrayEncoder.encode
ueth_abi\encoding.py
T a.0
wiaitem_encoder
T a.0
offset
head_length
T a.0
weT a__class__
T a.0
chunk
offset
head_length
T a.0
item
T a.0
wcaregistry
u<module eth_abi.encoding>
T aself
value
T aself
kwargs
a__class__
T aself
value_bit_size
T acls
value
value_length
encoded_size
padded_value
T aself
value
encoded_size
encoded_elements
encoded_value
T aself
value
base_encoded_value
padded_encoded_value
T aself
value
encoded_elements
T acls
value
T acls
value
value_as_bytes
value_length
encoded_size
padded_value
T
self
values
raw_head_chunks
tail_chunks
value
encoder
head_length
tail_offsets
head_chunks
encoded_value
T aself
value
item_encoder
tail_chunks
items_are_dynamic
head_length
tail_offsets
head_chunks
T avalue
T aself
value
scaled_value
integer_value
unsigned_integer_value
T aself
value
scaled_value
integer_value
T acls
abi_type
registry
T acls
abi_type
registry
item_encoder
array_spec
T acls
abi_type
registry
value_bit_size
frac_places
T acls
abi_type
registry
encoders
T acls
value
exc
msg
T aself
a__class__
T aself
value
item
T aself
value
residue
a__class__
T aself
value
byte_size
T aself
value
illegal_value
lower_bound
upper_bound
T aself
value
a__class__
T aself
value
item
encoder
a__spec__
.eth_abi.exceptions
=
uParse error at '
text
pos
l u
u' (column
column
u) in type string '
w'a__doc__
a__file__
origin
has_location
a__cached__
parsimonious
T EException
a__prepare__
aEncodingError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
