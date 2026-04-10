# Reconstructed from integrated Nuitka blob
# Module: ueth_abi.decoding


A byte stream which can track a series of contextual frames in a stack. This
data structure is necessary to perform nested decodings using the
:py:class:``HeadTailDecoder`` since offsets present in head sections are
relative only to a particular encoded object.  These offsets can only be
used to locate a position in a decoding stream if they are paired with a
contextual offset that establishes the position of the object in which they
re found.
For example, consider the encoding of a value for the following type::
type: (int,(int,int[]))
value: (1,(2,[3,3]))
There are two tuples in this type: one inner and one outer.  The inner tuple
type contains a dynamic type ``int[]`` and, therefore, is itself dynamic.
This means that its value encoding will be placed in the tail section of the
outer tuple's encoding.  Furthermore, the inner tuple's encoding will,
itself, contain a tail section with the encoding for ``[3,3]``.  All
together, the encoded value of ``(1,(2,[3,3]))`` would look like this (the
data values are normally 32 bytes wide but have been truncated to remove the
redundant zeros at the beginnings of their encodings)::
offset data
--------------------------
^              0 0x01
|             32 0x40 <-- Offset of object A in global frame (64)
-----|--------------------
Global frame ^     64 0x02 <-- Beginning of object A (64 w/offset 0 = 64)
|       |     96 0x40 <-- Offset of object B in frame of object A (64)
-----|-Object A's frame---
|       |    128 0x02 <-- Beginning of object B (64 w/offset 64 = 128)
|       |    160 0x03
v       v    192 0x03
--------------------------
Note that the offset of object B is encoded as 64 which only specifies the
beginning of its encoded value relative to the beginning of object A's
encoding.  Globally, object B is located at offset 128.  In order to make
sense out of object B's offset, it needs to be positioned in the context of
its enclosing object's frame (object A).
a__qualname__
uContextFramesBytesIO.__init__
pos
int
args
kwargs
return
uContextFramesBytesIO.seek_in_frame
offset
uContextFramesBytesIO.push_frame
uContextFramesBytesIO.pop_frame
a__orig_bases__
metaclass
aABCMeta
aBaseDecoder

Base class for all decoder classes.  Subclass this if you want to define a
custom decoder class.  Subclasses must also implement
:any:`BaseCoder.from_type_str`.
abstractmethod

Decodes the given stream of bytes into a python value.  Should raise
:any:`exceptions.DecodingError` if a python value cannot be decoded
from the given byte stream.
uBaseDecoder.decode
a__call__
uBaseDecoder.__call__

Decoder for a dynamic element of a dynamic container (a dynamic array, or a sized
rray or tuple that contains dynamic elements). A dynamic element consists of a
pointer, aka offset, which is located in the head section of the encoded container,
nd the actual value, which is located in the tail section of the encoding.
uHeadTailDecoder.validate
uHeadTailDecoder.decode
aTupleDecoder
uTupleDecoder.__init__
uTupleDecoder.validate
uTupleDecoder.validate_pointers
from_type_str
uTupleDecoder.from_type_str
aSingleDecoder
uSingleDecoder.validate
uSingleDecoder.validate_padding_bytes
uSingleDecoder.decode
uSingleDecoder.read_data_from_stream
uSingleDecoder.split_data_and_padding
aBaseArrayDecoder
uBaseArrayDecoder.__init__
uBaseArrayDecoder.validate
T tT awith_arrlist
uBaseArrayDecoder.from_type_str
uBaseArrayDecoder.validate_pointers
uSizedArrayDecoder.__init__
aFixedByteSizeDecoder
uFixedByteSizeDecoder.validate
uFixedByteSizeDecoder.read_data_from_stream
uFixedByteSizeDecoder.split_data_and_padding
uFixedByteSizeDecoder.validate_padding_bytes
uFixedByteSizeDecoder._get_value_byte_size
aFixed32ByteSizeDecoder
aBooleanDecoder
staticmethod
uBooleanDecoder.decoder_fn
T abool
uBooleanDecoder.from_type_str
aAddressDecoder
l  T aaddress
uAddressDecoder.from_type_str
aUnsignedIntegerDecoder
T auint
uUnsignedIntegerDecoder.from_type_str
T l  aSignedIntegerDecoder
uSignedIntegerDecoder.decoder_fn
uSignedIntegerDecoder.validate_padding_bytes
T aint
uSignedIntegerDecoder.from_type_str
aBytesDecoder
uBytesDecoder.decoder_fn
T abytes
uBytesDecoder.from_type_str
aBaseFixedDecoder
uBaseFixedDecoder.validate
aUnsignedFixedDecoder
uUnsignedFixedDecoder.decoder_fn
T aufixed
uUnsignedFixedDecoder.from_type_str
aSignedFixedDecoder
uSignedFixedDecoder.decoder_fn
uSignedFixedDecoder.validate_padding_bytes
T afixed
uSignedFixedDecoder.from_type_str
aByteStringDecoder
uByteStringDecoder.decoder_fn
uByteStringDecoder.read_data_from_stream
uByteStringDecoder.validate_padding_bytes
uByteStringDecoder.from_type_str
aStringDecoder
T astrict
uStringDecoder.__init__
T astring
uStringDecoder.from_type_str
uStringDecoder.decode
uStringDecoder.decoder_fn
ueth_abi\decoding.py
T a.0
wdT a__class__
T a.0
wcaregistry
T a.0
decoder
u<module eth_abi.decoding>
T aself
stream
T aself
kwargs
a__class__
T aself
args
kwargs
a__class__
T aself
handle_string_errors
a__class__
T aself
value_byte_size
T aself
stream
array_size
w_T aself
stream
start_pos
value
T aself
stream
raw_data
data
padding_bytes
value
T aself
stream
w_T aself
stream
decoder
T adata
T aself
data
value
signed_value
decimal_value
T aself
data
value
T adata
handle_string_errors
T aself
data
value
decimal_value
T acls
abi_type
registry
T acls
abi_type
registry
item_decoder
array_spec
T acls
abi_type
registry
value_bit_size
frac_places
T acls
abi_type
registry
decoders
T aself
offset
return_pos
T aself
offset
T aself
stream
data_length
padded_length
data
padding_bytes
T aself
stream
data
T aself
pos
args
kwargs
T aself
raw_data
value_byte_size
padding_size
padding_bytes
data
T aself
raw_data
T aself
a__class__
T aself
value
padding_bytes
T aself
value
padding_bytes
value_byte_size
padding_size
T aself
value
padding_bytes
value_byte_size
padding_size
expected_padding_bytes
T	aself
stream
array_size
current_location
end_of_offsets
total_stream_length
w_aoffset
indicated_idx
T	aself
stream
current_location
len_of_head
end_of_offsets
total_stream_length
decoder
offset
indicated_idx
a__spec__
.eth_abi.encoding
V
B uValue `
abbr

u` of type
u cannot be encoded by
a__name__
u:

Throws a standard exception for when a value is not encodable by an
encoder.
encode
a__class__
a__init__
encoders
is_dynamic
u<genexpr>
uTupleEncoder.__init__.<locals>.<genexpr>
validate
u`encoders` may not be none
is_list_like
invalidate_value
D amsg
umust be list-like object such as array or tuple
aValueOutOfBounds
uvalue has
u items when
u were expected
T aexc
msg
validate_value
raw_head_chunks
tail_chunks
c
T l
accumulate
len
:nq nl uTupleEncoder.encode.<locals>.<genexpr>
encode_uint_256
head_length
components
T aencoders
registry
get_encoder
to_type_str
uTupleEncoder.from_type_str.<locals>.<genexpr>
value_bit_size
u`value_bit_size` may not be none
data_byte_size
u`data_byte_size` may not be none
encode_fn
u`encode_fn` may not be none
is_big_endian
u`is_big_endian` may not be none
l uInvalid value bit size:
u. Must be a multiple of 8
uValue byte size exceeds data size
uMust be implemented by subclasses
u`encode_fn` is None
zpad
zpad_right
is_boolean
d d
aInvariant
bounds_fn
u`bounds_fn` cannot be null
type_check_fn
u`type_check_fn` cannot be null
u`type_check_fn` is None
illegal_value_fn
aIllegalValue
T aexc
uCannot be encoded in
u bits. Must be bounded between [
u,
u].
sub
T avalue_bit_size
T avalue_bit_size
data_byte_size
int_to_big_endian
l afpad
is_number
decimal
aDecimal
is_nan
is_infinite
localcontext
abi_decimal_context
a__enter__
a__exit__
aTEN
frac_places
T nnnaresidue
uresidue
u outside allowed fractional precision of
umust specify `frac_places`
lPu`frac_places` must be in range (0, 80]
compute_unsigned_fixed_bounds
integer_value
T avalue_bit_size
frac_places
T avalue_bit_size
data_byte_size
frac_places
compute_signed_fixed_bounds
is_address
l  uAddresses must be 160 bits in length
is_bytes
uexceeds total byte size for bytes
u encoding
ceil32
is_text
codecs
utf8
item_encoder
u`item_encoder` may not be none
D amsg
umust be list-like such as array or tuple
self
u`item_encoder` is None
uBaseArrayEncoder.encode_elements.<locals>.<genexpr>
item_type
arrlist
aSizedArrayEncoder
T aarray_size
item_encoder
aDynamicArrayEncoder
T aitem_encoder
array_size
encode_elements
u`array_size` may not be none
a__doc__
a__file__
origin
has_location
a__cached__
abc
itertools
T aaccumulate
aAny
aOptional
aType
eth_utils
T	aint_to_big_endian
is_address
is_boolean
is_bytes
is_integer
is_list_like
is_number
is_text
to_canonical_address
is_integer
to_canonical_address
ueth_abi.base
T aBaseCoder
parse_tuple_type_str
parse_type_str
aBaseCoder
parse_tuple_type_str
parse_type_str
ueth_abi.exceptions
T aEncodingTypeError
aIllegalValue
aValueOutOfBounds
aEncodingTypeError
ueth_abi.utils.numeric
T aTEN
abi_decimal_context
ceil32
compute_signed_fixed_bounds
compute_signed_integer_bounds
compute_unsigned_fixed_bounds
compute_unsigned_integer_bounds
compute_signed_integer_bounds
compute_unsigned_integer_bounds
ueth_abi.utils.padding
T afpad
zpad
zpad_right
ueth_abi.utils.string
T aabbr
metaclass
aABCMeta
a__prepare__
aBaseEncoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
