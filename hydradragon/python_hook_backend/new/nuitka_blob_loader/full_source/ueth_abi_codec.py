# Reconstructed from integrated Nuitka blob
# Module: ueth_abi.codec


Base class for porcelain coding APIs.  These are classes which wrap
instances of :class:`~eth_abi.registry.ABIRegistry` to provide last-mile
coding functionality.
aBaseABICoder
a__qualname__
registry
a__init__
uBaseABICoder.__init__
a__prepare__
aABIEncoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Wraps a registry to provide last-mile encoding functionality.
return
bytes
encode
uABIEncoder.encode
typ
arg
bool
is_encodable
uABIEncoder.is_encodable
uABIEncoder.is_encodable_type
a__orig_bases__
aABIDecoder

Wraps a registry to provide last-mile decoding functionality.
T tadecode
uABIDecoder.decode
aABICodec
ueth_abi\codec.py
u<module eth_abi.codec>
T a__class__
T aself
registry
T aself
types
data
strict
decoders
decoder
stream
T aself
types
args
encoders
encoder
T aself
typ
arg
encoder
T aself
typ

a__spec__
.eth_abi
p
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_eth_abi
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
version
a__version
ueth_abi.abi
T adecode
encode
is_encodable
is_encodable_type
decode
encode
is_encodable
is_encodable_type
u5.2.0
a__version__
ueth_abi\__init__.py
u<module eth_abi>

a__spec__
.eth_abi.decoding
$
a__class__
a__init__
a_frames
a_total_offset
seek

Seeks relative to the total offset of the current contextual frames.
append
tell
seek_in_frame
T l

Pushes a new contextual frame onto the stack with the given offset and a
return position at the current cursor position then seeks to the new
total offset.
pop
uno frames to pop

Pops the current contextual frame off of the stack and returns the
cursor to the frame's return position.
decode
validate
tail_decoder
uNo `tail_decoder` set
decode_uint_256
push_frame
u`tail_decoder` is None
pop_frame
decoders
is_dynamic
aHeadTailDecoder
T atail_decoder
u<genexpr>
uTupleDecoder.__init__.<locals>.<genexpr>
uNo `decoders` set
l agetbuffer
stream
current_location
aInvalidPointer
uInvalid pointer in tuple at location

u in payload

Verify that all pointers point to a valid location in the stream.
array_size
uTupleDecoder.validate_pointers.<locals>.<genexpr>
self
validate_pointers
uTupleDecoder.decode
components
T adecoders
registry
get_decoder
to_type_str
uTupleDecoder.from_type_str.<locals>.<genexpr>
decoder_fn
uNo `decoder_fn` set
uMust be implemented by subclasses
read_data_from_stream
split_data_and_padding
u`decoder_fn` is None
validate_padding_bytes
c
item_decoder
uNo `item_decoder` set
item_type
arrlist
aSizedArrayDecoder
T aarray_size
item_decoder
aDynamicArrayDecoder
T aitem_decoder
uInvalid pointer in array at location
u`item_decoder` is None
uSizedArrayDecoder.decode
T l uDynamicArrayDecoder.decode
value_bit_size
u`value_bit_size` may not be None
data_byte_size
u`data_byte_size` may not be None
u`decoder_fn` may not be None
is_big_endian
u`is_big_endian` may not be None
l uInvalid value bit size: {self.value_bit_size}. Must be a multiple of 8
uValue byte size exceeds data size
read
aInsufficientDataBytes
uTried to read
u bytes, only got
u bytes.
a_get_value_byte_size
d
aNonEmptyPaddingBytes
uPadding bytes were not empty:
d uBoolean must be either 0x0 or 0x1.  Got:
sub
T avalue_bit_size
big_endian_to_int
l d afrac_places
umust specify `frac_places`
lPu`frac_places` must be in range (0, 80]
decimal
localcontext
abi_decimal_context
a__enter__
a__exit__
aDecimal
aTEN
T nnnadecimal_value
T avalue_bit_size
frac_places
ceil32
strict
u bytes
bytes_errors
T uutf-8
T aerrors
a__doc__
a__file__
origin
has_location
a__cached__
abc
io
aAny
aGenerator
eth_utils
T abig_endian_to_int
to_normalized_address
to_tuple
to_normalized_address
to_tuple
ueth_abi.base
T aBaseCoder
parse_tuple_type_str
parse_type_str
aBaseCoder
parse_tuple_type_str
parse_type_str
ueth_abi.exceptions
T aInsufficientDataBytes
aInvalidPointer
aNonEmptyPaddingBytes
ueth_abi.utils.numeric
T aTEN
abi_decimal_context
ceil32
aBytesIO
a__prepare__
aContextFramesBytesIO
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
