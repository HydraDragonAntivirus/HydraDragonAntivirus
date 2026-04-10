# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.misc.cbor_indefinite_len_array

uEnumerative for CBOR identifiers.
a__qualname__
l aUINT8
l aUINT16
l aUINT32
l aUINT64
l  l  a__orig_bases__
uClass container for CBOR indefinite length arrays constants.
a__annotations__
l l l l	T Oint
pu
CBOR indefinite length arrays decoder.
It decodes bytes back to array.
aCborIndefiniteLenArrayDecoder
enc_bytes
return
aDecode
uCborIndefiniteLenArrayDecoder.Decode

CBOR indefinite length arrays encoder.
It encodes indefinite length arrays to bytes.
aCborIndefiniteLenArrayEncoder
int_seq
aEncode
uCborIndefiniteLenArrayEncoder.Encode
ubip_utils\utils\misc\cbor_indefinite_len_array.py
u<module bip_utils.utils.misc.cbor_indefinite_len_array>
T a__class__
T aenc_bytes
wiaint_elems
curr_val
curr_len
T aint_seq
a__spec__
.bip_utils.utils.misc
/
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uutils\misc
T aNUITKA_PACKAGE_bip_utils_utils
u\not_existing
misc
T aNUITKA_PACKAGE_bip_utils_utils_misc
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.utils.misc.algo
T aAlgoUtils
aAlgoUtils
ubip_utils.utils.misc.base32
T aBase32Decoder
aBase32Encoder
aBase32Decoder
aBase32Encoder
ubip_utils.utils.misc.bit
T aBitUtils
aBitUtils
ubip_utils.utils.misc.bytes
T aBytesUtils
aBytesUtils
ubip_utils.utils.misc.cbor_indefinite_len_array
T aCborIndefiniteLenArrayDecoder
aCborIndefiniteLenArrayEncoder
aCborIndefiniteLenArrayDecoder
aCborIndefiniteLenArrayEncoder
ubip_utils.utils.misc.data_bytes
T aDataBytes
aDataBytes
ubip_utils.utils.misc.integer
T aIntegerUtils
aIntegerUtils
ubip_utils.utils.misc.string
T aStringUtils
aStringUtils
ubip_utils\utils\misc\__init__.py
u<module bip_utils.utils.misc>

a__spec__
.bip_utils.utils.misc.data_bytes
R
m_data_bytes

Construct class.
Args:
data_bytes (bytes): Data bytes

Get length in bytes.
Returns:
int: Length in bytes
aLength

Get length in bytes (same of Length()).
Returns:
int: Length in bytes

Get data bytes.
Returns:
bytes: Data bytes
aBytesUtils
aToHexString

Get data bytes in hex format.
Returns:
str: Data bytes in hex format
aToInteger

Get data bytes as an integer.
Args:
endianness ("big" or "little", optional): Endianness (default: big)
Returns:
int: Data bytes as an integer
aToBytes
aToInt

Get data bytes as integer.
Returns:
bytes: Data bytes as integer
aToHex

Get data bytes representation.
Returns:
str: Data bytes representation

Get the element with the specified index.
Args:
idx (int): Index
Returns:
int: Element
Raises:
IndexError: If the index is not valid

Get the iterator to the current element.
Returns:
Iterator object: Iterator to the current element
self
a__iter__
uDataBytes.__iter__
aDataBytes
uInvalid type for checking equality (

w)u
Equality operator.
Args:
other (bytes, str, int or DataBytes object): Other object to compare
Returns:
bool: True if equal false otherwise
Raises:
TypeError: If the other object is not of the correct type
uModule with helper class for data bytes.
a__doc__
a__file__
origin
has_location
a__cached__
aIterator
ubip_utils.utils.misc.bytes
T aBytesUtils
ubip_utils.utils.typing
T aLiteral
aLiteral
