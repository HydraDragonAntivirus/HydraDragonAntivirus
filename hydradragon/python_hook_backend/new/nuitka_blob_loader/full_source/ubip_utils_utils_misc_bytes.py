# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.misc.bytes

uClass container for bytes utility functions.
a__qualname__
D adata_bytes
return
Obytes
paReverse
uBytesUtils.Reverse
D adata_bytes_1
data_bytes_2
return
Obytes
ppaXor
uBytesUtils.Xor
aAddNoCarry
uBytesUtils.AddNoCarry
D adata_bytes
scalar
return
Obytes
Oint
Obytes
aMultiplyScalarNoCarry
uBytesUtils.MultiplyScalarNoCarry
T l
D adata_bytes
zero_pad_bit_len
return
Obytes
Oint
Ostr
uBytesUtils.ToBinaryStr
T abig
Fadata_bytes
endianness
T alittle
big
signed
return
uBytesUtils.ToInteger
data
T Obytes
Ostr
zero_pad_byte_len
uBytesUtils.FromBinaryStr
T uutf-8
D adata_bytes
encoding
return
Obytes
Ostr
paToHexString
uBytesUtils.ToHexString
aFromHexString
uBytesUtils.FromHexString
data_list
aFromList
uBytesUtils.FromList
aToList
uBytesUtils.ToList
ubip_utils\utils\misc\bytes.py
u<module bip_utils.utils.misc.bytes>
T adata_bytes_1
data_bytes_2
T a__class__
T adata
zero_pad_byte_len
T adata
T adata_list
T adata_bytes
scalar
T adata_bytes
tmp
T adata_bytes
zero_pad_bit_len
T adata_bytes
encoding
T adata_bytes
endianness
signed
T adata_bytes

a__spec__
.bip_utils.utils.misc.cbor_indefinite_len_array
R
uInvalid length (

w)aCborIds
aINDEF_LEN_ARRAY_START
uInvalid first byte (
aINDEF_LEN_ARRAY_END
uInvalid last byte (
wiuInvalid encoding (index overflow)
aCborIndefiniteLenArrayConst
aUINT_IDS_TO_BYTE_LEN
get
int_elems
cbor2
loads

CBOR-decode the specified bytes.
Args:
enc_bytes (bytes): Encoded bytes
Returns:
list[int]: List of integers
Raises:
ValueError: If encoding is not valid
aIntegerUtils
aToBytes
D abytes_num
l c
dumps

CBOR-encode the specified elements.
Args:
int_seq (sequence[int]): Collection of integers
Returns:
bytes: CBOR-encoded bytes

Module for CBOR decoding/encoding indefinite length arrays.
Indefinite length arrays are encoded without writing the array length, so elements shall be read until
the termination byte is found.
NOTE: encoding of values greater than 2^64 is not supported.
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aIntEnum
unique
aIntEnum
unique
aDict
aList
aSequence
ubip_utils.utils.misc.integer
T aIntegerUtils
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
