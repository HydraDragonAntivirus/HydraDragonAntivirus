# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.misc.bit

uClass container for bit utility functions.
aBitUtils
a__qualname__
D avalue
bit_num
return
Oint
pObool
aIsBitSet
uBitUtils.IsBitSet
D avalue
bit_mask
return
Oint
pObool
aAreBitsSet
uBitUtils.AreBitsSet
D avalue
bit_num
return
Oint
ppaSetBit
uBitUtils.SetBit
D avalue
bit_mask
return
Oint
ppaSetBits
uBitUtils.SetBits
aResetBit
uBitUtils.ResetBit
aResetBits
uBitUtils.ResetBits
ubip_utils\utils\misc\bit.py
u<module bip_utils.utils.misc.bit>
T avalue
bit_mask
T avalue
bit_num

a__spec__
.bip_utils.utils.misc.bytes
.
c
reverse

Reverse the specified bytes.
Args:
data_bytes (bytes): Data bytes
Returns:
bytes: Original bytes in the reverse order

XOR the specified bytes.
Args:
data_bytes_1 (bytes): Data bytes 1
data_bytes_2 (bytes): Data bytes 2
Returns:
bytes: XORed bytes
l  u
Add the specified bytes (byte-by-byte, no carry).
Args:
data_bytes_1 (bytes): Data bytes 1
data_bytes_2 (bytes): Data bytes 2
Returns:
bytes: XORed bytes
scalar

Multiply the specified bytes with the specified scalar (byte-by-byte, no carry).
Args:
data_bytes (bytes): Data bytes
scalar (int)      : Scalar
Returns:
bytes: XORed bytes
aIntegerUtils
aToBinaryStr
aBytesUtils
aToInteger

Convert the specified bytes to a binary string.
Args:
data_bytes (bytes)              : Data bytes
zero_pad_bit_len (int, optional): Zero pad length in bits, 0 if not specified
Returns:
str: Binary string
from_bytes
T abyteorder
signed

Convert the specified bytes to integer.
Args:
data_bytes (bytes)                      : Data bytes
endianness ("big" or "little", optional): Endianness (default: big)
signed (bool, optional)                 : True if signed, false otherwise (default: false)
Returns:
int: Integer representation
binascii
unhexlify
aFromBinaryStr
:l nnazfill

Convert the specified binary string to bytes.
Args:
data (str or bytes)              : Data
zero_pad_byte_len (int, optional): Zero pad length in bytes, 0 if not specified
Returns:
bytes: Bytes representation
aAlgoUtils
aDecode
hexlify

Convert bytes to hex string.
Args:
data_bytes (bytes)      : Data bytes
encoding (str, optional): Encoding type, utf-8 by default
Returns:
str: Bytes converted to hex string
aEncode

Convert hex string to bytes.
Args:
data (str or bytes): Data bytes
Returns
bytes: Hex string converted to bytes

Convert the specified list of integers to bytes.
Args:
data_list (list[int]): List of integers
Returns:
bytes: Bytes representation

Convert the specified bytes to a list of integers.
Args:
data_bytes (bytes): Data bytes
Returns:
list[int]: List of integers
uModule with some bytes utility functions.
a__doc__
a__file__
origin
has_location
a__cached__
aList
aUnion
ubip_utils.utils.misc.algo
T aAlgoUtils
ubip_utils.utils.misc.integer
T aIntegerUtils
ubip_utils.utils.typing
T aLiteral
aLiteral
