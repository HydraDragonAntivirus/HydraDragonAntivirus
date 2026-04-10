# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bech32.bech32

uEnumerative for Bech32 encoding types.
a__qualname__
aBECH32
aBECH32M
a__orig_bases__
uClass container for Bech32 constants.
a__annotations__
w1l l     uClass container for Bech32 utility functions.
values
return
uBech32Utils.PolyMod
hrp
uBech32Utils.HrpExpand
data
encoding
uBech32Utils.ComputeChecksum
uBech32Utils.VerifyChecksum
aBech32Encoder

Bech32 encoder class.
It provides methods for encoding to Bech32 format.
classmethod
str
bytes
aEncode
uBech32Encoder.Encode
staticmethod
int
a_ComputeChecksum
uBech32Encoder._ComputeChecksum
aBech32Decoder

Bech32 decoder class.
It provides methods for decoding  Bech32 format.
addr
aDecode
uBech32Decoder.Decode
bool
a_VerifyChecksum
uBech32Decoder._VerifyChecksum
ubip_utils\bech32\bech32.py
u<module bip_utils.bech32.bech32>
T a__class__
T ahrp
data
encoding
values
polymod
T acls
hrp
addr
hrp_got
data
T acls
hrp
data
T ahrp
T avalues
generator
chk
value
top
wiT ahrp
data
encoding
polymod
T ahrp
data
a__spec__
.bip_utils.bech32.bech32_base
i
n
aBech32BaseUtils
aConvertBits
l l uInvalid data, cannot perform conversion to base32

Convert data to base32.
Args:
data (list[int] or bytes): Data to be converted
Returns:
list[int]: Converted data
Raises:
ValueError: If the string is not valid
uInvalid data, cannot perform conversion from base32

Convert data from base32.
Args:
data (list[int] or bytes): Data to be converted
Returns:
list[int]: Converted data
Raises:
ValueError: If the string is not valid
from_bits
acc
max_acc
bits
to_bits
ret
max_out_val

Perform bit conversion.
The function takes the input data (list of integers or byte sequence) and convert every value from
the specified number of bits to the specified one.
It returns a list of integer where every number is less than 2^to_bits.
Args:
data (list[int] or bytes): Data to be converted
from_bits (int)          : Number of bits to start from
to_bits (int)            : Number of bits to end with
pad (bool, optional)     : True if data must be padded with zeros, false otherwise
Returns:
list[int]: List of converted values, None in case of errors
a_ComputeChecksum

aBech32BaseConst
aCHARSET

Encode a Bech32 string from the specified HRP and data.
Args:
hrp (str)       : HRP
data (list[int]): Data part
sep (str)       : Bech32 separator
Returns:
str: Encoded data
aAlgoUtils
aIsStringMixed
uInvalid bech32 format (string is mixed case)
lower
rfind
uInvalid bech32 format (no separator found)
uInvalid bech32 format (HRP not valid:
w)uInvalid bech32 format (data part not valid)
find
a_VerifyChecksum
aBech32ChecksumError
T uInvalid bech32 checksum

Decode and validate a Bech32 string, determining its HRP and data.
Args:
bech_str (str)    : Bech32 string
sep (str)         : Bech32 separator
checksum_len (int): Checksum length
Returns:
tuple[str, list[int]]: HRP (index 0) and data part (index 1)
Raises:
ValueError: If the string is not valid
Bech32ChecksumError: If the checksum is not valid
l!l~u<genexpr>
uBech32DecoderBase._DecodeBech32.<locals>.<genexpr>
uModule for base bech32 decoding/encoding.
a__doc__
a__file__
origin
has_location
a__cached__
abc
T aABC
abstractmethod
aABC
abstractmethod
aList
aOptional
aTuple
aUnion
ubip_utils.bech32.bech32_ex
T aBech32ChecksumError
ubip_utils.utils.misc
T aAlgoUtils
