# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bech32.bech32_base

uClass container for Bech32 constants.
a__qualname__
a__annotations__
qpzry9x8gf2tvdw0s3jn54khce6mua7l
uClass container for Bech32 utility functions.
data
return
aConvertToBase32
uBech32BaseUtils.ConvertToBase32
aConvertFromBase32
uBech32BaseUtils.ConvertFromBase32
T tapad
uBech32BaseUtils.ConvertBits
a__prepare__
aBech32EncoderBase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Bech32 encoder base class.
It provides methods for encoding to Bech32 format.
classmethod
hrp
str
int
sep
a_EncodeBech32
uBech32EncoderBase._EncodeBech32
staticmethod

Compute the checksum from the specified HRP and data.
Args:
hrp (str)       : HRP
data (list[int]): Data part
Returns:
list[int]: Computed checksum
uBech32EncoderBase._ComputeChecksum
a__orig_bases__
aBech32DecoderBase

Bech32 decoder base class.
It provides methods for decoding Bech32 format.
bech_str
checksum_len
a_DecodeBech32
uBech32DecoderBase._DecodeBech32
bool

Verify the checksum from the specified HRP and converted data characters.
Args:
hrp  (str)      : HRP
data (list[int]): Data part
Returns:
bool: True if valid, false otherwise
uBech32DecoderBase._VerifyChecksum
ubip_utils\bech32\bech32_base.py
T a.0
wxu<module bip_utils.bech32.bech32_base>
T a__class__
T
data
from_bits
to_bits
pad
max_out_val
max_acc
acc
bits
ret
value
T adata
conv_data
T ahrp
data
T acls
bech_str
sep
checksum_len
sep_pos
hrp
data_part
int_data
T acls
hrp
data
sep
a__spec__
.bip_utils.bech32.bech32_ex
uModule for bech32 exceptions.
a__doc__
a__file__
origin
has_location
a__cached__
T EException
a__prepare__
aBech32ChecksumError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
