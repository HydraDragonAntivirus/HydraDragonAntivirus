# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bech32.bch_bech32

uClass container for Bitcoin Cash Bech32 constants.
a__qualname__
a__annotations__
w:l uClass container for Bitcoin Cash utility functions.
values
return
uBchBech32Utils.PolyMod
hrp
uBchBech32Utils.HrpExpand
data
uBchBech32Utils.ComputeChecksum
uBchBech32Utils.VerifyChecksum
a__prepare__
aBchBech32Encoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Bitcoin Cash Bech32 encoder class.
It provides methods for encoding to Bitcoin Cash Bech32 format.
classmethod
str
net_ver
bytes
aEncode
uBchBech32Encoder.Encode
staticmethod
int
a_ComputeChecksum
uBchBech32Encoder._ComputeChecksum
a__orig_bases__
aBchBech32Decoder

Bitcoin Cash Bech32 decoder class.
It provides methods for decoding Bitcoin Cash Bech32 format.
addr
aDecode
uBchBech32Decoder.Decode
bool
a_VerifyChecksum
uBchBech32Decoder._VerifyChecksum
ubip_utils\bech32\bch_bech32.py
u<module bip_utils.bech32.bch_bech32>
T a__class__
T ahrp
data
values
polymod
T acls
hrp
addr
hrp_got
data
conv_data
T acls
hrp
net_ver
data
T ahrp
T avalues
generator
chk
value
top
wiT ahrp
data
a__spec__
.bip_utils.bech32.bech32
Q
r
L l     l     l     l     l     achk
l l    l ;l
l l atop

Computes the polynomial modulus.
Args:
values (list[int]): List of polynomial coefficients
Returns:
int: Computed modulus
l u
Expand the HRP into values for checksum computation.
Args:
hrp (str): HRP
Returns:
list[int]: Expanded HRP values
aBech32Utils
aHrpExpand
aPolyMod
aBech32Const
aENCODING_CHECKSUM_CONST
aCHECKSUM_STR_LEN
polymod

Compute the checksum from the specified HRP and data.
Args:
hrp (str)                           : HRP
data (list[int])                    : Data part
encoding (Bech32Encodings, optional): Encoding type (BECH32 by default)
Returns:
list[int]: Computed checksum

Verify the checksum from the specified HRP and converted data characters.
Args:
hrp  (str)                          : HRP
data (list[int])                    : Data part
encoding (Bech32Encodings, optional): Encoding type (BECH32 by default)
Returns:
bool: True if valid, false otherwise
a_EncodeBech32
aBech32BaseUtils
aConvertToBase32
aSEPARATOR

Encode to Bech32.
Args:
hrp (str)   : HRP
data (bytes): Data
Returns:
str: Encoded address
Raises:
ValueError: If the data is not valid
aComputeChecksum

Compute the checksum from the specified HRP and data.
Args:
hrp (str)       : HRP
data (list[int]): Data part
Returns:
list[int]: Computed checksum
a_DecodeBech32
uInvalid format (HRP not valid, expected

u, got
w)aBytesUtils
aFromList
aConvertFromBase32

Decode from Bech32.
Args:
hrp (str) : Human readable part
ddr (str): Address
Returns:
bytes: Decoded address
Raises:
ValueError: If the bech32 string is not valid
Bech32ChecksumError: If the checksum is not valid
aVerifyChecksum

Verify the checksum from the specified HRP and converted data characters.
Args:
hrp  (str)      : HRP
data (list[int]): Data part
Returns:
bool: True if valid, false otherwise

Module for bech32/bech32m decoding/encoding.
References:
https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
https://github.com/sipa/bech32/blob/master/ref/python/segwit_addr.py
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aEnum
auto
unique
aEnum
auto
unique
aDict
aList
ubip_utils.bech32.bech32_base
T aBech32BaseUtils
aBech32DecoderBase
aBech32EncoderBase
aBech32DecoderBase
aBech32EncoderBase
ubip_utils.utils.misc
T aBytesUtils
a__prepare__
aBech32Encodings
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
