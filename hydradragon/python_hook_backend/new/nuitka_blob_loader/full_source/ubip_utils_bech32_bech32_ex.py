# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bech32.bech32_ex

uException in case of checksum error.
a__qualname__
a__orig_bases__
ubip_utils\bech32\bech32_ex.py
u<module bip_utils.bech32.bech32_ex>

a__spec__
.bip_utils.bech32
"
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
bech32
T aNUITKA_PACKAGE_bip_utils_bech32
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bech32.bch_bech32
T aBchBech32Decoder
aBchBech32Encoder
aBchBech32Decoder
aBchBech32Encoder
ubip_utils.bech32.bech32
T aBech32Decoder
aBech32Encoder
aBech32Decoder
aBech32Encoder
ubip_utils.bech32.bech32_ex
T aBech32ChecksumError
aBech32ChecksumError
ubip_utils.bech32.segwit_bech32
T aSegwitBech32Decoder
aSegwitBech32Encoder
aSegwitBech32Decoder
aSegwitBech32Encoder
ubip_utils\bech32\__init__.py
u<module bip_utils.bech32>

a__spec__
.bip_utils.bech32.segwit_bech32
}
a
def a_EncodeBech32
aBech32BaseUtils
aConvertToBase32
aSegwitBech32Const
aSEPARATOR

Encode to Segwit Bech32.
Args:
hrp (str)       : HRP
wit_ver (int)   : Witness version
wit_prog (bytes): Witness program
Returns:
str: Encoded address
Raises:
ValueError: If the data is not valid
aWITNESS_VER_BECH32
aBech32Encodings
aBECH32
aBECH32M
aBech32Utils
aComputeChecksum

Compute the checksum from the specified HRP and data.
Args:
hrp (str)       : HRP
data (list[int]): Data part
Returns:
list[int]: Computed checksum
a_DecodeBech32
aCHECKSUM_STR_LEN
uInvalid format (HRP not valid, expected

u, got
w)aConvertFromBase32
:l nnaWITNESS_PROG_MIN_BYTE_LEN
aWITNESS_PROG_MAX_BYTE_LEN
uInvalid format (witness program length not valid:
aWITNESS_VER_MAX_VAL
uInvalid format (witness version not valid:
aWITNESS_VER_ZERO_DATA_BYTE_LEN
uInvalid format (length not valid:
aBytesUtils
aFromList

Decode from Segwit Bech32.
Args:
hrp (str) : Human readable part
ddr (str): Address
Returns:
tuple[int, bytes]: Witness version (index 0) and witness program (index 1)
Raises:
Bech32ChecksumError: If the checksum is not valid
ValueError: If the bech32 string is not valid
aVerifyChecksum

Verify the checksum from the specified HRP and converted data characters.
Args:
hrp  (str)      : HRP
data (list[int]): Data part
Returns:
bool: True if valid, false otherwise

Module for segwit bech32/bech32m decoding/encoding.
References:
https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
aList
aTuple
ubip_utils.bech32.bech32
T aBech32Const
aBech32Encodings
aBech32Utils
aBech32Const
ubip_utils.bech32.bech32_base
T aBech32BaseUtils
aBech32DecoderBase
aBech32EncoderBase
aBech32DecoderBase
aBech32EncoderBase
ubip_utils.utils.misc
T aBytesUtils
