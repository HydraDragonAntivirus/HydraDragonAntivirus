# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.base58.base58_xmr

uClass container for Base58 Monero constants.
a__qualname__
a__annotations__
aALPHABETS
aBITCOIN
l l L	l
l l l l l l	l
l u
Base58 Monero encoder class.
It provides methods for encoding to Base58 format with Monero variation (encoding by blocks of 8-byte).
D adata_bytes
return
Obytes
Ostr
uBase58XmrEncoder.Encode
D aenc_str
pad_len
return
Ostr
Oint
Ostr
a__Pad
uBase58XmrEncoder.__Pad

Base58 Monero decoder class.
It provides methods for decoding Base58 format with Monero variation (encoding by blocks of 8-byte).
D adata_str
return
Ostr
Obytes
uBase58XmrDecoder.Decode
D adec_bytes
unpad_len
return
Obytes
Oint
Obytes
a__UnPad
uBase58XmrDecoder.__UnPad
ubip_utils\base58\base58_xmr.py
u<module bip_utils.base58.base58_xmr>
T a__class__
T
data_str
dec
data_len
block_dec_len
block_enc_len
tot_block_cnt
last_block_enc_len
last_block_dec_len
wiablock_dec
T adata_bytes
enc
data_len
block_dec_len
tot_block_cnt
last_block_enc_len
wiablock_enc
T aenc_str
pad_len
T adec_bytes
unpad_len
a__spec__
.bip_utils.base58
S
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
base58
T aNUITKA_PACKAGE_bip_utils_base58
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.base58.base58
T aBase58Alphabets
aBase58Decoder
aBase58Encoder
aBase58Alphabets
aBase58Decoder
aBase58Encoder
ubip_utils.base58.base58_ex
T aBase58ChecksumError
aBase58ChecksumError
ubip_utils.base58.base58_xmr
T aBase58XmrDecoder
aBase58XmrEncoder
aBase58XmrDecoder
aBase58XmrEncoder
ubip_utils\base58\__init__.py
u<module bip_utils.base58>

a__spec__
.bip_utils.bech32.bch_bech32
h
L T l g        T l g        T l g        T l g        T l g <     achk
l#g       l agenerator
top

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
aBchBech32Utils
aHrpExpand
aPolyMod
aBchBech32Const
aCHECKSUM_STR_LEN
polymod
l u
Compute the checksum from the specified HRP and data.
Args:
hrp (str)       : HRP
data (list[int]): Data part
Returns:
list[int]: Computed checksum

Verify the checksum from the specified HRP and converted data characters.
Args:
hrp  (str)      : HRP
data (list[int]): Data part
Returns:
bool: True if valid, false otherwise
a_EncodeBech32
aBech32BaseUtils
aConvertToBase32
aSEPARATOR

Encode to Bitcoin Cash Bech32.
Args:
hrp (str)      : HRP
net_ver (bytes): Net version
data (bytes)   : Data
Returns:
str: Encoded address
Raises:
ValueError: If the data is not valid
aComputeChecksum
a_DecodeBech32
uInvalid format (HRP not valid, expected

u, got
w)aConvertFromBase32
aIntegerUtils
aToBytes
aBytesUtils
aFromList
:l nnu
Decode from Bitcoin Cash Bech32.
Args:
hrp (str) : Human readable part
ddr (str): Address
Returns:
tuple[bytes, bytes]: Net version (index 0) and data (index 1)
Raises:
ValueError: If the bech32 string is not valid
Bech32ChecksumError: If the checksum is not valid
aVerifyChecksum

Module for BitcoinCash bech32 decoding/encoding.
Reference: https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
a__doc__
a__file__
origin
has_location
a__cached__
aList
aTuple
ubip_utils.bech32.bech32_base
T aBech32BaseUtils
aBech32DecoderBase
aBech32EncoderBase
aBech32DecoderBase
aBech32EncoderBase
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
