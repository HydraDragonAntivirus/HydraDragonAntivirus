# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.near_addr


Near address decoder class.
It allows the Near Protocol address decoding.
a__qualname__
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uNearAddrDecoder.DecodeAddr
a__orig_bases__
aNearAddrEncoder

Near address encoder class.
It allows the Near Protocol address encoding.
pub_key
aEncodeKey
uNearAddrEncoder.EncodeKey
aNearAddr
ubip_utils\addr\near_addr.py
u<module bip_utils.addr.near_addr>
T aaddr
kwargs
pub_key_bytes
T apub_key
kwargs
pub_key_obj
T a__class__

a__spec__
.bip_utils.addr.neo_addr
'
[
ver
aBase58Decoder
aCheckDecode
aBase58ChecksumError
uInvalid base58 checksum
aAddrDecUtils
aValidateLength
aHash160
aDigestSize
aIntegerUtils
aToBytes
uInvalid version (expected
aBytesUtils
aToHexString

u, got
w):l nnu
Decode a Neo address to bytes.
Args:
ddr (str): Address string
Other Parameters:
ver (bytes): Expected version
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetNist256p1Key
aNeoAddrConst
aPREFIX_BYTE
aRawCompressed
aSUFFIX_BYTE
aBase58Encoder
aCheckEncode
aQuickDigest

Encode a public key to Neo address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
ver (bytes): Version
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not nist256p1
uModule for Neo address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aUnion
ubip_utils.addr.addr_dec_utils
T aAddrDecUtils
ubip_utils.addr.addr_key_validator
T aAddrKeyValidator
ubip_utils.addr.iaddr_decoder
T aIAddrDecoder
aIAddrDecoder
ubip_utils.addr.iaddr_encoder
T aIAddrEncoder
aIAddrEncoder
ubip_utils.base58
T aBase58ChecksumError
aBase58Decoder
aBase58Encoder
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aHash160
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
