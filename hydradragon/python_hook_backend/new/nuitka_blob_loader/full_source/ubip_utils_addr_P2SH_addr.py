# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.P2SH_addr

uClass container for P2SH constants.
a__qualname__
a__annotations__
b
uClass container for P2SH utility functions.
pub_key
return
u_P2SHAddrUtils.AddScriptSig
a__prepare__
aP2SHAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

P2SH address decoder class.
It allows the Pay-to-Script-Hash address decoding.
staticmethod
addr
str
kwargs
bytes
uP2SHAddrDecoder.DecodeAddr
a__orig_bases__
aP2SHAddrEncoder

P2SH address encoder class.
It allows the Pay-to-Script-Hash address encoding.
aEncodeKey
uP2SHAddrEncoder.EncodeKey
aBchP2SHAddrDecoder

Bitcoin Cash P2SH address decoder class.
It allows the Bitcoin Cash P2SH decoding.
uBchP2SHAddrDecoder.DecodeAddr
aBchP2SHAddrEncoder

Bitcoin Cash P2SH address encoder class.
It allows the Bitcoin Cash P2SH encoding.
uBchP2SHAddrEncoder.EncodeKey
aP2SHAddr
aBchP2SHAddr
ubip_utils\addr\P2SH_addr.py
u<module bip_utils.addr.P2SH_addr>
T apub_key
key_hash_bytes
script_sig_bytes
T a__class__
T aaddr
kwargs
T apub_key
kwargs
hrp
net_ver_bytes
pub_key_obj
T apub_key
kwargs
net_ver_bytes
pub_key_obj

a__spec__
.bip_utils.addr.P2TR_addr
%
aSha256
aQuickDigest

Implementation of the hash tag function as defined by BIP-0340.
Tagged hash = SHA256(SHA256(tag) || SHA256(tag) || data)
Args:
tag (bytes or str): Tag, if bytes it'll be considered already hashed
data_bytes (bytes): Data bytes
Returns:
bytes: Tagged hash
a_P2TRUtils
aTaggedHash
aP2TRConst
aTAP_TWEAK_SHA256
aIntegerUtils
aToBytes
aPoint
wXaSecp256k1Point
aCoordinateLength
T abytes_num

Compute the HashTapTweak of the specified public key.
Args:
pub_key (IPublicKey object): Public key
Returns:
bytes: Computed hash
aFIELD_SIZE
uUnable to compute LiftX point
pow
l l l l aFromCoordinates

Implementation of the lift_x function as defined by BIP-0340.
It computes the point P for which P.X() = pub_key.X() and has_even_y(P).
Args:
pub_key (IPublicKey object): Public key
Returns:
IPoint: Computed point
Raises:
ValueError: If the point doesn't exist
aHashTapTweak
aLiftX
aBytesUtils
aToInteger
aSecp256k1
aGenerator

Tweak a public key as defined by BIP-0086.
tweaked_pub_key = lift_x(pub_key.X()) + int(HashTapTweak(bytes(pub_key.X()))) * G
Args:
pub_key (IPublicKey object): Public key
Returns:
bytes: X coordinate of the tweaked public key
hrp
aSegwitBech32Decoder
aDecode
aBech32ChecksumError
uInvalid bech32 checksum
aAddrDecUtils
aValidateLength
aSecp256k1PublicKey
aCompressedLength
aWITNESS_VER
uInvalid witness version (expected

u, got
w)u
Decode a P2TR address to bytes.
Args:
ddr (str): Address string
Other Parameters:
hrp (str): Expected HRP
Returns:
bytes: X coordinate of the tweaked public key
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aSegwitBech32Encoder
aEncode
aTweakPublicKey

Encode a public key to P2TR address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
hrp (str): HRP
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid or cannot be tweaked
TypeError: If the public key is not secp256k1

Module for P2TR address encoding/decoding.
References:
https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
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
ubip_utils.bech32
T aBech32ChecksumError
aSegwitBech32Decoder
aSegwitBech32Encoder
ubip_utils.ecc
T aIPoint
aIPublicKey
aSecp256k1
aSecp256k1Point
aSecp256k1PublicKey
aIPoint
aIPublicKey
ubip_utils.utils.crypto
T aSha256
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
