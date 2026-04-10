# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.xrp_addr


Ripple address decoder class.
It allows the Ripple address decoding.
a__qualname__
staticmethod
addr
str
kwargs
return
bytes
uXrpAddrDecoder.DecodeAddr
a__orig_bases__
aXrpAddrEncoder

Ripple address encoder class.
It allows the Ripple address encoding.
pub_key
uXrpAddrEncoder.EncodeKey
aXrpAddr
ubip_utils\addr\xrp_addr.py
u<module bip_utils.addr.xrp_addr>
T aaddr
kwargs
T apub_key
kwargs
T a__class__

a__spec__
.bip_utils.addr.xtz_addr
[
prefix
aXtzAddrPrefixes
uAddress type is not an enumerative of XtzAddrPrefixes
aBase58Decoder
aCheckDecode
aBase58ChecksumError
uInvalid base58 checksum
aAddrDecUtils
aValidateLength
value
aBlake2b160
aDigestSize
aValidateAndRemovePrefix

Decode a Tezos address to bytes.
Args:
ddr (str): Address string
Other Parameters:
prefix (XtzAddrPrefixes): Expected address prefix
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
TypeError: If the prefix is not a XtzAddrPrefixes enum
aAddrKeyValidator
aValidateAndGetEd25519Key
aQuickDigest
aRawCompressed
aToBytes
:l nnaBase58Encoder
aCheckEncode

Encode a public key to Tezos address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
prefix (XtzAddrPrefixes): Address prefix
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519 or the prefix is not a XtzAddrPrefixes enum
uModule for Tezos address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aEnum
unique
aEnum
unique
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
T aBlake2b160
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
