# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.iaddr_encoder

uAddress encoder interface.
a__qualname__
staticmethod
pub_key
bytes
kwargs
return
str

Encode public key to address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Arbitrary arguments depending on the address type
Returns:
str: Address string
Raised:
ValueError: If the public key is not valid
TypeError: If the public key is not of the correct type (it depends on the address type)
aEncodeKey
uIAddrEncoder.EncodeKey
a__orig_bases__
ubip_utils\addr\iaddr_encoder.py
u<module bip_utils.addr.iaddr_encoder>
T apub_key
kwargs
T a__class__

a__spec__
.bip_utils.addr.icx_addr
k
S
aAddrDecUtils
aValidateAndRemovePrefix
aCoinsConf
aIcon
aParamByKey
T aaddr_prefix
aBytesUtils
aFromHexString
aValidateLength
aIcxAddrConst
aKEY_HASH_BYTE_LEN

Decode an Icon address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aSha3_256
aQuickDigest
aRawUncompressed
aToBytes
:l nnaToHexString

Encode a public key to Icon address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raised:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for Icon address encoding/decoding.
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
ubip_utils.coin_conf
T aCoinsConf
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aSha3_256
ubip_utils.utils.misc
T aBytesUtils
