# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.eos_addr

uClass container for EOS address constants.
a__qualname__
a__annotations__
l uEOS address utility class.
D apub_key_bytes
return
Obytes
pu_EosAddrUtils.ComputeChecksum
a__prepare__
aEosAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

EOS address decoder class.
It allows the EOS address decoding.
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uEosAddrDecoder.DecodeAddr
a__orig_bases__
aEosAddrEncoder

EOS address encoder class.
It allows the EOS address encoding.
pub_key
aEncodeKey
uEosAddrEncoder.EncodeKey
aEosAddr
ubip_utils\addr\eos_addr.py
u<module bip_utils.addr.eos_addr>
T apub_key_bytes
T aaddr
kwargs
addr_no_prefix
addr_dec_bytes
pub_key_bytes
checksum_bytes
T apub_key
kwargs
pub_key_obj
pub_key_bytes
checksum_bytes
T a__class__

a__spec__
.bip_utils.addr.ergo_addr
q
aBlake2b256
aQuickDigest
aErgoAddrConst
aCHECKSUM_BYTE_LEN

Compute checksum in Ergo format.
Args:
pub_key_bytes (bytes): Public key bytes
Returns:
bytes: Computed checksum
aIntegerUtils
aToBytes

Encode prefix.
Args:
ddr_type (ErgoAddressTypes): Address type
net_type (ErgoNetworkTypes) : Network type
Returns:
bytes: Prefix byte
net_type
aErgoNetworkTypes
aMAINNET
uAddress type is not an enumerative of ErgoNetworkTypes
aBase58Decoder
aDecode
aAddrDecUtils
aValidateLength
aSecp256k1PublicKey
aCompressedLength
aSplitPartsByChecksum
aValidateChecksum
a_ErgoAddrUtils
aComputeChecksum
aValidateAndRemovePrefix
aEncodePrefix
aErgoAddressTypes
aP2PKH
aValidatePubKey

Decode an Ergo P2PKH address to bytes.
Args:
ddr (str): Address string
Other Parameters:
net_type (ErgoNetworkTypes): Expected network type (default: main net)
Returns:
bytes: Public key bytes
Raises:
ValueError: If the address encoding is not valid
TypeError: If the network tag is not a ErgoNetworkTypes enum
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aRawCompressed
aBase58Encoder
aEncode

Encode a public key to Ergo P2PKH address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
net_type (ErgoNetworkTypes): Network type (default: main net)
Returns:
str: Address string
Raised:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1 or the network tag is not a ErgoNetworkTypes enum
uModule for Ergo address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aIntEnum
unique
aIntEnum
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
T aBase58Decoder
aBase58Encoder
ubip_utils.ecc
T aIPublicKey
aSecp256k1PublicKey
aIPublicKey
ubip_utils.utils.crypto
T aBlake2b256
ubip_utils.utils.misc
T aIntegerUtils
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
