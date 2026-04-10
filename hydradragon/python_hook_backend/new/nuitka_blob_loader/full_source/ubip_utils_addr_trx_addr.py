# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.trx_addr


Tron address decoder class.
It allows the Tron address decoding.
a__qualname__
staticmethod
addr
str
kwargs
return
bytes
uTrxAddrDecoder.DecodeAddr
a__orig_bases__
aTrxAddrEncoder

Tron address encoder class.
It allows the Tron address encoding.
pub_key
uTrxAddrEncoder.EncodeKey
aTrxAddr
ubip_utils\addr\trx_addr.py
u<module bip_utils.addr.trx_addr>
T aaddr
kwargs
addr_dec
ex
addr_no_prefix
T apub_key
kwargs
eth_addr
T a__class__

a__spec__
.bip_utils.addr.xlm_addr
=
l
aBytesUtils
aReverse
aXModemCrc
aQuickDigest

Compute checksum in Stellar format.
Args:
payload_bytes (bytes): Payload bytes
Returns:
bytes: Computed checksum
addr_type
aXlmAddrTypes
aPUB_KEY
uAddress type is not an enumerative of XlmAddrTypes
aBase32Decoder
aDecode
aAddrDecUtils
aValidateLength
aEd25519PublicKey
aCompressedLength
aXlmAddrConst
aCHECKSUM_BYTE_LEN
aSplitPartsByChecksum
uInvalid address type (expected
value

u, got
w)aValidateChecksum
a_XlmAddrUtils
aComputeChecksum
:l nnaValidatePubKey

Decode a Stellar address to bytes.
Args:
ddr (str): Address string
Other Parameters:
ddr_type (XlmAddrTypes): Expected address type (default: public key)
Returns:
bytes: Public key bytes
Raises:
ValueError: If the address encoding is not valid
TypeError: If the address type is not a XlmAddrTypes enum
aAddrKeyValidator
aValidateAndGetEd25519Key
aIntegerUtils
aToBytes
aRawCompressed
aBase32Encoder
aEncodeNoPadding

Encode a public key to Stellar address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
ddr_type (XlmAddrTypes): Address type (default: public key)
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519 or address type is not a XlmAddrTypes enum
uModule for Stellar address encoding/decoding.
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
ubip_utils.ecc
T aEd25519PublicKey
aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aXModemCrc
ubip_utils.utils.misc
T aBase32Decoder
aBase32Encoder
aBytesUtils
aIntegerUtils
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
