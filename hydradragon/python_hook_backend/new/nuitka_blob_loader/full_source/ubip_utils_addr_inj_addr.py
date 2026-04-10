# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.inj_addr


Injective address decoder class.
It allows the Injective address decoding.
a__qualname__
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uInjAddrDecoder.DecodeAddr
a__orig_bases__
aInjAddrEncoder

Injective address encoder class.
It allows the Injective address encoding.
pub_key
uInjAddrEncoder.EncodeKey
aInjAddr
ubip_utils\addr\inj_addr.py
u<module bip_utils.addr.inj_addr>
T aaddr
kwargs
addr_dec_bytes
ex
T apub_key
kwargs
pub_key_obj
eth_addr
T a__class__

a__spec__
.bip_utils.addr.nano_addr
g
aBytesUtils
aReverse
aBlake2b40
aQuickDigest

Compute checksum in Nano format.
Args:
pub_key_bytes (bytes): Public key bytes
Returns:
bytes: Computed checksum
aAddrDecUtils
aValidateAndRemovePrefix
aCoinsConf
aNano
aParamByKey
T aaddr_prefix
aBase32Decoder
aDecode
aNanoAddrConst
aPAYLOAD_PAD_ENC
aBASE32_ALPHABET
aValidateLength
aEd25519Blake2bPublicKey
aCompressedLength
aDigestSize
aPAYLOAD_PAD_DEC
aSplitPartsByChecksum
aValidateChecksum
a_NanoAddrUtils
aComputeChecksum
aValidatePubKey

Decode a Nano address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetEd25519Blake2bKey
aRawCompressed
aToBytes
:l nnaBase32Encoder
aEncodeNoPadding

Encode a public key to Nano address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs: Not used
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519-blake2b
uModule for Nano address encoding/decoding.
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
T aEd25519Blake2bPublicKey
aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aBlake2b40
ubip_utils.utils.misc
T aBase32Decoder
aBase32Encoder
aBytesUtils
