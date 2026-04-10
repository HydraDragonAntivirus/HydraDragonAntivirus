# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.egld_addr


Elrond address decoder class.
It allows the Elrond address decoding.
a__qualname__
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uEgldAddrDecoder.DecodeAddr
a__orig_bases__
aEgldAddrEncoder

Elrond address encoder class.
It allows the Elrond address encoding.
pub_key
aEncodeKey
uEgldAddrEncoder.EncodeKey
aEgldAddr
ubip_utils\addr\egld_addr.py
u<module bip_utils.addr.egld_addr>
T aaddr
kwargs
addr_dec_bytes
ex
T a__class__
T apub_key
kwargs
pub_key_obj

a__spec__
.bip_utils.addr.eos_addr
>
_
aRipemd160
aQuickDigest
aEosAddrConst
aCHECKSUM_BYTE_LEN

Compute checksum in EOS format.
Args:
pub_key_bytes (bytes): Public key bytes
Returns:
bytes: Computed checksum
aAddrDecUtils
aValidateAndRemovePrefix
aCoinsConf
aEos
aParamByKey
T aaddr_prefix
aBase58Decoder
aDecode
aValidateLength
aSecp256k1PublicKey
aCompressedLength
aSplitPartsByChecksum
aValidateChecksum
a_EosAddrUtils
aComputeChecksum
aValidatePubKey

Decode an EOS address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aRawCompressed
aToBytes
aBase58Encoder
aEncode

Encode a public key to EOS address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raised:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for EOS address encoding/decoding.
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
T aBase58Decoder
aBase58Encoder
ubip_utils.coin_conf
T aCoinsConf
ubip_utils.ecc
T aIPublicKey
aSecp256k1PublicKey
aIPublicKey
ubip_utils.utils.crypto
T aRipemd160
