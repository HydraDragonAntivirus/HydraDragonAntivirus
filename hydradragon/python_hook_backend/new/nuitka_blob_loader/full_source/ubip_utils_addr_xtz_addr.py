# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.xtz_addr

uEnumerative for Tezos address prefixes.
a__qualname__
c
aTZ1
c
aTZ2
c
aTZ3
a__orig_bases__
aXtzAddrDecoder

Tezos address decoder class.
It allows the Tezos address decoding.
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uXtzAddrDecoder.DecodeAddr
aXtzAddrEncoder

Tezos address encoder class.
It allows the Tezos address encoding.
pub_key
aEncodeKey
uXtzAddrEncoder.EncodeKey
aXtzAddr
ubip_utils\addr\xtz_addr.py
u<module bip_utils.addr.xtz_addr>
T aaddr
kwargs
prefix
addr_dec_bytes
ex
blake_bytes
T apub_key
kwargs
prefix
pub_key_obj
blake_bytes
T a__class__

a__spec__
.bip_utils.addr.zil_addr
T
aBech32Decoder
aDecode
aCoinsConf
aZilliqa
aParamByKey
T aaddr_hrp
aBech32ChecksumError
uInvalid bech32 checksum
aAddrDecUtils
aValidateLength
aZilAddrConst
aSHA256_BYTE_LEN

Decode a Zilliqa address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aSha256
aQuickDigest
aRawCompressed
aToBytes
aBech32Encoder
aEncode

Encode a public key to Zilliqa address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for Zilliqa address encoding/decoding.
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
aBech32Decoder
aBech32Encoder
ubip_utils.coin_conf
T aCoinsConf
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aSha256
