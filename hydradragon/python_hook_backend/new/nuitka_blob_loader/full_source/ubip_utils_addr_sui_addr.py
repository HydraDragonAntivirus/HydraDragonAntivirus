# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.sui_addr

uClass container for Sui address constants.
a__qualname__
a__annotations__
d
a__prepare__
aSuiAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Sui address decoder class.
It allows the Sui address decoding.
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uSuiAddrDecoder.DecodeAddr
a__orig_bases__
aSuiAddrEncoder

Sui address encoder class.
It allows the Sui address encoding.
pub_key
aEncodeKey
uSuiAddrEncoder.EncodeKey
aSuiAddr
ubip_utils\addr\sui_addr.py
u<module bip_utils.addr.sui_addr>
T aaddr
kwargs
addr_no_prefix
T apub_key
kwargs
pub_key_obj
digest_bytes
T a__class__

a__spec__
.bip_utils.addr.trx_addr
U
aBase58Decoder
aCheckDecode
aBase58ChecksumError
uInvalid base58 checksum
aAddrDecUtils
aValidateLength
aEthAddrConst
aADDR_LEN
l aCoinsConf
aTron
aParamByKey
T aaddr_prefix
aValidateAndRemovePrefix
aEthAddrDecoder
aDecodeAddr
aEthereum
aBytesUtils
aToHexString
D askip_chksum_enc
tu
Decode a Tron address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aEthAddrEncoder
aEncodeKey
:l nnaBase58Encoder
aCheckEncode
aFromHexString

Encode a public key to Tron address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raised:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for Tron address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aUnion
ubip_utils.addr.addr_dec_utils
T aAddrDecUtils
ubip_utils.addr.eth_addr
T aEthAddrConst
aEthAddrDecoder
aEthAddrEncoder
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
ubip_utils.coin_conf
T aCoinsConf
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.misc
T aBytesUtils
a__prepare__
aTrxAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
