# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.okex_addr


OKEx Chain address decoder class.
It allows the OKEx Chain address decoding.
a__qualname__
staticmethod
addr
str
kwargs
return
bytes
uOkexAddrDecoder.DecodeAddr
a__orig_bases__
aOkexAddrEncoder

OKEx Chain address encoder class.
It allows the OKEx Chain address encoding.
pub_key
uOkexAddrEncoder.EncodeKey
aOkexAddr
ubip_utils\addr\okex_addr.py
u<module bip_utils.addr.okex_addr>
T aaddr
kwargs
addr_dec_bytes
ex
T apub_key
kwargs
eth_addr
T a__class__

a__spec__
.bip_utils.addr.one_addr
N
aBech32Decoder
aDecode
aCoinsConf
aHarmonyOne
aParamByKey
T aaddr_hrp
aBech32ChecksumError
uInvalid bech32 checksum
aEthAddrDecoder
aDecodeAddr
aEthereum
T aaddr_prefix
aBytesUtils
aToHexString
D askip_chksum_enc
tu
Decode a OKEx Chain address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aEthAddrEncoder
aEncodeKey
:l nnaBech32Encoder
aEncode
aFromHexString

Encode a public key to Harmony One address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs: Not used
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for Harmony One address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aUnion
ubip_utils.addr.eth_addr
T aEthAddrDecoder
aEthAddrEncoder
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
ubip_utils.utils.misc
T aBytesUtils
a__prepare__
aOneAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
