# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.substrate_addr

uSubstrate address utility class.
a__qualname__
addr
pub_key_cls
return
u_SubstrateAddrUtils.DecodeAddr
a__prepare__
aSubstrateEd25519AddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Substrate address decoder class, based on ed25519 curve.
It allows the Substrate address decoding.
staticmethod
str
kwargs
bytes
uSubstrateEd25519AddrDecoder.DecodeAddr
a__orig_bases__
aSubstrateEd25519AddrEncoder

Substrate address encoder class, based on ed25519 curve.
It allows the Substrate address encoding.
pub_key
aEncodeKey
uSubstrateEd25519AddrEncoder.EncodeKey
aSubstrateSr25519AddrDecoder

Substrate address decoder class, based on sr25519 curve.
It allows the Substrate address decoding.
uSubstrateSr25519AddrDecoder.DecodeAddr
aSubstrateSr25519AddrEncoder

Substrate address encoder class, based on sr25519 curve.
It allows the Substrate address encoding.
uSubstrateSr25519AddrEncoder.EncodeKey
aSubstrateEd25519Addr
aSubstrateSr25519Addr
ubip_utils\addr\substrate_addr.py
u<module bip_utils.addr.substrate_addr>
T aaddr
kwargs
T aaddr
ss58_format
pub_key_cls
ss58_format_got
addr_dec_bytes
ex
T apub_key
kwargs
ss58_format
pub_key_obj
T a__class__
a__spec__
.bip_utils.addr.sui_addr
M
U
aAddrDecUtils
aValidateAndRemovePrefix
aCoinsConf
aSui
aParamByKey
T aaddr_prefix
aValidateLength
aBlake2b256
aDigestSize
l aBytesUtils
aFromHexString

Decode a Sui address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetEd25519Key
aQuickDigest
aSuiAddrConst
aKEY_TYPE
aRawCompressed
aToBytes
:l nnaToHexString

Encode a public key to Sui address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519
uModule for Solana address encoding/decoding.
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
T aBlake2b256
ubip_utils.utils.misc
T aBytesUtils
