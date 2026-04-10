# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.P2TR_addr

uClass container for P2TR constants.
a__qualname__
a__annotations__
g	                                          aFromHexString
T ae80fe1639c9ca050e3af1b39c143c63e429cbceb15d940fbb5c5a1f4af57c5e9
uClass container for P2TR utility functions.
tag
T Obytes
Ostr
data_bytes
return
u_P2TRUtils.TaggedHash
pub_key
u_P2TRUtils.HashTapTweak
u_P2TRUtils.LiftX
u_P2TRUtils.TweakPublicKey
a__prepare__
aP2TRAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

P2WPKH address decoder class.
It allows the Pay-to-Witness-Public-Key-Hash address decoding.
staticmethod
addr
str
kwargs
bytes
aDecodeAddr
uP2TRAddrDecoder.DecodeAddr
a__orig_bases__
aP2TRAddrEncoder

P2TR address encoder class.
It allows the Pay-to-Taproot address encoding.
aEncodeKey
uP2TRAddrEncoder.EncodeKey
aP2TRAddr
ubip_utils\addr\P2TR_addr.py
u<module bip_utils.addr.P2TR_addr>
T aaddr
kwargs
hrp
wit_ver_got
addr_dec_bytes
ex
T apub_key
kwargs
hrp
pub_key_obj
T apub_key
T apub_key
wpwxwcwyT a__class__
T atag
data_bytes
tag_hash
T apub_key
whaout_point
a__spec__
.bip_utils.addr.P2WPKH_addr
B
M
hrp
aSegwitBech32Decoder
aDecode
aBech32ChecksumError
uInvalid bech32 checksum
aP2WPKHAddrConst
aWITNESS_VER
uInvalid witness version (expected

u, got
w)u
Decode a P2WPKH address to bytes.
Args:
ddr (str): Address string
Other Parameters:
hrp (str): Expected HRP
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aSegwitBech32Encoder
aEncode
aHash160
aQuickDigest
aRawCompressed
aToBytes

Encode a public key to P2WPKH address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
hrp (str): HRP
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1

Module for P2WPKH address encoding/decoding.
References:
https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aUnion
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
aSegwitBech32Decoder
aSegwitBech32Encoder
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aHash160
