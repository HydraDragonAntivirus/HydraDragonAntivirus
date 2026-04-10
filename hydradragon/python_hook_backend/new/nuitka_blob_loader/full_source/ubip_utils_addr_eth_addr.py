# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.eth_addr

uClass container for Ethereum address constants.
a__qualname__
a__annotations__
l l(uClass container for Ethereum address utility functions.
D aaddr
return
Ostr
pu_EthAddrUtils.ChecksumEncode
a__prepare__
aEthAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Ethereum address decoder class.
It allows the Ethereum address decoding.
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uEthAddrDecoder.DecodeAddr
a__orig_bases__
aEthAddrEncoder

Ethereum address encoder class.
It allows the Ethereum address encoding.
pub_key
aEncodeKey
uEthAddrEncoder.EncodeKey
aEthAddr
ubip_utils\addr\eth_addr.py
u<module bip_utils.addr.eth_addr>
T aaddr
addr_hex_digest
enc_addr
T aaddr
kwargs
skip_chksum_enc
addr_no_prefix
T apub_key
kwargs
skip_chksum_enc
pub_key_obj
kekkak_hex
addr
T a__class__
a__spec__
.bip_utils.addr.fil_addr
g
z
aIntegerUtils
aToBytes
aBlake2b32
aQuickDigest

Compute checksum in EOS format.
Args:
pub_key_hash (bytes)     : Public key hash
ddr_type (FillAddrTypes): Address type
Returns:
bytes: Computed checksum
aAddrDecUtils
aValidateAndRemovePrefix
aCoinsConf
aFilecoin
aParamByKey
T aaddr_prefix
l0uInvalid address type (expected

u, got
w)aBase32Decoder
aDecode
:l nnaFilAddrConst
aBASE32_ALPHABET
aValidateLength
aBlake2b160
aDigestSize
aSplitPartsByChecksum
aValidateChecksum
u<lambda>
u_FilAddrUtils.DecodeAddr.<locals>.<lambda>

Decode a Filecoin address to bytes.
Args:
ddr (str)               : Address string
ddr_type (FillAddrTypes): Address type
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
a_FilAddrUtils
aComputeChecksum
addr_type
aBase32Encoder
aEncodeNoPadding

Encode a public key to Filecoin address.
Args:
pub_key_bytes (bytes)    : Public key bytes
ddr_type (FillAddrTypes): Address type
Returns:
str: Address string
aDecodeAddr
aFillAddrTypes
aSECP256K1

Decode a Filecoin address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aRawUncompressed
aEncodeKeyBytes

Encode a public key to Filecoin address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
**kwargs                     : Not used
Returns:
str: Address string
Raised:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1 or the address type is not valid
uModule for Filecoin address encoding/decoding.
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
ubip_utils.coin_conf
T aCoinsConf
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aBlake2b32
aBlake2b160
ubip_utils.utils.misc
T aBase32Decoder
aBase32Encoder
aIntegerUtils
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
