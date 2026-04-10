# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.ergo_addr

uEnumerative for Ergo address types.
a__qualname__
l aP2SH
a__orig_bases__
uEnumerative for Ergo network types.
l aTESTNET
uClass container for Ergo address constants.
a__annotations__
l uErgo address utility class.
D apub_key_bytes
return
Obytes
pu_ErgoAddrUtils.ComputeChecksum
addr_type
return
u_ErgoAddrUtils.EncodePrefix
aErgoP2PKHAddrDecoder

Ergo P2PKH address decoder class.
It allows the Ergo P2PKH address decoding.
staticmethod
addr
str
kwargs
bytes
aDecodeAddr
uErgoP2PKHAddrDecoder.DecodeAddr
aErgoP2PKHAddrEncoder

Ergo P2PKH address encoder class.
It allows the Ergo P2PKH address encoding.
pub_key
aEncodeKey
uErgoP2PKHAddrEncoder.EncodeKey
aErgoP2PKHAddr
ubip_utils\addr\ergo_addr.py
u<module bip_utils.addr.ergo_addr>
T apub_key_bytes
T aaddr
kwargs
net_type
addr_dec_bytes
addr_with_prefix
checksum_bytes
pub_key_bytes
T apub_key
kwargs
net_type
pub_key_obj
pub_key_bytes
prefix_byte
addr_payload_bytes
T aaddr_type
net_type
T a__class__

a__spec__
.bip_utils.addr.eth_addr
a
def aBytesUtils
aToHexString
aKekkak256
aQuickDigest
lower
l aupper


Checksum encode the specified address.
Args:
ddr (str): Address string
Returns:
str: Checksum encoded address
skip_chksum_enc
aAddrDecUtils
aValidateAndRemovePrefix
aCoinsConf
aEthereum
aParamByKey
T aaddr_prefix
aValidateLength
aEthAddrConst
aADDR_LEN
a_EthAddrUtils
aChecksumEncode
uInvalid checksum encoding
aFromHexString

Decode an Ethereum address to bytes.
Args:
ddr (str): Address string
Other Parameters:
skip_chksum_enc (bool, optional): True to skip checksum encoding verification, false otherwise (default)
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aRawUncompressed
aToBytes
:l nnaSTART_BYTE

Encode a public key to Ethereum address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
skip_chksum_enc (bool, optional): True to skip checksum encoding, false otherwise (default)
Returns:
str: Address string
Raised:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for Ethereum address encoding/decoding.
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
T aKekkak256
ubip_utils.utils.misc
T aBytesUtils
