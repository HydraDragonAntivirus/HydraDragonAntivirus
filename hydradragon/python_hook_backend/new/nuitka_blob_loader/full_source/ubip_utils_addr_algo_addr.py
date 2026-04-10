# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.algo_addr

uClass container for Algorand address constants.
a__qualname__
a__annotations__
l uAlgorand address utility class.
D apub_key_bytes
return
Obytes
pu_AlgoAddrUtils.ComputeChecksum
a__prepare__
aAlgoAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Algorand address decoder class.
It allows the Algorand address decoding.
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uAlgoAddrDecoder.DecodeAddr
a__orig_bases__
aAlgoAddrEncoder

Algorand address encoder class.
It allows the Algorand address encoding.
pub_key
aEncodeKey
uAlgoAddrEncoder.EncodeKey
aAlgoAddr
ubip_utils\addr\algo_addr.py
u<module bip_utils.addr.algo_addr>
T a__class__
T apub_key_bytes
T aaddr
kwargs
addr_dec_bytes
pub_key_bytes
checksum_bytes
T apub_key
kwargs
pub_key_obj
pub_key_bytes
checksum_bytes

a__spec__
.bip_utils.addr.aptos_addr
:
]
aAddrDecUtils
aValidateAndRemovePrefix
aCoinsConf
aAptos
aParamByKey
T aaddr_prefix
rjust
aSha3_256
aDigestSize
l w0aValidateLength
aBytesUtils
aFromHexString
binascii
aError
uInvalid hex encoding

Decode an Aptos address to bytes.
Args:
ddr (str): Address string
**kwargs  : Not used
Returns:
bytes: Public key bytes
Raises:
ValueError: If the address encoding is not valid
trim_zeroes
aAddrKeyValidator
aValidateAndGetEd25519Key
aRawCompressed
aToBytes
:l nnaAptosAddrConst
aSINGLE_SIG_SUFFIX_BYTE
aToHexString
aQuickDigest
lstrip
T w0u
Encode a public key to Aptos address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
trim_zeroes (bool, optional): True to trim left zeroes from the address string, false otherwise (default)
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not ed25519
uModule for Aptos address encoding/decoding.
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
T aSha3_256
ubip_utils.utils.misc
T aBytesUtils
