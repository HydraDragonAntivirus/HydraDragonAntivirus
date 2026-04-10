# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.aptos_addr

uClass container for Aptos address constants.
a__qualname__
a__annotations__
d
a__prepare__
aAptosAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Aptos address decoder class.
It allows the Aptos address decoding.
staticmethod
addr
str
kwargs
return
bytes
aDecodeAddr
uAptosAddrDecoder.DecodeAddr
a__orig_bases__
aAptosAddrEncoder

Aptos address encoder class.
It allows the Aptos address encoding.
pub_key
aEncodeKey
uAptosAddrEncoder.EncodeKey
aAptosAddr
ubip_utils\addr\aptos_addr.py
u<module bip_utils.addr.aptos_addr>
T a__class__
T aaddr
kwargs
addr_no_prefix
ex
T apub_key
kwargs
trim_zeroes
pub_key_obj
payload_bytes
key_hash_str

a__spec__
.bip_utils.addr.atom_addr
K
hrp
aBech32Decoder
aDecode
aBech32ChecksumError
uInvalid bech32 checksum
aAddrDecUtils
aValidateLength
aHash160
aDigestSize

Decode an Algorand address to bytes.
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
aBech32Encoder
aEncode
aQuickDigest
aRawCompressed
aToBytes

Encode a public key to Atom address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
hrp (str): HRP
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for Atom address encoding/decoding.
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
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aHash160
a__prepare__
aAtomAddrDecoder
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
