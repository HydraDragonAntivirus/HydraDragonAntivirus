# Reconstructed from integrated Nuitka blob
# Module: ubip32.utils

uWe derived an invalid (secret > N or point(secret) is infinity) key!
a__qualname__
a__orig_bases__
a_privkey_is_valid
a_pubkey_is_valid
a_derive_unhardened_private_child
a_derive_hardened_private_child
a_derive_public_child
T amain
a_serialize_extended_key
a_unserialize_extended_key
a_hardened_index_in_path
a_deriv_path_str_to_list
ubip32\utils.py
u<module bip32.utils>
T astrpath
indexes
list_path
wiT aprivkey
chaincode
index
payload
child_private
T apubkey
chaincode
index
payload
tmp_pub
parent_pub
child_pub
T aprivkey
chaincode
index
pubkey
payload
child_private
T apath
T aprivkey
T apubkey
T adata
rip
ripemd160
T akey
depth
parent
index
chaincode
network
param
fingerprint
is_privkey
prefix
extended
T aextended_key
prefix
network
depth
fingerprint
index
chaincode
key
a__spec__
.bip_utils._version
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
u2.9.3
a__version__
ubip_utils\_version.py
u<module bip_utils._version>

a__spec__
.bip_utils.addr.P2PKH_addr
'

net_ver
base58_alph
aBase58Alphabets
aBITCOIN
aBase58Decoder
aCheckDecode
aBase58ChecksumError
uInvalid base58 checksum
aAddrDecUtils
aValidateLength
aHash160
aDigestSize
aValidateAndRemovePrefix

Decode a P2PKH address to bytes.
Args:
ddr (str): Address string
Other Parameters:
net_ver (bytes)                        : Expected net address version
base58_alph (Base58Alphabets, optional): Base58 alphabet (default: Bitcoin alphabet)
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
pub_key_mode
aP2PKHPubKeyModes
aCOMPRESSED
aAddrKeyValidator
aValidateAndGetSecp256k1Key
aRawCompressed
aToBytes
aRawUncompressed
aBase58Encoder
aCheckEncode
aQuickDigest

Encode a public key to P2PKH address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
net_ver (bytes)                          : Net address version
base58_alph (Base58Alphabets, optional)  : Base58 alphabet, Bitcoin alphabet by default
pub_key_mode (P2PKHPubKeyModes, optional): Public key mode, compressed key by default
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
hrp
aBchBech32Decoder
aDecode
aBech32ChecksumError
uInvalid bech32 checksum
uInvalid net version (expected
aBytesUtils
aToHexString

u, got
w)u
Decode a Bitcoin Cash P2PKH address to bytes.
Args:
ddr (str): Address string
Other Parameters:
hrp (str)      : Expected HRP
net_ver (bytes): Expected net address version
Returns:
bytes: Public key hash bytes
Raises:
ValueError: If the address encoding is not valid
aBchBech32Encoder
aEncode

Encode a public key to Bitcoin Cash P2PKH address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
hrp (str)      : HRP
net_ver (bytes): Net address version
Returns:
str: Address string
Raises:
ValueError: If the public key is not valid
TypeError: If the public key is not secp256k1
uModule for P2PKH address encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aEnum
auto
unique
aEnum
auto
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
ubip_utils.base58
T aBase58Alphabets
aBase58ChecksumError
aBase58Decoder
aBase58Encoder
ubip_utils.bech32
T aBchBech32Decoder
aBchBech32Encoder
aBech32ChecksumError
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aHash160
ubip_utils.utils.misc
T aBytesUtils
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
