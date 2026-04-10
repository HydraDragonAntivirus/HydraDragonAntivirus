# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.addr.P2WPKH_addr

uClass container for P2WPKH constants.
a__qualname__
a__annotations__
a__prepare__
aP2WPKHAddrDecoder
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
return
bytes
aDecodeAddr
uP2WPKHAddrDecoder.DecodeAddr
a__orig_bases__
aP2WPKHAddrEncoder

P2WPKH address encoder class.
It allows the Pay-to-Witness-Public-Key-Hash address encoding.
pub_key
aEncodeKey
uP2WPKHAddrEncoder.EncodeKey
aP2WPKHAddr
ubip_utils\addr\P2WPKH_addr.py
u<module bip_utils.addr.P2WPKH_addr>
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
T a__class__
a__spec__
.bip_utils.addr.ada_byron_addr
)
aChaCha20Poly1305
aDecrypt
aAdaByronAddrConst
aCHACHA20_POLY1305_NONCE
aCHACHA20_POLY1305_ASSOC_DATA
aTagSize
T akey
nonce
assoc_data
cipher_text
tag
aBip32Path
aCborIndefiniteLenArrayDecoder
aDecode

Encrypt the HD path.
Args:
hd_path_enc_bytes (bytes): Encrypted HD path bytes
hd_path_key_bytes (bytes): HD path key bytes
Returns:
Bip32Path object: Bip32Path object
Raises:
ValueError: If the decryption fails or the path cannot be decoded
aEncrypt
aCborIndefiniteLenArrayEncoder
aEncode
aToList
T akey
nonce
assoc_data
plain_text

Encrypt the HD path.
Args:
hd_path (Bip32Path object): HD path
hd_path_key_bytes (bytes) : HD path key bytes
Returns:
bytes: Computed key bytes
l uInvalid address attributes
cbor2
loads

Create from dictionary.
Args:
ttrs_dict (dict[int, bytes]): Attributes dictionary
Returns:
_AdaByronAddrAttrs object: _AdaByronAddrAttrs object
Raises:
ValueError: If the dictionary is not valid
hd_path_enc_bytes
dumps
network_magic

Get as a dictionary.
Returns:
dict[int, bytes]: Attributes dictionary
aBlake2b224
aQuickDigest
aSha3_256
aSerialize

Get the address root hash.
Returns:
bytes: Address root hash bytes
type
spending_data
attrs
aToDict

Serialize the address root.
Returns:
bytes: Serialized address root bytes
uInvalid address payload
aAddrDecUtils
aValidateLength
aDigestSize
a_AdaByronAddrAttrs
aFromDict
aAdaByronAddrTypes

Deserialize from payload bytes.
Args:
ser_payload_bytes (bytes): Serialized payload bytes
Returns:
_AdaByronAddrPayload object: _AdaByronAddrPayload object
Raises:
ValueError: If the serialization is not valid
root_hash_bytes

Serialize the address payload.
Returns:
bytes: Serialized address payload bytes
aDeserialize
aBase58Decoder

Decode address.
Args:
ddr (str): Address string
Returns:
_AdaByronAddr object: _AdaByronAddr object
Raises:
ValueError: If the serialization is not valid
aBase58Encoder

Encode address.
Returns:
str: Encoded address string
aCBORTag
uInvalid address encoding
tag
aPAYLOAD_TAG
uInvalid CBOR tag (

w)aCrc32
aQuickIntDigest
value
uInvalid CRC (expected:
u, got:
a_AdaByronAddrPayload

Deserialize from address bytes.
Args:
ser_addr_bytes (bytes): Serialized address bytes
Returns:
_AdaByronAddrPayload object: _AdaByronAddrPayload object
Raises:
ValueError: If the serialization is not valid
payload

Serialize the address.
Returns:
bytes: Serialized address bytes
a_AdaByronAddrRoot
a_AdaByronAddrSpendingData
:l nnaHash
a_AdaByronAddr

Encode a public key to Cardano Byron address.
Args:
pub_key_bytes (bytes)              : Public key bytes
chain_code_bytes (bytes)           : Chain code bytes
ddr_type (AdaByronAddrTypes)      : Address type
hd_path_enc_bytes (bytes, optional): Encrypted HD path bytes
Returns:
str: Address string
a_AdaByronAddrHdPath

Decrypt an HD path using the specified key.
Args:
hd_path_enc_bytes (bytes): Encrypted HD path bytes
hd_path_key_bytes (bytes): HD path key bytes
Returns:
Bip32Path object: Bip32Path object
Raises:
ValueError: If the decryption fails

Split the decoded bytes into address root hash and encrypted HD path.
Args:
dec_bytes (bytes): Decoded bytes
Returns:
tuple[bytes, bytes]: Address root hash (index 0), encrypted HD path (index 1)
addr_type
aPUBLIC_KEY
uAddress type is not an enumerative of AdaByronAddrTypes
uInvalid address type (expected:
c
aCBORDecodeValueError
uInvalid CBOR encoding

Decode a Cardano Byron address (either legacy or Icarus) to bytes.
The result can be split with SplitDecodedBytes if needed, to get the address root hash and
encrypted HD path separately.
Args:
ddr (str): Address string
Other Parameters:
ddr_type (AdaByronAddrTypes): Expected address type (default: public key)
Returns:
bytes: Address root hash bytes (first 28-byte) and encrypted HD path (following bytes, if present)
Raises:
ValueError: If the address encoding is not valid
TypeError: If the address type is not a AdaByronAddrTypes enum
chain_code
aBip32ChainCode
aToBytes
a_AdaByronAddrUtils
aEncodeKey
aAddrKeyValidator
aValidateAndGetEd25519Key
aRawCompressed

Encode a public key to Cardano Byron address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
chain_code (bytes or Bip32ChainCode object): Chain code bytes or object
Returns:
str: Address string
Raises:
Bip32PathError: If the path indexes are not valid
ValueError: If the public key, the chain code or the HD path key is not valid
TypeError: If the public key is not ed25519
hd_path
aBip32PathParser
aParse
hd_path_key
aKeySize
uHD path key shall be 32-byte long

Encode a public key to Cardano Byron address.
Args:
pub_key (bytes or IPublicKey): Public key bytes or object
Other Parameters:
chain_code (bytes or Bip32ChainCode object): Chain code bytes or object
hd_path (str or Bip32Path object)          : HD path
hd_path_key (bytes)                        : HD path key bytes, shall be 32-byte long
Returns:
str: Address string
Raises:
Bip32PathError: If the path indexes are not valid
ValueError: If the public key, the chain code or the HD path key is not valid
TypeError: If the public key is not ed25519

Module for Cardano Byron address encoding/decoding. Both legacy and Icarus addresses are supported.
References:
https://cips.cardano.org/cips/cip19
https://raw.githubusercontent.com/cardano-foundation/CIPs/master/CIP-0019/CIP-0019-byron-addresses.cddl
a__doc__
a__file__
origin
has_location
a__cached__
annotations
enum
T aIntEnum
unique
aIntEnum
unique
aAny
aDict
aNamedTuple
aOptional
aTuple
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
T aBase58Decoder
aBase58Encoder
ubip_utils.bip.bip32
T aBip32ChainCode
aBip32Path
aBip32PathParser
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aBlake2b224
aChaCha20Poly1305
aCrc32
aSha3_256
ubip_utils.utils.misc
T aCborIndefiniteLenArrayDecoder
aCborIndefiniteLenArrayEncoder
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
