# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.bip32_key_net_ver

uClass container for BIP32 key net versions constants.
a__qualname__
a__annotations__
l u
BIP32 key net versions class.
It represents a BIP32 key net versions.
aBip32KeyNetVersions
D apub_net_ver
priv_net_ver
return
Obytes
pna__init__
uBip32KeyNetVersions.__init__
D areturn
Oint
uBip32KeyNetVersions.Length
D areturn
Obytes
aPublic
uBip32KeyNetVersions.Public
aPrivate
uBip32KeyNetVersions.Private
ubip_utils\bip\bip32\bip32_key_net_ver.py
u<module bip_utils.bip.bip32.bip32_key_net_ver>
T a__class__
T aself
T aself
pub_net_ver
priv_net_ver

a__spec__
.bip_utils.bip.bip32.bip32_key_ser
O
aDepth
aParentFingerPrint
aIndex
aChainCode
aBase58Encoder
aCheckEncode

Serialize the specified key bytes.
Args:
key_bytes (bytes)           : Key bytes
key_data (BipKeyData object): Key data
key_net_ver_bytes (bytes)   : Key net version bytes
Returns:
str: Serialized key
a_Bip32KeySerializer
aSerialize
d
aRaw
aToBytes
aPrivate

Serialize a private key.
Args:
priv_key (IPrivateKey object)                     : IPrivateKey object
key_data (BipKeyData object)                      : Key data
key_net_ver (Bip32KeyNetVersions object, optional): Key net versions (BIP32 main net version by default)
Returns:
str: Serialized private key
aRawCompressed
aPublic

Serialize a public key.
Args:
pub_key (IPublicKey object)                       : IPublicKey object
key_data (BipKeyData object)                      : Key data
key_net_ver (Bip32KeyNetVersions object, optional): Key net versions (BIP32 main net version by default)
Returns:
str: Serialized public key
m_key_bytes
m_key_data
m_is_public

Construct class.
Args:
key_bytes (bytes)           : Key bytes
key_data (BipKeyData object): Key data
is_public (bool)            : True if the key is public, false otherwise
Returns:
str: Serialized public key

Get key bytes.
Returns:
bytes: Key bytes

Get key data.
Returns:
Bip32KeyData object: Bip32KeyData object

Get if public.
Returns:
bool: True if the key is public, false otherwise
aBase58Decoder
aCheckDecode
a_Bip32KeyDeserializer__GetIfPublic
aBip32KeySerConst
aSERIALIZED_PUB_KEY_BYTE_LEN
aBip32KeyError
uInvalid extended public key (wrong length:

w)aSERIALIZED_PRIV_KEY_BYTE_LEN
uInvalid extended private key (wrong length:
a_Bip32KeyDeserializer__GetPartsFromBytes
aBip32DeserializedKey

Deserialize a key.
Args:
ser_key_str (str)                                 : Serialized key string
key_net_ver (Bip32KeyNetVersions object, optional): Key net versions (BIP32 main net version by default)
Returns:
Bip32DeserializedKey object: Bip32DeserializedKey object
Raises:
Bip32KeyError: If the key is not valid
aBip32KeyNetVersions
aLength
uInvalid extended key (wrong net version:
aBytesUtils
aToHexString

Get if the key is public.
Args:
ser_key_bytes (bytes)                   : Serialized key bytes
key_net_ver (Bip32KeyNetVersions object): Key net versions
Returns:
bool: True if public, false otherwise
Raises:
Bip32KeyError: If the key net version is not valid
aBip32Depth
aFixedLength
aBip32FingerPrint
aBip32KeyIndex
aBip32ChainCode
aBip32KeyData
aFromBytes
uInvalid extended private key (wrong secret:
:l nnu
Get back key parts from serialized key bytes.
Args:
ser_key_bytes (bytes): Serialized key bytes
is_public (bool)     : True if the key is public, false otherwise
Returns:
tuple[bytes, Bip32KeyData]: key bytes (index 0) and key data (index 1)
Raises:
Bip32KeyError: If the private key first byte is not zero
uModule for BIP32 extended key serialization/deserialization.
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
ubip_utils.base58
T aBase58Decoder
aBase58Encoder
ubip_utils.bip.bip32.bip32_const
T aBip32Const
aBip32Const
ubip_utils.bip.bip32.bip32_ex
T aBip32KeyError
ubip_utils.bip.bip32.bip32_key_data
T aBip32ChainCode
aBip32Depth
aBip32FingerPrint
aBip32KeyData
aBip32KeyIndex
ubip_utils.bip.bip32.bip32_key_net_ver
T aBip32KeyNetVersions
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
ubip_utils.utils.misc
T aBytesUtils
