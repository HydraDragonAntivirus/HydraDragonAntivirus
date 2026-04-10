# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.bip32_key_ser

uClass container for BIP32 key serialize constants.
a__qualname__
a__annotations__
lNT lNlnT Oint
pu
BIP32 key serializer class.
It serializes private/public keys.
key_bytes
key_data
key_net_ver_bytes
return
u_Bip32KeySerializer.Serialize

BIP32 private key serializer class.
It serializes private keys.
aBip32PrivateKeySerializer
aMAIN_NET_KEY_NET_VERSIONS
priv_key
key_net_ver
uBip32PrivateKeySerializer.Serialize

BIP32 public key serializer class.
It serializes public keys.
aBip32PublicKeySerializer
pub_key
uBip32PublicKeySerializer.Serialize

BIP32 deserialized key class.
It represents a key deserialized with the Bip32KeyDeserializer.
is_public
a__init__
uBip32DeserializedKey.__init__
D areturn
Obytes
aKeyBytes
uBip32DeserializedKey.KeyBytes
aKeyData
uBip32DeserializedKey.KeyData
D areturn
Obool
aIsPublic
uBip32DeserializedKey.IsPublic

BIP32 key deserializer class.
It deserializes an extended key.
aBip32KeyDeserializer
ser_key_str
aDeserializeKey
uBip32KeyDeserializer.DeserializeKey
ser_key_bytes
a__GetIfPublic
uBip32KeyDeserializer.__GetIfPublic
a__GetPartsFromBytes
uBip32KeyDeserializer.__GetPartsFromBytes
ubip_utils\bip\bip32\bip32_key_ser.py
u<module bip_utils.bip.bip32.bip32_key_ser>
T a__class__
T acls
ser_key_str
key_net_ver
ser_key_bytes
is_public
key_bytes
key_data
T aself
T apriv_key
key_data
key_net_ver
T apub_key
key_data
key_net_ver
T akey_bytes
key_data
key_net_ver_bytes
ser_key
T aser_key_bytes
key_net_ver
key_net_ver_got
is_public
Taser_key_bytes
is_public
depth_idx
fprint_idx
key_index_idx
chain_code_idx
key_idx
depth
fprint_bytes
key_index_bytes
chain_code_bytes
key_bytes
key_data
T aself
key_bytes
key_data
is_public
a__spec__
.bip_utils.bip.bip32.bip32_keys
2'
aEllipticCurveGetter
aFromType
m_curve
m_curve_type
m_key_data
m_key_net_ver

Construct class.
Args:
key_data (Bip32KeyData object)          : Key data
key_net_ver (Bip32KeyNetVersions object): Key net versions
curve_type (EllipticCurveTypes)         : Elliptic curve type

Return key elliptic curve.
Returns:
EllipticCurve object: EllipticCurve object

Return key elliptic curve type.
Returns:
EllipticCurveTypes: Elliptic curve type

Return key data.
Returns:
BipKeyData object: BipKeyData object
aData
aChainCode

Return the chain code.
Returns:
Bip32ChainCode object: Bip32ChainCode object

Get key net versions.
Returns:
Bip32KeyNetVersions object: Bip32KeyNetVersions object
aFromBytes
aIPoint
aFromPoint

Get the public key from key bytes or object.
Args:
pub_key (bytes, IPoint or IPublicKey)   : Public key
key_data (Bip32KeyData object)          : Key data
key_net_ver (Bip32KeyNetVersions object): Key net versions
curve_type (EllipticCurveTypes)         : Elliptic curve type
Returns:
Bip32PublicKey object: Bip32PublicKey object
Raises:
Bip32KeyError: If the key constructed from the bytes is not valid
a_Bip32PublicKey__KeyFromBytes

Create from bytes.
Args:
key_bytes (bytes)                       : Key bytes
key_data (Bip32KeyData object)          : Key data
key_net_ver (Bip32KeyNetVersions object): Key net versions
curve_type (EllipticCurveTypes)         : Elliptic curve type
Raises:
Bip32KeyError: If the key constructed from the bytes is not valid
a_Bip32PublicKey__KeyFromPoint

Create from point.
Args:
key_point (IPoint object)               : Key point
key_data (Bip32KeyData object)          : Key data
key_net_ver (Bip32KeyNetVersions object): Key net versions
Raises:
Bip32KeyError: If the key constructed from the bytes is not valid
a__class__
a__init__
aCurveType
m_pub_key

Construct class.
Args:
pub_key (IPublicKey object)             : Key object
key_data (Bip32KeyData object)          : Key data
key_net_ver (Bip32KeyNetVersions object): Key net versions

Return the key object.
Returns:
IPublicKey object: Key object
aRawCompressed

Return raw compressed public key.
Returns:
DataBytes object: DataBytes object
aRawUncompressed

Return raw uncompressed public key.
Returns:
DataBytes object: DataBytes object
aPoint

Get public key point.
Returns:
IPoint object: IPoint object
aBip32FingerPrint
aKeyIdentifier

Get key fingerprint.
Returns:
bytes: Key fingerprint bytes
aHash160
aQuickDigest
aToBytes

Get key identifier.
Returns:
bytes: Key identifier bytes
aBip32PublicKeySerializer
aSerialize

Return key in serialized extended format.
Returns:
str: Key in serialized extended format
aPublicKeyClass
aBip32KeyError
T uInvalid public key bytes

Construct key from bytes.
Args:
key_bytes (bytes)              : Key bytes
curve_type (EllipticCurveTypes): Elliptic curve type
Returns:
IPublicKey object: IPublicKey object
Raises:
Bip32KeyError: If the key constructed from the bytes is not valid
T uInvalid public key point

Construct key from point.
Args:
key_point (IPoint object): Key point
Returns:
IPublicKey object: IPublicKey object
Raises:
Bip32KeyError: If the key constructed from the bytes is not valid

Get the public key from key bytes or object.
Args:
priv_key (bytes or IPrivateKey)         : Private key
key_data (Bip32KeyData object)          : Key data
key_net_ver (Bip32KeyNetVersions object): Key net versions
curve_type (EllipticCurveTypes)         : Elliptic curve type
Returns:
Bip32PrivateKey object: Bip32PrivateKey object
Raises:
Bip32KeyError: If the key constructed from the bytes is not valid
a_Bip32PrivateKey__KeyFromBytes
m_priv_key

Construct class.
Args:
priv_key (IPrivateKey object)           : Key object
key_data (Bip32KeyData object)          : Key data
key_net_ver (Bip32KeyNetVersions object): Key net versions

Return the key object.
Returns:
IPrivateKey object: Key object
aRaw

Return raw private key.
Returns:
DataBytes object: DataBytes object
aBip32PublicKey
aPublicKey

Get the public key correspondent to the private one.
Returns:
Bip32PublicKey object: Bip32PublicKey object
aBip32PrivateKeySerializer
aPrivateKeyClass
T uInvalid private key bytes

Construct key from bytes.
Args:
key_bytes (bytes)              : Key bytes
curve_type (EllipticCurveTypes): Elliptic curve type
Returns:
IPrivateKey object: IPrivateKey object
Raises:
Bip32KeyError: If the key constructed from the bytes is not valid
uModule for BIP32 keys handling.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
T aABC
abstractmethod
aABC
abstractmethod
lru_cache
aUnion
ubip_utils.bip.bip32.bip32_ex
T aBip32KeyError
ubip_utils.bip.bip32.bip32_key_data
T aBip32ChainCode
aBip32FingerPrint
aBip32KeyData
aBip32ChainCode
aBip32KeyData
ubip_utils.bip.bip32.bip32_key_net_ver
T aBip32KeyNetVersions
aBip32KeyNetVersions
ubip_utils.bip.bip32.bip32_key_ser
T aBip32PrivateKeySerializer
aBip32PublicKeySerializer
ubip_utils.ecc
T aEllipticCurve
aEllipticCurveGetter
aEllipticCurveTypes
aIPoint
aIPrivateKey
aIPublicKey
aEllipticCurve
aEllipticCurveTypes
aIPrivateKey
aIPublicKey
ubip_utils.utils.crypto
T aHash160
ubip_utils.utils.misc
T aDataBytes
aDataBytes
a__prepare__
a_Bip32KeyBase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
