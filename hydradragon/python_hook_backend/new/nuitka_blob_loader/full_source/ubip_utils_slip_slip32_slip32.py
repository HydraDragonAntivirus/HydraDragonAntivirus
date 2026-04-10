# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.slip.slip32.slip32

uClass container for SLIP32 key serialize constants.
aSlip32KeySerConst
a__qualname__
a__annotations__
T axpub
xprv
aSTD_KEY_NET_VERSIONS

SLIP32 key serializer class.
It serializes private/public keys.
key_bytes
chain_code
key_net_ver_str
return
u_Slip32KeySerializer.Serialize
a__SerializePath
u_Slip32KeySerializer.__SerializePath

SLIP32 private key serializer class.
It serializes private keys.
aSlip32PrivateKeySerializer
priv_key
key_net_ver
uSlip32PrivateKeySerializer.Serialize

SLIP32 public key serializer class.
It serializes public keys.
aSlip32PublicKeySerializer
pub_key
uSlip32PublicKeySerializer.Serialize

SLIP32 deserialized key class.
It represents a key deserialized with the Slip32KeyDeserializer.
is_public
a__init__
uSlip32DeserializedKey.__init__
D areturn
Obytes
aKeyBytes
uSlip32DeserializedKey.KeyBytes
aPath
uSlip32DeserializedKey.Path
aChainCode
uSlip32DeserializedKey.ChainCode
D areturn
Obool
aIsPublic
uSlip32DeserializedKey.IsPublic

SLIP32 key deserializer class.
It deserializes an extended key.
aSlip32KeyDeserializer
ser_key_str
aDeserializeKey
uSlip32KeyDeserializer.DeserializeKey
a__GetIfPublic
uSlip32KeyDeserializer.__GetIfPublic
ser_key_bytes
a__GetPartsFromBytes
uSlip32KeyDeserializer.__GetPartsFromBytes
ubip_utils\slip\slip32\slip32.py
u<module bip_utils.slip.slip32.slip32>
T aself
T acls
ser_key_str
key_net_ver
is_public
ser_key_bytes
key_bytes
path
chain_code
T apriv_key
path
chain_code
key_net_ver
T apub_key
path
chain_code
key_net_ver
T acls
key_bytes
path
chain_code
key_net_ver_str
ser_key
T a__class__
T aser_key_str
key_net_ver
is_public
T aser_key_bytes
is_public
depth_idx
path_idx
depth
path
wiakey_index_bytes
chain_code_idx
key_idx
chain_code_bytes
key_bytes
T apath
path_bytes
path_elem
T aself
key_bytes
path
chain_code
is_public
a__spec__
.bip_utils.slip.slip32.slip32_key_net_ver
m_pub_net_ver
m_priv_net_ver

Construct class.
Args:
pub_net_ver (str) : Public net version
priv_net_ver (str): Private net version

Get public net version.
Returns:
str: Public net version

Get private net version.
Returns:
str: Private net version
uModule for SLIP32 net version class.
a__doc__
a__file__
origin
has_location
a__cached__
