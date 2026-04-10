# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.substrate.substrate_ex

uException in case of Substrate key error.
a__qualname__
a__orig_bases__
aSubstratePathError
uException in case of Substrate path error.
ubip_utils\substrate\substrate_ex.py
u<module bip_utils.substrate.substrate_ex>

a__spec__
.bip_utils.substrate.substrate_keys
n
aFromBytes

Get the public key from key bytes or object.
Args:
pub_key (bytes or IPublicKey)       : Public key
coin_conf (SubstrateCoinConf object): SubstrateCoinConf object
Returns:
SubstratePublicKey object: SubstratePublicKey object
Raises:
SubstrateKeyError: If the key constructed from the bytes is not valid
a_SubstratePublicKey__KeyFromBytes

Create from bytes.
Args:
key_bytes (bytes)                   : Key bytes
coin_conf (SubstrateCoinConf object): SubstrateCoinConf object
Raises:
SubstrateKeyError: If the key constructed from the bytes is not valid
aSr25519PublicKey
uInvalid public key object type
m_pub_key
m_coin_conf

Construct class.
Args:
pub_key (IPublicKey object)         : Key object
coin_conf (SubstrateCoinConf object): SubstrateCoinConf object
Raises:
SubstrateKeyError: If the bytes length is not valid
TypeError: If the key is not a Sr25519PublicKey object

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
aSubstrateSr25519AddrEncoder
aEncodeKey
aAddrParams

Return the address correspondent to the public key.
Returns:
str: Address string
aSubstrateKeyError
T uInvalid public key

Construct key from bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPublicKey object: IPublicKey object
Raises:
SubstrateKeyError: If the key constructed from the bytes is not valid

Get the private key from key bytes or object.
Args:
priv_key (bytes or IPrivateKey)     : Private key
coin_conf (SubstrateCoinConf object): SubstrateCoinConf object
Returns:
SubstratePrivateKey object: SubstratePrivateKey object
Raises:
SubstrateKeyError: If the key constructed from the bytes is not valid
a_SubstratePrivateKey__KeyFromBytes
aSr25519PrivateKey
uInvalid private key object type
m_priv_key

Construct class.
Args:
priv_key (IPrivateKey object) : Key object
coin_conf (SubstrateCoinConf object): SubstrateCoinConf object
Raises:
SubstrateKeyError: If the bytes length is not valid
TypeError: If the key is not a Sr25519PrivateKey object

Return the key object.
Returns:
IPrivateKey object: Key object
aRaw

Return raw private key.
Returns:
DataBytes object: DataBytes object
aSubstratePublicKey
aPublicKey

Get the public key correspondent to the private one.
Returns:
SubstratePublicKey object: SubstratePublicKey object
T uInvalid private key

Construct key from bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPrivateKey object: IPrivateKey object
Raises:
SubstrateKeyError: If the key constructed from the bytes is not valid
uModule for Substrate keys handling.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
lru_cache
aUnion
ubip_utils.addr
T aSubstrateSr25519AddrEncoder
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aSr25519PrivateKey
aSr25519PublicKey
aIPrivateKey
aIPublicKey
ubip_utils.substrate.conf
T aSubstrateCoinConf
aSubstrateCoinConf
ubip_utils.substrate.substrate_ex
T aSubstrateKeyError
ubip_utils.utils.misc
T aDataBytes
aDataBytes
