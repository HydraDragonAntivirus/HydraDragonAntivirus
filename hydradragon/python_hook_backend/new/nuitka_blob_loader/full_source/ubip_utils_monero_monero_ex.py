# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.monero_ex

uException in case of Monero key error.
a__qualname__
a__orig_bases__
ubip_utils\monero\monero_ex.py
u<module bip_utils.monero.monero_ex>

a__spec__
.bip_utils.monero.monero_keys
o
aFromBytes

Get the public key from key bytes or object.
Args:
pub_key (bytes or IPublicKey): Public key
Returns:
MoneroPublicKey object: MoneroPublicKey object
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid
a_MoneroPublicKey__KeyFromBytes

Create from bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
MoneroPublicKey object: MoneroPublicKey object
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid
a_MoneroPublicKey__KeyFromPoint

Create from point.
Args:
key_point (IPoint object): Key point
Returns:
MoneroPublicKey object: MoneroPublicKey object
Raises:
Bip32KeyError: If the key constructed from the bytes is not valid
aEd25519MoneroPublicKey
uInvalid public key object type
m_pub_key

Construct class.
Args:
pub_key (IPublicKey object): Key object
Raises:
MoneroKeyError: If the bytes length is not valid
TypeError: If the key is not a Ed25519MoneroPublicKey object

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
aMoneroKeyError
T uInvalid public key

Construct key from bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPublicKey object: IPublicKey object
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid
aFromPoint
T uInvalid key point

Construct key from point.
Args:
key_point (IPoint object): Key point
Returns:
IPublicKey object: IPublicKey object
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid

Get the private key from key bytes or object.
Args:
priv_key (bytes or IPrivateKey): Private key
Returns:
MoneroPrivateKey object: MoneroPrivateKey object
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid
a_MoneroPrivateKey__KeyFromBytes

Create from bytes.
Args:
key_bytes (bytes): Key bytes
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid
aEd25519MoneroPrivateKey
uInvalid private key object type
m_priv_key

Construct class.
Args:
priv_key (IPrivateKey object): Key object
Raises:
MoneroKeyError: If the bytes length is not valid
TypeError: If the key is not a Ed25519MoneroPrivateKey object

Return the key object.
Returns:
IPrivateKey object: Key object
aRaw

Return raw private key.
Returns:
DataBytes object: DataBytes object
aMoneroPublicKey
aPublicKey

Get the public key correspondent to the private one.
Returns:
MoneroPublicKey object: MoneroPublicKey object
T uInvalid private key

Construct key from bytes.
Args:
key_bytes (bytes): Key bytes
Returns:
IPrivateKey object: IPrivateKey object
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid
uModule for Monero keys handling.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
lru_cache
aUnion
ubip_utils.ecc
T aEd25519MoneroPrivateKey
aEd25519MoneroPublicKey
aIPoint
aIPrivateKey
aIPublicKey
aIPoint
aIPrivateKey
aIPublicKey
ubip_utils.monero.monero_ex
T aMoneroKeyError
ubip_utils.utils.misc
T aDataBytes
aDataBytes
