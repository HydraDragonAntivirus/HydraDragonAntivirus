# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.mnemonic.monero_seed_generator


Monero seed generator class.
It generates the seed from a mnemonic.
aMoneroSeedGenerator
a__qualname__
a__annotations__
T namnemonic
lang
return
a__init__
uMoneroSeedGenerator.__init__
D areturn
Obytes
aGenerate
uMoneroSeedGenerator.Generate
ubip_utils\monero\mnemonic\monero_seed_generator.py
u<module bip_utils.monero.mnemonic.monero_seed_generator>
T aself
T a__class__
T aself
mnemonic
lang

a__spec__
.bip_utils.monero.monero
aEd25519MoneroPrivateKey
aLength
aKekkak256
aQuickDigest
aFromPrivateSpendKey
aEd25519Utils
aScalarReduce

Create from seed bytes.
Args:
seed_bytes (bytes)               : Seed bytes
coin_type (MoneroCoins, optional): Coin type (default: main net)
Returns:
Monero object: Monero object
aRaw
aToBytes

Create from Bip44 private key bytes.
Args:
priv_key (bytes or IPrivateKey)  : Private key
coin_type (MoneroCoins, optional): Coin type (default: main net)
Returns:
Monero object: Monero object
T apriv_key
coin_type

Create from private spend key.
Args:
priv_skey (bytes or IPrivateKey) : Private spend key
coin_type (MoneroCoins, optional): Coin type (default: main net)
Returns:
Monero object: Monero object
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid
T apriv_key
pub_key
coin_type

Create from private view key and public spend key (i.e. watch-only wallet).
Args:
priv_vkey (bytes or IPrivateKey) : Private view key
pub_skey (bytes or IPublicKey)   : Public spend key
coin_type (MoneroCoins, optional): Coin type (default: main net)
Returns:
Monero object: Monero object
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid
aMoneroPrivateKey
aFromBytesOrKeyObject
m_priv_skey
a_Monero__ViewFromSpendKey
m_priv_vkey
aPublicKey
m_pub_skey
m_pub_vkey
aMoneroPublicKey
aMoneroConfGetter
aGetConfig
self
m_coin_conf
aMoneroSubaddress
m_subaddr

Construct class.
Args:
priv_key (bytes or IPrivateKey)  : Private key (view key if watch-only wallet, otherwise spend key)
pub_key (bytes or IPublicKey)    : Public spend key (only needed for watch-only wallets, otherwise None)
coin_type (MoneroCoins, optional): Coin type (default: main net)
Raises:
MoneroKeyError: If the key constructed from the bytes is not valid

Return if it's a watch-only object.
Returns:
bool: True if watch-only, false otherwise

Return coin configuration.
Returns:
MoneroCoinConf object: MoneroCoinConf object
aIsWatchOnly
aMoneroKeyError
T uWatch-only class has not a private spend key

Return the private spend key.
Returns:
MoneroPrivateKey object: MoneroPrivateKey object
Raises:
MoneroKeyError: If the class is watch-only

Return the private view key.
Returns:
MoneroPrivateKey object: MoneroPrivateKey object

Return the public spend key.
Returns:
MoneroPublicKey object: MoneroPublicKey object

Return the public view key.
Returns:
MoneroPublicKey object: MoneroPublicKey object
aXmrIntegratedAddrEncoder
aEncodeKey
aKeyObject
aIntegratedAddrNetVersion
T apub_vkey
net_ver
payment_id

Return the integrated address with the specified payment ID.
Args:
payment_id (bytes): Payment ID
Returns:
str: Integrated address string
aComputeAndEncodeKeys
aAddrNetVersion

Return the primary address.
Returns:
str: Primary address string
aPrimaryAddress
aSubaddrNetVersion

Return the specified subaddress.
Args:
minor_idx (int)          : Minor index (i.e. subaddress index)
major_idx (int, optional): Major index (i.e. account index, default: 0)
Returns:
str: Subaddress string
Raises:
ValueError: If one of the indexes is not valid
aFromBytes

Get the private view key from the private spend key.
Args:
priv_skey (MoneroPrivateKey object): Private spend key
Returns:
MoneroPrivateKey object: Private view key
uModule for Monero keys computation and derivation.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
lru_cache
aOptional
aUnion
ubip_utils.addr
T aXmrIntegratedAddrEncoder
ubip_utils.ecc
T aEd25519MoneroPrivateKey
aEd25519Utils
aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
ubip_utils.monero.conf
T aMoneroCoinConf
aMoneroCoins
aMoneroConfGetter
aMoneroCoinConf
aMoneroCoins
ubip_utils.monero.monero_ex
T aMoneroKeyError
ubip_utils.monero.monero_keys
T aMoneroPrivateKey
aMoneroPublicKey
ubip_utils.monero.monero_subaddr
T aMoneroSubaddress
ubip_utils.utils.crypto
T aKekkak256
