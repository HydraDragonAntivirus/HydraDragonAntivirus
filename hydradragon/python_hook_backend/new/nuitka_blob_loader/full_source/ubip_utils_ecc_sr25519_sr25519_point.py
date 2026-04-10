# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.sr25519.sr25519_point

uSr25519 point class. Dummy class since not needed.
a__qualname__
staticmethod
return
aCurveType
uSr25519Point.CurveType
a__orig_bases__
ubip_utils\ecc\sr25519\sr25519_point.py
u<module bip_utils.ecc.sr25519.sr25519_point>
T a__class__

a__spec__
.bip_utils.electrum
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
electrum
T aNUITKA_PACKAGE_bip_utils_electrum
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.electrum.electrum_v1
T aElectrumV1
aElectrumV1
ubip_utils.electrum.electrum_v2
T aElectrumV2Segwit
aElectrumV2Standard
aElectrumV2Segwit
aElectrumV2Standard
ubip_utils\electrum\__init__.py
u<module bip_utils.electrum>

a__spec__
.bip_utils.electrum.electrum_v1
aFromPrivateKey

Construct class from seed bytes.
Args:
seed_bytes (bytes): Seed bytes
Returns:
ElectrumV1 object: ElectrumV1 object
aSecp256k1PrivateKey
aFromBytes

Construct class from private key.
Args:
priv_key (bytes or IPrivateKey): Private key
Returns:
ElectrumV1 object: ElectrumV1 object
Raises:
TypeError: if the private key is not a Secp256k1PrivateKey
aSecp256k1PublicKey

Construct class from public key.
Args:
pub_key (bytes or IPublicKey): Public key
Returns:
ElectrumV1 object: ElectrumV1 object
Raises:
TypeError: if the public key is not a Secp256k1PublicKey
uPrivate key shall be a secp256k1 key
m_priv_key
aPublicKey
m_pub_key
uPublic key shall be a secp256k1 key

Construct class.
Args:
priv_key (IPrivateKey object, optional): Private key (None for a public-only object)
pub_key (IPublicKey object, optional)  : Public key (only needed for a public-only object)
If priv_key is not None, it'll be discarded
Raises:
TypeError: if the private key is not a Secp256k1PrivateKey or the public key is not a Secp256k1PublicKey

Get if it's public-only.
Returns:
bool: True if public-only, false otherwise
aIsPublicOnly
uPublic-only deterministic keys have no private half

Get the master private key.
Returns:
IPrivateKey object: IPrivateKey object

Get the master public key.
Returns:
IPublicKey object: IPublicKey object
a_ElectrumV1__DerivePrivateKey

Get the private key with the specified change and address indexes.
Derivation path (not BIP32 derivation): m/change_idx/addr_idx
Args:
change_idx (int): Change index
ddr_idx (int)  : Address index
Returns:
IPrivateKey object: IPrivateKey object
Raises:
ValueError: If one of the index is not valid
a_ElectrumV1__DerivePublicKey
aGetPrivateKey

Get the public key with the specified change and address indexes.
Derivation path (not BIP32 derivation): m/change_idx/addr_idx
Args:
change_idx (int): Change index
ddr_idx (int)  : Address index
Returns:
IPublicKey object: IPublicKey object
Raises:
ValueError: If one of the index is not valid
aP2PKHAddr
aEncodeKey
aGetPublicKey
aCoinsConf
aBitcoinMainNet
aParamByKey
T ap2pkh_net_ver
aP2PKHPubKeyModes
aUNCOMPRESSED
T anet_ver
pub_key_mode

Get the address with the specified change and address indexes.
Derivation path (not BIP32 derivation): m/change_idx/addr_idx
Args:
change_idx (int): Change index
ddr_idx (int)  : Address index
Returns:
str: Address
Raises:
ValueError: If one of the index is not valid
a_ElectrumV1__ValidateIndexes
a_ElectrumV1__GetSequence
aMasterPrivateKey
aRaw
aToInt
aBytesUtils
aToInteger
aSecp256k1
aOrder
aIntegerUtils
aToBytes
aLength

Derive the private key with the specified change and address indexes.
Derivation path (not BIP32 derivation): m/change_idx/addr_idx
Args:
change_idx (int): Change index
ddr_idx (int)  : Address index
Returns:
IPrivateKey object: IPrivateKey object
Raises:
ValueError: If one of the index is not valid
aFromPoint
aMasterPublicKey
aPoint
aGenerator

Derive the public key with the specified change and address indexes.
Derivation path (not BIP32 derivation): m/change_idx/addr_idx
Args:
change_idx (int): Change index
ddr_idx (int)  : Address index
Returns:
IPublicKey object: IPublicKey object
Raises:
ValueError: If one of the index is not valid
aDoubleSha256
aQuickDigest
aAlgoUtils
aEncode

w:aRawUncompressed
:l nnu
Get sequence.
Args:
change_idx (int): Change index
ddr_idx (int)  : Address index
Returns:
bytes: Sequence bytes
aBip32KeyIndex

Validate indexes and raise a ValueError if not valid.
Args:
change_idx (int): Change index
ddr_idx (int)  : Address index
Raises:
ValueError: If one of the index is not valid
uModule containing utility classes for Electrum v1 keys derivation, since it uses its own algorithm.
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
T aP2PKHAddr
aP2PKHPubKeyModes
ubip_utils.bip.bip32
T aBip32KeyIndex
ubip_utils.coin_conf
T aCoinsConf
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aSecp256k1
aSecp256k1PrivateKey
aSecp256k1PublicKey
aIPrivateKey
aIPublicKey
ubip_utils.utils.crypto
T aDoubleSha256
ubip_utils.utils.misc
T aAlgoUtils
aBytesUtils
aIntegerUtils
