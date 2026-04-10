# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.mnemonic.cardano_icarus_seed_generator


Cardano Icarus seed generator class.
It generates seeds from a BIP39 mnemonic for Cardano Icarus.
aCardanoIcarusSeedGenerator
a__qualname__
a__annotations__
T namnemonic
lang
return
a__init__
uCardanoIcarusSeedGenerator.__init__
D areturn
Obytes
aGenerate
uCardanoIcarusSeedGenerator.Generate
ubip_utils\cardano\mnemonic\cardano_icarus_seed_generator.py
u<module bip_utils.cardano.mnemonic.cardano_icarus_seed_generator>
T a__class__
T aself
T aself
mnemonic
lang

a__spec__
.bip_utils.cardano.mnemonic
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ucardano\mnemonic
T aNUITKA_PACKAGE_bip_utils_cardano
u\not_existing
mnemonic
T aNUITKA_PACKAGE_bip_utils_cardano_mnemonic
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.cardano.mnemonic.cardano_byron_legacy_seed_generator
T aCardanoByronLegacySeedGenerator
aCardanoByronLegacySeedGenerator
ubip_utils.cardano.mnemonic.cardano_icarus_seed_generator
T aCardanoIcarusSeedGenerator
aCardanoIcarusSeedGenerator
ubip_utils\cardano\mnemonic\__init__.py
u<module bip_utils.cardano.mnemonic>

a__spec__
.bip_utils.cardano.shelley.cardano_shelley
P
a
def aCip1852
uThe Bip object shall be a Cip1852 instance
a_CardanoShelley__DeriveStakingKeys

Create a CardanoShelley object from the specified Cip1852 object.
Args:
bip_obj (Bip44Base object): Bip44Base object
Returns:
CardanoShelley object: CardanoShelley object
Raises:
ValueError: If the seed is too short
Bip32KeyError: If the seed is not suitable for master key generation
aLevel
aBip44Levels
aACCOUNT
uThe bip_obj shall not be below account level
aADDRESS_INDEX
uThe bip_sk_obj shall be of address index level
m_bip_obj
m_bip_sk_obj

Construct class.
Args:
bip_obj (Bip44Base object)   : Bip44Base object
bip_sk_obj (Bip44Base object): Bip44Base object (staking)
Raises:
ValueError: If the bip_sk_obj object is below account level
aCardanoShelleyPublicKeys
aPublicKey
aBip32Key
aCoinConf

Return the public keys.
Returns:
CardanoShelleyPublicKeys object: CardanoShelleyPublicKeys object
aCardanoShelleyPrivateKeys
aPrivateKey

Return the private keys.
Returns:
CardanoShelleyPrivateKeys object: CardanoShelleyPrivateKeys object
Raises:
Bip32KeyError: If the Bip32 object is public-only
aStakingObject

Alias for StakingObject.
Returns:
Bip44Base object: Bip44Base object

Return the staking object.
Returns:
Bip44Base object: Bip44Base object
aIsPublicOnly

Get if it's public-only.
Returns:
bool: True if public-only, false otherwise
aCardanoShelley
aChange

Derive a child key from the specified change type and return a new CardanoShelley object.
Args:
change_type (Bip44Changes): Change type, must a Bip44Changes enum
Returns:
CardanoShelley object: CardanoShelley object
Raises:
TypeError: If change type is not a Bip44Changes enum
Bip44DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
aAddressIndex

Derive a child key from the specified address index and return a new CardanoShelley object.
Args:
ddr_idx (int): Address index
Returns:
CardanoShelley object: CardanoShelley object
Raises:
Cip1852DepthError: If current depth is not suitable for deriving keys
Bip32KeyError: If the derivation results in an invalid key
copy
aAdaShelleyStakingAddrEncoder
m_addr_cls
aBip32Object
aDerivePath
T u2/0

Derive staking keys from a Bip44Base object.
Args:
bip_obj (Bip44Base object): Bip44Base object
Returns:
Bip44Base object: Bip44Base object
Raises:
Bip32KeyError: If the derivation results in an invalid key

Module for Cardano Shelley keys derivation.
Reference: https://cips.cardano.org/cips/cip11
a__doc__
a__file__
origin
has_location
a__cached__
annotations
lru_cache
ubip_utils.addr
T aAdaShelleyStakingAddrEncoder
ubip_utils.bip.bip44_base
T aBip44Base
aBip44Changes
aBip44Levels
aBip44Base
aBip44Changes
ubip_utils.cardano.cip1852
T aCip1852
ubip_utils.cardano.shelley.cardano_shelley_keys
T aCardanoShelleyPrivateKeys
aCardanoShelleyPublicKeys
