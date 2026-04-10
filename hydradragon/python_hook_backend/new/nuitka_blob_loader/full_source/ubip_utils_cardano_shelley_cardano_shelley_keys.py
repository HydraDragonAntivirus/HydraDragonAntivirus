# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.shelley.cardano_shelley_keys


Cardano Shelley public key class.
It contains 2 CIP-1852 public keys (address + staking) and allows to get the Cardano Shelley address from them.
a__qualname__
a__annotations__
pub_addr_key
pub_sk_key
coin_conf
return
a__init__
uCardanoShelleyPublicKeys.__init__
aAddressKey
uCardanoShelleyPublicKeys.AddressKey
aRewardKey
uCardanoShelleyPublicKeys.RewardKey
uCardanoShelleyPublicKeys.StakingKey
D areturn
Ostr
aToRewardAddress
uCardanoShelleyPublicKeys.ToRewardAddress
uCardanoShelleyPublicKeys.ToStakingAddress
aToAddress
uCardanoShelleyPublicKeys.ToAddress

Cardano Shelley private key class.
It contains 2 BIP32 private keys (address + staking).
aCardanoShelleyPrivateKeys
priv_addr_key
priv_sk_key
uCardanoShelleyPrivateKeys.__init__
uCardanoShelleyPrivateKeys.AddressKey
uCardanoShelleyPrivateKeys.RewardKey
uCardanoShelleyPrivateKeys.StakingKey
aPublicKeys
uCardanoShelleyPrivateKeys.PublicKeys
ubip_utils\cardano\shelley\cardano_shelley_keys.py
u<module bip_utils.cardano.shelley.cardano_shelley_keys>
T aself
T a__class__
T aself
priv_addr_key
priv_sk_key
coin_conf
T aself
pub_addr_key
pub_sk_key
coin_conf

a__spec__
.bip_utils.cardano.shelley
t
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ucardano\shelley
T aNUITKA_PACKAGE_bip_utils_cardano
u\not_existing
shelley
T aNUITKA_PACKAGE_bip_utils_cardano_shelley
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.cardano.shelley.cardano_shelley
T aCardanoShelley
aCardanoShelley
ubip_utils.cardano.shelley.cardano_shelley_keys
T aCardanoShelleyPrivateKeys
aCardanoShelleyPublicKeys
aCardanoShelleyPrivateKeys
aCardanoShelleyPublicKeys
ubip_utils\cardano\shelley\__init__.py
u<module bip_utils.cardano.shelley>

a__spec__
.bip_utils.coin_conf.coin_conf
(
m_coin_name
m_params

Construct class.
Args:
coin_name (CoinNames object): Coin names
params (dict)               : SS58 format

Get coin names.
Returns:
CoinNames object: CoinNames object

Get the parameter by key.
Args:
key (str): Parameter key
Returns:
Any: Parameter value
uModule with helper class for generic coins configuration handling.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aDict
ubip_utils.utils.conf
T aCoinNames
aCoinNames
aConfCoinNames
