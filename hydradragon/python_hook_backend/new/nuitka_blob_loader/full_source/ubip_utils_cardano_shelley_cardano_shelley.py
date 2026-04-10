# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.cardano.shelley.cardano_shelley


Cardano Shelley class.
It allows keys derivation and addresses computation (including the staking one) in according to Cardano Shelley.
a__qualname__
a__annotations__
D abip_obj
return
aBip44Base
aCardanoShelley
aFromCip1852Object
uCardanoShelley.FromCip1852Object
D abip_obj
bip_sk_obj
return
aBip44Base
paNone
a__init__
uCardanoShelley.__init__
D areturn
aCardanoShelleyPublicKeys
aPublicKeys
uCardanoShelley.PublicKeys
D areturn
aCardanoShelleyPrivateKeys
aPrivateKeys
uCardanoShelley.PrivateKeys
D areturn
aBip44Base
aRewardObject
uCardanoShelley.RewardObject
uCardanoShelley.StakingObject
D areturn
bool
uCardanoShelley.IsPublicOnly
D achange_type
return
aBip44Changes
aCardanoShelley
uCardanoShelley.Change
D aaddr_idx
return
int
aCardanoShelley
uCardanoShelley.AddressIndex
D abip_obj
return
aBip44Base
pa__DeriveStakingKeys
uCardanoShelley.__DeriveStakingKeys
ubip_utils\cardano\shelley\cardano_shelley.py
u<module bip_utils.cardano.shelley.cardano_shelley>
T aself
addr_idx
T a__class__
T aself
change_type
T acls
bip_obj
T aself
T abip_obj
coin_conf
T aself
bip_obj
bip_sk_obj

a__spec__
.bip_utils.cardano.shelley.cardano_shelley_keys
{
S
m_pub_addr_key
m_pub_sk_key
m_coin_conf

Construct class.
Args:
pub_addr_key (Bip32PublicKey object): Bip32PublicKey object (address)
pub_sk_key (Bip32PublicKey object)  : Bip32PublicKey object (staking)
coin_conf (BipCoinConf object)      : BipCoinConf object

Get the address public key.
Returns:
Bip32PublicKey object: Bip32PublicKey object
aStakingKey

Alias for StakingKey.
Returns:
Bip32PublicKey object: Bip32PublicKey object

Get the staking address public key.
Returns:
Bip32PublicKey object: Bip32PublicKey object
aToStakingAddress

Alias for ToStakingAddress.
Returns:
str: Reward address string
Raises:
ValueError: If the public key is not correspondent to an address index level
aAdaShelleyStakingAddrEncoder
aEncodeKey
aKeyObject
aAddrParams

Return the staking address correspondent to the public key.
Returns:
str: Staking address string
Raises:
ValueError: If the public key is not correspondent to an address index level
aAdaShelleyAddrEncoder
pub_skey

Return the address correspondent to the public key.
Returns:
str: Address string
Raises:
ValueError: If the public key is not correspondent to an address index level
m_priv_addr_key
m_priv_sk_key

Construct class.
Args:
priv_addr_key (Bip32PrivateKey object): Bip32PrivateKey object (address)
priv_sk_key (Bip32PrivateKey object)  : Bip32PrivateKey object (staking)
coin_conf (BipCoinConf object)        : BipCoinConf object

Get the address private key.
Returns:
Bip32PrivateKey object: Bip32PrivateKey object

Alias for StakingKey.
Returns:
Bip32PrivateKey object: Bip32PrivateKey object

Get the staking address private key.
Returns:
Bip32PrivateKey object: Bip32PrivateKey object
aCardanoShelleyPublicKeys
aPublicKey

Get the public keys correspondent to the private ones.
Returns:
CardanoShelleyPublicKeys object: CardanoShelleyPublicKeys object
uModule for Cardano Shelley keys handling.
a__doc__
a__file__
origin
has_location
a__cached__
lru_cache
ubip_utils.addr
T aAdaShelleyAddrEncoder
aAdaShelleyStakingAddrEncoder
ubip_utils.bip.bip32
T aBip32PrivateKey
aBip32PublicKey
aBip32PrivateKey
aBip32PublicKey
ubip_utils.bip.conf.common
T aBipCoinConf
aBipCoinConf
