# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.electrum_v1


Electrum v1 class.
It derives keys like the Electrum wallet with old (v1) mnemonic.
aElectrumV1
a__qualname__
a__annotations__
uOptional[IPrivateKey]
D aseed_bytes
return
bytes
aElectrumV1
aFromSeed
uElectrumV1.FromSeed
D apriv_key
return
uUnion[bytes, IPrivateKey]
aElectrumV1
uElectrumV1.FromPrivateKey
D apub_key
return
uUnion[bytes, IPublicKey]
aElectrumV1
aFromPublicKey
uElectrumV1.FromPublicKey
D apriv_key
pub_key
return
uOptional[IPrivateKey]
uOptional[IPublicKey]
aNone
a__init__
uElectrumV1.__init__
D areturn
bool
uElectrumV1.IsPublicOnly
D areturn
aIPrivateKey
uElectrumV1.MasterPrivateKey
D areturn
aIPublicKey
uElectrumV1.MasterPublicKey
D achange_idx
addr_idx
return
int
paIPrivateKey
uElectrumV1.GetPrivateKey
D achange_idx
addr_idx
return
int
paIPublicKey
uElectrumV1.GetPublicKey
D achange_idx
addr_idx
return
int
pastr
aGetAddress
uElectrumV1.GetAddress
a__DerivePrivateKey
uElectrumV1.__DerivePrivateKey
a__DerivePublicKey
uElectrumV1.__DerivePublicKey
D achange_idx
addr_idx
return
int
pabytes
a__GetSequence
uElectrumV1.__GetSequence
D achange_idx
addr_idx
return
int
paNone
a__ValidateIndexes
uElectrumV1.__ValidateIndexes
ubip_utils\electrum\electrum_v1.py
u<module bip_utils.electrum.electrum_v1>
T a__class__
T acls
priv_key
T acls
pub_key
T acls
seed_bytes
T aself
change_idx
addr_idx
T aself
T aself
change_idx
addr_idx
seq_bytes
priv_key_int
T aself
change_idx
addr_idx
seq_bytes
T achange_idx
addr_idx
T aself
priv_key
pub_key
a__spec__
.bip_utils.electrum.electrum_v2
$
aBip32Slip10Secp256k1
aFromSeed

Construct class from seed bytes.
Args:
seed_bytes (bytes): Seed bytes
Returns:
ElectrumV2Base object: ElectrumV2Base object
uA Bip32Slip10Secp256k1 class instance is required
aDepth
uThe Bip32 object shall be a master key (i.e. depth equal to 0)
m_bip32_obj

Construct class.
Args:
bip32_obj (Bip32Base object): Bip32Base object (shall be a Bip32Slip10Secp256k1 instance)
Raises:
TypeError: If the bip32 object is not a Bip32Slip10Secp256k1 class instance
ValueError: If the bip32 object is not a master key

Return the BIP32 object.
Returns:
Bip32Base object: Bip32Base object
aIsPublicOnly

Get if it's public-only.
Returns:
bool: True if public-only, false otherwise
aPrivateKey

Get the master private key.
Returns:
Bip32PrivateKey object: Bip32PrivateKey object
aPublicKey

Get the master public key.
Returns:
Bip32PublicKey object: Bip32PublicKey object
a_ElectrumV2Standard__DeriveKey

Get the private key with the specified change and address indexes.
Derivation path: m/change_idx/addr_idx
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
Bip32PrivateKey object: Bip32PrivateKey object
Raises:
Bip32KeyError: If the derivation results in an invalid key or the object is public-only
Bip32PathError: If the path indexes are not valid

Get the public key with the specified change and address indexes.
Derivation path: m/change_idx/addr_idx
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
Bip32PublicKey object: Bip32PublicKey object
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
aP2PKHAddr
aEncodeKey
aGetPublicKey
aKeyObject
aCoinsConf
aBitcoinMainNet
aParamByKey
T ap2pkh_net_ver
T anet_ver

Get the address with the specified change and address indexes.
Derivation path: m/change_idx/addr_idx
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
str: Address
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
aDerivePath
um/

w/u
Derive the key with the specified change and address indexes.
Derivation path: m/change_idx/addr_idx
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
a__class__
a__init__
T um/0'
m_bip32_acc

Construct class.
Args:
bip32 (Bip32Base object): Bip32Base object
a_ElectrumV2Segwit__DeriveKey

Get the private key with the specified change and address indexes.
Derivation path: m/0'/change_idx/addr_idx
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
Bip32PrivateKey object: Bip32PrivateKey object
Raises:
Bip32KeyError: If the derivation results in an invalid key or the object is public-only
Bip32PathError: If the path indexes are not valid

Get the public key with the specified change and address indexes.
Derivation path: m/0'/change_idx/addr_idx
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
Bip32PublicKey object: Bip32PublicKey object
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
aP2WPKHAddr
T ap2wpkh_hrp
T ahrp

Get the address with the specified change and address indexes.
Derivation path: m/0'/change_idx/addr_idx
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
str: Address
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid

Derive the key with the specified change and address indexes.
Derivation path: m/0'/change_idx/addr_idx
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
Bip32Base object: Bip32Base object
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
uModule containing utility classes for Electrum v2 keys derivation, since it uses its own paths.
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
ubip_utils.addr
T aP2PKHAddr
aP2WPKHAddr
ubip_utils.bip.bip32
T aBip32Base
aBip32KeyIndex
aBip32PrivateKey
aBip32PublicKey
aBip32Slip10Secp256k1
aBip32Base
aBip32KeyIndex
aBip32PrivateKey
aBip32PublicKey
ubip_utils.coin_conf
T aCoinsConf
a__prepare__
aElectrumV2Base
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
