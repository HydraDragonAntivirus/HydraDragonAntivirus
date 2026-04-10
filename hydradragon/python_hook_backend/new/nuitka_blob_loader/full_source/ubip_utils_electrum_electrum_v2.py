# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.electrum_v2

uElectrum v2 base class.
a__qualname__
a__annotations__
classmethod
D aseed_bytes
return
bytes
aElectrumV2Base
uElectrumV2Base.FromSeed
D abip32_obj
return
aBip32Base
aNone
uElectrumV2Base.__init__
D areturn
aBip32Base
aBip32Object
uElectrumV2Base.Bip32Object
D areturn
bool
uElectrumV2Base.IsPublicOnly
D areturn
aBip32PrivateKey
aMasterPrivateKey
uElectrumV2Base.MasterPrivateKey
D areturn
aBip32PublicKey
aMasterPublicKey
uElectrumV2Base.MasterPublicKey
D achange_idx
addr_idx
return
uUnion[int, Bip32KeyIndex]
uUnion[int, Bip32KeyIndex]
aBip32PrivateKey

Get the private key with the specified change and address indexes.
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
Bip32PrivateKey object: Bip32PrivateKey object
Raises:
Bip32KeyError: If the derivation results in an invalid key or the object is public-only
Bip32PathError: If the path indexes are not valid
aGetPrivateKey
uElectrumV2Base.GetPrivateKey
D achange_idx
addr_idx
return
uUnion[int, Bip32KeyIndex]
uUnion[int, Bip32KeyIndex]
aBip32PublicKey

Get the public key with the specified change and address indexes.
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
Bip32PublicKey object: Bip32PublicKey object
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
uElectrumV2Base.GetPublicKey
D achange_idx
addr_idx
return
uUnion[int, Bip32KeyIndex]
uUnion[int, Bip32KeyIndex]
str

Get the address with the specified change and address indexes.
Args:
change_idx (int or Bip32KeyIndex object): Change index
ddr_idx (int or Bip32KeyIndex object)  : Address index
Returns:
str: Address
Raises:
Bip32KeyError: If the derivation results in an invalid key
Bip32PathError: If the path indexes are not valid
aGetAddress
uElectrumV2Base.GetAddress
a__orig_bases__
aElectrumV2Standard

Electrum v2 standard class.
It derives keys like the Electrum wallet with standard mnemonic.
uElectrumV2Standard.GetPrivateKey
uElectrumV2Standard.GetPublicKey
uElectrumV2Standard.GetAddress
D achange_idx
addr_idx
return
uUnion[int, Bip32KeyIndex]
uUnion[int, Bip32KeyIndex]
aBip32Base
a__DeriveKey
uElectrumV2Standard.__DeriveKey
aElectrumV2Segwit

Electrum v2 segwit class.
It derives keys like the Electrum wallet with segwit mnemonic.
D abip32
return
aBip32Base
aNone
uElectrumV2Segwit.__init__
uElectrumV2Segwit.GetPrivateKey
uElectrumV2Segwit.GetPublicKey
uElectrumV2Segwit.GetAddress
uElectrumV2Segwit.__DeriveKey
ubip_utils\electrum\electrum_v2.py
u<module bip_utils.electrum.electrum_v2>
T aself
T a__class__
T acls
seed_bytes
T aself
change_idx
addr_idx
T aself
bip32_obj
T aself
bip32
a__class__
a__spec__
.bip_utils.electrum.mnemonic_v1
N
-
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uelectrum\mnemonic_v1
T aNUITKA_PACKAGE_bip_utils_electrum
u\not_existing
mnemonic_v1
T aNUITKA_PACKAGE_bip_utils_electrum_mnemonic_v1
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.electrum.mnemonic_v1.electrum_v1_entropy_generator
T aElectrumV1EntropyBitLen
aElectrumV1EntropyGenerator
aElectrumV1EntropyBitLen
aElectrumV1EntropyGenerator
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic
T aElectrumV1Languages
aElectrumV1Mnemonic
aElectrumV1WordsNum
aElectrumV1Languages
aElectrumV1Mnemonic
aElectrumV1WordsNum
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_decoder
T aElectrumV1MnemonicDecoder
aElectrumV1MnemonicDecoder
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_encoder
T aElectrumV1MnemonicEncoder
aElectrumV1MnemonicEncoder
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_generator
T aElectrumV1MnemonicGenerator
aElectrumV1MnemonicGenerator
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_validator
T aElectrumV1MnemonicValidator
aElectrumV1MnemonicValidator
ubip_utils.electrum.mnemonic_v1.electrum_v1_seed_generator
T aElectrumV1SeedGenerator
aElectrumV1SeedGenerator
ubip_utils\electrum\mnemonic_v1\__init__.py
u<module bip_utils.electrum.mnemonic_v1>

a__spec__
.bip_utils.electrum.mnemonic_v1.electrum_v1_entropy_generator
q
=
aIsValidEntropyBitLen
uEntropy bit length is not valid (

w)a__class__
a__init__

Construct class.
Args:
bit_len (int or ElectrumV1EntropyBitLen, optional): Entropy length in bits (default: 128)
Raises:
ValueError: If the bit length is not valid
aElectrumV1EntropyGeneratorConst
aENTROPY_BIT_LEN

Get if the specified entropy bit length is valid.
Args:
bit_len (int): Entropy length in bits
Returns:
bool: True if valid, false otherwise
aElectrumV1EntropyGenerator
l u
Get if the specified entropy byte length is valid.
Args:
byte_len (int): Entropy length in bytes
Returns:
bool: True if valid, false otherwise
uModule for Electrum v1 mnemonic entropy generation.
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aIntEnum
unique
aIntEnum
unique
aList
aUnion
ubip_utils.utils.mnemonic
T aEntropyGenerator
aEntropyGenerator
a__prepare__
aElectrumV1EntropyBitLen
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
