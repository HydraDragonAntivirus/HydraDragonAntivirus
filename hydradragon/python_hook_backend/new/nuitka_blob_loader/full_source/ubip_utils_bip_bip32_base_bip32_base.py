# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.base.bip32_base


BIP32 base class.
It allows master key generation and children keys derivation in according to BIP-0032/SLIP-0010.
It shall be derived to implement derivation for a specific elliptic curve.
a__qualname__
a__annotations__
uOptional[Bip32PrivateKey]
classmethod
T nD aseed_bytes
key_net_ver
return
bytes
uOptional[Bip32KeyNetVersions]
aBip32Base
uBip32Base.FromSeed
D aseed_bytes
path
key_net_ver
return
bytes
uUnion[str, Bip32Path]
uOptional[Bip32KeyNetVersions]
aBip32Base
aFromSeedAndPath
uBip32Base.FromSeedAndPath
D aex_key_str
key_net_ver
return
str
uOptional[Bip32KeyNetVersions]
aBip32Base
aFromExtendedKey
uBip32Base.FromExtendedKey
D apriv_key
key_data
key_net_ver
return
uUnion[bytes, IPrivateKey]
aBip32KeyData
uOptional[Bip32KeyNetVersions]
aBip32Base
aFromPrivateKey
uBip32Base.FromPrivateKey
D apub_key
key_data
key_net_ver
return
uUnion[bytes, IPoint, IPublicKey]
aBip32KeyData
uOptional[Bip32KeyNetVersions]
aBip32Base
aFromPublicKey
uBip32Base.FromPublicKey
D apriv_key
pub_key
key_data
key_net_ver
return
uOptional[Union[bytes, IPrivateKey]]
uOptional[Union[bytes, IPoint, IPublicKey]]
aBip32KeyData
aBip32KeyNetVersions
aNone
a__init__
uBip32Base.__init__
D aindex
return
uUnion[int, Bip32KeyIndex]
aBip32Base
uBip32Base.ChildKey
D apath
return
uUnion[str, Bip32Path]
aBip32Base
uBip32Base.DerivePath
D areturn
aNone
aConvertToPublic
uBip32Base.ConvertToPublic
D areturn
bool
uBip32Base.IsPublicOnly
D areturn
aBip32PrivateKey
aPrivateKey
uBip32Base.PrivateKey
D areturn
aBip32PublicKey
uBip32Base.PublicKey
D areturn
aBip32KeyNetVersions
uBip32Base.KeyNetVersions
D areturn
aBip32Depth
uBip32Base.Depth
D areturn
aBip32KeyIndex
uBip32Base.Index
D areturn
aBip32ChainCode
uBip32Base.ChainCode
D areturn
aBip32FingerPrint
uBip32Base.FingerPrint
uBip32Base.ParentFingerPrint
D areturn
aEllipticCurve
uBip32Base.Curve
uBip32Base.IsPublicDerivationSupported
D aindex
return
aBip32KeyIndex
aBip32Base
a__ValidateAndCkdPriv
uBip32Base.__ValidateAndCkdPriv
a__ValidateAndCkdPub
uBip32Base.__ValidateAndCkdPub
a__CkdPriv
uBip32Base.__CkdPriv
a__CkdPub
uBip32Base.__CkdPub
staticmethod
D aindex
return
uUnion[int, Bip32KeyIndex]
aBip32KeyIndex
a__GetIndex
uBip32Base.__GetIndex
D apath
return
uUnion[str, Bip32Path]
aBip32Path
a__GetPath
uBip32Base.__GetPath
D areturn
aEllipticCurveTypes

Return the elliptic curve type.
Returns:
EllipticCurveTypes: Curve type
uBip32Base.CurveType

Return the default key net version.
Returns:
Bip32KeyNetVersions object: Bip32KeyNetVersions object
uBip32Base._DefaultKeyNetVersion
D areturn
uType[IBip32KeyDerivator]

Return the key derivator class.
Returns:
IBip32KeyDerivator class: Key derivator class
uBip32Base._KeyDerivator
D areturn
uType[IBip32MstKeyGenerator]

Return the master key generator class.
Returns:
IBip32MstKeyGenerator class: Master key generator class
uBip32Base._MasterKeyGenerator
a__orig_bases__
ubip_utils\bip\bip32\base\bip32_base.py
u<module bip_utils.bip.bip32.base.bip32_base>
T a__class__
T aself
T aself
index
T acls
T aself
path
bip32_obj
path_elem
T acls
ex_key_str
key_net_ver
deser_key
key_bytes
key_data
is_public
T acls
priv_key
key_data
key_net_ver
T acls
pub_key
key_data
key_net_ver
T acls
seed_bytes
key_net_ver
priv_key_bytes
chain_code_bytes
T acls
seed_bytes
path
key_net_ver
T aself
index
priv_key_bytes
chain_code_bytes
T aself
index
pub_key_bytes
chain_code_bytes
T aindex
T apath
T aself
priv_key
pub_key
key_data
key_net_ver
curve
a__spec__
.bip_utils.bip.bip32.base
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
ubip\bip32\base
T aNUITKA_PACKAGE_bip_utils_bip
u\not_existing
ubip32\base
T aNUITKA_PACKAGE_bip_utils_bip_bip32
u\not_existing
base
T aNUITKA_PACKAGE_bip_utils_bip_bip32_base
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.bip.bip32.base.bip32_base
T aBip32Base
aBip32Base
ubip_utils.bip.bip32.base.ibip32_key_derivator
T aIBip32KeyDerivator
aIBip32KeyDerivator
ubip_utils.bip.bip32.base.ibip32_mst_key_generator
T aIBip32MstKeyGenerator
aIBip32MstKeyGenerator
ubip_utils\bip\bip32\base\__init__.py
u<module bip_utils.bip.bip32.base>

a__spec__
.bip_utils.bip.bip32.base.ibip32_key_derivator
$
9
uModule for BIP32 SLIP-0010 keys derivation.
a__doc__
a__file__
origin
has_location
a__cached__
abc
T aABC
abstractmethod
aABC
abstractmethod
aTuple
aUnion
ubip_utils.bip.bip32.bip32_key_data
T aBip32KeyIndex
aBip32KeyIndex
ubip_utils.bip.bip32.bip32_keys
T aBip32PrivateKey
aBip32PublicKey
aBip32PrivateKey
aBip32PublicKey
ubip_utils.ecc
T aIPoint
aIPoint
a__prepare__
aIBip32KeyDerivator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
