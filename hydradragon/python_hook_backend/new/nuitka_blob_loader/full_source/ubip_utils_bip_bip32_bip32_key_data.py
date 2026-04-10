# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.bip32_key_data

uClass container for BIP32 key data constants.
a__qualname__
a__annotations__
l aint
l b
bytes
g       l a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

BIP32 chaincode class.
It represents a BIP32 chaincode.
d
D achaincode
return
bytes
aNone
uBip32ChainCode.__init__
staticmethod
D areturn
int
uBip32ChainCode.FixedLength
a__orig_bases__

BIP32 fingerprint class.
It represents a BIP32 fingerprint.
D afprint
return
bytes
aNone
uBip32FingerPrint.__init__
uBip32FingerPrint.FixedLength
D areturn
bool
aIsMasterKey
uBip32FingerPrint.IsMasterKey

BIP32 depth class.
It represents a BIP32 depth.
D adepth
return
int
aNone
uBip32Depth.__init__
uBip32Depth.FixedLength
D areturn
aBip32Depth
aIncrease
uBip32Depth.Increase
D areturn
bytes
uBip32Depth.ToBytes
uBip32Depth.ToInt
a__int__
uBip32Depth.__int__
a__bytes__
uBip32Depth.__bytes__
D aother
return
object
bool
a__eq__
uBip32Depth.__eq__
D aother
return
uUnion[int, Bip32Depth]
bool
a__gt__
uBip32Depth.__gt__
a__lt__
uBip32Depth.__lt__

BIP32 key index class.
It represents a BIP32 key index.
D aindex
return
int
puBip32KeyIndex.HardenIndex
uBip32KeyIndex.UnhardenIndex
D aindex
return
int
bool
uBip32KeyIndex.IsHardenedIndex
D aindex_bytes
return
bytes
aBip32KeyIndex
aFromBytes
uBip32KeyIndex.FromBytes
D aidx
return
int
aNone
uBip32KeyIndex.__init__
uBip32KeyIndex.FixedLength
D areturn
aBip32KeyIndex
aHarden
uBip32KeyIndex.Harden
aUnharden
uBip32KeyIndex.Unharden
aIsHardened
uBip32KeyIndex.IsHardened
T abig
D aendianness
return
uLiteral['little', 'big']
bytes
uBip32KeyIndex.ToBytes
uBip32KeyIndex.ToInt
uBip32KeyIndex.__int__
uBip32KeyIndex.__bytes__
uBip32KeyIndex.__eq__

BIP32 key data class.
It contains all additional data related to a BIP32 key (e.g. depth, chain code, etc...).
aBip32KeyData
T l
D adepth
index
chain_code
parent_fprint
return
uUnion[int, Bip32Depth]
uUnion[int, Bip32KeyIndex]
uUnion[bytes, Bip32ChainCode]
uUnion[bytes, Bip32FingerPrint]
aNone
uBip32KeyData.__init__
aDepth
uBip32KeyData.Depth
aIndex
uBip32KeyData.Index
D areturn
aBip32ChainCode
aChainCode
uBip32KeyData.ChainCode
D areturn
aBip32FingerPrint
aParentFingerPrint
uBip32KeyData.ParentFingerPrint
ubip_utils\bip\bip32\bip32_key_data.py
u<module bip_utils.bip.bip32.bip32_key_data>
T a__class__
T aself
T acls
index_bytes
T aindex
T aself
endianness
T aself
other
T aself
chaincode
a__class__
T aself
depth
T aself
fprint
a__class__
T aself
depth
index
chain_code
parent_fprint
T aself
idx
a__spec__
.bip_utils.bip.bip32.bip32_key_net_ver
)
aLength
uInvalid key net version length
m_pub_net_ver
m_priv_net_ver

Construct class.
Args:
pub_net_ver (bytes) : Public net version
priv_net_ver (bytes): Private net version
aBip32KeyNetVersionsConst
aKEY_NET_VERSION_BYTE_LEN

Get the key net version length.
Returns:
int: Key net version length

Get public net version.
Returns:
bytes: Public net version

Get private net version.
Returns:
bytes: Private net version
uModule for BIP32 net version class.
a__doc__
a__file__
origin
has_location
a__cached__
