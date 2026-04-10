# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.bip32_path

uClass container for BIP32 path constants.
a__qualname__
a__annotations__
T w'whwpuTuple[str, str, str]
wmastr

BIP32 path class.
It represents a BIP-0032 path.
uList[Bip32KeyIndex]
bool
T ntD aelems
is_absolute
return
uOptional[Sequence[Union[int, Bip32KeyIndex]]]
bool
aNone
a__init__
uBip32Path.__init__
D aelem
return
uUnion[int, Bip32KeyIndex]
aBip32Path
aAddElem
uBip32Path.AddElem
D areturn
bool
aIsAbsolute
uBip32Path.IsAbsolute
D areturn
int
aLength
uBip32Path.Length
D areturn
uList[int]
aToList
uBip32Path.ToList
D areturn
str
uBip32Path.ToStr
a__str__
uBip32Path.__str__
D aidx
return
int
aBip32KeyIndex
a__getitem__
uBip32Path.__getitem__
D areturn
uIterator[Bip32KeyIndex]

BIP32 path parser class.
It parses a BIP-0032 path and returns a Bip32Path object.
D apath
return
str
aBip32Path
aParse
uBip32PathParser.Parse
D apath_elems
return
uList[str]
aBip32Path
a__ParseElements
uBip32PathParser.__ParseElements
D apath_elem
return
str
int
a__ParseElem
uBip32PathParser.__ParseElem
ubip_utils\bip\bip32\bip32_path.py
u<module bip_utils.bip.bip32.bip32_path>
T aself
elem
T a__class__
T aself
T apath
T aself
path_str
elem
T apath_elem
is_hardened
T apath_elems
is_absolute
parsed_elems
T aself
idx
T aself
elems
is_absolute
ex
a__spec__
.bip_utils.bip.bip32.bip32_utils
aBip32KeyIndex
aHardenIndex

Harden the specified index and return it.
Args:
index (int): Index
Returns:
int: Hardened index
aUnhardenIndex

Unharden the specified index and return it.
Args:
index (int): Index
Returns:
int: Unhardened index
aIsHardenedIndex

Get if the specified index is hardened.
Args:
index (int): Index
Returns:
bool: True if hardened, false otherwise
uModule with BIP32 utility functions.
a__doc__
a__file__
origin
has_location
a__cached__
ubip_utils.bip.bip32.bip32_key_data
T aBip32KeyIndex
