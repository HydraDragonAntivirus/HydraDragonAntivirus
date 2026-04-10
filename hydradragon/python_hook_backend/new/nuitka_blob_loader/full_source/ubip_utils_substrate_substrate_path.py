# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.substrate.substrate_path

uContainer for Substrate path constants.
a__qualname__
a__annotations__
l aint
u\/+[^/]+
str
w/u//
l l l@l  l  uDict[int, Type[SubstrateScaleEncoderBase]]

Substrate path element.
It represents a Substrate path element.
bool
D aelem
return
str
aNone
a__init__
uSubstratePathElem.__init__
D areturn
bool
uSubstratePathElem.IsHard
aIsSoft
uSubstratePathElem.IsSoft
D areturn
bytes
aChainCode
uSubstratePathElem.ChainCode
D areturn
str
uSubstratePathElem.ToStr
a__str__
uSubstratePathElem.__str__
a__ComputeChainCode
uSubstratePathElem.__ComputeChainCode
D aelem
return
str
bool
a__IsElemValid
uSubstratePathElem.__IsElemValid

Substrate path.
It represents a Substrate path.
uList[SubstratePathElem]
T nD aelems
return
uOptional[Sequence[Union[str, SubstratePathElem]]]
aNone
uSubstratePath.__init__
D aelem
return
uUnion[str, SubstratePathElem]
aSubstratePath
aAddElem
uSubstratePath.AddElem
D areturn
int
aLength
uSubstratePath.Length
D areturn
uList[str]
uSubstratePath.ToList
uSubstratePath.ToStr
uSubstratePath.__str__
D aidx
return
int
aSubstratePathElem
a__getitem__
uSubstratePath.__getitem__
D areturn
uIterator[SubstratePathElem]

Substrate path parser.
It parses a Substrate path and returns a SubstratePath object.
aSubstratePathParser
D apath
return
str
aSubstratePath
aParse
uSubstratePathParser.Parse
ubip_utils\substrate\substrate_path.py
u<module bip_utils.substrate.substrate_path>
T aself
elem
T aself
T apath
paths
T a__class__
T aself
prefix
T aself
bit_len
scale_enc
min_bit_len
int_scale_enc
enc_data
max_len
chain_code
T aelem
T aself
idx
T aself
elems
a__spec__
.bip_utils.utils.conf.coin_names
m_name
m_abbr

Construct class.
Args:
name (str): Name
bbr (str): Abbreviation

Get name.
Returns :
str: Name

Get abbreviation.
Returns:
str: Abbreviation
uModule with helper class for coin names.
a__doc__
a__file__
origin
has_location
a__cached__
