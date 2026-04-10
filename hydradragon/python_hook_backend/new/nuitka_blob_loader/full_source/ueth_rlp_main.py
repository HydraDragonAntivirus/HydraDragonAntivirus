# Reconstructed from integrated Nuitka blob
# Module: ueth_rlp.main


An extension of :class:`rlp.Serializable`. In addition to the below
functions, the class is iterable.
Use like:
::
class MyRLP(HashableRLP):
fields = (
('name1', rlp.sedes.big_endian_int),
('name2', rlp.sedes.binary),
etc...
)
my_obj = MyRLP(name2=b'\xff', name1=1)
list(my_obj) == [1, b'\xff']
# note that the iteration order is always in RLP-defined order
a__qualname__
classmethod
field_dict
str
return
from_dict
uHashableRLP.from_dict
serialized_bytes
bytes
bytearray
from_bytes
uHashableRLP.from_bytes
hash
uHashableRLP.hash
uHashableRLP.__iter__
uHashableRLP.as_dict
a__orig_bases__
ueth_rlp\main.py
T a.0
field
w_aself
T a__class__
u<module eth_rlp.main>
T aself
a__class__
T aself
a_as_dict
a__class__
T acls
serialized_bytes
decoded
T acls
field_dict
T aself

a__spec__
.eth_typing.abi
R

Types for Contract ABIs and related components.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aLiteral
aSequence
aTuple
aTypedDict
aUnion
typing_extensions
T aNotRequired
aNotRequired
ueth_typing.encoding
T aHexStr
aHexStr
aTypeStr
T Obytes
Obytearray
aDecodable
a__prepare__
aABIComponent
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
