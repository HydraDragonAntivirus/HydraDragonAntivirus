# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.misc.data_bytes


Data bytes class.
It allows to get bytes in different formats.
a__qualname__
a__annotations__
D adata_bytes
return
Obytes
na__init__
uDataBytes.__init__
D areturn
Oint
uDataBytes.Length
aSize
uDataBytes.Size
D areturn
Obytes
uDataBytes.ToBytes
D areturn
Ostr
uDataBytes.ToHex
T abig
endianness
T alittle
big
return
uDataBytes.ToInt
a__len__
uDataBytes.__len__
a__bytes__
uDataBytes.__bytes__
a__int__
uDataBytes.__int__
a__repr__
uDataBytes.__repr__
D aidx
return
Oint
pa__getitem__
uDataBytes.__getitem__
D aother
return
Oobject
Obool
a__eq__
uDataBytes.__eq__
ubip_utils\utils\misc\data_bytes.py
u<module bip_utils.utils.misc.data_bytes>
T a__class__
T aself
T aself
endianness
T aself
other
T aself
idx
T aself
data_bytes
a__spec__
.bip_utils.utils.misc.integer
?
bit_length
l l u
Get the number of bytes of the specified integer.
Args:
data_int (int): Data integer
Returns:
int: Number of bytes
a__name__
mpz
aIntegerUtils
aGetBytesNumber
data_int
to_bytes
T abyteorder
signed

Convert integer to bytes.
Args:
data_int (int)                          : Data integer
bytes_num (int, optional)               : Number of bytes, automatic if None
endianness ("big" or "little", optional): Endianness (default: big)
signed (bool, optional)                 : True if signed, false otherwise (default: false)
Returns:
bytes: Bytes representation
aAlgoUtils
aEncode
l u
Convert the specified binary string to integer.
Args:
data (str or bytes): Data
Returns:
int: Integer representation
:l nnazfill

Convert the specified integer to a binary string.
Args:
data_int (int)                  : Data integer
zero_pad_bit_len (int, optional): Zero pad length in bits, 0 if not specified
Returns:
str: Binary string
uModule with some integer utility functions.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.utils.misc.algo
T aAlgoUtils
ubip_utils.utils.typing
T aLiteral
aLiteral
