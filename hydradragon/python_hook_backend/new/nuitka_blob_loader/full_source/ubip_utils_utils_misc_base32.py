# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.misc.base32

uClass container for Base32 constants.
a__qualname__
a__annotations__
aABCDEFGHIJKLMNOPQRSTUVWXYZ234567
w=u
Base32 utility class.
It provides some helper methods for decoding/encoding Base32 format.
D adata
return
Ostr
pu_Base32Utils.AddPadding
D adata
from_alphabet
to_alphabet
return
Ostr
pppu_Base32Utils.TranslateAlphabet

Base32 decoder class.
It provides methods for decoding to Base32 format.
aBase32Decoder
T nacustom_alphabet
return
uBase32Decoder.Decode

Base32 encoder class.
It provides methods for encoding to Base32 format.
T Obytes
Ostr
uBase32Encoder.Encode
aEncodeNoPadding
uBase32Encoder.EncodeNoPadding
ubip_utils\utils\misc\base32.py
u<module bip_utils.utils.misc.base32>
T adata
last_block_width
T a__class__
T adata
custom_alphabet
data_dec
ex
T adata
custom_alphabet
b32_enc
T adata
custom_alphabet
T adata
from_alphabet
to_alphabet

a__spec__
.bip_utils.utils.misc.bit
m
'

Get if the specified bit is set.
Args:
value (int)  : Value
bit_num (int): Bit number to check
Returns:
bool: True if bit is set, false otherwise

Get if the specified bits are set.
Args:
value (int)   : Value
bit_mask (int): Bit mask to check
Returns:
bool: True if bit is set, false otherwise

Set the specified bit.
Args:
value (int)  : Value
bit_num (int): Bit number to set
Returns:
int: Value with the specified bit set

Set the specified bits.
Args:
value (int)   : Value
bit_mask (int): Bit mask to set
Returns:
int: Value with the specified bit set

Reset the specified bit.
Args:
value (int)  : Value
bit_num (int): Bit number to reset
Returns:
int: Value with the specified bit reset

Reset the specified bits.
Args:
value (int)   : Value
bit_mask (int): Bit mask to reset
Returns:
int: Value with the specified bit reset
uModule with some bits utility functions.
a__doc__
a__file__
origin
has_location
a__cached__
