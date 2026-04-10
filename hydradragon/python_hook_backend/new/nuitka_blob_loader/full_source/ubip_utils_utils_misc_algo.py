# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.misc.algo

uClass container for algorithm utility functions.
aAlgoUtils
a__qualname__
arr
elem
return
aBinarySearch
uAlgoUtils.BinarySearch
T uutf-8
data
T Obytes
Ostr
encoding
aDecode
uAlgoUtils.Decode
aEncode
uAlgoUtils.Encode
D adata_str
return
Ostr
Obool
aIsStringMixed
uAlgoUtils.IsStringMixed
ubip_utils\utils\misc\algo.py
T a.0
wcu<module bip_utils.utils.misc.algo>
T a__class__
T aarr
elem
invalid_idx
wiT adata
encoding
T adata_str

a__spec__
.bip_utils.utils.misc.base32
Z
E
l aBase32Const
aPADDING_CHAR
data

Add padding to an encoded Base32 string.
Used if the string was encoded with Base32Encoder.EncodeNoPadding
Args:
data (str): Data
Returns:
str: Padded string
translate
maketrans

Translate the standard Base32 alphabet to a custom one.
Args:
data (str)         : Data
from_alphabet (str): Starting alphabet string
to_alphabet (str)  : Final alphabet string
Returns:
str: String with translated alphabet
a_Base32Utils
aAddPadding
aTranslateAlphabet
aALPHABET
base64
b32decode
binascii
aError
uInvalid Base32 string

Decode from Base32.
Args:
data (str)                     : Data
custom_alphabet (str, optional): Custom alphabet string
Returns:
bytes: Decoded bytes
Raises:
ValueError: If the Base32 string is not valid
aAlgoUtils
aDecode
b32encode
aEncode

Encode to Base32.
Args:
data (str or bytes)            : Data
custom_alphabet (str, optional): Custom alphabet string
Returns:
str: Encoded string
aBase32Encoder
rstrip

Encode to Base32 by removing the final padding.
Args:
data (str or bytes)            : Data
custom_alphabet (str, optional): Custom alphabet string
Returns:
str: Encoded string
uModule with helper class for Base32.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.utils.misc.algo
T aAlgoUtils
