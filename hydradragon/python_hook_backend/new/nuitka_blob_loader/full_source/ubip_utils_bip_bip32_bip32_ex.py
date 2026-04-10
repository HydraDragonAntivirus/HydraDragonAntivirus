# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip32.bip32_ex

uException in case of key error.
a__qualname__
a__orig_bases__
aBip32PathError
uException in case of path error.
ubip_utils\bip\bip32\bip32_ex.py
u<module bip_utils.bip.bip32.bip32_ex>

a__spec__
.bip_utils.bip.bip32.bip32_key_data
aFixedLength
uInvalid chaincode length (

w)a__class__
a__init__

Construct class.
Args:
chaincode (bytes, optional): Fingerprint bytes (default: zero)
Raises:
ValueError: If the chain code length is not valid
aBip32KeyDataConst
aCHAINCODE_BYTE_LEN

Get the fixed length in bytes.
Returns:
int: Length in bytes
uInvalid fingerprint length (
aFINGERPRINT_BYTE_LEN

Construct class.
Args:
fprint (bytes, optional): Fingerprint bytes (default: master key)
Raises:
ValueError: If the chain code length is not valid
aToBytes
aFINGERPRINT_MASTER_KEY

Get if the fingerprint corresponds to a master key.
Returns:
bool: True if it corresponds to a master key, false otherwise
uInvalid depth (
m_depth

Construct class.
Args:
depth (int): Depth
Raises:
ValueError: If the depth value is not valid
aDEPTH_BYTE_LEN
aBip32Depth

Get a new object with increased depth.
Returns:
Bip32Depth object: Bip32Depth object
aIntegerUtils
T abytes_num

Get the depth as bytes.
Returns:
bytes: Depth bytes

Get the depth as integer.
Returns:
int: Depth index
aToInt
uInvalid type for checking equality (

Equality operator.
Args:
other (int or Bip32Depth object): Other object to compare
Returns:
bool: True if equal false otherwise
Raises:
TypeError: If the other object is not of the correct type

Greater than operator.
Args:
other (int or Bip32Depth object): Other value to compare
Returns:
bool: True if greater false otherwise

Lower than operator.
Args:
other (int or Bip32Depth object): Other value to compare
Returns:
bool: True if lower false otherwise
aBitUtils
aSetBit
aKEY_INDEX_HARDENED_BIT_NUM

Harden the specified index and return it.
Args:
index (int): Index
Returns:
int: Hardened index
aResetBit

Unharden the specified index and return it.
Args:
index (int): Index
Returns:
int: Unhardened index
aIsBitSet

Get if the specified index is hardened.
Args:
index (int): Index
Returns:
bool: True if hardened, false otherwise
aBytesUtils
aToInteger

Construct class from bytes.
Args:
index_bytes (bytes): Key index bytes
Returns:
Bip32KeyIndex object: Bip32KeyIndex object
Raises:
ValueError: If the index is not valid
aKEY_INDEX_MAX_VAL
uInvalid key index (
m_idx

Construct class.
Args:
idx (int): Key index
Raises:
ValueError: If the index value is not valid
aKEY_INDEX_BYTE_LEN
aBip32KeyIndex
aHardenIndex

Get a new Bip32KeyIndex object with the current key index hardened.
Returns:
Bip32KeyIndex object: Bip32KeyIndex object
aUnhardenIndex

Get a new Bip32KeyIndex object with the current key index unhardened.
Returns:
Bip32KeyIndex object: Bip32KeyIndex object
aIsHardenedIndex

Get if the key index is hardened.
Returns:
bool: True if hardened, false otherwise
T abytes_num
endianness

Get the key index as bytes.
Args:
endianness ("big" or "little", optional): Endianness (default: big)
Returns:
bytes: Key bytes

Get the key index as integer.
Returns:
int: Key index

Get the key index as bytes.
Returns:
bytes: Key bytes

Equality operator.
Args:
other (int or Bip32KeyIndex object): Other value to compare
Returns:
bool: True if equal false otherwise
Raises:
TypeError: If the object is not of the correct type
m_index
aBip32ChainCode
m_chain_code
aBip32FingerPrint
m_parent_fprint

Construct class.
Args:
depth (Bip32Depth object)               : Key depth
index (Bip32KeyIndex object)            : Key index
chain_code (Bip32ChainCode object)      : Key chain code
parent_fprint (Bip32FingerPrint object) : Key parent fingerprint

Get current depth.
Returns:
Bip32Depth object: Current depth

Get current index.
Returns:
Bip32KeyIndex object: Current index

Get current chain code.
Returns:
Bip32ChainCode object: Chain code

Get parent fingerprint.
Returns:
Bip32FingerPrint object: Parent fingerprint
uModule with helper classes for BIP32 key data.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aUnion
ubip_utils.utils.misc
T aBitUtils
aBytesUtils
aDataBytes
aIntegerUtils
aDataBytes
ubip_utils.utils.typing
T aLiteral
aLiteral
