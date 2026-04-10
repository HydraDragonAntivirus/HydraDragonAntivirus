# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.mnemonic.mnemonic_ex

uException in case of checksum error.
a__qualname__
a__orig_bases__
ubip_utils\utils\mnemonic\mnemonic_ex.py
u<module bip_utils.utils.mnemonic.mnemonic_ex>

a__spec__
.bip_utils.utils.mnemonic.mnemonic_utils
aLength
aBytesUtils
aToInteger
T aendianness
words_list
aGetWordAtIdx

Get words from a bytes chunk.
Args:
bytes_chunk (bytes)                  : Bytes chunk
words_list (MnemonicWordsList object): Mnemonic list
endianness ("big" or "little")       : Bytes endianness
Returns:
list[str]: 3 word indexes
aGetWordIdx
aIntegerUtils
aGetBytesNumber
l aToBytes
l T abytes_num
endianness

Get bytes chunk from words.
Args:
word1 (str)                          : Word 1
word2 (str)                          : Word 2
word3 (str)                          : Word 3
words_list (MnemonicWordsList object): Mnemonic list
endianness ("big" or "little")       : Bytes endianness
Returns:
bytes: Bytes chunk
m_idx_to_words
m_words_to_idx

Construct class.
Args:
words_list (list[str]): Words list

Get the length of the words list.
Returns:
int: Words list length
uUnable to find word


Get the index of the specified word.
Args:
word (str): Word to be searched
Returns:
int: Word index
Raises:
ValueError: If the word is not found

Get the word at the specified index.
Args:
word_idx (int): Word index
Returns:
str: Word at the specified index
wruutf-8
a__enter__
a__exit__
readlines
strip
startswith
T w#T nnnuNumber of loaded words list (
u) is not valid
aMnemonicWordsList

Load words list file correspondent to the specified language.
Args:
file_path (str): File name
words_num (int): Number of expected words
Returns:
MnemonicWordsList: MnemonicWordsList object
Raises:
ValueError: If loaded words list is not valid
m_words_lists
uConstruct class.
aMnemonicWordsListFileReader
aLoadFile

Load words list.
Args:
lang (MnemonicLanguages): Language
file_name (str)         : File name
words_num (int)         : Number of expected words
Returns:
MnemonicWordsList object: MnemonicWordsList object
Raises:
ValueError: If loaded words list is not valid
a_MnemonicWordsListGetterBase__instance

Get the global class instance.
Returns:
MnemonicWordsListGetterBase object: MnemonicWordsListGetterBase object
words_list_getter_cls
aInstance
aGetByLanguage
mnemonic
aToList
uInvalid language for mnemonic '
aToStr
w'u
Automatically find the language of the specified mnemonic and get the correct MnemonicWordsList class for it.
Generic version that doesn't depending on a specific mnemonic type.
Args:
mnemonic (Mnemonic object)                         : Mnemonic object
langs_enum (MnemonicLanguages class)               : Language class
words_list_getter_cls (MnemonicWordsListGetterBase): Word list getter class type
Returns:
tuple[MnemonicWordsList, MnemonicLanguages]: MnemonicWordsList object (index 0), mnemonic language (index 1)
Raises:
ValueError: If the mnemonic language cannot be found
uModule containing common utility classes for mnemonic.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
abc
T aABC
abstractmethod
aABC
abstractmethod
aDict
aList
aOptional
aTuple
aType
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
ubip_utils.utils.mnemonic.mnemonic
T aMnemonic
aMnemonicLanguages
aMnemonic
aMnemonicLanguages
ubip_utils.utils.typing
T aLiteral
aLiteral
