# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.mnemonic.mnemonic_utils

uClass container for mnemonic utility functions.
aMnemonicUtils
a__qualname__
D abytes_chunk
words_list
endianness
return
bytes
aMnemonicWordsList
uLiteral['little', 'big']
uList[str]
aBytesChunkToWords
uMnemonicUtils.BytesChunkToWords
D aword1
word2
word3
words_list
endianness
return
str
ppaMnemonicWordsList
uLiteral['little', 'big']
bytes
aWordsToBytesChunk
uMnemonicUtils.WordsToBytesChunk
uMnemonic words list class.
a__annotations__
uList[str]
uDict[str, int]
D awords_list
return
uList[str]
aNone
a__init__
uMnemonicWordsList.__init__
D areturn
int
uMnemonicWordsList.Length
D aword
return
str
int
uMnemonicWordsList.GetWordIdx
D aword_idx
return
int
str
uMnemonicWordsList.GetWordAtIdx

Mnemonic words list file reader class.
It reads the words list from a file.
D afile_path
words_num
return
str
int
aMnemonicWordsList
uMnemonicWordsListFileReader.LoadFile
a__prepare__
aMnemonicWordsListGetterBase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uMnemonic words list getter base class.
uDict[MnemonicLanguages, MnemonicWordsList]
uOptional[MnemonicWordsListGetterBase]
uMnemonicWordsListGetterBase.__init__
D alang
return
aMnemonicLanguages
aMnemonicWordsList

Get words list by language.
Words list of a specific language are loaded from file only the first time they are requested.
Args:
lang (MnemonicLanguages): Language
Returns:
MnemonicWordsList object: MnemonicWordsList object
Raises:
TypeError: If the language is not of the correct enumerative
ValueError: If loaded words list is not valid
uMnemonicWordsListGetterBase.GetByLanguage
D alang
file_name
words_num
return
aMnemonicLanguages
str
int
aMnemonicWordsList
a_LoadWordsList
uMnemonicWordsListGetterBase._LoadWordsList
classmethod
D areturn
aMnemonicWordsListGetterBase
uMnemonicWordsListGetterBase.Instance
a__orig_bases__
aMnemonicWordsListFinderBase

Mnemonic words list finder base class.
It automatically finds the correct words list from a mnemonic.
D amnemonic
return
aMnemonic
uTuple[MnemonicWordsList, MnemonicLanguages]

Automatically find the language of the specified mnemonic and get the correct MnemonicWordsList class for it.
Args:
mnemonic (Mnemonic object): Mnemonic object
Returns:
tuple[MnemonicWordsList, MnemonicLanguages]: MnemonicWordsList object (index 0), mnemonic language (index 1)
Raises:
ValueError: If the mnemonic language cannot be found
aFindLanguage
uMnemonicWordsListFinderBase.FindLanguage
staticmethod
D amnemonic
langs_enum
words_list_getter_cls
return
aMnemonic
uType[MnemonicLanguages]
uType[MnemonicWordsListGetterBase]
uTuple[MnemonicWordsList, MnemonicLanguages]
a_FindLanguageGeneric
uMnemonicWordsListFinderBase._FindLanguageGeneric
ubip_utils\utils\mnemonic\mnemonic_utils.py
u<module bip_utils.utils.mnemonic.mnemonic_utils>
T abytes_chunk
words_list
endianness
wnaint_chunk
word1_idx
word2_idx
word3_idx
T acls
mnemonic
T aself
lang
T aself
word_idx
T aself
word
ex
T acls
T aself
T afile_path
words_num
fin
words_list
T a__class__
T
word1
word2
word3
words_list
endianness
wnaword1_idx
word2_idx
word3_idx
int_chunk
T amnemonic
langs_enum
words_list_getter_cls
lang
words_list
word
T aself
lang
file_name
words_num
T aself
words_list
a__spec__
.bip_utils.utils.mnemonic.mnemonic_validator
+
m_mnemonic_decoder

Construct class.
Args:
mnemonic_decoder (MnemonicDecoderBase object): Mnemonic decoder class instance
aDecode

Validate the mnemonic specified at construction.
Args:
mnemonic (str or Mnemonic object): Mnemonic
Raises:
MnemonicChecksumError: If checksum is not valid
ValueError: If mnemonic is not valid
aValidate
aMnemonicChecksumError

Get if the mnemonic specified at construction is valid.
Args:
mnemonic (str or Mnemonic object): Mnemonic
Returns:
bool: True if valid, False otherwise
uModule for generic mnemonic validation.
a__doc__
a__file__
origin
has_location
a__cached__
aUnion
ubip_utils.utils.mnemonic.mnemonic
T aMnemonic
aMnemonic
ubip_utils.utils.mnemonic.mnemonic_decoder_base
T aMnemonicDecoderBase
aMnemonicDecoderBase
ubip_utils.utils.mnemonic.mnemonic_ex
T aMnemonicChecksumError
