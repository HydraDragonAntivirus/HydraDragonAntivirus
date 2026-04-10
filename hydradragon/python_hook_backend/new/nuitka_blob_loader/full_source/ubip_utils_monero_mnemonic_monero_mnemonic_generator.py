# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.mnemonic.monero_mnemonic_generator

uClass container for Monero mnemonic generator constants.
a__qualname__
a__annotations__
aWORDS_NUM_12
aBIT_LEN_128
aWORDS_NUM_13
aWORDS_NUM_24
aBIT_LEN_256
aWORDS_NUM_25

Monero mnemonic generator class.
Mnemonic can be generated randomly from words number or from a specified entropy.
aMoneroMnemonicGenerator
aENGLISH
lang
return
a__init__
uMoneroMnemonicGenerator.__init__
words_num
aFromWordsNumber
uMoneroMnemonicGenerator.FromWordsNumber
entropy_bytes
uMoneroMnemonicGenerator.FromEntropyNoChecksum
uMoneroMnemonicGenerator.FromEntropyWithChecksum
ubip_utils\monero\mnemonic\monero_mnemonic_generator.py
u<module bip_utils.monero.mnemonic.monero_mnemonic_generator>
T aself
entropy_bytes
T aself
words_num
entropy_bit_len
entropy_bytes
T a__class__
T aself
lang
a__spec__
.bip_utils.monero.mnemonic.monero_mnemonic_utils
:
N
aMoneroLanguages
uLanguage is not an enumerative of MoneroLanguages
a_LoadWordsList
a_MoneroWordsListGetter__GetLanguageFile
aMoneroMnemonicConst
aWORDS_LIST_NUM

Get words list by language.
Words list of a specific language are loaded from file only the first time they are requested.
Args:
lang (MnemonicLanguages): Language
Returns:
MnemonicWordsList object: MnemonicWordsList object
Raises:
TypeError: If the language is not a MoneroLanguages enum
ValueError: If loaded words list is not valid
join
a__file__
aLANGUAGE_FILES

Get the specified language file name.
Args:
lang (MnemonicLanguages): Language
Returns:
str: Language file name
a_FindLanguageGeneric
aMoneroWordsListGetter

Automatically find the language of the specified mnemonic and get the correct MnemonicWordsList class for it.
Args:
mnemonic (Mnemonic object): Mnemonic object
Returns:
tuple[MnemonicWordsList, MnemonicLanguages]: MnemonicWordsList object (index 0), mnemonic language (index 1)
Raises:
ValueError: If the mnemonic language cannot be found
aLANGUAGE_UNIQUE_PREFIX_LEN

aCrc32
aQuickIntDigest

Compute checksum.
Args:
mnemonic (list[str])    : Mnemonic list of words
lang (MnemonicLanguages): Language
Returns:
str: Checksum word
unique_prefix_len
u<genexpr>
uMoneroMnemonicUtils.ComputeChecksum.<locals>.<genexpr>
uModule for Monero mnemonic utility classes.
a__doc__
origin
has_location
a__cached__
os
aList
aTuple
ubip_utils.monero.mnemonic.monero_mnemonic
T aMoneroLanguages
aMoneroMnemonicConst
ubip_utils.utils.crypto
T aCrc32
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonicLanguages
aMnemonicWordsList
aMnemonicWordsListFinderBase
aMnemonicWordsListGetterBase
aMnemonic
aMnemonicLanguages
aMnemonicWordsList
aMnemonicWordsListFinderBase
aMnemonicWordsListGetterBase
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
