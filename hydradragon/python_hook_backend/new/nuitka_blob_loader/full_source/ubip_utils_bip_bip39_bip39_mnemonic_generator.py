# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip39.bip39_mnemonic_generator


BIP39 mnemonic generator class. It generates mnemonics in according to BIP39.
Mnemonic can be generated randomly from words number or from a specified entropy.
aBip39MnemonicGenerator
a__qualname__
a__annotations__
aENGLISH
lang
return
a__init__
uBip39MnemonicGenerator.__init__
words_num
aFromWordsNumber
uBip39MnemonicGenerator.FromWordsNumber
entropy_bytes
uBip39MnemonicGenerator.FromEntropy
D awords_num
return
Oint
pa__EntropyBitLenFromWordsNum
uBip39MnemonicGenerator.__EntropyBitLenFromWordsNum
ubip_utils\bip\bip39\bip39_mnemonic_generator.py
u<module bip_utils.bip.bip39.bip39_mnemonic_generator>
T a__class__
T aself
entropy_bytes
T aself
words_num
entropy_bit_len
entropy_bytes
T awords_num
T aself
lang
a__spec__
.bip_utils.bip.bip39.bip39_mnemonic_utils
>
aBip39Languages
uLanguage is not an enumerative of Bip39Languages
a_LoadWordsList
a_Bip39WordsListGetter__GetLanguageFile
aBip39MnemonicConst
aWORDS_LIST_NUM

Get words list by language.
Words list of a specific language are loaded from file only the first time they are requested.
Args:
lang (MnemonicLanguages): Language
Returns:
MnemonicWordsList object: MnemonicWordsList object
Raises:
TypeError: If the language is not a Bip39Languages enum
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
aBip39WordsListGetter

Automatically find the language of the specified mnemonic and get the correct MnemonicWordsList class for it.
Args:
mnemonic (Mnemonic object): Mnemonic object
Returns:
tuple[MnemonicWordsList, MnemonicLanguages]: MnemonicWordsList object (index 0), mnemonic language (index 1)
Raises:
ValueError: If the mnemonic language cannot be found
uModule for BIP39 mnemonic utility classes.
a__doc__
origin
has_location
a__cached__
os
aTuple
ubip_utils.bip.bip39.bip39_mnemonic
T aBip39Languages
aBip39MnemonicConst
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
