# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_generator

uClass container for Electrum v1 mnemonic generator constants.
a__qualname__
a__annotations__
aWORDS_NUM_12
aBIT_LEN_128

Electrum v1 mnemonic generator class.
It generates 12-words mnemonic in according to v1 Electrum mnemonic.
aElectrumV1MnemonicGenerator
aENGLISH
lang
return
a__init__
uElectrumV1MnemonicGenerator.__init__
words_num
aFromWordsNumber
uElectrumV1MnemonicGenerator.FromWordsNumber
entropy_bytes
uElectrumV1MnemonicGenerator.FromEntropy
ubip_utils\electrum\mnemonic_v1\electrum_v1_mnemonic_generator.py
u<module bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_generator>
T a__class__
T aself
entropy_bytes
T aself
words_num
entropy_bit_len
entropy_bytes
T aself
lang
a__spec__
.bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_utils
V
>
aElectrumV1Languages
uLanguage is not an enumerative of Bip39Languages
a_LoadWordsList
a_ElectrumV1WordsListGetter__GetLanguageFile
aElectrumV1MnemonicConst
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
lang (Bip39Languages): Language
Returns:
str: Language file name
a_FindLanguageGeneric
aElectrumV1WordsListGetter

Automatically find the language of the specified mnemonic and get the correct MnemonicWordsList class for it.
Args:
mnemonic (Mnemonic object): Mnemonic object
Returns:
tuple[MnemonicWordsList, MnemonicLanguages]: MnemonicWordsList object (index 0), mnemonic language (index 1)
Raises:
ValueError: If the mnemonic language cannot be found
uModule for Electrum v1 mnemonic utility classes.
a__doc__
origin
has_location
a__cached__
os
aTuple
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic
T aElectrumV1Languages
aElectrumV1MnemonicConst
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
