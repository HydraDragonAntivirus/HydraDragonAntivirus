# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.mnemonic.mnemonic

uBase enum for mnemonic languages.
a__qualname__
a__orig_bases__

Mnemonic class. It represents a generic mnemonic phrase.
It acts as a simple container with some helper functions, so it doesn't validate the given mnemonic.
aMnemonic
a__annotations__
uList[str]
D amnemonic_str
return
str
aMnemonic
aFromString
uMnemonic.FromString
D amnemonic_list
return
uList[str]
aMnemonic
uMnemonic.FromList
D amnemonic_list
return
uList[str]
aNone
a__init__
uMnemonic.__init__
D areturn
int
aWordsCount
uMnemonic.WordsCount
D areturn
uList[str]
aToList
uMnemonic.ToList
D areturn
str
uMnemonic.ToStr
a__str__
uMnemonic.__str__
D amnemonic
return
uUnion[str, List[str]]
uList[str]
uMnemonic._Normalize
ubip_utils\utils\mnemonic\mnemonic.py
u<module bip_utils.utils.mnemonic.mnemonic>
T acls
mnemonic_list
T acls
mnemonic_str
T a__class__
T aself
T amnemonic
T aself
mnemonic_list

a__spec__
.bip_utils.utils.mnemonic.mnemonic_decoder_base
v
@
m_lang
aInstance
aGetByLanguage
m_words_list
m_words_list_finder_cls

Construct class.
Args:
lang (MoneroLanguages, optional)                   : Language, None for automatic detection
words_list_finder_cls (MnemonicWordsListFinderBase): Words list finder class type
words_list_getter_cls (MnemonicWordsListGetterBase): Words list getter class type
Raises:
TypeError: If the language is not of the correct enum
ValueError: If loaded words list is not valid
aFindLanguage

Find mnemonic language.
Args:
mnemonic (Mnemonic object): Mnemonic
Returns:
tuple[MnemonicWordsList, MnemonicLanguages]: MnemonicWordsList object (index 0), mnemonic language (index 1)
Raises:
ValueError: If the mnemonic language cannot be found
uModule for mnemonic decoder base class.
a__doc__
a__file__
origin
has_location
a__cached__
abc
T aABC
abstractmethod
aABC
abstractmethod
aOptional
aTuple
aType
aUnion
ubip_utils.utils.mnemonic.mnemonic
T aMnemonic
aMnemonicLanguages
aMnemonic
aMnemonicLanguages
ubip_utils.utils.mnemonic.mnemonic_utils
T aMnemonicWordsList
aMnemonicWordsListFinderBase
aMnemonicWordsListGetterBase
aMnemonicWordsList
aMnemonicWordsListFinderBase
aMnemonicWordsListGetterBase
a__prepare__
aMnemonicDecoderBase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
