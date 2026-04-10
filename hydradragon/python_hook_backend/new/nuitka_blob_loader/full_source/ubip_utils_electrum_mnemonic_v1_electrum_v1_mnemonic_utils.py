# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_utils


Electrum words list getter class (v1).
It allows to get words list by language so that they are loaded from file only once per language.
a__qualname__
lang
return
aGetByLanguage
uElectrumV1WordsListGetter.GetByLanguage
staticmethod
str
a__GetLanguageFile
uElectrumV1WordsListGetter.__GetLanguageFile
a__orig_bases__
aElectrumV1WordsListFinder

Electrum words list finder class (v1).
It automatically finds the correct words list from a mnemonic.
classmethod
mnemonic
aFindLanguage
uElectrumV1WordsListFinder.FindLanguage
ubip_utils\electrum\mnemonic_v1\electrum_v1_mnemonic_utils.py
u<module bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_utils>
T a__class__
T acls
mnemonic
T aself
lang
T alang

a__spec__
.bip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_validator
3
*
a__class__
a__init__
aElectrumV1MnemonicDecoder

Construct class.
Language is set to English by default because Electrum v1 mnemonic only support one language,
so it's useless (and slower) to automatically detect the language.
Args:
lang (ElectrumV1Languages, optional): Language, None for automatic detection
uModule for Electrum v1 mnemonic validation.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic
T aElectrumV1Languages
aElectrumV1Languages
ubip_utils.electrum.mnemonic_v1.electrum_v1_mnemonic_decoder
T aElectrumV1MnemonicDecoder
ubip_utils.utils.mnemonic
T aMnemonicValidator
aMnemonicValidator
a__prepare__
aElectrumV1MnemonicValidator
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
