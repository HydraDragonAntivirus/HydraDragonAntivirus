# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.mnemonic.mnemonic_decoder_base


Mnemonic decoder base class.
It decodes a mnemonic phrase to bytes.
a__qualname__
a__annotations__
lang
words_list_finder_cls
words_list_getter_cls
return
a__init__
uMnemonicDecoderBase.__init__
mnemonic
str
bytes

Decode a mnemonic phrase to bytes (no checksum).
Args:
mnemonic (str or Mnemonic object): Mnemonic
Returns:
bytes: Decoded bytes (no checksum)
Raises:
MnemonicChecksumError: If checksum is not valid
ValueError: If mnemonic is not valid
aDecode
uMnemonicDecoderBase.Decode
a_FindLanguage
uMnemonicDecoderBase._FindLanguage
a__orig_bases__
ubip_utils\utils\mnemonic\mnemonic_decoder_base.py
u<module bip_utils.utils.mnemonic.mnemonic_decoder_base>
T aself
mnemonic
T a__class__
T aself
lang
words_list_finder_cls
words_list_getter_cls

a__spec__
.bip_utils.utils.mnemonic.mnemonic_encoder_base
4
aInstance
aGetByLanguage
m_words_list

Construct class.
Args:
lang (MnemonicLanguages)                           : Language
words_list_getter_cls (MnemonicWordsListGetterBase): Words list getter class type
Raises:
TypeError: If the language is not of the correct enum
ValueError: If loaded words list is not valid
uModule for mnemonic encoder base class.
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
aType
ubip_utils.utils.mnemonic.mnemonic
T aMnemonic
aMnemonicLanguages
aMnemonic
aMnemonicLanguages
ubip_utils.utils.mnemonic.mnemonic_utils
T aMnemonicWordsList
aMnemonicWordsListGetterBase
aMnemonicWordsList
aMnemonicWordsListGetterBase
a__prepare__
aMnemonicEncoderBase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
