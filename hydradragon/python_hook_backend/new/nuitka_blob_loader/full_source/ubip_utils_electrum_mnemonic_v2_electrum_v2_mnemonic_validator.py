# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_validator


Electrum v2 mnemonic validator class.
It validates a mnemonic phrase.
a__qualname__
a__annotations__
m_mnemonic_decoder
T nnamnemonic_type
lang
return
uElectrumV2MnemonicValidator.__init__
a__orig_bases__
ubip_utils\electrum\mnemonic_v2\electrum_v2_mnemonic_validator.py
u<module bip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_validator>
T a__class__
T aself
mnemonic_type
lang
a__class__

a__spec__
.bip_utils.electrum.mnemonic_v2.electrum_v2_seed_generator
%
?
aElectrumV2MnemonicValidator
T alang
aValidate
aElectrumV2Mnemonic
aFromString
m_mnemonic

Construct class.
Args:
mnemonic (str or Mnemonic object)   : Mnemonic
lang (ElectrumV2Languages, optional): Language, None for automatic detection
Raises:
ValueError: If the mnemonic is not valid
aStringUtils
aNormalizeNfkd
aElectrumV2SeedGeneratorConst
aSEED_SALT_MOD
aPbkdf2HmacSha512
aDeriveKey
aToStr
aSEED_PBKDF2_ROUNDS

Generate the seed using the specified passphrase.
Args:
passphrase (str, optional): Passphrase, empty if not specified
Returns:
bytes: Generated seed
uModule for Electrum v2 mnemonic seed generation.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic
T aElectrumV2Languages
aElectrumV2Mnemonic
aElectrumV2Languages
ubip_utils.electrum.mnemonic_v2.electrum_v2_mnemonic_validator
T aElectrumV2MnemonicValidator
ubip_utils.utils.crypto
T aPbkdf2HmacSha512
ubip_utils.utils.misc
T aStringUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
