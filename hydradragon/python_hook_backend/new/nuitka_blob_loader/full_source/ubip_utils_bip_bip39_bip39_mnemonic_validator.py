# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip39.bip39_mnemonic_validator


BIP39 mnemonic validator class.
It validates a mnemonic phrase.
a__qualname__
T nalang
return
uBip39MnemonicValidator.__init__
a__orig_bases__
ubip_utils\bip\bip39\bip39_mnemonic_validator.py
u<module bip_utils.bip.bip39.bip39_mnemonic_validator>
T a__class__
T aself
lang
a__class__

a__spec__
.bip_utils.bip.bip39.bip39_seed_generator
H
a__class__
a__init__
aBip39MnemonicValidator
aValidate
aBip39Mnemonic
aFromString
m_mnemonic

Construct class.
Args:
mnemonic (str or Mnemonic object): Mnemonic
lang (Bip39Languages, optional)  : Language, None for automatic detection
Raises:
ValueError: If the mnemonic is not valid
aStringUtils
aNormalizeNfkd
aBip39SeedGeneratorConst
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

Module for BIP39 mnemonic seed generation.
Reference: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.bip.bip39.bip39_mnemonic
T aBip39Languages
aBip39Mnemonic
aBip39Languages
ubip_utils.bip.bip39.bip39_mnemonic_validator
T aBip39MnemonicValidator
ubip_utils.bip.bip39.ibip39_seed_generator
T aIBip39SeedGenerator
aIBip39SeedGenerator
ubip_utils.utils.crypto
T aPbkdf2HmacSha512
ubip_utils.utils.misc
T aStringUtils
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
