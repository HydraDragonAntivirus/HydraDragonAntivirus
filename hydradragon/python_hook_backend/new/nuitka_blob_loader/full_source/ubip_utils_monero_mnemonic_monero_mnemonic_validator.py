# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.mnemonic.monero_mnemonic_validator


Monero mnemonic validator class.
It validates a mnemonic phrase.
a__qualname__
T nalang
return
uMoneroMnemonicValidator.__init__
a__orig_bases__
ubip_utils\monero\mnemonic\monero_mnemonic_validator.py
u<module bip_utils.monero.mnemonic.monero_mnemonic_validator>
T a__class__
T aself
lang
a__class__

a__spec__
.bip_utils.monero.mnemonic.monero_seed_generator
+
aMoneroMnemonicDecoder
aDecode
m_entropy_bytes

Construct class.
Args:
mnemonic (str or Mnemonic object): Mnemonic
lang (MoneroLanguages, optional) : Language, None for automatic detection
Raises:
ValueError: If the mnemonic is not valid

Generate seed. The seed is simply the entropy bytes in Monero case.
There is no really need of this method, since the seed is always the same, but it's
kept in this way to have the same usage of Bip39/Substrate seed generator
(i.e. MoneroSeedGenerator(mnemonic).Generate() ).
Returns:
bytes: Generated seed
uModule for Monero seed generation.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aUnion
ubip_utils.monero.mnemonic.monero_mnemonic
T aMoneroLanguages
aMoneroLanguages
ubip_utils.monero.mnemonic.monero_mnemonic_decoder
T aMoneroMnemonicDecoder
ubip_utils.utils.mnemonic
T aMnemonic
aMnemonic
