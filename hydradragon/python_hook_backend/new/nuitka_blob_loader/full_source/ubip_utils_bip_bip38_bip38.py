# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.bip.bip38.bip38


BIP38 encrypter class.
It encrypts a private key using the algorithm specified in BIP38.
aBip38Encrypter
a__qualname__
aCOMPRESSED
priv_key
passphrase
pub_key_mode
return
aEncryptNoEc
uBip38Encrypter.EncryptNoEc
lot_num
sequence_num
aGeneratePrivateKeyEc
uBip38Encrypter.GeneratePrivateKeyEc

BIP38 decrypter class.
It decrypts a private key using the algorithm specified in BIP38.
aBip38Decrypter
priv_key_enc
aDecryptNoEc
uBip38Decrypter.DecryptNoEc
aDecryptEc
uBip38Decrypter.DecryptEc
ubip_utils\bip\bip38\bip38.py
u<module bip_utils.bip.bip38.bip38>
T a__class__
T apriv_key_enc
passphrase
T apriv_key
passphrase
pub_key_mode
T apassphrase
pub_key_mode
lot_num
sequence_num
int_pass

a__spec__
.bip_utils.bip.bip38.bip38_addr
3
aP2PKHAddr
aEncodeKey
aCoinsConf
aBitcoinMainNet
aParamByKey
T ap2pkh_net_ver
T anet_ver
pub_key_mode
aDoubleSha256
aQuickDigest
aBip38AddrConst
aADDR_HASH_LEN

Compute the address hash as specified in BIP38.
Args:
pub_key (bytes or IPublicKey)  : Public key bytes or object
pub_key_mode (Bip38PubKeyModes): Public key mode
Returns:
bytes: Address hash
Raises:
TypeError: If the public key is not a Secp256k1PublicKey
ValueError: If the public key bytes are not valid
uModule with BIP38 utility functions.
a__doc__
a__file__
origin
has_location
a__cached__
aUnion
ubip_utils.addr
T aP2PKHAddr
ubip_utils.coin_conf
T aCoinsConf
ubip_utils.ecc
T aIPublicKey
aIPublicKey
ubip_utils.utils.crypto
T aDoubleSha256
ubip_utils.wif
T aWifPubKeyModes
aWifPubKeyModes
aBip38PubKeyModes
