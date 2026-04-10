# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.mnemonic.mnemonic_validator

uMnemonic validator class.
aMnemonicValidator
a__qualname__
a__annotations__
mnemonic_decoder
return
a__init__
uMnemonicValidator.__init__
mnemonic
uMnemonicValidator.Validate
aIsValid
uMnemonicValidator.IsValid
ubip_utils\utils\mnemonic\mnemonic_validator.py
u<module bip_utils.utils.mnemonic.mnemonic_validator>
T aself
mnemonic
T a__class__
T aself
mnemonic_decoder

a__spec__
.bip_utils.utils.typing
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uutils\typing
T aNUITKA_PACKAGE_bip_utils_utils
u\not_existing
typing
T aNUITKA_PACKAGE_bip_utils_utils_typing
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.utils.typing.literal
T aLiteral
aLiteral
ubip_utils\utils\typing\__init__.py
u<module bip_utils.utils.typing>

a__spec__
.bip_utils.utils.typing.literal
uModule with Literal type definition.
a__doc__
a__file__
origin
has_location
a__cached__
aLiteral
typing_extensions
T aLiteral
ubip_utils\utils\typing\literal.py
u<module bip_utils.utils.typing.literal>

a__spec__
.bip_utils.wif
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
wif
T aNUITKA_PACKAGE_bip_utils_wif
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.wif.wif
T aWifDecoder
aWifEncoder
aWifPubKeyModes
aWifDecoder
aWifEncoder
aWifPubKeyModes
ubip_utils\wif\__init__.py
u<module bip_utils.wif>

a__spec__
.bip_utils.wif.wif
h
N
aWifPubKeyModes
uPublic key mode is not an enumerative of WifPubKeyModes
aSecp256k1PrivateKey
aFromBytes
uA secp256k1 private key is required
aRaw
aToBytes
aCOMPRESSED
aWifConst
aCOMPR_PUB_KEY_SUFFIX
aBase58Encoder
aCheckEncode

Encode key bytes into a WIF string.
Args:
priv_key (bytes or IPrivateKey)        : Private key bytes or object
net_ver (bytes, optional)              : Net version (Bitcoin main net by default)
pub_key_mode (WifPubKeyModes, optional): Specify if the private key corresponds to a compressed public key
Returns:
str: WIF encoded string
Raises:
TypeError: If pub_key_mode is not a WifPubKeyModes enum or
the private key is not a valid Secp256k1PrivateKey
ValueError: If the key is not valid
aBase58Decoder
aCheckDecode
uInvalid net version (expected 0x
u02X
u, got 0x
w)u
:l nnaIsValidBytes
:nq nuInvalid compressed public key suffix (expected 0x
uInvalid decoded key (
aBytesUtils
aToHexString
aUNCOMPRESSED
priv_key_bytes

Decode key bytes from a WIF string.
Args:
wif_str (str)            : WIF string
net_ver (bytes, optional): Net version (Bitcoin main net by default)
Returns:
tuple[bytes, WifPubKeyModes]: Key bytes (index 0), public key mode (index 1)
Raises:
Base58ChecksumError: If the base58 checksum is not valid
ValueError: If the resulting key is not valid
uModule for WIF encoding/decoding.
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
aUnion
ubip_utils.addr
T aP2PKHPubKeyModes
aP2PKHPubKeyModes
ubip_utils.base58
T aBase58Decoder
aBase58Encoder
ubip_utils.coin_conf
T aCoinsConf
aCoinsConf
ubip_utils.ecc
T aIPrivateKey
aSecp256k1PrivateKey
aIPrivateKey
ubip_utils.utils.misc
T aBytesUtils
