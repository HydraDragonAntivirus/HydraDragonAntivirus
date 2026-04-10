# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.utils.conf.coin_names

uHelper class for representing coin names.
aCoinNames
a__qualname__
a__annotations__
D aname
abbr
return
Ostr
pna__init__
uCoinNames.__init__
D areturn
Ostr
aName
uCoinNames.Name
aAbbreviation
uCoinNames.Abbreviation
ubip_utils\utils\conf\coin_names.py
u<module bip_utils.utils.conf.coin_names>
T aself
T a__class__
T aself
name
abbr

a__spec__
.bip_utils.utils.conf
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uutils\conf
T aNUITKA_PACKAGE_bip_utils_utils
u\not_existing
conf
T aNUITKA_PACKAGE_bip_utils_utils_conf
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.utils.conf.coin_names
T aCoinNames
aCoinNames
ubip_utils\utils\conf\__init__.py
u<module bip_utils.utils.conf>

a__spec__
.bip_utils.utils
'
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
utils
T aNUITKA_PACKAGE_bip_utils_utils
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils\utils\__init__.py
u<module bip_utils.utils>

a__spec__
.bip_utils.utils.crypto.aes_ecb
I
aAES
new
aAlgoUtils
aEncode
aMODE_ECB
aes
auto_pad

Construct class.
Args:
key (str or bytes): AES key

Set the auto-pad flag.
Args:
value (bool): Flag value
aPad
encrypt

Encrypt data using AES-ECB algorithm.
Args:
data (str or bytes): Data to be encrypted
Returns:
bytes: Encrypted data
pad
block_size

Pad data using PKCS7 algorithm.
Args:
data (str or bytes): Data to be padded
Returns:
bytes: Padded data
auto_unpad

Set the auto-unpad flag.
Args:
value (bool): Flag value
decrypt
aUnPad

Decrypt data using AES-ECB algorithm.
Args:
data (bytes): Data to be decrypted
Returns:
bytes: Decrypted data
unpad

Unpad data using PKCS7 algorithm.
Args:
data (bytes): Data to be unpadded
Returns:
bytes: Unpadded data
uModule for AES-ECB encryption/decryption.
a__doc__
a__file__
origin
has_location
a__cached__
aAny
aUnion
uCrypto.Cipher
T aAES
uCrypto.Util.Padding
T apad
unpad
ubip_utils.utils.misc.algo
T aAlgoUtils
