# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.slip.slip173.slip173


SLIP-0173 class.
It defines the human-readable parts in according to SLIP-0173.
aSlip173
a__qualname__
a__annotations__
akash
aAKASH_NETWORK
axelar
aAXELAR
band
aBAND_PROTOCOL
bnb
aBINANCE_CHAIN
abc
aBITCOIN_MAINNET
bcrt
aBITCOIN_REGTEST
tb
aBITCOIN_TESTNET
certik
aCERTIK
chihuahua
aCHIHUAHUA
cosmos
aCOSMOS
erd
aELROND
fetch
aFETCH_AI
one
aHARMONY_ONE
inj
aINJECTIVE
iaa
aIRIS_NETWORK
kava
aKAVA
ltc
aLITECOIN_MAINNET
tltc
aLITECOIN_TESTNET
ex
aOKEX_CHAIN
osmo
aOSMOSIS
secret
aSECRET_NETWORK
stafi
aSTAFI
terra
aTERRA
zil
aZILLIQA
ubip_utils\slip\slip173\slip173.py
u<module bip_utils.slip.slip173.slip173>
T a__class__

a__spec__
.bip_utils.slip.slip32
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uslip\slip32
T aNUITKA_PACKAGE_bip_utils_slip
u\not_existing
slip32
T aNUITKA_PACKAGE_bip_utils_slip_slip32
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils.slip.slip32.slip32
T aSlip32DeserializedKey
aSlip32KeyDeserializer
aSlip32PrivateKeySerializer
aSlip32PublicKeySerializer
aSlip32DeserializedKey
aSlip32KeyDeserializer
aSlip32PrivateKeySerializer
aSlip32PublicKeySerializer
ubip_utils.slip.slip32.slip32_key_net_ver
T aSlip32KeyNetVersions
aSlip32KeyNetVersions
ubip_utils\slip\slip32\__init__.py
u<module bip_utils.slip.slip32>

a__spec__
.bip_utils.slip.slip32.slip32
aBip32PathParser
aParse
aBip32ChainCode
aBip32Depth
aLength
a_Slip32KeySerializer__SerializePath
aBech32Encoder
aEncode

Serialize the specified key bytes.
Args:
key_bytes (bytes)                          : Key bytes
path (str or Bip32Path object)             : BIP32 path
chain_code (bytes or Bip32ChainCode object): Chain code
key_net_ver_str (str)                      : Key net version string
Returns:
str: Serialized key
c
path_bytes
aToBytes

Serialize BIP32 path.
Args:
path (Bip32Path object): BIP32 path
Returns:
bytes: Serialized path
a_Slip32KeySerializer
aSerialize
d
aRaw
aPrivate

Serialize a private key.
Args:
priv_key (IPrivateKey object)                      : IPrivateKey object
path (str or Bip32Path object)                     : BIP32 path
chain_code (bytes or Bip32ChainCode object)        : Chain code
key_net_ver (Slip32KeyNetVersions object, optional): Key net versions (SLIP32 net version by default)
Returns:
str: Serialized private key
aRawCompressed
aPublic

Serialize a public key.
Args:
pub_key (IPublicKey object)                        : IPublicKey object
path (str or Bip32Path object)                     : BIP32 path
chain_code (bytes or Bip32ChainCode object)        : Chain code
key_net_ver (Slip32KeyNetVersions object, optional): Key net versions (SLIP32 net version by default)
Returns:
str: Serialized public key
m_key_bytes
m_path
m_chain_code
m_is_public

Construct class.
Args:
key_bytes (bytes)                 : Key bytes
path (Bip32Path object)           : BIP32 path
chain_code (Bip32ChainCode object): Chain code
is_public (bool)                  : True if the key is public, false otherwise
Returns:
str: Serialized public key

Get key bytes.
Returns:
bytes: Key bytes

Get path.
Returns:
Bip32Path object: Bip32Path object

Get chain code.
Returns:
Bip32ChainCode object: Bip32ChainCode object

Get if public.
Returns:
bool: True if the key is public, false otherwise
a_Slip32KeyDeserializer__GetIfPublic
aBech32Decoder
aDecode
a_Slip32KeyDeserializer__GetPartsFromBytes
aSlip32DeserializedKey

Deserialize a key.
Args:
ser_key_str (str)                                  : Serialized key string
key_net_ver (Slip32KeyNetVersions object, optional): Key net versions (SLIP32 net version by default)
Returns:
Slip32DeserializedKey object: Slip32DeserializedKey object
Raises:
ValueError: If the key net version is not valid
uInvalid extended key (wrong net version)

Get if the key is public.
Args:
ser_key_str (str)                        : Serialized key string
key_net_ver (Slip32KeyNetVersions object): Key net versions
Returns:
bool: True if public, false otherwise
aFixedLength
aBip32Path
path_idx
aBip32KeyIndex
path
aAddElem
aFromBytes
uInvalid extended private key (wrong secret:

w):l nnu
Get back key parts from serialized key bytes.
Args:
ser_key_bytes (bytes): Serialized key bytes
is_public (bool)     : True if the key is public, false otherwise
Returns:
Tuple[bytes, Bip32Path, Bip32ChainCode]: key bytes (index 0), BIP32 path (index 1) and chain code (index 2)

Module for SLIP32 extended key serialization/deserialization.
Reference: https://github.com/satoshilabs/slips/blob/master/slip-0032.md
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
aUnion
ubip_utils.bech32
T aBech32Decoder
aBech32Encoder
ubip_utils.bip.bip32
T aBip32ChainCode
aBip32Depth
aBip32KeyIndex
aBip32Path
aBip32PathParser
ubip_utils.ecc
T aIPrivateKey
aIPublicKey
aIPrivateKey
aIPublicKey
ubip_utils.slip.slip32.slip32_key_net_ver
T aSlip32KeyNetVersions
aSlip32KeyNetVersions
