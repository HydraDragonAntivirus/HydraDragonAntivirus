# Reconstructed from integrated Nuitka blob
# Module: ucoincurve.context

aContext
a__qualname__
seed
a__init__
uContext.__init__
T nuContext.reseed
uContext.__repr__
T aGLOBAL_CONTEXT
T aname
aGLOBAL_CONTEXT
ucoincurve\context.py
u<module coincurve.context>
T a__class__
T aself
seed
flag
name
T aself
a__class__
T aself
seed
res
a__spec__
.coincurve.ecdsa
S
ffi
new
uunsigned char[%d]
aMAX_SIG_LENGTH
usize_t *
lib
secp256k1_ecdsa_signature_serialize_der
ctx
buffer
T usecp256k1_ecdsa_signature *
secp256k1_ecdsa_signature_parse_der
uThe DER-encoded signature could not be parsed.
uMessage hash must be 32 bytes long.
T usecp256k1_pubkey *
secp256k1_ecdsa_recover
ufailed to recover ECDSA public key
aCDATA_SIG_LENGTH
T uint *
secp256k1_ecdsa_recoverable_signature_serialize_compact
int_to_bytes
uSerialized signature must be 65 bytes long.
:nl@nabytes_to_int
:l@nnl uInvalid recovery id.
T usecp256k1_ecdsa_recoverable_signature *
secp256k1_ecdsa_recoverable_signature_parse_compact
uFailed to parse recoverable signature.
secp256k1_ecdsa_signature_serialize_compact
uinvalid signature length
secp256k1_ecdsa_signature_parse_compact
secp256k1_ecdsa_signature_normalize

Check and optionally convert a signature to a normalized lower-S form.
This function always return a tuple containing a boolean (True if
not previously normalized or False if signature was already
normalized), and the normalized signature.
secp256k1_ecdsa_recoverable_signature_convert
a__doc__
a__file__
origin
has_location
a__cached__
ucoincurve.context
T aGLOBAL_CONTEXT
aContext
aGLOBAL_CONTEXT
aContext
ucoincurve.types
T aHasher
aHasher
ucoincurve.utils
T abytes_to_int
int_to_bytes
sha256
sha256
a_libsecp256k1
T affi
lib
lHl@acontext
return
cdata_to_der
der
der_to_cdata
message
hasher
recover
serialize_recoverable
serialized
deserialize_recoverable
serialize_compact
ser_sig
deserialize_compact
signature_normalize
recoverable_convert
ucoincurve\ecdsa.py
u<module coincurve.ecdsa>
T acdata
context
der
der_length
T ader
context
cdata
parsed
T aser_sig
context
raw_sig
res
T aserialized
context
ser_sig
rec_id
recover_sig
parsed
T amessage
recover_sig
hasher
context
msg_hash
pubkey
recovered
T arecover_sig
context
normal_sig
T araw_sig
context
output
res
T arecover_sig
context
output
recid
T araw_sig
context
sigout
res

a__spec__
.coincurve.flags
a__doc__
a__file__
origin
has_location
a__cached__
a_libsecp256k1
T alib
lib
aSECP256K1_CONTEXT_NONE
aCONTEXT_NONE
aCONTEXT_FLAGS
aSECP256K1_EC_COMPRESSED
aEC_COMPRESSED
aSECP256K1_EC_UNCOMPRESSED
aEC_UNCOMPRESSED
ucoincurve\flags.py
u<module coincurve.flags>

a__spec__
.coincurve.keys
L9
+ avalidate_secret
get_valid_secret
secret
context
aPublicKey
from_valid_secret
public_key
aPublicKeyXOnly
public_key_xonly

:param secret: The secret used to initialize the private key.
If not provided or `None`, a new key will be generated.
uMessage hash must be 32 bytes long.
ffi
new
T usecp256k1_ecdsa_signature *
lib
secp256k1_ecdsa_sign
ctx
uThe nonce generation function failed, or the private key was invalid.
cdata_to_der

Create an ECDSA signature.
:param message: The message to sign.
:param hasher: The hash function to use, which must return 32 bytes. By default,
the `sha256` algorithm is used. If `None`, no hashing occurs.
:param custom_nonce: Custom nonce data in the form `(nonce_function, input_data)`. Refer to
[secp256k1.h](https://github.com/bitcoin-core/secp256k1/blob/f8c0b57e6ba202b1ce7c5357688de97c9c067697/include/secp256k1.h#L546-L547).
:return: The ECDSA signature.
:raises ValueError: If the message hash was not 32 bytes long, the nonce generation
function failed, or the private key was invalid.
uMessage must be 32 bytes long.
c
urandom
T l aNULL
uAuxiliary random data must be 32 bytes long.
T usecp256k1_keypair *
secp256k1_keypair_create
uSecret was invalid
T uunsigned char[64]
secp256k1_schnorrsig_sign32
aux_randomness
uSigning failed
secp256k1_schnorrsig_verify
uInvalid signature
buffer
uCreate a Schnorr signature.
:param message: The message to sign.
:param aux_randomness: An optional 32 bytes of fresh randomness. By default (empty bytestring), this
will be generated automatically. Set to `None` to disable this behavior.
:return: The Schnorr signature.
:raises ValueError: If the message was not 32 bytes long, the optional auxiliary random data was not
32 bytes long, signing failed, or the signature was invalid.
T usecp256k1_ecdsa_recoverable_signature *
secp256k1_ecdsa_sign_recoverable
serialize_recoverable

Create a recoverable ECDSA signature.
:param message: The message to sign.
:param hasher: The hash function to use, which must return 32 bytes. By default,
the `sha256` algorithm is used. If `None`, no hashing occurs.
:param custom_nonce: Custom nonce data in the form `(nonce_function, input_data)`. Refer to
[secp256k1_recovery.h](https://github.com/bitcoin-core/secp256k1/blob/f8c0b57e6ba202b1ce7c5357688de97c9c067697/include/secp256k1_recovery.h#L78-L79).
:return: The recoverable ECDSA signature.
:raises ValueError: If the message hash was not 32 bytes long, the nonce generation
function failed, or the private key was invalid.
T uunsigned char [32]
secp256k1_ecdh
l u
Compute an EC Diffie-Hellman secret in constant time.
!!! note
This prevents malleability by returning `sha256(compressed_public_key)` instead of the `x` coordinate
directly. See #9.
:param public_key: The formatted public key.
:return: The 32 byte shared secret.
:raises ValueError: If the public key could not be parsed or was invalid.
pad_scalar
uunsigned char [32]
secp256k1_ec_seckey_tweak_add
uThe tweak was out of range, or the resulting private key is invalid.
a_update_public_key
aPrivateKey

Add a scalar to the private key.
:param scalar: The scalar with which to add.
:param update: Whether or not to update and return the private key in-place.
:return: The new private key, or the modified private key if `update` is `True`.
:rtype: PrivateKey
:raises ValueError: If the tweak was out of range or the resulting private key was invalid.
secp256k1_ec_seckey_tweak_mul

Multiply the private key by a scalar.
:param scalar: The scalar with which to multiply.
:param update: Whether or not to update and return the private key in-place.
:return: The new private key, or the modified private key if `update` is `True`.
:rtype: PrivateKey
hex

:return: The private key encoded as a hex string.
bytes_to_int

:return: The private key as an integer.
der_to_pem
to_der

:return: The private key encoded in PEM format.
aECPrivateKey
version
ecPrivkeyVer1
private_key
to_int
aECPointBitString
format
T FT acompressed
aPrivateKeyInfo
private_key_algorithm
aPrivateKeyAlgorithm
algorithm
ec
parameters
aECDomainParameters
T anamed
u1.3.132.0.10
T aname
value
dump

:return: The private key encoded in DER format.
hex_to_bytes

:param hexed: The private key encoded as a hex string.
:param context:
:return: The private key.
:rtype: PrivateKey
int_to_bytes_padded

:param num: The private key as an integer.
:param context:
:return: The private key.
:rtype: PrivateKey
load
pem_to_der
native

:param pem: The private key encoded in PEM format.
:param context:
:return: The private key.
:rtype: PrivateKey

:param der: The private key encoded in DER format.
:param context:
:return: The private key.
:rtype: PrivateKey
secp256k1_ec_pubkey_create
uInvalid secret.
T usecp256k1_pubkey *
secp256k1_ec_pubkey_parse
uThe public key could not be parsed or is invalid.
self

:param data: The formatted public key. This class supports parsing
compressed (33 bytes, header byte `0x02` or `0x03`),
uncompressed (65 bytes, header byte `0x04`), or
hybrid (65 bytes, header byte `0x06` or `0x07`) format public keys.
:type data: bytes
:param context:
:raises ValueError: If the public key could not be parsed or was invalid.
uSomehow an invalid secret was used. Please submit this as an issue here: https://github.com/ofek/coincurve/issues/new

Derive a public key from a private key secret.
:param secret: The private key secret.
:param context:
:return: The public key.
:rtype: PublicKey
d u
Derive a public key from a coordinate point in the form `(x, y)`.
:param x:
:param y:
:param context:
:return: The public key.
:rtype: PublicKey
recover
deserialize_recoverable
T acontext
T ahasher
context

Recover an ECDSA public key from a recoverable signature.
:param signature: The recoverable ECDSA signature.
:param message: The message that was supposedly signed.
:param hasher: The hash function to use, which must return 32 bytes. By default,
the `sha256` algorithm is used. If `None`, no hashing occurs.
:param context:
:return: The public key that signed the message.
:rtype: PublicKey
:raises ValueError: If the message hash was not 32 bytes long or recovery of the ECDSA public key failed.
secp256k1_ec_pubkey_combine
uThe sum of the public keys is invalid.

Add a number of public keys together.
:param public_keys: A sequence of public keys.
:type public_keys: List[PublicKey]
:param context:
:return: The combined public key.
:rtype: PublicKey
:raises ValueError: If the sum of the public keys was invalid.
l!lAuunsigned char [%d]
usize_t *
secp256k1_ec_pubkey_serialize
aEC_COMPRESSED
aEC_UNCOMPRESSED

Format the public key.
:param compressed: Whether or to use the compressed format.
:return: The 33 byte formatted public key, or the 65 byte formatted public key if `compressed` is `False`.
:l l!n:l!nnu
:return: The public key as a coordinate point.
secp256k1_ecdsa_verify
der_to_cdata

:param signature: The ECDSA signature.
:param message: The message that was supposedly signed.
:param hasher: The hash function to use, which must return 32 bytes. By default,
the `sha256` algorithm is used. If `None`, no hashing occurs.
:return: A boolean indicating whether or not the signature is correct.
:raises ValueError: If the message hash was not 32 bytes long or the DER-encoded signature could not be parsed.
usecp256k1_pubkey *
secp256k1_ec_pubkey_tweak_add
uThe tweak was out of range, or the resulting public key is invalid.

Add a scalar to the public key.
:param scalar: The scalar with which to add.
:param update: Whether or not to update and return the public key in-place.
:return: The new public key, or the modified public key if `update` is `True`.
:rtype: PublicKey
:raises ValueError: If the tweak was out of range or the resulting public key was invalid.
secp256k1_ec_pubkey_tweak_mul

Multiply the public key by a scalar.
:param scalar: The scalar with which to multiply.
:param update: Whether or not to update and return the public key in-place.
:return: The new public key, or the modified public key if `update` is `True`.
:rtype: PublicKey

Add a number of public keys together.
:param public_keys: A sequence of public keys.
:type public_keys: List[PublicKey]
:param update: Whether or not to update and return the public key in-place.
:return: The combined public key, or the modified public key if `update` is `True`.
:rtype: PublicKey
:raises ValueError: If the sum of the public keys was invalid.
T usecp256k1_xonly_pubkey *
secp256k1_xonly_pubkey_parse
parity
uA BIP340 `x-only` public key.
:param data: The formatted public key.
:type data: bytes
:param parity: Whether the encoded point is the negation of the public key.
:param context:
T uint *
secp256k1_keypair_xonly_pub
T aparity
context
uDerive an x-only public key from a private key secret.
:param secret: The private key secret.
:param context:
:return: The x-only public key.
secp256k1_xonly_pubkey_serialize
uPublic key in self.public_key must be valid
uSerialize the public key.
:return: The public key serialized as 32 bytes.
uSignature must be 32 bytes long.
uVerify a Schnorr signature over a given message.
:param signature: The 64-byte Schnorr signature to verify.
:param message: The message to be verified.
:return: A boolean indicating whether or not the signature is correct.
secp256k1_xonly_pubkey_tweak_add
uThe tweak was out of range, or the resulting public key would be invalid
secp256k1_xonly_pubkey_from_pubkey
uAdd a scalar to the public key.
:param scalar: The scalar with which to add.
:return: The modified public key.
:rtype: PublicKeyXOnly
:raises ValueError: If the tweak was out of range or the resulting public key was invalid.
secp256k1_xonly_pubkey_cmp
a__doc__
a__file__
origin
has_location
a__cached__
os
aOptional
aTuple
uasn1crypto.keys
T aECDomainParameters
aECPointBitString
aECPrivateKey
aPrivateKeyAlgorithm
aPrivateKeyInfo
ucoincurve.context
T aGLOBAL_CONTEXT
aContext
aGLOBAL_CONTEXT
aContext
ucoincurve.ecdsa
T acdata_to_der
der_to_cdata
deserialize_recoverable
recover
serialize_recoverable
ucoincurve.flags
T aEC_COMPRESSED
aEC_UNCOMPRESSED
ucoincurve.types
T aHasher
aNonce
aHasher
aNonce
ucoincurve.utils
T
aDEFAULT_NONCE
bytes_to_int
der_to_pem
get_valid_secret
hex_to_bytes
int_to_bytes_padded
pad_scalar
pem_to_der
sha256
validate_secret
aDEFAULT_NONCE
sha256
a_libsecp256k1
T affi
lib
