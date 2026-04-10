# Reconstructed from integrated Nuitka blob
# Module: unacl.signing


A bytes subclass that holds a messaged that has been signed by a
:class:`SigningKey`.
a__qualname__
a__annotations__
bytes
classmethod
signature
message
combined
return
uSignedMessage._from_parts
property
uSignedMessage.signature
uSignedMessage.message
a__orig_bases__
aEncodable

The public key counterpart to an Ed25519 SigningKey for producing digital
signatures.
:param key: [:class:`bytes`] Serialized Ed25519 public key
:param encoder: A class that is able to decode the `key`
key
encoder
aEncoder
a__init__
uVerifyKey.__init__
a__bytes__
uVerifyKey.__bytes__
int
a__hash__
uVerifyKey.__hash__
other
object
bool
a__eq__
uVerifyKey.__eq__
a__ne__
uVerifyKey.__ne__
smessage
verify
uVerifyKey.verify
to_curve25519_public_key
uVerifyKey.to_curve25519_public_key
aSigningKey

Private key for producing digital signatures using the Ed25519 algorithm.
Signing keys are produced from a 32-byte (256-bit) random seed value. This
value can be passed into the :class:`~nacl.signing.SigningKey` as a
:func:`bytes` whose length is 32.
.. warning:: This **must** be protected and remain secret. Anyone who knows
the value of your :class:`~nacl.signing.SigningKey` or it's seed can
masquerade as you.
:param seed: [:class:`bytes`] Random 32-byte value (i.e. private key)
:param encoder: A class that is able to decode the seed
:ivar: verify_key: [:class:`~nacl.signing.VerifyKey`] The verify
(i.e. public) key that corresponds with this signing key.
seed
uSigningKey.__init__
uSigningKey.__bytes__
uSigningKey.__hash__
uSigningKey.__eq__
uSigningKey.__ne__
D areturn
aSigningKey
generate
uSigningKey.generate
sign
uSigningKey.sign
to_curve25519_private_key
uSigningKey.to_curve25519_private_key
unacl\signing.py
u<module nacl.signing>
T a__class__
T aself
T aself
other
T aself
seed
encoder
public_key
secret_key
T aself
key
encoder
T acls
signature
message
combined
obj
T acls
T aself
message
encoder
raw_signed
crypto_sign_BYTES
signature
signed
T aself
sk
raw_private
T aself
raw_pk
T aself
smessage
signature
encoder

a__spec__
.nacl.utils
N
a_nonce
a_ciphertext

The nonce used during the encryption of the :class:`EncryptedMessage`.

The ciphertext contained within the :class:`EncryptedMessage`.
a__bytes__
decode
T aascii
urandom
nacl
bindings
randombytes_buf_deterministic
encode

Returns ``size`` number of deterministically generated pseudorandom bytes
from a seed
:param size: int
:param seed: bytes
:param encoder: The encoder class used to encode the produced bytes
:rtype: bytes
a__doc__
a__file__
origin
has_location
a__cached__
os
aSupportsBytes
aType
aTypeVar
unacl.bindings
T aencoding
encoding
T a_EncryptedMessage
aEncryptedMessage
T abound
a_EncryptedMessage
T Obytes
a__prepare__
aEncryptedMessage
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
