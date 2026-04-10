# Reconstructed from integrated Nuitka blob
# Module: unacl.exceptions


Base exception for all nacl related errors
a__qualname__
a__orig_bases__
aBadSignatureError

Raised when the signature was forged or otherwise corrupt.
aRuntimeError
aValueError
aInvalidkeyError
aCryptPrefixError
aUnavailableError

is a subclass of :class:`~nacl.exceptions.RuntimeError`, raised when
trying to call functions not available in a minimal build of
libsodium.
cond
args
kwds
return
ensure
unacl\exceptions.py
u<module nacl.exceptions>
T acond
args
kwds
a_CHK_UNEXP
raising

a__spec__
.nacl.public
!
decode
a_public_key
exc
aTypeError
T uPublicKey must be created from 32 bytes
aSIZE
aValueError
uThe public key must be exactly {} bytes long
nacl
bindings
sodium_memcmp
uPrivateKey must be created from a {} bytes long raw secret key
crypto_scalarmult_base
a_private_key
aPublicKey
public_key
aSEED_SIZE
uPrivateKey seed must be a {} bytes long binary sequence
crypto_box_seed_keypair

Generate a PrivateKey using a deterministic construction
starting from a caller-provided seed
.. warning:: The seed **must** be high-entropy; therefore,
its generator **must** be a cryptographic quality
random function like, for example, :func:`~nacl.utils.random`.
.. warning:: The seed **must** be protected and remain secret.
Anyone who knows the seed is really in possession of
the corresponding PrivateKey.
:param seed: The seed used to generate the private key
:rtype: :class:`~nacl.public.PrivateKey`
random
aPrivateKey
encoding
aRawEncoder
T aencoder

Generates a random :class:`~nacl.public.PrivateKey` object
:rtype: :class:`~nacl.public.PrivateKey`
T uBox must be created from a PrivateKey and a PublicKey
crypto_box_beforenm
encode
a_shared_key
a__new__

Alternative constructor. Creates a Box from an existing Box's shared key.
aNONCE_SIZE
uThe nonce must be exactly %s bytes long
crypto_box_afternm
aEncryptedMessage
a_from_parts

Encrypts the plaintext message using the given `nonce` (or generates
one randomly if omitted) and returns the ciphertext encoded with the
encoder.
.. warning:: It is **VITALLY** important that the nonce is a nonce,
i.e. it is a number used only once for any given key. If you fail
to do this, you compromise the privacy of the messages encrypted.
:param plaintext: [:class:`bytes`] The plaintext message to encrypt
:param nonce: [:class:`bytes`] The nonce to use in the encryption
:param encoder: The encoder to use to encode the ciphertext
:rtype: [:class:`nacl.utils.EncryptedMessage`]
crypto_box_open_afternm

Decrypts the ciphertext using the `nonce` (explicitly, when passed as a
parameter or implicitly, when omitted, as part of the ciphertext) and
returns the plaintext message.
:param ciphertext: [:class:`bytes`] The encrypted message to decrypt
:param nonce: [:class:`bytes`] The nonce used when encrypting the
ciphertext
:param encoder: The encoder used to decode the ciphertext.
:rtype: [:class:`bytes`]

Returns the Curve25519 shared secret, that can then be used as a key in
other symmetric ciphers.
.. warning:: It is **VITALLY** important that you use a nonce with your
symmetric cipher. If you fail to do this, you compromise the
privacy of the messages encrypted. Ensure that the key length of
your cipher is 32 bytes.
:rtype: [:class:`bytes`]
T uSealedBox must be created from a PublicKey or a PrivateKey
crypto_box_seal

Encrypts the plaintext message using a random-generated ephemeral
keypair and returns a "composed ciphertext", containing both
the public part of the keypair and the ciphertext proper,
encoded with the encoder.
The private part of the ephemeral key-pair will be scrubbed before
returning the ciphertext, therefore, the sender will not be able to
decrypt the generated ciphertext.
:param plaintext: [:class:`bytes`] The plaintext message to encrypt
:param encoder: The encoder to use to encode the ciphertext
:return bytes: encoded ciphertext
uSealedBoxes created with a public key cannot decrypt
crypto_box_seal_open

Decrypts the ciphertext using the ephemeral public key enclosed
in the ciphertext and the SealedBox private key, returning
the plaintext message.
:param ciphertext: [:class:`bytes`] The encrypted message to decrypt
:param encoder: The encoder used to decode the ciphertext.
:return bytes: The original plaintext
:raises TypeError: if this SealedBox was created with a
:class:`~nacl.public.PublicKey` rather than a
:class:`~nacl.public.PrivateKey`.
a__doc__
a__file__
origin
has_location
a__cached__
aClassVar
aGeneric
aOptional
aType
aTypeVar
unacl.bindings
T aencoding
T aexceptions
exceptions
unacl.encoding
T aEncoder
aEncoder
unacl.utils
T aEncryptedMessage
aStringFixer
random
aStringFixer
aEncodable
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
