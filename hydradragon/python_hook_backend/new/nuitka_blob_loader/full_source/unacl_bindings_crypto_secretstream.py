# Reconstructed from integrated Nuitka blob
# Module: unacl.bindings.crypto_secretstream


An object wrapping the crypto_secretstream_xchacha20poly1305 state.
a__qualname__
a__slots__
D areturn
na__init__
ucrypto_secretstream_xchacha20poly1305_state.__init__
state
key
return
wmatag
header
T nwcT Obytes
Oint
unacl\bindings\crypto_secretstream.py
u<module nacl.bindings.crypto_secretstream>
T aself
T astate
header
key
rc
T astate
key
headerbuf
rc
T akeybuf
T astate
wcaad
mlen
adlen
rc
T astate
wmaad
tag
clen
adlen
rc
T astate

a__spec__
.nacl.bindings.crypto_shorthash
$
-
aKEYBYTES
exc
aValueError
uKey length must be exactly {} bytes
ffi
new
uunsigned char[]
aBYTES
lib
crypto_shorthash_siphash24
ensure
aRuntimeError
T araising
buffer
:nnnuCompute a fast, cryptographic quality, keyed hash of the input data
:param data:
:type data: bytes
:param key: len(key) must be equal to
:py:data:`.KEYBYTES` (16)
:type key: bytes
has_crypto_shorthash_siphashx24
uNot available in minimal build
aUnavailableError
aXKEYBYTES
aXBYTES
crypto_shorthash_siphashx24
uCompute a fast, cryptographic quality, keyed hash of the input data
:param data:
:type data: bytes
:param key: len(key) must be equal to
:py:data:`.XKEYBYTES` (16)
:type key: bytes
:raises nacl.exceptions.UnavailableError: If called when using a
minimal build of libsodium.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
unacl.exceptions
exceptions
unacl._sodium
T affi
lib
T aensure
aPYNACL_HAS_CRYPTO_SHORTHASH_SIPHASHX24
crypto_shorthash_siphash24_bytes
crypto_shorthash_siphash24_keybytes
crypto_shorthash_siphashx24_bytes
crypto_shorthash_siphashx24_keybytes
D adata
key
return
Obytes
ppunacl\bindings\crypto_shorthash.py
u<module nacl.bindings.crypto_shorthash>
T adata
key
digest
rc

a__spec__
.nacl.bindings.crypto_sign
s
ffi
new
uunsigned char[]
crypto_sign_PUBLICKEYBYTES
crypto_sign_SECRETKEYBYTES
lib
crypto_sign_keypair
ensure
uUnexpected library error
exc
aRuntimeError
T araising
buffer
:nnnu
Returns a randomly generated public key and secret key.
:rtype: (bytes(public_key), bytes(secret_key))
crypto_sign_SEEDBYTES
aValueError
T uInvalid seed
crypto_sign_seed_keypair

Computes and returns the public key and secret key using the seed ``seed``.
:param seed: bytes
:rtype: (bytes(public_key), bytes(secret_key))
crypto_sign_BYTES
T uunsigned long long *
crypto_sign

Signs the message ``message`` using the secret key ``sk`` and returns the
signed message.
:param message: bytes
:param sk: bytes
:rtype: bytes
crypto_sign_open
aBadSignatureError
T uSignature was forged or corrupt

Verifies the signature of the signed message ``signed`` using the public
key ``pk`` and returns the unsigned message.
:param signed: bytes
:param pk: bytes
:rtype: bytes
T uInvalid curve public key
crypto_sign_curve25519_BYTES
crypto_sign_ed25519_pk_to_curve25519

Converts a public Ed25519 key (encoded as bytes ``public_key_bytes``) to
a public Curve25519 key as bytes.
Raises a ValueError if ``public_key_bytes`` is not of length
``crypto_sign_PUBLICKEYBYTES``
:param public_key_bytes: bytes
:rtype: bytes
T uInvalid curve secret key
crypto_sign_ed25519_sk_to_curve25519

Converts a secret Ed25519 key (encoded as bytes ``secret_key_bytes``) to
a secret Curve25519 key as bytes.
Raises a ValueError if ``secret_key_bytes``is not of length
``crypto_sign_SECRETKEYBYTES``
:param secret_key_bytes: bytes
:rtype: bytes
T uInvalid secret key

Extract the public Ed25519 key from a secret Ed25519 key (encoded
s bytes ``secret_key_bytes``).
Raises a ValueError if ``secret_key_bytes``is not of length
``crypto_sign_SECRETKEYBYTES``
:param secret_key_bytes: bytes
:rtype: bytes

Extract the seed from a secret Ed25519 key (encoded
s bytes ``secret_key_bytes``).
Raises a ValueError if ``secret_key_bytes``is not of length
``crypto_sign_SECRETKEYBYTES``
:param secret_key_bytes: bytes
:rtype: bytes
crypto_sign_ed25519ph_STATEBYTES
state
crypto_sign_ed25519ph_init
crypto_sign_ed25519ph_state
uedph parameter must be a ed25519ph_state object
aTypeError
upmsg parameter must be a bytes object
crypto_sign_ed25519ph_update

Update the hash state wrapped in edph
:param edph: the ed25519ph state being updated
:type edph: crypto_sign_ed25519ph_state
:param pmsg: the partial message
:type pmsg: bytes
:rtype: None
usecret key parameter must be a bytes object
usecret key must be {} bytes long
crypto_sign_ed25519ph_final_create
aNULL

Create a signature for the data hashed in edph
using the secret key sk
:param edph: the ed25519ph state for the data
being signed
:type edph: crypto_sign_ed25519ph_state
:param sk: the ed25519 secret part of the signing key
:type sk: bytes
:return: ed25519ph signature
:rtype: bytes
usignature parameter must be a bytes object
usignature must be {} bytes long
upublic key parameter must be a bytes object
upublic key must be {} bytes long
crypto_sign_ed25519ph_final_verify

Verify a prehashed signature using the public key pk
:param edph: the ed25519ph state for the data
being verified
:type edph: crypto_sign_ed25519ph_state
:param signature: the signature being verified
:type signature: bytes
:param pk: the ed25519 public part of the signing key
:type pk: bytes
:return: True if the signature is valid
:rtype: boolean
:raises exc.BadSignatureError: if the signature is not valid
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
aTuple
nacl
T aexceptions
exceptions
unacl._sodium
T affi
lib
unacl.exceptions
T aensure
crypto_sign_bytes
crypto_sign_secretkeybytes
l acrypto_sign_publickeybytes
crypto_box_secretkeybytes
crypto_sign_ed25519ph_statebytes
return
T Obytes
paseed
D amessage
sk
return
Obytes
ppD asigned
pk
return
Obytes
ppD apublic_key_bytes
return
Obytes
pD asecret_key_bytes
return
Obytes
pacrypto_sign_ed25519_sk_to_pk
crypto_sign_ed25519_sk_to_seed
