# Reconstructed from integrated Nuitka blob
# Module: unacl.bindings.crypto_generichash


Python-level wrapper for the crypto_generichash_blake2b state buffer
a__qualname__
a__slots__
D adigest_size
Oint
a__init__
uBlake2State.__init__
return
a__reduce__
uBlake2State.__reduce__
self
copy
uBlake2State.copy
key
salt
person
generichash_blake2b_init
state
data
generichash_blake2b_update
generichash_blake2b_final
unacl\bindings\crypto_generichash.py
u<module nacl.bindings.crypto_generichash>
T a__class__
T aself
digest_size
T aself
T adigest_size
key
salt
person
T aself
a_st
T astate
a_digest
rc
T akey
salt
person
digest_size
state
a_salt
a_person
rc
T	adata
digest_size
key
salt
person
digest
a_salt
a_person
rc
T astate
data
rc

a__spec__
.nacl.bindings.crypto_hash
'
ffi
new
uunsigned char[]
crypto_hash_BYTES
lib
crypto_hash
ensure
uUnexpected library error
exc
aRuntimeError
T araising
buffer
:nnnu
Hashes and returns the message ``message``.
:param message: bytes
:rtype: bytes
crypto_hash_sha256_BYTES
crypto_hash_sha256
crypto_hash_sha512_BYTES
crypto_hash_sha512
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
nacl
T aexceptions
exceptions
unacl._sodium
T affi
lib
unacl.exceptions
T aensure
crypto_hash_sha512_bytes
crypto_hash_sha256_bytes
D amessage
return
Obytes
punacl\bindings\crypto_hash.py
u<module nacl.bindings.crypto_hash>
T amessage
digest
rc

a__spec__
.nacl.bindings.crypto_kx
B
ffi
new
uunsigned char[]
crypto_kx_PUBLIC_KEY_BYTES
crypto_kx_SECRET_KEY_BYTES
lib
crypto_kx_keypair
ensure
uKey generation failed.
exc
aCryptoError
T araising
buffer
:nnnu
Generate a keypair.
This is a duplicate crypto_box_keypair, but
is included for api consistency.
:return: (public_key, secret_key)
:rtype: (bytes, bytes)
crypto_kx_SEED_BYTES
uSeed must be a {} byte long bytes sequence
aTypeError
crypto_kx_seed_keypair

Generate a keypair with a given seed.
This is functionally the same as crypto_box_seed_keypair, however
it uses the blake2b hash primitive instead of sha512.
It is included mainly for api consistency when using crypto_kx.
:param seed: random seed
:type seed: bytes
:return: (public_key, secret_key)
:rtype: (bytes, bytes)
uClient public key must be a {} bytes long bytes sequence
uClient secret key must be a {} bytes long bytes sequence
uServer public key must be a {} bytes long bytes sequence
crypto_kx_SESSION_KEY_BYTES
crypto_kx_client_session_keys
uClient session key generation failed.

Generate session keys for the client.
:param client_public_key:
:type client_public_key: bytes
:param client_secret_key:
:type client_secret_key: bytes
:param server_public_key:
:type server_public_key: bytes
:return: (rx_key, tx_key)
:rtype: (bytes, bytes)
uServer secret key must be a {} bytes long bytes sequence
crypto_kx_server_session_keys
uServer session key generation failed.

Generate session keys for the server.
:param server_public_key:
:type server_public_key: bytes
:param server_secret_key:
:type server_secret_key: bytes
:param client_public_key:
:type client_public_key: bytes
:return: (rx_key, tx_key)
:rtype: (bytes, bytes)
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
L acrypto_kx_keypair
crypto_kx_client_session_keys
crypto_kx_server_session_keys
crypto_kx_PUBLIC_KEY_BYTES
crypto_kx_SECRET_KEY_BYTES
crypto_kx_SEED_BYTES
crypto_kx_SESSION_KEY_BYTES
a__all__
crypto_kx_publickeybytes
crypto_kx_secretkeybytes
crypto_kx_seedbytes
crypto_kx_sessionkeybytes
return
T Obytes
paseed
client_public_key
client_secret_key
server_public_key
server_secret_key
unacl\bindings\crypto_kx.py
u<module nacl.bindings.crypto_kx>
T aclient_public_key
client_secret_key
server_public_key
rx_key
tx_key
res
T apublic_key
secret_key
res
T aseed
public_key
secret_key
res
T aserver_public_key
server_secret_key
client_public_key
rx_key
tx_key
res

a__spec__
.nacl.bindings.crypto_pwhash
[$
ensure
uInvalid block size
exc
aValueError
T araising
uInvalid parallelization factor
uCost factor must be a power of 2
uCost factor must be at least 2
aSCRYPT_PR_MAX
up*r is greater than {}
l l  aUINT64_MAX
l l l g            uMemory limit would be exceeded with the choosen n, r, p
l   ;l l?l amaxn
l  an_log2
l     l uPython implementation of libsodium's pickparams
has_crypto_pwhash_scryptsalsa208sha256
uNot available in minimal build
aUnavailableError
D araising
ETypeError
a_check_memory_occupation
ffi
new
uuint8_t[]
lib
crypto_pwhash_scryptsalsa208sha256_ll
uUnexpected failure in key derivation
aRuntimeError
buffer
cast
uchar *
:nnnu
Derive a cryptographic key using the ``passwd`` and ``salt``
given as input.
The work factor can be tuned by by picking different
values for the parameters
:param bytes passwd:
:param bytes salt:
:param bytes salt: *must* be *exactly* :py:const:`.SALTBYTES` long
:param int dklen:
:param int opslimit:
:param int n:
:param int r: block size,
:param int p: the parallelism factor
:param int maxmem: the maximum available memory available for scrypt's
operations
:rtype: bytes
:raises nacl.exceptions.UnavailableError: If called when using a
minimal build of libsodium.
uchar[]
aSCRYPT_STRBYTES
crypto_pwhash_scryptsalsa208sha256_str
uUnexpected failure in password hashing
string

Derive a cryptographic key using the ``passwd`` and ``salt``
given as input, returning a string representation which includes
the salt and the tuning parameters.
The returned string can be directly stored as a password hash.
See :py:func:`.crypto_pwhash_scryptsalsa208sha256` for a short
discussion about ``opslimit`` and ``memlimit`` values.
:param bytes passwd:
:param int opslimit:
:param int memlimit:
:return: serialized key hash, including salt and tuning parameters
:rtype: bytes
:raises nacl.exceptions.UnavailableError: If called when using a
minimal build of libsodium.
uInvalid password hash
crypto_pwhash_scryptsalsa208sha256_str_verify
uWrong password
aInvalidkeyError

Verifies the ``passwd`` against the ``passwd_hash`` that was generated.
Returns True or False depending on the success
:param passwd_hash: bytes
:param passwd: bytes
:rtype: boolean
:raises nacl.exceptions.UnavailableError: If called when using a
minimal build of libsodium.
crypto_pwhash_ALG_ARGON2I13
crypto_pwhash_argon2i_MEMLIMIT_MIN
umemlimit must be at least {} bytes
crypto_pwhash_argon2i_MEMLIMIT_MAX
umemlimit must be at most {} bytes
crypto_pwhash_argon2i_OPSLIMIT_MIN
uopslimit must be at least {}
crypto_pwhash_argon2i_OPSLIMIT_MAX
uopslimit must be at most {}
crypto_pwhash_ALG_ARGON2ID13
crypto_pwhash_argon2id_MEMLIMIT_MIN
crypto_pwhash_argon2id_MEMLIMIT_MAX
crypto_pwhash_argon2id_OPSLIMIT_MIN
crypto_pwhash_argon2id_OPSLIMIT_MAX
aTypeError
T uUnsupported algorithm
crypto_pwhash_SALTBYTES
usalt must be exactly {} bytes long
crypto_pwhash_BYTES_MIN
uderived key must be at least {} bytes long
crypto_pwhash_BYTES_MAX
uderived key must be at most {} bytes long
a_check_argon2_limits_alg
uunsigned char[]
crypto_pwhash

Derive a raw cryptographic key using the ``passwd`` and the ``salt``
given as input to the ``alg`` algorithm.
:param outlen: the length of the derived key
:type outlen: int
:param passwd: The input password
:type passwd: bytes
:param salt:
:type salt: bytes
:param opslimit: computational cost
:type opslimit: int
:param memlimit: memory cost
:type memlimit: int
:param alg: algorithm identifier
:type alg: int
:return: derived key
:rtype: bytes
T uchar[]
l  acrypto_pwhash_str_alg

Derive a cryptographic key using the ``passwd`` given as input
nd a random salt, returning a string representation which
includes the salt, the tuning parameters and the used algorithm.
:param passwd: The input password
:type passwd: bytes
:param opslimit: computational cost
:type opslimit: int
:param memlimit: memory cost
:type memlimit: int
:param alg: The algorithm to use
:type alg: int
:return: serialized derived key and parameters
:rtype: bytes
uHash must be at most 127 bytes long
crypto_pwhash_str_verify

Verifies the ``passwd`` against a given password hash.
Returns True on success, raises InvalidkeyError on failure
:param passwd_hash: saved password hash
:type passwd_hash: bytes
:param passwd: password to be checked
:type passwd: bytes
:return: success
:rtype: boolean
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
sys
aTuple
unacl.exceptions
exceptions
unacl._sodium
T affi
lib
T aensure
aPYNACL_HAS_CRYPTO_PWHASH_SCRYPTSALSA208SHA256
c
crypto_pwhash_scryptsalsa208sha256_STRPREFIX
crypto_pwhash_scryptsalsa208sha256_SALTBYTES
crypto_pwhash_scryptsalsa208sha256_STRBYTES
crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN
crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX
crypto_pwhash_scryptsalsa208sha256_BYTES_MIN
crypto_pwhash_scryptsalsa208sha256_BYTES_MAX
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE
crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE
crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE
crypto_pwhash_scryptsalsa208sha256_strprefix
crypto_pwhash_scryptsalsa208sha256_saltbytes
crypto_pwhash_scryptsalsa208sha256_strbytes
crypto_pwhash_scryptsalsa208sha256_passwd_min
crypto_pwhash_scryptsalsa208sha256_passwd_max
crypto_pwhash_scryptsalsa208sha256_bytes_min
crypto_pwhash_scryptsalsa208sha256_bytes_max
crypto_pwhash_scryptsalsa208sha256_memlimit_min
crypto_pwhash_scryptsalsa208sha256_memlimit_max
crypto_pwhash_scryptsalsa208sha256_opslimit_min
crypto_pwhash_scryptsalsa208sha256_opslimit_max
crypto_pwhash_scryptsalsa208sha256_opslimit_interactive
crypto_pwhash_scryptsalsa208sha256_memlimit_interactive
crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive
crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive
crypto_pwhash_alg_argon2i13
crypto_pwhash_alg_argon2id13
crypto_pwhash_alg_default
crypto_pwhash_ALG_DEFAULT
crypto_pwhash_saltbytes
crypto_pwhash_strbytes
crypto_pwhash_STRBYTES
crypto_pwhash_passwd_min
crypto_pwhash_PASSWD_MIN
crypto_pwhash_passwd_max
crypto_pwhash_PASSWD_MAX
crypto_pwhash_bytes_min
crypto_pwhash_bytes_max
crypto_pwhash_argon2i_strprefix
crypto_pwhash_argon2i_STRPREFIX
crypto_pwhash_argon2i_memlimit_min
crypto_pwhash_argon2i_memlimit_max
crypto_pwhash_argon2i_opslimit_min
crypto_pwhash_argon2i_opslimit_max
crypto_pwhash_argon2i_opslimit_interactive
crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE
crypto_pwhash_argon2i_memlimit_interactive
crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE
crypto_pwhash_argon2i_opslimit_moderate
crypto_pwhash_argon2i_OPSLIMIT_MODERATE
crypto_pwhash_argon2i_memlimit_moderate
crypto_pwhash_argon2i_MEMLIMIT_MODERATE
crypto_pwhash_argon2i_opslimit_sensitive
crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE
crypto_pwhash_argon2i_memlimit_sensitive
crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE
crypto_pwhash_argon2id_strprefix
crypto_pwhash_argon2id_STRPREFIX
crypto_pwhash_argon2id_memlimit_min
crypto_pwhash_argon2id_memlimit_max
crypto_pwhash_argon2id_opslimit_min
crypto_pwhash_argon2id_opslimit_max
crypto_pwhash_argon2id_opslimit_interactive
crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE
crypto_pwhash_argon2id_memlimit_interactive
crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE
crypto_pwhash_argon2id_opslimit_moderate
crypto_pwhash_argon2id_OPSLIMIT_MODERATE
crypto_pwhash_argon2id_memlimit_moderate
crypto_pwhash_argon2id_MEMLIMIT_MODERATE
crypto_pwhash_argon2id_opslimit_sensitive
crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE
crypto_pwhash_argon2id_memlimit_sensitive
crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE
aSCRYPT_OPSLIMIT_INTERACTIVE
aSCRYPT_MEMLIMIT_INTERACTIVE
aSCRYPT_OPSLIMIT_SENSITIVE
aSCRYPT_MEMLIMIT_SENSITIVE
aSCRYPT_SALTBYTES
l?aLOG2_UINT64_MAX
g            l    aSCRYPT_MAX_MEM
D wnwrwpamaxmem
return
Oint
pppnaopslimit
memlimit
return
T Oint
ppanacl_bindings_pick_scrypt_params
l@D apasswd
salt
wnwrwpadklen
maxmem
return
Obytes
pOint
ppppObytes
D apasswd
opslimit
memlimit
return
Obytes
Oint
pObytes
D apasswd_hash
passwd
return
Obytes
pObool
D aopslimit
memlimit
alg
return
Oint
ppnD aoutlen
passwd
salt
opslimit
memlimit
alg
return
Oint
Obytes
pOint
ppObytes
crypto_pwhash_alg
D apasswd
opslimit
memlimit
alg
return
Obytes
Oint
ppObytes
crypto_pwhash_argon2i_str_verify
unacl\bindings\crypto_pwhash.py
u<module nacl.bindings.crypto_pwhash>
T aopslimit
memlimit
alg
T wnwrwpamaxmem
aBlen
wiaVlen
T aoutlen
passwd
salt
opslimit
memlimit
alg
outbuf
ret
T	apasswd
salt
wnwrwpadklen
maxmem
buf
ret
T apasswd
opslimit
memlimit
buf
ret
T apasswd_hash
passwd
ret
T apasswd
opslimit
memlimit
alg
outbuf
ret
T aopslimit
memlimit
wrwpamaxn
n_log2
maxrp

a__spec__
.nacl.bindings.crypto_scalarmult
C
;
ffi
new
uunsigned char[]
crypto_scalarmult_BYTES
lib
crypto_scalarmult_base
ensure
uUnexpected library error
exc
aRuntimeError
T araising
buffer
crypto_scalarmult_SCALARBYTES
:nnnu
Computes and returns the scalar product of a standard group element and an
integer ``n``.
:param n: bytes
:rtype: bytes
crypto_scalarmult

Computes and returns the scalar product of the given group element and an
integer ``n``.
:param p: bytes
:param n: bytes
:rtype: bytes
has_crypto_scalarmult_ed25519
uNot available in minimal build
aUnavailableError
crypto_scalarmult_ed25519_SCALARBYTES
uInput must be a crypto_scalarmult_ed25519_SCALARBYTES long bytes sequence
aTypeError
crypto_scalarmult_ed25519_BYTES
crypto_scalarmult_ed25519_base

Computes and returns the scalar product of a standard group element and an
integer ``n`` on the edwards25519 curve.
:param n: a :py:data:`.crypto_scalarmult_ed25519_SCALARBYTES` long bytes
sequence representing a scalar
:type n: bytes
:return: a point on the edwards25519 curve, represented as a
:py:data:`.crypto_scalarmult_ed25519_BYTES` long bytes sequence
:rtype: bytes
:raises nacl.exceptions.UnavailableError: If called when using a
minimal build of libsodium.
crypto_scalarmult_ed25519_base_noclamp

Computes and returns the scalar product of a standard group element and an
integer ``n`` on the edwards25519 curve. The integer ``n`` is not clamped.
:param n: a :py:data:`.crypto_scalarmult_ed25519_SCALARBYTES` long bytes
sequence representing a scalar
:type n: bytes
:return: a point on the edwards25519 curve, represented as a
:py:data:`.crypto_scalarmult_ed25519_BYTES` long bytes sequence
:rtype: bytes
:raises nacl.exceptions.UnavailableError: If called when using a
minimal build of libsodium.
uInput must be a crypto_scalarmult_ed25519_BYTES long bytes sequence
crypto_scalarmult_ed25519

Computes and returns the scalar product of a *clamped* integer ``n``
nd the given group element on the edwards25519 curve.
The scalar is clamped, as done in the public key generation case,
by setting to zero the bits in position [0, 1, 2, 255] and setting
to one the bit in position 254.
:param n: a :py:data:`.crypto_scalarmult_ed25519_SCALARBYTES` long bytes
sequence representing a scalar
:type n: bytes
:param p: a :py:data:`.crypto_scalarmult_ed25519_BYTES` long bytes sequence
representing a point on the edwards25519 curve
:type p: bytes
:return: a point on the edwards25519 curve, represented as a
:py:data:`.crypto_scalarmult_ed25519_BYTES` long bytes sequence
:rtype: bytes
:raises nacl.exceptions.UnavailableError: If called when using a
minimal build of libsodium.
crypto_scalarmult_ed25519_noclamp

Computes and returns the scalar product of an integer ``n``
nd the given group element on the edwards25519 curve. The integer
``n`` is not clamped.
:param n: a :py:data:`.crypto_scalarmult_ed25519_SCALARBYTES` long bytes
sequence representing a scalar
:type n: bytes
:param p: a :py:data:`.crypto_scalarmult_ed25519_BYTES` long bytes sequence
representing a point on the edwards25519 curve
:type p: bytes
:return: a point on the edwards25519 curve, represented as a
:py:data:`.crypto_scalarmult_ed25519_BYTES` long bytes sequence
:rtype: bytes
:raises nacl.exceptions.UnavailableError: If called when using a
minimal build of libsodium.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
nacl
T aexceptions
exceptions
unacl._sodium
T affi
lib
unacl.exceptions
T aensure
aPYNACL_HAS_CRYPTO_SCALARMULT_ED25519
crypto_scalarmult_bytes
crypto_scalarmult_scalarbytes
crypto_scalarmult_ed25519_bytes
crypto_scalarmult_ed25519_scalarbytes
D wnareturn
Obytes
pD wnwpareturn
Obytes
ppunacl\bindings\crypto_scalarmult.py
u<module nacl.bindings.crypto_scalarmult>
T wnwpwqarc
T wnwqarc

a__spec__
.nacl.bindings.crypto_secretbox
4
crypto_secretbox_KEYBYTES
exc
aValueError
T uInvalid key
crypto_secretbox_NONCEBYTES
T uInvalid nonce
d
crypto_secretbox_ZEROBYTES
ffi
new
uunsigned char[]
lib
crypto_secretbox
ensure
uEncryption failed
aCryptoError
T araising
buffer
crypto_secretbox_BOXZEROBYTES

Encrypts and returns the message ``message`` with the secret ``key`` and
the nonce ``nonce``.
:param message: bytes
:param nonce: bytes
:param key: bytes
:rtype: bytes
crypto_secretbox_open
uDecryption failed. Ciphertext failed verification

Decrypt and returns the encrypted message ``ciphertext`` with the secret
``key`` and the nonce ``nonce``.
:param ciphertext: bytes
:param nonce: bytes
:param key: bytes
:rtype: bytes
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
nacl
T aexceptions
exceptions
unacl._sodium
T affi
lib
unacl.exceptions
T aensure
crypto_secretbox_keybytes
crypto_secretbox_noncebytes
crypto_secretbox_zerobytes
crypto_secretbox_boxzerobytes
crypto_secretbox_macbytes
crypto_secretbox_MACBYTES
crypto_secretbox_messagebytes_max
crypto_secretbox_MESSAGEBYTES_MAX
D amessage
nonce
key
return
Obytes
pppD aciphertext
nonce
key
return
Obytes
pppunacl\bindings\crypto_secretbox.py
u<module nacl.bindings.crypto_secretbox>
T amessage
nonce
key
padded
ciphertext
res
T aciphertext
nonce
key
padded
plaintext
res

a__spec__
.nacl.bindings.crypto_secretstream
n
ffi
new
uunsigned char[]
crypto_secretstream_xchacha20poly1305_KEYBYTES
lib
crypto_secretstream_xchacha20poly1305_keygen
buffer
:nnnu
Generate a key for use with
:func:`.crypto_secretstream_xchacha20poly1305_init_push`.
crypto_secretstream_xchacha20poly1305_STATEBYTES
statebuf
rawbuf
tagbuf
uInitialize a clean state object.
ensure
crypto_secretstream_xchacha20poly1305_state
uState must be a crypto_secretstream_xchacha20poly1305_state object
exc
aTypeError
T araising
uKey must be a bytes sequence
uInvalid key length
aValueError
uunsigned char []
crypto_secretstream_xchacha20poly1305_HEADERBYTES
crypto_secretstream_xchacha20poly1305_init_push
uUnexpected failure
aRuntimeError

Initialize a crypto_secretstream_xchacha20poly1305 encryption buffer.
:param state: a secretstream state object
:type state: crypto_secretstream_xchacha20poly1305_state
:param key: must be
:data:`.crypto_secretstream_xchacha20poly1305_KEYBYTES` long
:type key: bytes
:return: header
:rtype: bytes
uMessage is not bytes
crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX
uMessage is too long
uAdditional data must be bytes or None
crypto_secretstream_xchacha20poly1305_ABYTES
aNULL
crypto_secretstream_xchacha20poly1305_push
ad

Add an encrypted message to the secret stream.
:param state: a secretstream state object
:type state: crypto_secretstream_xchacha20poly1305_state
:param m: the message to encrypt, the maximum length of an individual
message is
:data:`.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX`.
:type m: bytes
:param ad: additional data to include in the authentication tag
:type ad: bytes or None
:param tag: the message tag, usually
:data:`.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE` or
:data:`.crypto_secretstream_xchacha20poly1305_TAG_FINAL`.
:type tag: int
:return: ciphertext
:rtype: bytes
uHeader must be a bytes sequence
uInvalid header length
T uunsigned char *
crypto_secretstream_xchacha20poly1305_init_pull

Initialize a crypto_secretstream_xchacha20poly1305 decryption buffer.
:param state: a secretstream state object
:type state: crypto_secretstream_xchacha20poly1305_state
:param header: must be
:data:`.crypto_secretstream_xchacha20poly1305_HEADERBYTES` long
:type header: bytes
:param key: must be
:data:`.crypto_secretstream_xchacha20poly1305_KEYBYTES` long
:type key: bytes
uState must be initialized using crypto_secretstream_xchacha20poly1305_init_pull
uCiphertext is not bytes
uCiphertext is too short
uCiphertext is too long
crypto_secretstream_xchacha20poly1305_pull
cast

Read a decrypted message from the secret stream.
:param state: a secretstream state object
:type state: crypto_secretstream_xchacha20poly1305_state
:param c: the ciphertext to decrypt, the maximum length of an individual
ciphertext is
:data:`.crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX` +
:data:`.crypto_secretstream_xchacha20poly1305_ABYTES`.
:type c: bytes
:param ad: additional data to include in the authentication tag
:type ad: bytes or None
:return: (message, tag)
:rtype: (bytes, int)
crypto_secretstream_xchacha20poly1305_rekey

Explicitly change the encryption key in the stream.
Normally the stream is re-keyed as needed or an explicit ``tag`` of
:data:`.crypto_secretstream_xchacha20poly1305_TAG_REKEY` is added to a
message to ensure forward secrecy, but this method can be used instead
if the re-keying is controlled without adding the tag.
:param state: a secretstream state object
:type state: crypto_secretstream_xchacha20poly1305_state
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
aByteString
aOptional
aTuple
nacl
T aexceptions
exceptions
unacl._sodium
T affi
lib
unacl.exceptions
T aensure
crypto_secretstream_xchacha20poly1305_abytes
crypto_secretstream_xchacha20poly1305_headerbytes
crypto_secretstream_xchacha20poly1305_keybytes
crypto_secretstream_xchacha20poly1305_messagebytes_max
crypto_secretstream_xchacha20poly1305_statebytes
crypto_secretstream_xchacha20poly1305_tag_message
crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
crypto_secretstream_xchacha20poly1305_tag_push
crypto_secretstream_xchacha20poly1305_TAG_PUSH
crypto_secretstream_xchacha20poly1305_tag_rekey
crypto_secretstream_xchacha20poly1305_TAG_REKEY
crypto_secretstream_xchacha20poly1305_tag_final
crypto_secretstream_xchacha20poly1305_TAG_FINAL
D areturn
Obytes
