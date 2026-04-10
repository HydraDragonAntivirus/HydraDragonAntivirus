# Reconstructed from integrated Nuitka blob
# Module: uCrypto.PublicKey.ElGamal

uClass defining an ElGamal key.
Do not instantiate directly.
Use :func:`generate` or :func:`construct` instead.
:ivar p: Modulus
:vartype d: integer
:ivar g: Generator
:vartype e: integer
:ivar y: Public key component
:vartype y: integer
:ivar x: Private key component
:vartype x: integer
a__qualname__
L wpwgwywxT na__init__
uElGamalKey.__init__
a_encrypt
uElGamalKey._encrypt
a_decrypt
uElGamalKey._decrypt
a_sign
uElGamalKey._sign
a_verify
uElGamalKey._verify
uElGamalKey.has_private
can_encrypt
uElGamalKey.can_encrypt
can_sign
uElGamalKey.can_sign
publickey
uElGamalKey.publickey
uElGamalKey.__eq__
a__ne__
uElGamalKey.__ne__
a__getstate__
uElGamalKey.__getstate__
sign
uElGamalKey.sign
verify
uElGamalKey.verify
encrypt
uElGamalKey.encrypt
decrypt
uElGamalKey.decrypt
blind
uElGamalKey.blind
unblind
uElGamalKey.unblind
size
uElGamalKey.size
a__orig_bases__
uCrypto\PublicKey\ElGamal.py
u<module Crypto.PublicKey.ElGamal>
T a__class__
T aself
other
result
comp
T aself
aPicklingError
T aself
randfunc
T aself
other
T aself
wMwraa_blind
ax
plaintext_blind
plaintext
T aself
wMwKwawbT aself
wMwKap1
wawtwbT aself
wMasig
v1
v2
T aself
wMwBT aself
T atup
obj
wiafield
fmt_error
T aself
ciphertext
T aself
plaintext
wKT abits
randfunc
obj
wqaginv
T aself
wMwKT aself
wMasignature

a__spec__
.Crypto.PublicKey.RSA
9
G S wewnS wqwpwdwuuSome RSA components are missing
w_a_d
a_p
a_dp
a_q
a_dq
a_invq
uBuild an RSA key.
:Keywords:
n : integer
The modulus.
e : integer
The public exponent.
d : integer
The private exponent. Only required for private keys.
p : integer
The first factor of the modulus. Only required for private keys.
q : integer
The second factor of the modulus. Only required for private keys.
u : integer
The CRT coefficient (inverse of p modulo q). Only required for
private keys.
a_n
a_e
has_private
uNo private exponent available for public keys
uNo CRT component 'p' available for public keys
uNo CRT component 'q' available for public keys
uNo CRT component 'dp' available for public keys
uNo CRT component 'dq' available for public keys
uNo CRT component 'invq' available for public keys
inverse
wuuNo CRT component 'u' available for public keys
a_u
size_in_bits
uSize of the RSA modulus in bits
l uThe minimal amount of bytes that can hold the RSA modulus
uPlaintext too large
pow
aInteger
uCiphertext too large
uThis is not a private key
random_range
T amin_inclusive
max_exclusive
a_mult_modulo_bytes
bytes_to_long
a_decrypt_to_bytes
uLegacy private method
uWhether this is an RSA private key
aRsaKey
T wnweuA matching RSA public key.
Returns:
a new :class:`RsaKey` object
wnwewdapickle
T aPicklingError
aPicklingError
u, d=%d, p=%d, q=%d, u=%d

uRsaKey(n=%d, e=%d%s)
aPrivate
aPublic
u%s RSA key at 0x%X
tobytes
aRandom
get_random_bytes
aOpenSSH
to_bytes
bord
l  d
cssh-rsa
c
struct
pack
u>I
cssh-rsa
binascii
b2a_base64
:nq naDerSequence
wpwqaencode
uRSA PRIVATE KEY
aDER
uPKCS#1 private key cannot be encrypted
uCrypto.IO
T aPKCS8
aPKCS8
aPEM
uPRIVATE KEY
wrap
oid
aDerNull
T akey_params
uENCRYPTED PRIVATE KEY
u'protection' parameter must be set
uPBKDF2WithHMAC-SHA1AndDES-EDE3-CBC
T aprot_params
key_params
uPUBLIC KEY
a_create_subject_public_key_info
T aPEM
uUnknown key format '%s'. Cannot export the RSA key.
uExport this RSA key.
Keyword Args:
format (string):
The desired output format:
- ``'PEM'``. (default) Text output, according to `RFC1421`_/`RFC1423`_.
- ``'DER'``. Binary output.
- ``'OpenSSH'``. Text output, according to the OpenSSH specification.
Only suitable for public keys (not private keys).
Note that PEM contains a DER structure.
passphrase (bytes or string):
(*Private keys only*) The passphrase to protect the
private key.
pkcs (integer):
(*Private keys only*) The standard to use for
serializing the key: PKCS#1 or PKCS#8.
With ``pkcs=1`` (*default*), the private key is encoded with a
simple `PKCS#1`_ structure (``RSAPrivateKey``). The key cannot be
securely encrypted.
With ``pkcs=8``, the private key is encoded with a `PKCS#8`_ structure
(``PrivateKeyInfo``). PKCS#8 offers the best ways to securely
encrypt the key.
.. note::
This parameter is ignored for a public key.
For DER and PEM, the output is always an
ASN.1 DER ``SubjectPublicKeyInfo`` structure.
protection (string):
(*For private keys only*)
The encryption scheme to use for protecting the private key
using the passphrase.
You can only specify a value if ``pkcs=8``.
For all possible protection schemes,
refer to :ref:`the encryption parameters of PKCS#8<enc_params>`.
The recommended value is
``'PBKDF2WithHMAC-SHA512AndAES256-CBC'``.
If ``None`` (default), the behavior depends on :attr:`format`:
- if ``format='PEM'``, the obsolete PEM encryption scheme is used.
It is based on MD5 for key derivation, and 3DES for encryption.
- if ``format='DER'``, the ``'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC'``
scheme is used.
prot_params (dict):
(*For private keys only*)
The parameters to use to derive the encryption key
from the passphrase. ``'protection'`` must be also specified.
For all possible values,
refer to :ref:`the encryption parameters of PKCS#8<enc_params>`.
The recommendation is to use ``{'iteration_count':21000}`` for PBKDF2,
nd ``{'iteration_count':131072}`` for scrypt.
randfunc (callable):
A function that provides random bytes. Only used for PEM encoding.
The default is :func:`Crypto.Random.get_random_bytes`.
Returns:
bytes: the encoded key
Raises:
ValueError:when the format is unknown or when you try to encrypt a private
key with *DER* format and PKCS#1.
.. warning::
If you don't provide a pass phrase, the private key will be
exported in the clear!
.. _RFC1421:    http://www.ietf.org/rfc/rfc1421.txt
.. _RFC1423:    http://www.ietf.org/rfc/rfc1423.txt
.. _`PKCS#1`:   http://www.ietf.org/rfc/rfc3447.txt
.. _`PKCS#8`:   http://www.ietf.org/rfc/rfc5208.txt
export_key
u:meta private:
public_key
uUse module Crypto.Signature.pkcs1_15 instead
uUse module Crypto.Cipher.PKCS1_OAEP instead
l  uRSA modulus length must be >= 1024
l l uRSA public exponent must be a positive, odd integer larger than 2.
T l abits
sqrt
filter_p
ugenerate.<locals>.filter_p
generate_probable_prime
randfunc
T aexact_bits
randfunc
prime_filter
ldafilter_q
ugenerate.<locals>.filter_q
lcm
T wnwewdwpwqwuuCreate a new RSA key pair.
The algorithm closely follows NIST `FIPS 186-4`_ in its
sections B.3.1 and B.3.3. The modulus is the product of
two non-strong probable primes.
Each prime passes a suitable number of Miller-Rabin tests
with random bases and a single Lucas test.
Args:
bits (integer):
Key length, or size (in bits) of the RSA modulus.
It must be at least 1024, but **2048 is recommended.**
The FIPS standard only defines 1024, 2048 and 3072.
Keyword Args:
randfunc (callable):
Function that returns random bytes.
The default is :func:`Crypto.Random.get_random_bytes`.
e (integer):
Public RSA exponent. It must be an odd positive integer.
It is typically a small number with very few ones in its
binary representation.
The FIPS standard requires the public exponent to be
t least 65537 (the default).
Returns: an RSA key object (:class:`RsaKey`, with private key).
.. _FIPS 186-4: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
min_p
gcd
min_q
min_distance
T Oobject
a__prepare__
aInputComps
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
