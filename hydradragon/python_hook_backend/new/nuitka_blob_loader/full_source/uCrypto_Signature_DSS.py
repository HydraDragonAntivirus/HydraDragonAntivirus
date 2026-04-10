# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Signature.DSS

uA (EC)DSA signature object.
Do not instantiate directly.
Use :func:`Crypto.Signature.DSS.new`.
a__qualname__
uDssSigScheme.__init__
can_sign
uDssSigScheme.can_sign
uDssSigScheme._compute_nonce
uDssSigScheme._valid_hash
sign
uDssSigScheme.sign
verify
uDssSigScheme.verify
a__orig_bases__
uDeterministicDsaSigScheme.__init__
uDeterministicDsaSigScheme._bits2int
uDeterministicDsaSigScheme._int2octets
uDeterministicDsaSigScheme._bits2octets
uDeterministicDsaSigScheme._compute_nonce
uDeterministicDsaSigScheme._valid_hash
T T l  l  T l  l  T l  l  T l  l  uFipsDsaSigScheme.__init__
uFipsDsaSigScheme._compute_nonce
uFipsDsaSigScheme._valid_hash
uFipsEcDsaSigScheme.__init__
uFipsEcDsaSigScheme._compute_nonce
uFipsEcDsaSigScheme._valid_hash
T abinary
nuCrypto\Signature\DSS.py
u<module Crypto.Signature.DSS>
T a__class__
T aself
key
encoding
order
private_key
a__class__
T aself
key
encoding
order
T aself
key
encoding
order
randfunc
wLaerror
a__class__
T aself
key
encoding
order
randfunc
a__class__
T aself
bstr
result
q_len
b_len
T aself
bstr
z1
z2
T aself
mhash
h1
mask_v
nonce_k
int_oct
nonce
mask_t
T aself
msg_hash
T aself
int_mod_q
T	aself
msg_hash
modulus_bits
sha224
sha256
sha384
sha512
shs
result
T aself
T akey
mode
encoding
randfunc
order
private_key_attr
private_key
T aself
msg_hash
nonce
wzasig_pair
output
T aself
msg_hash
signature
r_prime
s_prime
der_seq
wzaresult

a__spec__
.Crypto.Signature.PKCS1_PSS
a_verify
T EValueError
ETypeError
pss
new
T amask_func
salt_bytes
rand_func
verify
aMethodType
a_pycrypto_verify

Legacy module for PKCS#1 PSS signatures.
:undocumented: __package__
a__doc__
a__file__
origin
has_location
a__cached__
types
uCrypto.Signature
T apss
T nnnuCrypto\Signature\PKCS1_PSS.py
u<module Crypto.Signature.PKCS1_PSS>
T aself
hash_object
signature
T arsa_key
mgfunc
saltLen
randfunc
pkcs1

a__spec__
.Crypto.Signature.PKCS1_v1_5
a_verify
T EValueError
ETypeError
pkcs1_15
new
verify
aMethodType
a_pycrypto_verify

Legacy module for PKCS#1 v1.5 signatures.
:undocumented: __package__
a__doc__
a__file__
origin
has_location
a__cached__
types
uCrypto.Signature
T apkcs1_15
uCrypto\Signature\PKCS1_v1_5.py
u<module Crypto.Signature.PKCS1_v1_5>
T aself
hash_object
signature
T arsa_key
pkcs1

a__spec__
.Crypto.Signature
uDigital signature protocols
A collection of standardized protocols to carry out digital signatures.
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
aSignature
T aNUITKA_PACKAGE_Crypto_Signature
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
L aPKCS1_v1_5
aPKCS1_PSS
aDSS
pkcs1_15
pss
eddsa
a__all__
uCrypto\Signature\__init__.py
u<module Crypto.Signature>

a__spec__
.Crypto.Signature.eddsa
a_import_ed25519_public_key
aEd25519
a_import_ed448_public_key
aEd448
uNot an EdDSA key (%d bytes)
construct
T acurve
point_x
point_y
uCreate a new Ed25519 or Ed448 public key object,
starting from the key encoded as raw ``bytes``,
in the format described in RFC8032.
Args:
encoded (bytes):
The EdDSA public key to import.
It must be 32 bytes for Ed25519, and 57 bytes for Ed448.
Returns:
:class:`Crypto.PublicKey.EccKey` : a new ECC key object.
Raises:
ValueError: when the given key cannot be parsed.
ed25519
ed448
uIncorrect length. Only EdDSA private keys are supported.
T aseed
curve
uCreate a new Ed25519 or Ed448 private key object,
starting from the key encoded as raw ``bytes``,
in the format described in RFC8032.
Args:
encoded (bytes):
The EdDSA private key to import.
It must be 32 bytes for Ed25519, and 57 bytes for Ed448.
Returns:
:class:`Crypto.PublicKey.EccKey` : a new ECC key object.
Raises:
ValueError: when the given key cannot be parsed.
a_key
a_context
a_export_eddsa_public
a_A
a_curve
order
a_order
uCreate a new EdDSA object.
Do not instantiate this object directly,
use `Crypto.Signature.DSS.new` instead.
has_private
uReturn ``True`` if this signature object can be used
for signing messages.
uPrivate key is needed to sign
curve
aSHA512
aSHA512Hash
is_bytes
u'msg_or_hash' must be bytes of a SHA-512 hash
a_sign_ed25519
aSHAKE256
aSHAKE256_XOF
u'msg_or_hash' must be bytes of a SHAKE256 hash
a_sign_ed448
uIncorrect curve for EdDSA
msg_or_hash
uCompute the EdDSA signature of a message.
Args:
msg_or_hash (bytes or a hash object):
The message to sign (``bytes``, in case of *PureEdDSA*) or
the hash that was carried out over the message (hash object, for *HashEdDSA*).
The hash object must be :class:`Crypto.Hash.SHA512` for Ed25519,
nd :class:`Crypto.Hash.SHAKE256` object for Ed448.
:return: The signature as ``bytes``. It is always 64 bytes for Ed25519, and 114 bytes for Ed448.
:raise TypeError: if the EdDSA key has no private half
cSigEd25519 no Ed25519 collisions
bchr
c
digest
new
a_prefix
aInteger
from_bytes
little
aEccKey
wGT apoint
wdato_bytes
T l alittle
cSigEd448
read
T l@T lrT l9alittle
a_verify_ed25519
a_verify_ed448
uCheck if an EdDSA signature is authentic.
Args:
msg_or_hash (bytes or a hash object):
The message to verify (``bytes``, in case of *PureEdDSA*) or
the hash that was carried out over the message (hash object, for *HashEdDSA*).
The hash object must be :class:`Crypto.Hash.SHA512` object for Ed25519,
nd :class:`Crypto.Hash.SHAKE256` for Ed448.
signature (``bytes``):
The signature that needs to be validated.
It must be 64 bytes for Ed25519, and 114 bytes for Ed448.
:raise ValueError: if the signature is not authentic
uThe signature is not authentic (length)
import_public_key
:nl napointQ
uThe signature is not authentic (R)
:l nnuThe signature is not authentic (S)
l uThe signature is not authentic
:nl9n:l9nnT aEd25519
aEd448
uEdDSA can only be used with EdDSA keys
rfc8032
uMode must be 'rfc8032'
uContext for EdDSA must not be longer than 255 bytes
aEdDSASigScheme
context
uCreate a signature object :class:`EdDSASigScheme` that
can perform or verify an EdDSA signature.
Args:
key (:class:`Crypto.PublicKey.ECC` object):
The key to use for computing the signature (*private* keys only)
or for verifying one.
The key must be on the curve ``Ed25519`` or ``Ed448``.
mode (string):
This parameter must be ``'rfc8032'``.
context (bytes):
Up to 255 bytes of `context <https://datatracker.ietf.org/doc/html/rfc8032#page-41>`_,
which is a constant byte string to segregate different protocols or
different applications of the same key.
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Math.Numbers
T aInteger
uCrypto.Hash
T aSHA512
aSHAKE256
uCrypto.Util.py3compat
T abchr
is_bytes
uCrypto.PublicKey.ECC
T aEccKey
construct
a_import_ed25519_public_key
a_import_ed448_public_key
import_private_key
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
