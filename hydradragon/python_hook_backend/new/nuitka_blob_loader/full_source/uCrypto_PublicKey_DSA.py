# Reconstructed from integrated Nuitka blob
# Module: uCrypto.PublicKey.DSA

uClass defining an actual DSA key.
Do not instantiate directly.
Use :func:`generate`, :func:`construct` or :func:`import_key` instead.
:ivar p: DSA modulus
:vartype p: integer
:ivar q: Order of the subgroup
:vartype q: integer
:ivar g: Generator
:vartype g: integer
:ivar y: Public key
:vartype y: integer
:ivar x: Private key
:vartype x: integer
:undocumented: exportKey, publickey
a__qualname__
L wywgwpwqwxa__init__
uDsaKey.__init__
a_sign
uDsaKey._sign
a_verify
uDsaKey._verify
uDsaKey.has_private
can_encrypt
uDsaKey.can_encrypt
can_sign
uDsaKey.can_sign
public_key
uDsaKey.public_key
uDsaKey.__eq__
a__ne__
uDsaKey.__ne__
a__getstate__
uDsaKey.__getstate__
domain
uDsaKey.domain
a__repr__
uDsaKey.__repr__
a__getattr__
uDsaKey.__getattr__
T aPEM
nnnnaexport_key
uDsaKey.export_key
exportKey
publickey
sign
uDsaKey.sign
verify
uDsaKey.verify
encrypt
uDsaKey.encrypt
decrypt
uDsaKey.decrypt
blind
uDsaKey.blind
unblind
uDsaKey.unblind
size
uDsaKey.size
a__orig_bases__
T nnagenerate
T tT naimport_key
importKey
u1.2.840.10040.4.1
uCrypto\PublicKey\DSA.py
T a.0
wkaself
u<module Crypto.PublicKey.DSA>
T a__class__
T aself
other
result
comp
T aself
item
T aself
aPicklingError
T aself
key_dict
input_set
public_set
extra_set
T aself
other
T aself
attrs
wkabits
T wLarandfunc
wNaoutlen
wnab_
wqaupper_bit
seed
wUaoffset
wVwWwXwcwpweacount
wgT akey_data
passphrase
params
decodings
decoding
T aencoded
passphrase
params
der
tup
T	aencoded
passphrase
params
wkwxwpwqwgatup
T aencoded
passphrase
params
algoid
encoded_key
emb_params
wywpwqwgatup
T aencoded
passphrase
params
sp_info
T aself
wmwkwxwqwpwgablind_factor
inv_blind_k
blind_x
wrwsTaself
wmasig
wrwswywqwpwgwwau1
u2
wvT aself
wMwBT aself
T atup
consistency_check
key_dict
key
fmt_error
T aself
ciphertext
T aself
plaintext
wKT aself
format
pkcs8
passphrase
protection
randfunc
tup1
func
tup2
keyparts
keystring
params
private_key
binary_key
key_type
ints
pem_str
T wxT abits
randfunc
domain
wpwqwgafmt_error
w_wLwNwcwxwyakey_dict
T	aextern_key
passphrase
der
marker
enc_flag
keystring
keyparts
length
tup
T aself
public_components
T aself
wMwKT aself
wMasignature

a__spec__
.Crypto.PublicKey.ECC
YP
curve
wda_d
seed
a_seed
point
a_point
uUnknown parameters:
a_curves
uUnsupported curve (%s)
a_curve
canonical
uAt lest one between parameters 'point', 'd' or 'seed' must be specified
l uParameters d and seed are mutually exclusive
id
a_CurveID
aED25519
uParameter d can only be used with NIST P curves
uParameter seed must be 32 bytes long for Ed25519
aSHA512
new
digest
:l nna_prefix
:nl nl  l l l@aInteger
from_bytes
D abyteorder
little
aED448
uParameter seed must be 57 bytes long for Ed448
aSHAKE256
read
T lr:l9nn:nl9nl  l7l  l8aCURVE25519
uParameter seed must be 32 bytes long for Curve25519
aCURVE448
uParameter seed must be 56 bytes long for Curve448
uParameter 'seed' cannot be used with NIST P-curves
order
uParameter d must be an integer smaller than the curve order
uCreate a new ECC key
Keywords:
curve : string
The name of the curve.
d : integer
Mandatory for a private key one NIST P curves.
It must be in the range ``[1..order-1]``.
seed : bytes
Mandatory for a private key on Ed25519 (32 bytes),
Curve25519 (32 bytes), Curve448 (56 bytes) or Ed448 (57 bytes).
point : EccPoint or EccXPoint
Mandatory for a public key. If provided for a private key,
the implementation will NOT check whether it matches ``d``.
Only one parameter among ``d``, ``seed`` or ``point`` may be used.
aEccKey
has_private
pointQ
is_edwards
u, seed=%s
tostr
binascii
hexlify
u, d=%d

wxuEccKey(curve='%s', point_x=%d%s)
xy
uEccKey(curve='%s', point_x=%d, point_y=%d%s)
u``True`` if this key can be used for making signatures or decrypting data.
random_range
T amin_inclusive
max_exclusive
inverse
wGuThis is not a private ECC key
T acurve
point
uA matching ECC public key.
Returns:
a new :class:`EccKey` object
is_weierstrass
uSEC1 format is only supported for NIST P curves
size_in_bytes
wyais_odd
d d ato_bytes
d T l alittle
T abyteorder
l T l9alittle
uNot an EdDSA key to export
result
is_montgomery
uNot a Montgomery key to export
oid
a_export_eddsa_public
a_export_montgomery_public
u1.2.840.10045.2.1
a_export_SEC1
aDerObjectId
a_create_subject_public_key_info
aDerOctetString
D aexplicit
l
aDerBitString
D aexplicit
l aDerSequence
encode
uCrypto.IO
T aPKCS8
aPKCS8
passphrase
protection
uAt least the 'protection' parameter must be present
a_export_rfc5915_private_der
T FT ainclude_ec_params
wrap
key_params
T aPEM
aPEM
a_export_subjectPublicKeyInfo
uPUBLIC KEY
uEC PRIVATE KEY
a_export_pkcs8
uPRIVATE KEY
uAt least the 'protection' parameter should be present
uENCRYPTED PRIVATE KEY
uCannot export OpenSSH private keys
openssh
uCannot export %s keys as OpenSSH
ussh-ed25519
tobytes
bchr
split
T w-c
struct
pack
u>I
desc
w ab2a_base64
format
T aPEM
aDER
aOpenSSH
aSEC1
raw
uUnknown format '%s'
compress
is_string
uEmpty passphrase
use_pkcs8
u'pkcs8' must be True for EdDSA curves
u'pkcs8' must be True for Curve25519
u'protection' is only supported for PKCS#8
a_export_private_encrypted_pkcs8_in_clear_pem
a_export_private_clear_pkcs8_in_clear_pem
a_export_private_pem
aDER
uPrivate keys can only be encrpyted with DER using PKCS#8
uPrivate keys cannot be exported in the '%s' format
uUnexpected parameters: '%s'
a_export_public_pem
aSEC1
raw
a_export_openssh
uExport this ECC key.
Args:
format (string):
The output format:
- ``'DER'``. The key will be encoded in ASN.1 DER format (binary).
For a public key, the ASN.1 ``subjectPublicKeyInfo`` structure
defined in `RFC5480`_ will be used.
For a private key, the ASN.1 ``ECPrivateKey`` structure defined
in `RFC5915`_ is used instead (possibly within a PKCS#8 envelope,
see the ``use_pkcs8`` flag below).
- ``'PEM'``. The key will be encoded in a PEM_ envelope (ASCII).
- ``'OpenSSH'``. The key will be encoded in the OpenSSH_ format
(ASCII, public keys only).
- ``'SEC1'``. The public key (i.e., the EC point) will be encoded
into ``bytes`` according to Section 2.3.3 of `SEC1`_
(which is a subset of the older X9.62 ITU standard).
Only for NIST P-curves.
- ``'raw'``. The public key will be encoded as ``bytes``,
without any metadata.
* For NIST P-curves: equivalent to ``'SEC1'``.
* For Ed25519 and Ed448: ``bytes`` in the format
defined in `RFC8032`_.
* For Curve25519 and Curve448: ``bytes`` in the format
defined in `RFC7748`_.
passphrase (bytes or string):
(*Private keys only*) The passphrase to protect the
private key.
use_pkcs8 (boolean):
(*Private keys only*)
If ``True`` (default and recommended), the `PKCS#8`_ representation
will be used.
It must be ``True`` for Ed25519, Ed448, Curve25519, and Curve448.
If ``False`` and a passphrase is present, the obsolete PEM
encryption will be used.
protection (string):
When a private key is exported with password-protection
nd PKCS#8 (both ``DER`` and ``PEM`` formats), this parameter MUST be
present,
For all possible protection schemes,
refer to :ref:`the encryption parameters of PKCS#8<enc_params>`.
It is recommended to use ``'PBKDF2WithHMAC-SHA512AndAES128-CBC'``.
compress (boolean):
If ``True``, the method returns a more compact representation
of the public key, with the X-coordinate only.
If ``False`` (default), the method returns the full public key.
This parameter is ignored for Ed25519/Ed448/Curve25519/Curve448,
s compression is mandatory.
prot_params (dict):
When a private key is exported with password-protection
nd PKCS#8 (both ``DER`` and ``PEM`` formats), this dictionary
contains the  parameters to use to derive the encryption key
from the passphrase.
For all possible values,
refer to :ref:`the encryption parameters of PKCS#8<enc_params>`.
The recommendation is to use ``{'iteration_count':21000}`` for PBKDF2,
nd ``{'iteration_count':131072}`` for scrypt.
.. warning::
If you don't provide a passphrase, the private key will be
exported in the clear!
.. note::
When exporting a private key with password-protection and `PKCS#8`_
(both ``DER`` and ``PEM`` formats), any extra parameters
to ``export_key()`` will be passed to :mod:`Crypto.IO.PKCS8`.
.. _PEM:        http://www.ietf.org/rfc/rfc1421.txt
.. _`PEM encryption`: http://www.ietf.org/rfc/rfc1423.txt
.. _OpenSSH:    http://www.openssh.com/txt/rfc5656.txt
.. _RFC5480:    https://tools.ietf.org/html/rfc5480
.. _SEC1:       https://www.secg.org/sec1-v2.pdf
.. _RFC7748:    https://tools.ietf.org/html/rfc7748
Returns:
A multi-line string (for ``'PEM'`` and ``'OpenSSH'``) or
``bytes`` (for ``'DER'``, ``'SEC1'``, and ``'raw'``) with the encoded key.
pop
randfunc
get_random_bytes
T l T acurve
seed
T l9avalidate
T l8T amin_inclusive
max_exclusive
randfunc
T acurve
wdanew_key
uGenerate a new private key on the given curve.
Args:
curve (string):
Mandatory. It must be a curve name defined in the `ECC table`_.
randfunc (callable):
Optional. The RNG to read randomness from.
If ``None``, :func:`Crypto.Random.get_random_bytes` is used.
point_x
T apoint_y
nuUnknown keyword: point
aEccXPoint
aEccPoint
uPrivate and public ECC keys do not match
uBuild a new ECC key (private or public) starting
from some base components.
In most cases, you will already have an existing key
which you can read in with :func:`import_key` instead
of this function.
Args:
curve (string):
Mandatory. The name of the elliptic curve, as defined in the `ECC table`_.
d (integer):
Mandatory for a private key and a NIST P-curve (e.g., P-256).
It must be an integer in the range ``[1..order-1]``.
seed (bytes):
Mandatory for a private key and curves Ed25519 (32 bytes),
Curve25519 (32 bytes), Curve448 (56 bytes) and Ed448 (57 bytes).
point_x (integer):
The X coordinate (affine) of the ECC point.
Mandatory for a public key.
point_y (integer):
The Y coordinate (affine) of the ECC point.
Mandatory for a public key,
except for Curve25519 and Curve448.
Returns:
:class:`EccKey` : a new ECC key object
items
aUnsupportedEccFeature
uUnsupported ECC curve (OID: %s)
uUnsupported ECC curve (%s)
wpabord
l uIncorrect EC point length
T l l :l nnl wbasqrt
is_even
uIncorrect EC point encoding
construct
a_curve_name
T acurve
point_x
point_y
uConvert an encoded EC point into an EccKey object
ec_point: byte string with the EC point (SEC1-encoded)
curve_oid: string with the name the curve
curve_name: string with the OID of the curve
Either curve_id or curve_name must be specified
a_expand_subject_public_key_info
u1.3.101.112
aEd25519
a_import_ed25519_public_key
u1.3.101.113
aEd448
a_import_ed448_public_key
u1.3.101.110
aCurve25519
a_import_curve25519_public_key
u1.3.101.111
aCurve448
a_import_curve448_public_key
T u1.2.840.10045.2.1
u1.3.132.1.12
u1.3.132.1.13
uMissing ECC parameters for ECC OID %s
decode
value
uError decoding namedCurve
a_import_public_der
T acurve_oid
uUnexpected ECC parameters for ECC OID %s
T apoint_x
point_y
curve
T apoint_x
curve
uUnsupported ECC OID: %s
uConvert a subjectPublicKeyInfo into an EccKey object
D anr_elements
T l l l uIncorrect ECC private key version
payload
T l
T aexplicit
uCurve mismatch
uNo curve found
uPrivate key is too small
T l acurve_name
T acurve
wdapoint_x
point_y
unwrap
D u1.3.101.112
u1.3.101.113
aEd25519
aEd448
D u1.3.101.110
u1.3.101.111
aCurve25519
aCurve448
a_import_rfc5915_der
uEdDSA ECC private key must not have parameters
u%s ECC private key must not have parameters
uUnsupported ECC purpose (OID: %s)
a_extract_subject_public_key_info
a_import_subjectPublicKeyInfo
T EValueError
ETypeError
EIndexError
a_import_x509_cert
a_import_pkcs8
uNot an ECC DER key
T d uNot an openssh public key
a2b_base64
keystring
unpack
:nl nakeyparts
uMismatch in openssh public key
startswith
T cecdsa-sha2-
T uecdsa-sha2
uUnsupported ECC curve:
middle
cssh-ed25519
uUnsupported SSH key type:
aError
uError parsing SSH key type:
a_openssh
T aimport_openssh_private_generic
read_bytes
read_string
check_padding
import_openssh_private_generic
read_bytes
read_string
check_padding
l uUnsupported ECC curve %s
modulus_bits
l uOnly uncompressed OpenSSH EC keys are supported
uIncorrect public key length
uUnsupport SSH agent key type:
point_y
uIncorrect length. Only Ed25519 public keys are supported.
T g	                                         uInvalid Ed25519 key (y)
T l
l g	R                         (          a_tonelli_shanks
uInvalid Ed25519 public key
uImport an Ed25519 ECC public key, encoded as raw bytes as described
in RFC8032_.
Args:
encoded (bytes):
The Ed25519 public key to import. It must be 32 bytes long.
Returns:
x and y (integer)
Raises:
ValueError: when the given key cannot be parsed.
.. _RFC8032: https://datatracker.ietf.org/doc/html/rfc8032
uIncorrect Curve25519 key length
uImport a Curve25519 ECC public key,
encoded as raw bytes as described in RFC7748_.
Args:
encoded (bytes):
The Curve25519 public key to import. It must be 32 bytes long.
Returns:
x (integer)
Raises:
ValueError: when the given key cannot be parsed.
.. _RFC7748: https://datatracker.ietf.org/doc/html/rfc7748
uIncorrect Curve448 key length
uImport a Curve448 ECC public key,
encoded as raw bytes as described in RFC7748_.
Args:
encoded (bytes):
The Curve448 public key to import. It must be 56 bytes long.
Returns:
x (integer)
Raises:
ValueError: when the given key cannot be parsed.
.. _RFC7748: https://datatracker.ietf.org/doc/html/rfc7748
uIncorrect length. Only Ed448 public keys are supported.
curve448
l   :nl8nuInvalid Ed448 key (y)
uInvalid Ed448 public key
uImport an Ed448 ECC public key, encoded as raw bytes as described
in RFC8032_.
Args:
encoded (bytes):
The Ed448 public key to import. It must be 57 bytes long.
Returns:
x and y (integer)
Raises:
ValueError: when the given key cannot be parsed.
.. _RFC8032: https://datatracker.ietf.org/doc/html/rfc8032
T c-----BEGIN OPENSSH PRIVATE KEY
a_import_openssh_private_ecc
T c-----
re
sub
u-----BEGIN EC PARAMETERS-----.*?-----END EC PARAMETERS-----
aDOTALL
T aflags
a_import_der
uInvalid DER encoding inside the PEM file
T T cecdsa-sha2-
cssh-ed25519
a_import_openssh_public
l0T l l l uNo curve name was provided
T acurve_name
uECC key format is not supported
uImport an ECC key (public or private).
Args:
encoded (bytes or multi-line string):
The ECC key to import.
The function will try to automatically detect the right format.
Supported formats for an ECC **public** key:
* X.509 certificate: binary (DER) or ASCII (PEM).
* X.509 ``subjectPublicKeyInfo``: binary (DER) or ASCII (PEM).
* SEC1_ (or X9.62), as ``bytes``. NIST P curves only.
You must also provide the ``curve_name`` (with a value from the `ECC table`_)
* OpenSSH line, defined in RFC5656_ and RFC8709_ (ASCII).
This is normally the content of files like ``~/.ssh/id_ecdsa.pub``.
Supported formats for an ECC **private** key:
* A binary ``ECPrivateKey`` structure, as defined in `RFC5915`_ (DER).
NIST P curves only.
* A `PKCS#8`_ structure (or the more recent Asymmetric Key
Package, RFC5958_): binary (DER) or ASCII (PEM).
* `OpenSSH 6.5`_ and newer versions (ASCII).
Private keys can be in the clear or password-protected.
For details about the PEM encoding, see `RFC1421`_/`RFC1423`_.
passphrase (byte string):
The passphrase to use for decrypting a private key.
Encryption may be applied protected at the PEM level (not recommended)
or at the PKCS#8 level (recommended).
This parameter is ignored if the key in input is not encrypted.
curve_name (string):
For a SEC1 encoding only. This is the name of the curve,
s defined in the `ECC table`_.
.. note::
To import EdDSA private and public keys, when encoded as raw ``bytes``, use:
* :func:`Crypto.Signature.eddsa.import_public_key`, or
* :func:`Crypto.Signature.eddsa.import_private_key`.
.. note::
To import X25519/X448 private and public keys, when encoded as raw ``bytes``, use:
* :func:`Crypto.Protocol.DH.import_x25519_public_key`
* :func:`Crypto.Protocol.DH.import_x25519_private_key`
* :func:`Crypto.Protocol.DH.import_x448_public_key`
* :func:`Crypto.Protocol.DH.import_x448_private_key`
Returns:
:class:`EccKey` : a new ECC key object
Raises:
ValueError: when the given key cannot be parsed (possibly because
the pass phrase is wrong).
.. _RFC1421: https://datatracker.ietf.org/doc/html/rfc1421
.. _RFC1423: https://datatracker.ietf.org/doc/html/rfc1423
.. _RFC5915: https://datatracker.ietf.org/doc/html/rfc5915
.. _RFC5656: https://datatracker.ietf.org/doc/html/rfc5656
.. _RFC8709: https://datatracker.ietf.org/doc/html/rfc8709
.. _RFC5958: https://datatracker.ietf.org/doc/html/rfc5958
.. _`PKCS#8`: https://datatracker.ietf.org/doc/html/rfc5208
.. _`OpenSSH 6.5`: https://flak.tedunangst.com/post/new-openssh-key-format-and-bcrypt-pbkdf
.. _SEC1: https://www.secg.org/sec1-v2.pdf
a__doc__
a__file__
origin
has_location
a__cached__
print_function
uCrypto.Util.py3compat
T abord
tobytes
tostr
bchr
is_string
uCrypto.Math.Numbers
T aInteger
uCrypto.Util.asn1
T aDerObjectId
aDerOctetString
aDerSequence
aDerBitString
uCrypto.PublicKey
T a_expand_subject_public_key_info
a_create_subject_public_key_info
a_extract_subject_public_key_info
uCrypto.Hash
T aSHA512
aSHAKE256
uCrypto.Random
T aget_random_bytes
T aEccPoint
aEccXPoint
a_curves
T aCurveID
aCurveID
T EValueError
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
