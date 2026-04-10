# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Protocol.SecretSharing

uElement of GF(2^128) field
a__qualname__
l  a__init__
u_Element.__init__
a__eq__
u_Element.__eq__
a__int__
u_Element.__int__
u_Element.encode
a__mul__
u_Element.__mul__
a__add__
u_Element.__add__
u_Element.inverse
a__pow__
u_Element.__pow__
a__orig_bases__
aShamir
uShamir's secret sharing scheme.
A secret is split into ``n`` shares, and it is sufficient to collect
``k`` of them to reconstruct the secret.
staticmethod
T Fasplit
uShamir.split
combine
uShamir.combine
uCrypto\Protocol\SecretSharing.py
T a.0
wyaidx
u<module Crypto.Protocol.SecretSharing>
T a__class__
T aself
term
T aself
other
T aself
encoded_value
T aself
T	aself
factor
f1
f2
mask1
wvwzamask2
mask3
T aself
exponent
result
w_T wawbadeg
wqwrwdwsT af1
f2
wzT ashares
ssss
wkagf_shares
wxaidx
value
result
wjax_j
y_j
numerator
denominator
wmax_m
T aself
r0
r1
s0
s1
wqT auser
coeffs
ssss
idx
share
coeff
T wkwnasecret
ssss
coeffs
make_share

a__spec__
.Crypto.Protocol
H
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
aProtocol
T aNUITKA_PACKAGE_Crypto_Protocol
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
aKDF
aSecretSharing
aDH
a__all__
uCrypto\Protocol\__init__.py
u<module Crypto.Protocol>

a__spec__
.Crypto.PublicKey.DSA
)
keys
S wywgwpwqaissubset
uSome DSA components are missing = %s
S wxuUnknown DSA components = %s
a_key
has_private
uDSA public key cannot be used for signing
wquk is not between 2 and q-1
T wxwqwpwgaself
aInteger
random_range
T amin_inclusive
max_exclusive
inverse
pow
T wywqwpwgwxuWhether this is a DSA private key
T wywgwpwqaDsaKey
uA matching DSA public key.
Returns:
a new :class:`DsaKey` object
u<genexpr>
uDsaKey.public_key.<locals>.<genexpr>
a_keydata
result
other
a__eq__
pickle
T aPicklingError
aPicklingError
T wpwqwguThe DSA domain parameters.
Returns
tuple : (p,q,g)
wpasize_in_bits
attrs
up(%d)
private
u<%s @0x%x %s>
a__name__
w,atobytes
aRandom
get_random_bytes
aOpenSSH
T wpwqwgwyato_bytes
func
uDsaKey.export_key.<locals>.func
cssh-dss
c
struct
pack
u>I
cssh-dss
binascii
b2a_base64
:nq naDerSequence
wguPBKDF2WithHMAC-SHA1AndDES-EDE3-CBC
aDerInteger
encode
aPKCS8
wrap
oid
T akey_params
randfunc
uENCRYPTED PRIVATE
aPRIVATE
aPEM
uDSA private key cannot be encrypted
wyuDSA PRIVATE
uPKCS#8 is only meaningful for private keys
a_create_subject_public_key_info
aPUBLIC
aDER
u KEY
uUnknown key format '%s'. Cannot export the DSA key.
uExport this DSA key.
Args:
format (string):
The encoding for the output:
- *'PEM'* (default). ASCII as per `RFC1421`_/ `RFC1423`_.
- *'DER'*. Binary ASN.1 encoding.
- *'OpenSSH'*. ASCII one-liner as per `RFC4253`_.
Only suitable for public keys, not for private keys.
passphrase (string):
*Private keys only*. The pass phrase to protect the output.
pkcs8 (boolean):
*Private keys only*. If ``True`` (default), the key is encoded
with `PKCS#8`_. If ``False``, it is encoded in the custom
OpenSSL/OpenSSH container.
protection (string):
*Only in combination with a pass phrase*.
The encryption scheme to use to protect the output.
If :data:`pkcs8` takes value ``True``, this is the PKCS#8
lgorithm to use for deriving the secret and encrypting
the private DSA key.
For a complete list of algorithms, see :mod:`Crypto.IO.PKCS8`.
The default is *PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC*.
If :data:`pkcs8` is ``False``, the obsolete PEM encryption scheme is
used. It is based on MD5 for key derivation, and Triple DES for
encryption. Parameter :data:`protection` is then ignored.
The combination ``format='DER'`` and ``pkcs8=False`` is not allowed
if a passphrase is present.
randfunc (callable):
A function that returns random bytes.
By default it is :func:`Crypto.Random.get_random_bytes`.
Returns:
byte string : the encoded key
Raises:
ValueError : when the format is unknown or when you try to encrypt a private
key with *DER* format and OpenSSL/OpenSSH.
.. warning::
If you don't provide a pass phrase, the private key will be
exported in the clear!
.. _RFC1421:    http://www.ietf.org/rfc/rfc1421.txt
.. _RFC1423:    http://www.ietf.org/rfc/rfc1423.txt
.. _RFC4253:    http://www.ietf.org/rfc/rfc4253.txt
.. _`PKCS#8`:   http://www.ietf.org/rfc/rfc5208.txt
bord
l  abchr
T l
uUse module Crypto.Signature.DSS instead
D l  l  l  l  l  l  uInvalid modulus length (%d)
aSHA256
digest_size
l T l atest_probable_prime
randfunc
aPROBABLY_PRIME
T l@afrom_bytes
new
digest
upper_bit
iter_range
wnaseed
offset
outlen
b_
l aitertools
count
T l cggen
uGenerate a new set of DSA domain parameters
aCOMPOSITE
uInvalid DSA domain parameters
a_generate_domain
uMismatch between size of modulus (%d) and 'bits' parameter (%d)
T T l  l  T l  l  T l  l  T l  l  uLengths of p and q (%d, %d) are not compatibleto FIPS 186-3
uIncorrent DSA generator
random
l@T aexact_bits
randfunc
uGenerate a new DSA key pair.
The algorithm follows Appendix A.1/A.2 and B.1 of `FIPS 186-4`_,
respectively for domain generation and key pair generation.
Args:
bits (integer):
Key length, or size (in bits) of the DSA modulus *p*.
It must be 1024, 2048 or 3072.
randfunc (callable):
Random number generation function; it accepts a single integer N
nd return a string of random data N bytes long.
If not specified, :func:`Crypto.Random.get_random_bytes` is used.
domain (tuple):
The DSA domain parameters *p*, *q* and *g* as a list of 3
integers. Size of *p* and *q* must comply to `FIPS 186-4`_.
If not specified, the parameters are created anew.
Returns:
:class:`DsaKey` : a new DSA key object
Raises:
ValueError : when **bits** is too little, too big, or not a multiple of 64.
.. _FIPS 186-4: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
T wywgwpwqwxuInvalid DSA key components
uConstruct a DSA key from a tuple of valid DSA components.
Args:
tup (tuple):
A tuple of long integers, with 4 or 5 items
in the following order:
1. Public key (*y*).
2. Sub-group generator (*g*).
3. Modulus, finite field order (*p*).
4. Sub-group order (*q*).
5. Private key (*x*). Optional.
consistency_check (boolean):
If ``True``, the library will verify that the provided components
fulfil the main DSA properties.
Raises:
ValueError: when the key being imported fails the most basic DSA validity checks.
Returns:
:class:`DsaKey` : a DSA key object
uDSA private key already comes with parameters
decode
D anr_elements
only_ints_expected
l tuNo version found
T l l l l l aconstruct
a_expand_subject_public_key_info
uNo DSA subjectPublicKeyInfo
uToo many DSA parameters
value
a_extract_subject_public_key_info
a_import_subjectPublicKeyInfo
uPKCS#8 already includes parameters
unwrap
uNo PKCS#8 encoded DSA key
a_import_openssl_private
a_import_x509_cert
a_import_pkcs8
key_data
passphrase
params
uDSA key format is not supported
uImport a DSA key (public or private half), encoded in DER form.
startswith
T c-----
tostr
a_import_key_der
T cssh-dss
a2b_base64
split
T d akeystring
unpack
:nl nakeyparts
append
l T l l l l l0uImport a DSA key.
Args:
extern_key (string or byte string):
The DSA key to import.
The following formats are supported for a DSA **public** key:
- X.509 certificate (binary DER or PEM)
- X.509 ``subjectPublicKeyInfo`` (binary DER or PEM)
- OpenSSH (ASCII one-liner, see `RFC4253`_)
The following formats are supported for a DSA **private** key:
- `PKCS#8`_ ``PrivateKeyInfo`` or ``EncryptedPrivateKeyInfo``
DER SEQUENCE (binary or PEM)
- OpenSSL/OpenSSH custom format (binary or PEM)
For details about the PEM encoding, see `RFC1421`_/`RFC1423`_.
passphrase (string):
In case of an encrypted private key, this is the pass phrase
from which the decryption key is derived.
Encryption may be applied either at the `PKCS#8`_ or at the PEM level.
Returns:
:class:`DsaKey` : a DSA key object
Raises:
ValueError : when the given key cannot be parsed (possibly because
the pass phrase is wrong).
.. _RFC1421: http://www.ietf.org/rfc/rfc1421.txt
.. _RFC1423: http://www.ietf.org/rfc/rfc1423.txt
.. _RFC4253: http://www.ietf.org/rfc/rfc4253.txt
.. _PKCS#8: http://www.ietf.org/rfc/rfc5208.txt
a__doc__
a__file__
origin
has_location
a__cached__
L agenerate
construct
aDsaKey
import_key
a__all__
uCrypto.Util.py3compat
T abchr
bord
tobytes
tostr
iter_range
aCrypto
T aRandom
uCrypto.IO
T aPKCS8
aPEM
uCrypto.Hash
T aSHA256
uCrypto.Util.asn1
T aDerObject
aDerSequence
aDerInteger
aDerObjectId
aDerBitString
aDerObject
aDerObjectId
aDerBitString
uCrypto.Math.Numbers
T aInteger
uCrypto.Math.Primality
T atest_probable_prime
aCOMPOSITE
aPROBABLY_PRIME
uCrypto.PublicKey
T a_expand_subject_public_key_info
a_create_subject_public_key_info
a_extract_subject_public_key_info
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
