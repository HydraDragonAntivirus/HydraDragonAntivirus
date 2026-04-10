# Reconstructed from integrated Nuitka blob
# Module: uCrypto.PublicKey.RSA

uconstruct.<locals>.InputComps
a__qualname__
a__orig_bases__
wtT l aspotted
wawkuUnable to compute factors p and q from exponent d.
uInvalid RSA public exponent
uRSA public exponent is not coprime to modulus
uRSA modulus is not odd
uInvalid RSA private exponent
uRSA private exponent is not coprime to modulus
uRSA factors do not match modulus
test_probable_prime
aCOMPOSITE
uRSA factor p is composite
uRSA factor q is composite
uInvalid RSA condition
uInvalid RSA component u
uInvalid RSA component u with p
uConstruct an RSA key from a tuple of valid RSA components.
The modulus **n** must be the product of two primes.
The public exponent **e** must be odd and larger than 1.
In case of a private key, the following equations must apply:
.. math::
\begin{align}
p*q &= n \\
e*d &\equiv 1 ( \text{mod lcm} [(p-1)(q-1)]) \\
p*u &\equiv 1 ( \text{mod } q)
\end{align}
Args:
rsa_components (tuple):
A tuple of integers, with at least 2 and no
more than 6 items. The items come in the following order:
1. RSA modulus *n*.
2. Public exponent *e*.
3. Private exponent *d*.
Only required if the key is private.
4. First factor of *n* (*p*).
Optional, but the other factor *q* must also be present.
5. Second factor of *n* (*q*). Optional.
6. CRT coefficient *q*, that is :math:`p^{-1} \text{mod }q`. Optional.
Keyword Args:
consistency_check (boolean):
If ``True``, the library will verify that the provided components
fulfil the main RSA properties.
Raises:
ValueError: when the key being imported fails the most basic RSA validity checks.
Returns: An RSA key object (:class:`RsaKey`).
decode
D anr_elements
only_ints_expected
l	tuNo PKCS#1 encoding of an RSA private key
construct
:l l nl l D anr_elements
only_ints_expected
l tu1.2.840.113549.1.1.10
a_expand_subject_public_key_info
uNo RSA subjectPublicKeyInfo
a_import_pkcs1_public
a_extract_subject_public_key_info
a_import_subjectPublicKeyInfo
unwrap
uNo PKCS#8 encoded RSA key
a_import_keyDER
a_import_pkcs1_private
a_import_x509_cert
a_import_pkcs8
extern_key
passphrase
uRSA key format is not supported
uImport an RSA key (public or private half), encoded in DER form.
a_openssh
T aimport_openssh_private_generic
read_bytes
read_string
check_padding
import_openssh_private_generic
read_bytes
read_string
check_padding
ussh-rsa
uThis SSH key is not RSA
from_bytes
startswith
T c-----BEGIN OPENSSH PRIVATE KEY
tostr
a_import_openssh_private_rsa
T c-----
T cssh-rsa
a2b_base64
split
T d akeystring
unpack
:nl nakeyparts
l0uImport an RSA key (public or private).
Args:
extern_key (string or byte string):
The RSA key to import.
The following formats are supported for an RSA **public key**:
- X.509 certificate (binary or PEM format)
- X.509 ``subjectPublicKeyInfo`` DER SEQUENCE (binary or PEM
encoding)
- `PKCS#1`_ ``RSAPublicKey`` DER SEQUENCE (binary or PEM encoding)
- An OpenSSH line (e.g. the content of ``~/.ssh/id_ecdsa``, ASCII)
The following formats are supported for an RSA **private key**:
- PKCS#1 ``RSAPrivateKey`` DER SEQUENCE (binary or PEM encoding)
- `PKCS#8`_ ``PrivateKeyInfo`` or ``EncryptedPrivateKeyInfo``
DER SEQUENCE (binary or PEM encoding)
- OpenSSH (text format, introduced in `OpenSSH 6.5`_)
For details about the PEM encoding, see `RFC1421`_/`RFC1423`_.
passphrase (string or byte string):
For private keys only, the pass phrase that encrypts the key.
Returns: An RSA key object (:class:`RsaKey`).
Raises:
ValueError/IndexError/TypeError:
When the given key cannot be parsed (possibly because the pass
phrase is wrong).
.. _RFC1421: http://www.ietf.org/rfc/rfc1421.txt
.. _RFC1423: http://www.ietf.org/rfc/rfc1423.txt
.. _`PKCS#1`: http://www.ietf.org/rfc/rfc3447.txt
.. _`PKCS#8`: http://www.ietf.org/rfc/rfc5208.txt
.. _`OpenSSH 6.5`: https://flak.tedunangst.com/post/new-openssh-key-format-and-bcrypt-pbkdf
a__doc__
a__file__
origin
has_location
a__cached__
L agenerate
construct
import_key
aRsaKey
oid
a__all__
aCrypto
T aRandom
uCrypto.Util.py3compat
T atobytes
bord
tostr
uCrypto.Util.asn1
T aDerSequence
aDerNull
uCrypto.Util.number
T abytes_to_long
uCrypto.Math.Numbers
T aInteger
uCrypto.Math.Primality
T atest_probable_prime
generate_probable_prime
aCOMPOSITE
uCrypto.PublicKey
T a_expand_subject_public_key_info
a_create_subject_public_key_info
a_extract_subject_public_key_info
uClass defining an RSA key, private or public.
Do not instantiate directly.
Use :func:`generate`, :func:`construct` or :func:`import_key` instead.
:ivar n: RSA modulus
:vartype n: integer
:ivar e: RSA public exponent
:vartype e: integer
:ivar d: RSA private exponent
:vartype d: integer
:ivar p: First factor of the RSA modulus
:vartype p: integer
:ivar q: Second factor of the RSA modulus
:vartype q: integer
:ivar invp: Chinese remainder component (:math:`p^{-1} \text{mod } q`)
:vartype invp: integer
:ivar invq: Chinese remainder component (:math:`q^{-1} \text{mod } p`)
:vartype invq: integer
:ivar u: Same as ``invp``
:vartype u: integer
a__init__
uRsaKey.__init__
property
uRsaKey.n
uRsaKey.e
uRsaKey.d
uRsaKey.p
uRsaKey.q
dp
uRsaKey.dp
dq
uRsaKey.dq
invq
uRsaKey.invq
invp
uRsaKey.invp
uRsaKey.u
uRsaKey.size_in_bits
size_in_bytes
uRsaKey.size_in_bytes
a_encrypt
uRsaKey._encrypt
uRsaKey._decrypt_to_bytes
a_decrypt
uRsaKey._decrypt
uRsaKey.has_private
can_encrypt
uRsaKey.can_encrypt
can_sign
uRsaKey.can_sign
uRsaKey.public_key
a__eq__
uRsaKey.__eq__
a__ne__
uRsaKey.__ne__
a__getstate__
uRsaKey.__getstate__
a__repr__
uRsaKey.__repr__
a__str__
uRsaKey.__str__
T aPEM
nl nnnuRsaKey.export_key
exportKey
uRsaKey.exportKey
publickey
uRsaKey.publickey
sign
uRsaKey.sign
verify
uRsaKey.verify
encrypt
uRsaKey.encrypt
decrypt
uRsaKey.decrypt
blind
uRsaKey.blind
unblind
uRsaKey.unblind
size
uRsaKey.size
T nl   agenerate
T tT naimport_key
importKey
u1.2.840.113549.1.1.1
uCrypto\PublicKey\RSA.py
u<module Crypto.PublicKey.RSA>
T a__class__
T aself
other
T aself
aPicklingError
T aself
kwargs
input_set
public_set
private_set
component
value
T aself
extra
T aself
key_type
T aself
ciphertext
T	aself
ciphertext
wracp
m1
m2
whamp
result
T aself
plaintext
T aextern_key
passphrase
decodings
decoding
T adata
password
import_openssh_private_generic
read_bytes
read_string
check_padding
ssh_name
decrypted
wnwewdaiqmp
wpwqw_apadded
build
T aencoded
kwargs
der
T aencoded
passphrase
aPKCS8
oids
wkT aencoded
kwargs
oids
algoid
encoded_key
params
T aencoded
kwargs
sp_info
T aself
wMwBT aself
T arsa_components
consistency_check
aInputComps
input_comps
comp
value
wnweakey
wdwpwqaktot
wtaspotted
wawkacand
wuaphi
lcm
T aself
plaintext
wKT aself
args
kwargs
T aself
format
passphrase
pkcs
protection
randfunc
prot_params
e_bytes
n_bytes
keyparts
keystring
binary_key
key_type
aPKCS8
aPEM
pem_str
T acandidate
min_p
weT weamin_p
T acandidate
min_q
wewpamin_distance
T weamin_distance
min_q
wpT abits
randfunc
wewdwnasize_q
size_p
min_p
min_q
filter_p
wpamin_distance
filter_q
wqalcm
wuT aextern_key
passphrase
aPEM
text_encoded
openssh_encoded
marker
enc_flag
result
der
keystring
keyparts
length
wewnT aself
wMwKT aself
wMasignature
a__spec__
.Crypto.PublicKey._curve
&
wpwbaorder
aGx
aGy
wGamodulus_bits
oid
context
canonical
openssh
rawlib
validate
a__doc__
a__file__
origin
has_location
a__cached__
T Oobject
a__prepare__
a_Curve
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
