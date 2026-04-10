# Reconstructed from integrated Nuitka blob
# Module: uCrypto.SelfTest.loader

u_load_tests.<locals>.TestVector
a__qualname__
a__init__
u_load_tests.<locals>.TestVector.__init__
a__orig_bases__
line_number
file_in
readline
test_vector
results
strip
startswith
T w#T w[aappend
new_group
count
u%s (#%d)
re
match
u([A-Za-z0-9]+) = ?(.*)
others
group
T l alower
T l aconversions
get
l w0abinascii
unhexlify
data
uLoad and parse a test vector file
Return a list of objects, one per group of adjacent
KV lines or for a single line in the form "[.*]".
For a group of lines, the object has one attribute per line.
desc
test_vectors_available
aFileNotFoundError
errno
aENOENT
strerror
u%s test (%s)
pycryptodome_test_vectors
a__file__
join
a__enter__
a__exit__
a_load_tests
T nnnawarnings
warn
uWarning: skipping extended tests for
description
aUserWarning
D astacklevel
l uLoad and parse a test vector file, formatted using the NIST style.
Args:
dir_comps (list of strings):
The path components under the ``pycryptodome_test_vectors`` package.
For instance ``("Cipher", "AES")``.
file_name (string):
The name of the file with the test vectors.
description (string):
A description applicable to the test vectors in the file.
conversions (dictionary):
The dictionary contains functions.
Values in the file that have an entry in this dictionary
will be converted usign the matching function.
Otherwise, values will be considered as hexadecimal and
converted to binary.
Returns:
A list of test vector objects.
The file is formatted in the following way:
- Lines starting with "#" are comments and will be ignored.
- Each test vector is a sequence of 1 or more adjacent lines, where
each lines is an assignement.
- Test vectors are separated by an empty line, a comment, or
a line starting with "[".
A test vector object has the following attributes:
- desc (string): description
- counter (int): the order of the test vector in the file (from 1)
- others (list): zero or more lines of the test vector that were not assignments
- left-hand side of each assignment (lowercase): the value of the
ssignement, either converted or bytes.
json
load
uload_test_vectors_wycheproof.<locals>.TestVector
S ainfo
ikm
sig
ct
okm
shared
msg
key
public
iv
salt
label
aad
tag
keys
items
tv_tree
common_root
testGroups
group_tag
common_group
tests
tcId
id
comment
unit_attr_hex
aError
uError decoding attribute '%s' (tcId=%s, file %s)
file_name
filename
unit_tag
test
result
invalid
valid
acceptable
warning
T aflags
flags
a__doc__
origin
has_location
a__cached__
os
T aunhexlify
uCrypto.Util.py3compat
T aFileNotFoundError
load_test_vectors
load_test_vectors_wycheproof
uCrypto\SelfTest\loader.py
u<module Crypto.SelfTest.loader>
T a__class__
T aself
description
count
T adir_comps
file_in
description
conversions
line_number
results
aTestVector
test_vector
count
new_group
line
res
token
data
conversion
T adir_comps
file_name
description
conversions
results
init_dir
full_file_name
file_in
T adir_comps
file_name
description
root_tag
group_tag
unit_tag
result
init_dir
full_file_name
file_in
tv_tree
aTestVector
unit_attr_hex
common_root
wkwvagroup
common_group
test
tv
attr

a__spec__
.Crypto.SelfTest.st_common
g
aTestLoader
loadTestsFromTestCase
uReturn a list of TestCase instances given a TestCase class
This is useful when you have defined test* methods on your TestCase class.
wbu
split
T u
join
uRemove whitespace from a text or byte string
binascii
a2b_hex
strip_whitespace
uConvert hexadecimal to binary, ignoring whitespace
b2a_hex
uConvert binary to hexadecimal
uCommon functions for SelfTest modules
a__doc__
a__file__
origin
has_location
a__cached__
unittest
uCrypto.Util.py3compat
T wbalist_test_cases
uCrypto\SelfTest\st_common.py
u<module Crypto.SelfTest.st_common>
T wsT aclass_
a__spec__
.Crypto.Signature.DSS
a_key
a_encoding
a_order
size_in_bits
a_order_bits
l a_order_bytes
uCreate a new Digital Signature Standard (DSS) object.
Do not instantiate this object directly,
use `Crypto.Signature.DSS.new` instead.
has_private
uReturn ``True`` if this signature object can be used
for signing messages.
uTo be provided by subclasses
uPrivate key is needed to sign
a_valid_hash
uHash is not sufficiently strong
a_compute_nonce
aInteger
from_bytes
digest
a_sign
binary
c
long_to_bytes
self
aDerSequence
encode
uCompute the DSA/ECDSA signature of a message.
Args:
msg_hash (hash object):
The hash that was carried out over the message.
The object belongs to the :mod:`Crypto.Hash` package.
Under mode ``'fips-186-3'``, the hash must be a FIPS
pproved secure hash (SHA-2 or SHA-3).
:return: The signature as ``bytes``
:raise ValueError: if the hash algorithm is incompatible to the (EC)DSA key
:raise TypeError: if the (EC)DSA key has no private half
l uThe signature is not authentic (length)
decode
D astrict
tT EValueError
EIndexError
uThe signature is not authentic (DER)
hasOnlyInts
uThe signature is not authentic (DER content)
uThe signature is not authentic (d)
a_verify
uThe signature is not authentic
uCheck if a certain (EC)DSA signature is authentic.
Args:
msg_hash (hash object):
The hash that was carried out over the message.
This is an object belonging to the :mod:`Crypto.Hash` module.
Under mode ``'fips-186-3'``, the hash must be a FIPS
pproved secure hash (SHA-2 or SHA-3).
signature (``bytes``):
The signature that needs to be validated.
:raise ValueError: if the signature is not authentic
aDeterministicDsaSigScheme
a__init__
a_private_key
uSee 2.3.2 in RFC6979
uSee 2.3.3 in RFC6979
a_bits2int
a_int2octets
uSee 2.3.4 in RFC6979
d adigest_size
d
T d
d aHMAC
new
nonce_k
mask_v
a_bits2octets
h1
mhash
nonce
mask_t
uGenerate k in a deterministic way
aFipsDsaSigScheme
a_randfunc
wpa_fips_186_3_L_N
uL/N (%d, %d) is not compliant to FIPS 186-3
random_range
T amin_inclusive
max_exclusive
randfunc
oid
u1.3.14.3.2.26
startswith
T u2.16.840.1.101.3.4.2.
uVerify that SHA-1, SHA-2 or SHA-3 are used
aFipsEcDsaSigScheme
a_curve
order
pointQ
T
u2.16.840.1.101.3.4.2.4
u2.16.840.1.101.3.4.2.7
u2.16.840.1.101.3.4.2.5
u2.16.840.1.101.3.4.2.1
u2.16.840.1.101.3.4.2.8
u2.16.840.1.101.3.4.2.6
u2.16.840.1.101.3.4.2.2
u2.16.840.1.101.3.4.2.9
u2.16.840.1.101.3.4.2.3
u2.16.840.1.101.3.4.2.10
uVerify that the strength of the hash matches or exceeds
the strength of the EC. We fail if the hash is too weak.
T abinary
der
uUnknown encoding '%s'
aEccKey
wdacurve
T aNIST
uECC key is not on a NIST P curve
aDsaKey
wqwxuUnsupported key type
key
udeterministic-rfc6979
ufips-186-3
uUnknown DSS mode '%s'
uCreate a signature object :class:`DssSigScheme` that
can perform (EC)DSA signature or verification.
.. note::
Refer to `NIST SP 800 Part 1 Rev 4`_ (or newer release) for an
overview of the recommended key lengths.
Args:
key (:class:`Crypto.PublicKey.DSA` or :class:`Crypto.PublicKey.ECC`):
The key to use for computing the signature (*private* keys only)
or for verifying one.
For DSA keys, let ``L`` and ``N`` be the bit lengths of the modulus ``p``
nd of ``q``: the pair ``(L,N)`` must appear in the following list,
in compliance to section 4.2 of `FIPS 186-4`_:
- (1024, 160) *legacy only; do not create new signatures with this*
- (2048, 224) *deprecated; do not create new signatures with this*
- (2048, 256)
- (3072, 256)
For ECC, only keys over P-224, P-256, P-384, and P-521 are accepted.
mode (string):
The parameter can take these values:
- ``'fips-186-3'``. The signature generation is randomized and carried out
ccording to `FIPS 186-3`_: the nonce ``k`` is taken from the RNG.
- ``'deterministic-rfc6979'``. The signature generation is not
randomized. See RFC6979_.
encoding (string):
How the signature is encoded. This value determines the output of
:meth:`sign` and the input to :meth:`verify`.
The following values are accepted:
- ``'binary'`` (default), the signature is the raw concatenation
of ``r`` and ``s``. It is defined in the IEEE P.1363 standard.
For DSA, the size in bytes of the signature is ``N/4`` bytes
(e.g. 64 for ``N=256``).
For ECDSA, the signature is always twice the length of a point
coordinate (e.g. 64 bytes for P-256).
- ``'der'``, the signature is a ASN.1 DER SEQUENCE
with two INTEGERs (``r`` and ``s``). It is defined in RFC3279_.
The size of the signature is variable.
randfunc (callable):
A function that returns random ``bytes``, of a given length.
If omitted, the internal RNG is used.
Only applicable for the *'fips-186-3'* mode.
.. _FIPS 186-3: http://csrc.nist.gov/publications/fips/fips186-3/fips_186-3.pdf
.. _FIPS 186-4: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
.. _NIST SP 800 Part 1 Rev 4: http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r4.pdf
.. _RFC6979: http://tools.ietf.org/html/rfc6979
.. _RFC3279: https://tools.ietf.org/html/rfc3279#section-2.2.2
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.asn1
T aDerSequence
uCrypto.Util.number
T along_to_bytes
uCrypto.Math.Numbers
T aInteger
uCrypto.Hash
T aHMAC
uCrypto.PublicKey.ECC
T aEccKey
uCrypto.PublicKey.DSA
T aDsaKey
aDssSigScheme
a__all__
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
