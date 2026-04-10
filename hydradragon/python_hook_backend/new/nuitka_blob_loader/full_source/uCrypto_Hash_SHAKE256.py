# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.SHAKE256

uA SHAKE256 hash object.
Do not instantiate directly.
Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
a__qualname__
u2.16.840.1.101.3.4.2.12
oid
T na__init__
uSHAKE256_XOF.__init__
uSHAKE256_XOF.update
read
uSHAKE256_XOF.read
new
uSHAKE256_XOF.new
a__orig_bases__
uCrypto\Hash\SHAKE256.py
u<module Crypto.Hash.SHAKE256>
T a__class__
T aself
data
state
result
T aself
data
T aself
length
bfr
result
T aself
data
result

a__spec__
.Crypto.Hash.TupleHash128
J
digest_size
a_new
c
cTupleHash
a_cshake
a_digest
uYou cannot call 'update' after 'digest' or 'hexdigest'
is_bytes
uYou can only call 'update' on bytes
self
update
a_encode_str
uAuthenticate the next tuple of byte strings.
TupleHash guarantees the logical separation between each byte string.
Args:
data (bytes/bytearray/memoryview): One or more items to hash.
a_right_encode
l aread
uReturn the **binary** (non-printable) digest of the tuple of byte strings.
:return: The hash digest. Binary form.
:rtype: byte string

digest
u%02x
bord
uReturn the **printable** digest of the tuple of byte strings.
:return: The hash digest. Hexadecimal encoded.
:rtype: string
digest_bytes
digest_bits
new
uReturn a new instance of a TupleHash object.
See :func:`new`.
pop
T adigest_bits
nuOnly one digest parameter must be provided
T nnl@u'digest_bytes' must be at least 8
u'digest_bytes' must be at least 64 in steps of 8
T acustom
c
aTupleHash
cSHAKE128
uCreate a new TupleHash128 object.
Args:
digest_bytes (integer):
Optional. The size of the digest, in bytes.
Default is 64. Minimum is 8.
digest_bits (integer):
Optional and alternative to ``digest_bytes``.
The size of the digest, in bits (and in steps of 8).
Default is 512. Minimum is 64.
custom (bytes):
Optional.
A customization bytestring (``S`` in SP 800-185).
:Return: A :class:`TupleHash` object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T abord
is_bytes
tobytes
tobytes
T acSHAKE128
T a_encode_str
a_right_encode
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
