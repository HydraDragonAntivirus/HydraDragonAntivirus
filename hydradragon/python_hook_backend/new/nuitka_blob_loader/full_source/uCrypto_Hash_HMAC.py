# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.HMAC

uAn HMAC hash object.
Do not instantiate directly. Use the :func:`new` function.
:ivar digest_size: the size in bytes of the resulting MAC tag
:vartype digest_size: integer
:ivar oid: the ASN.1 object ID of the HMAC algorithm.
Only present if the algorithm was officially assigned one.
a__qualname__
T c
na__init__
uHMAC.__init__
uHMAC.update
uHMAC._pbkdf2_hmac_assist
uHMAC.copy
uHMAC.digest
uHMAC.verify
hexdigest
uHMAC.hexdigest
hexverify
uHMAC.hexverify
a__orig_bases__
uCrypto\Hash\HMAC.py
u<module Crypto.Hash.HMAC>
T a__class__
T	aself
key
msg
digestmod
aMD5
key_0
hash_k
key_0_ipad
key_0_opad
T aself
first_digest
iterations
result
T aself
new_hmac
T aself
frozen_outer_hash
T aself
T aself
hex_mac_tag
T akey
msg
digestmod
T aself
msg
T aself
mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Hash.KMAC128
L
]
u2.16.840.1.101.3.4.2.
oid
digest_size
a_mac
a_bytepad
a_encode_str
tobytes
a_new
cKMAC
a_cshake
update
uYou can only call 'digest' or 'hexdigest' on this object
uAuthenticate the next chunk of message.
Args:
data (bytes/bytearray/memoryview): The next chunk of the message to
uthenticate.
a_right_encode
l aread
uReturn the **binary** (non-printable) MAC tag of the message.
:return: The MAC tag. Binary form.
:rtype: byte string

digest
u%02x
bord
uReturn the **printable** MAC tag of the message.
:return: The MAC tag. Hexadecimal encoded.
:rtype: string
get_random_bytes
T l aSHA3_256
new
uMAC check failed
uVerify that a given **binary** MAC (computed by another party)
is valid.
Args:
mac_tag (bytes/bytearray/memoryview): the expected MAC of the message.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.
verify
unhexlify
uVerify that a given **printable** MAC (computed by another party)
is valid.
Args:
hex_mac_tag (string): the expected MAC of the message, as a hexadecimal string.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.
mac_len
uReturn a new instance of a KMAC hash object.
See :func:`new`.
key
is_bytes
uYou must pass a key to KMAC128
uThe key must be at least 128 bits long (16 bytes)
pop
T adata
nT amac_len
l@u'mac_len' must be 8 bytes or more
T acustom
c
uUnknown parameters:
aKMAC_Hash
u19
cSHAKE128
l  uCreate a new KMAC128 object.
Args:
key (bytes/bytearray/memoryview):
The key to use to compute the MAC.
It must be at least 128 bits long (16 bytes).
data (bytes/bytearray/memoryview):
Optional. The very first chunk of the message to authenticate.
It is equivalent to an early call to :meth:`KMAC_Hash.update`.
mac_len (integer):
Optional. The size of the authentication tag, in bytes.
Default is 64. Minimum is 8.
custom (bytes/bytearray/memoryview):
Optional. A customization byte string (``S`` in SP 800-185).
Returns:
A :class:`KMAC_Hash` hash object
a__doc__
a__file__
origin
has_location
a__cached__
binascii
T aunhexlify
uCrypto.Util.py3compat
T abord
tobytes
is_bytes
uCrypto.Random
T aget_random_bytes
T acSHAKE128
aSHA3_256
T a_bytepad
a_encode_str
a_right_encode
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
