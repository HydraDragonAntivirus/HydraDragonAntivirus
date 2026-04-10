# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.CMAC

uA CMAC hash object.
Do not instantiate directly. Use the :func:`new` function.
:ivar digest_size: the size in bytes of the resulting MAC tag
:vartype digest_size: integer
a__qualname__
a__init__
uCMAC.__init__
uCMAC.update
uCMAC._update
uCMAC.copy
uCMAC.digest
hexdigest
uCMAC.hexdigest
uCMAC.verify
hexverify
uCMAC.hexverify
a__orig_bases__
T nnnnFuCrypto\Hash\CMAC.py
u<module Crypto.Hash.CMAC>
T a__class__
T aself
key
msg
ciphermod
cipher_params
mac_len
update_after_digest
abs
const_Rb
zero_block
wLT abs
xor_lsb
num
T aself
data_block
abs
ct
second_last
T aself
obj
T aself
abs
pt
partial
T aself
T aself
hex_mac_tag
T akey
msg
ciphermod
cipher_params
mac_len
update_after_digest
T aself
msg
abs
filler
remain
T aself
mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Hash.HMAC
b
uCrypto.Hash
T aMD5
aMD5
c
digest_size
a_digestmod
a_hash2hmac_oid
oid
T EKeyError
EAttributeError
tobytes
block_size
d
new
digest
uHash type incompatible to HMAC
strxor
d6a_inner
update
d\a_outer
uAuthenticate the next chunk of message.
Args:
data (byte string/byte array/memoryview): The next chunk of data
a_pbkdf2_hmac_assist
uCarry out the expensive inner loop for PBKDF2-HMAC
aHMAC
T cfake key
T adigestmod
copy
uReturn a copy ("clone") of the HMAC object.
The copy will have the same internal state as the original HMAC
object.
This can be used to efficiently compute the MAC tag of byte
strings that share a common initial substring.
:return: An :class:`HMAC`
uReturn the **binary** (non-printable) MAC tag of the message
uthenticated so far.
:return: The MAC tag digest, computed over the data processed so far.
Binary form.
:rtype: byte string
get_random_bytes
T l aBLAKE2s
l  T adigest_bits
key
data
uMAC check failed
uVerify that a given **binary** MAC (computed by another party)
is valid.
Args:
mac_tag (byte string/byte string/memoryview): the expected MAC of the message.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.

u%02x
bord
uReturn the **printable** MAC tag of the message authenticated so far.
:return: The MAC tag, computed over the data processed so far.
Hexadecimal encoded.
:rtype: string
verify
unhexlify
uVerify that a given **printable** MAC (computed by another party)
is valid.
Args:
hex_mac_tag (string): the expected MAC of the message,
s a hexadecimal string.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.
uCreate a new MAC object.
Args:
key (bytes/bytearray/memoryview):
key for the MAC object.
It must be long enough to match the expected security level of the
MAC.
msg (bytes/bytearray/memoryview):
Optional. The very first chunk of the message to authenticate.
It is equivalent to an early call to :meth:`HMAC.update`.
digestmod (module):
The hash to use to implement the HMAC.
Default is :mod:`Crypto.Hash.MD5`.
Returns:
An :class:`HMAC` object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T abord
tobytes
binascii
T aunhexlify
T aBLAKE2s
uCrypto.Util.strxor
T astrxor
uCrypto.Random
T aget_random_bytes
a__all__
D u1.3.14.3.2.26
u2.16.840.1.101.3.4.2.4
u2.16.840.1.101.3.4.2.1
u2.16.840.1.101.3.4.2.2
u2.16.840.1.101.3.4.2.3
u2.16.840.1.101.3.4.2.5
u2.16.840.1.101.3.4.2.6
u2.16.840.1.101.3.4.2.7
u2.16.840.1.101.3.4.2.8
u2.16.840.1.101.3.4.2.9
u2.16.840.1.101.3.4.2.10
u1.2.840.113549.2.7
u1.2.840.113549.2.8
u1.2.840.113549.2.9
u1.2.840.113549.2.10
u1.2.840.113549.2.11
u1.2.840.113549.2.12
u1.2.840.113549.2.13
u2.16.840.1.101.3.4.2.13
u2.16.840.1.101.3.4.2.14
u2.16.840.1.101.3.4.2.15
u2.16.840.1.101.3.4.2.16
a_hmac2hash_oid
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
