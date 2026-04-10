# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.BLAKE2s

uA BLAKE2s hash object.
Do not instantiate directly. Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
:ivar block_size: the size in bytes of the internal message block,
input to the compression function
:vartype block_size: integer
:ivar digest_size: the size in bytes of the resulting hash
:vartype digest_size: integer
a__qualname__
block_size
a__init__
uBLAKE2s_Hash.__init__
uBLAKE2s_Hash.update
uBLAKE2s_Hash.digest
hexdigest
uBLAKE2s_Hash.hexdigest
uBLAKE2s_Hash.verify
hexverify
uBLAKE2s_Hash.hexverify
uBLAKE2s_Hash.new
a__orig_bases__
uCrypto\Hash\BLAKE2s.py
u<module Crypto.Hash.BLAKE2s>
T a__class__
T aself
data
key
digest_bytes
update_after_digest
state
result
T aself
bfr
result
T aself
T aself
hex_mac_tag
T aself
kwargs
T akwargs
data
update_after_digest
digest_bytes
digest_bits
key
T aself
data
result
T aself
mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Hash.CMAC
~
bytes_to_long
long_to_bytes
digest_size
a_copy_bytes
a_key
a_factory
a_cipher_params
block_size
a_block_size
a_mac_tag
a_update_after_digest
l l l    a_max_size
l l  g
uCMAC requires a cipher with a block size of 8 or 16 bytes, not %d
d
new
aMODE_ECB
a_ecb
encrypt
bord
l  a_shift_bytes
a_k1
a_k2
aMODE_CBC
a_cbc
a_cache
a_cache_n
a_last_ct
a_last_pt
a_data_size
update
uupdate() cannot be called after digest() or verify()
min
a_update
msg
uAuthenticate the next chunk of message.
Args:
data (byte string/byte array/memoryview): The next chunk of data
l astrxor
uUpdate a block aligned to the block boundary
a__new__
aCMAC
copy
:nnnuReturn a copy ("clone") of the CMAC object.
The copy will have the same internal state as the original CMAC
object.
This can be used to efficiently compute the MAC tag of byte
strings that share a common initial substring.
:return: An :class:`CMAC`
uMAC is unsafe for this message
d uReturn the **binary** (non-printable) MAC tag of the message
that has been authenticated so far.
:return: The MAC tag, computed over the data processed so far.
Binary form.
:rtype: byte string

digest
u%02x
uReturn the **printable** MAC tag of the message authenticated so far.
:return: The MAC tag, computed over the data processed so far.
Hexadecimal encoded.
:rtype: string
get_random_bytes
T l aBLAKE2s
l  T adigest_bits
key
data
uMAC check failed
uVerify that a given **binary** MAC (computed by another party)
is valid.
Args:
mac_tag (byte string/byte array/memoryview): the expected MAC of the message.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.
verify
unhexlify
tobytes
uVerify that a given **printable** MAC (computed by another party)
is valid.
Args:
hex_mac_tag (string): the expected MAC of the message, as a hexadecimal string.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.
uciphermod must be specified (try AES)
l uMAC tag length must be at least 4 bytes long
uMAC tag length cannot be larger than a cipher block (%d) bytes
uCreate a new MAC object.
Args:
key (byte string/byte array/memoryview):
key for the CMAC object.
The key must be valid for the underlying cipher algorithm.
For instance, it must be 16 bytes long for AES-128.
ciphermod (module):
A cipher module from :mod:`Crypto.Cipher`.
The cipher's block size has to be 128 bits,
like :mod:`Crypto.Cipher.AES`, to reduce the probability
of collisions.
msg (byte string/byte array/memoryview):
Optional. The very first chunk of the message to authenticate.
It is equivalent to an early call to `CMAC.update`. Optional.
cipher_params (dict):
Optional. A set of parameters to use when instantiating a cipher
object.
mac_len (integer):
Length of the MAC, in bytes.
It must be at least 4 bytes long.
The default (and recommended) length matches the size of a cipher block.
update_after_digest (boolean):
Optional. By default, a hash object cannot be updated anymore after
the digest is computed. When this flag is ``True``, such check
is no longer enforced.
Returns:
A :class:`CMAC` object
a__doc__
a__file__
origin
has_location
a__cached__
binascii
T aunhexlify
uCrypto.Hash
T aBLAKE2s
uCrypto.Util.strxor
T astrxor
uCrypto.Util.number
T along_to_bytes
bytes_to_long
uCrypto.Util.py3compat
T abord
tobytes
a_copy_bytes
uCrypto.Random
T aget_random_bytes
T l
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
