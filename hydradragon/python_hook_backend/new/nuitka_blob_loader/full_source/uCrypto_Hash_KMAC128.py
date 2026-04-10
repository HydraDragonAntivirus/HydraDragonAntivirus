# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.KMAC128

uA KMAC hash object.
Do not instantiate directly.
Use the :func:`new` function.
a__qualname__
a__init__
uKMAC_Hash.__init__
uKMAC_Hash.update
uKMAC_Hash.digest
hexdigest
uKMAC_Hash.hexdigest
uKMAC_Hash.verify
hexverify
uKMAC_Hash.hexverify
uKMAC_Hash.new
a__orig_bases__
uCrypto\Hash\KMAC128.py
u<module Crypto.Hash.KMAC128>
T a__class__
T	aself
data
key
mac_len
custom
oid_variant
cshake
rate
partial_newX
T aself
T aself
hex_mac_tag
T aself
kwargs
T akwargs
key
data
mac_len
custom
T aself
data
T aself
mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Hash.KMAC256
key
is_bytes
uYou must pass a key to KMAC256
uThe key must be at least 256 bits long (32 bytes)
pop
T adata
nT amac_len
l@l u'mac_len' must be 8 bytes or more
T acustom
c
uUnknown parameters:
aKMAC_Hash
u20
cSHAKE256
l  uCreate a new KMAC256 object.
Args:
key (bytes/bytearray/memoryview):
The key to use to compute the MAC.
It must be at least 256 bits long (32 bytes).
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
uCrypto.Util.py3compat
T ais_bytes
aKMAC128
T aKMAC_Hash

T acSHAKE256
new
uCrypto\Hash\KMAC256.py
u<module Crypto.Hash.KMAC256>
T akwargs
key
data
mac_len
custom
a__spec__
.Crypto.Hash.KangarooTwelve
6
S
d
long_to_bytes
bchr
c
a_length_encode
a_custom
aSHORT_MSG
a_state
a_padding
aTurboSHAKE128
new
T l T adomain
a_hash1
a_length1
a_hash2
a_length2
a_ctr
update
aSQUEEZING
uYou cannot call 'update' after the first 'read'
l @aLONG_MSG_S0
min
T b
l T l aLONG_MSG_SX
index
self
read
T l l a_reset
uHash the next piece of data.
.. note::
For better performance, submit chunks with a length multiple of 8192 bytes.
Args:
data (byte string/byte array/memoryview): The next chunk of the
message to hash.
l c
l a_domain

Produce more bytes of the digest.
.. note::
You cannot use :meth:`update` anymore after the first call to
:meth:`read`.
Args:
length (integer): the amount of bytes this method must return
:return: the next piece of XOF output (of the given length)
:rtype: byte string
aK12_XOF
uReturn a fresh instance of a KangarooTwelve object.
Args:
data (bytes/bytearray/memoryview):
Optional.
The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`update`.
custom (bytes):
Optional.
A customization byte string.
:Return: A :class:`K12_XOF` object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.number
T along_to_bytes
uCrypto.Util.py3compat
T abchr

T aTurboSHAKE128
l l l T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
