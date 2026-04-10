# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.TurboSHAKE128

uA TurboSHAKE hash object.
Do not instantiate directly.
Use the :func:`new` function.
a__qualname__
a__init__
uTurboSHAKE.__init__
uTurboSHAKE.update
read
uTurboSHAKE.read
T nanew
uTurboSHAKE.new
a_reset
uTurboSHAKE._reset
a__orig_bases__
uCrypto\Hash\TurboSHAKE128.py
u<module Crypto.Hash.TurboSHAKE128>
T a__class__
T aself
capacity
domain_separation
data
state
result
T aself
result
T aself
data
T akwargs
domain_separation
data
T aself
length
bfr
result
T aself
data
result

a__spec__
.Crypto.Hash.TurboSHAKE256
domain
l l uIncorrect domain separation value (%d)
data
aTurboSHAKE
l@T adata
uCreate a new TurboSHAKE256 object.
Args:
domain (integer):
Optional - A domain separation byte, between 0x01 and 0x7F.
The default value is 0x1F.
data (bytes/bytearray/memoryview):
Optional - The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`update`.
:Return: A :class:`TurboSHAKE` object
a__doc__
a__file__
origin
has_location
a__cached__
aTurboSHAKE128
T aTurboSHAKE
new
uCrypto\Hash\TurboSHAKE256.py
u<module Crypto.Hash.TurboSHAKE256>
T akwargs
domain_separation
data

a__spec__
.Crypto.Hash.cSHAKE128
s
`
l  abit_length
l l abchr
long_to_bytes
uLeft encode function as defined in NIST SP 800-185
uRight encode function as defined in NIST SP 800-185
uString too large to encode in cSHAKE
concat_buffers
a_left_encode
uEncode string function as defined in NIST SP 800-185
d
uZero pad byte string as defined in NIST SP 800-185
aVoidPointer
a_encode_str
a_bytepad
l  l a_padding
l a_raw_keccak_lib
keccak_init
address_of
c_size_t
c_ubyte
T l uError %d while instantiating cSHAKE
aSmartPointer
get
keccak_destroy
self
a_state
a_is_squeezing
update
uYou cannot call 'update' after the first 'read'
keccak_absorb
c_uint8_ptr
uError %d while updating %s state
name
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
keccak_squeeze
uError %d while extracting from %s
get_raw_buffer

Compute the next piece of XOF output.
.. note::
You cannot use :meth:`update` anymore after the first call to
:meth:`read`.
Args:
length (integer): the amount of bytes this method must return
:return: the next piece of XOF output (of the given length)
:rtype: byte string
cSHAKE_XOF
l  c
uReturn a fresh instance of a cSHAKE128 object.
Args:
data (bytes/bytearray/memoryview):
Optional.
The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`update`.
custom (bytes):
Optional.
A customization bytestring (``S`` in SP 800-185).
:Return: A :class:`cSHAKE_XOF` object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T abchr
concat_buffers
uCrypto.Util._raw_api
T aVoidPointer
aSmartPointer
create_string_buffer
get_raw_buffer
c_size_t
c_uint8_ptr
c_ubyte
uCrypto.Util.number
T along_to_bytes
uCrypto.Hash.keccak
T a_raw_keccak_lib
a_right_encode
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
