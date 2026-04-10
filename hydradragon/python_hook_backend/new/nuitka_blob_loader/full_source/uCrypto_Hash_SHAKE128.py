# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.SHAKE128

uA SHAKE128 hash object.
Do not instantiate directly.
Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
a__qualname__
u2.16.840.1.101.3.4.2.11
oid
T na__init__
uSHAKE128_XOF.__init__
uSHAKE128_XOF.update
read
uSHAKE128_XOF.read
new
uSHAKE128_XOF.new
a__orig_bases__
uCrypto\Hash\SHAKE128.py
u<module Crypto.Hash.SHAKE128>
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
.Crypto.Hash.SHAKE256
I
aVoidPointer
a_raw_keccak_lib
keccak_init
address_of
c_size_t
T l@ac_ubyte
T l uError %d while instantiating SHAKE256
aSmartPointer
get
keccak_destroy
a_state
a_is_squeezing
l a_padding
update
uYou cannot call 'update' after the first 'read'
keccak_absorb
c_uint8_ptr
uError %d while updating SHAKE256 state
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
keccak_squeeze
uError %d while extracting from SHAKE256
get_raw_buffer

Compute the next piece of XOF output.
.. note::
You cannot use :meth:`update` anymore after the first call to
:meth:`read`.
Args:
length (integer): the amount of bytes this method must return
:return: the next piece of XOF output (of the given length)
:rtype: byte string
T adata
aSHAKE256_XOF
uReturn a fresh instance of a SHAKE256 object.
Args:
data (bytes/bytearray/memoryview):
The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`update`.
Optional.
:Return: A :class:`SHAKE256_XOF` object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T abord
bord
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
create_string_buffer
get_raw_buffer
c_size_t
c_uint8_ptr
c_ubyte
load_pycryptodome_raw_lib
uCrypto.Hash.keccak
T a_raw_keccak_lib
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
