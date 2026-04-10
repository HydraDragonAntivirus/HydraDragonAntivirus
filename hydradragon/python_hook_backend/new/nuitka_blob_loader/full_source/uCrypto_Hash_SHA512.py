# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.SHA512

uA SHA-512 hash object (possibly in its truncated version SHA-512/224 or
SHA-512/256.
Do not instantiate directly. Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
:ivar block_size: the size in bytes of the internal message block,
input to the compression function
:vartype block_size: integer
:ivar digest_size: the size in bytes of the resulting hash
:vartype digest_size: integer
a__qualname__
l  ablock_size
a__init__
uSHA512Hash.__init__
uSHA512Hash.update
uSHA512Hash.digest
hexdigest
uSHA512Hash.hexdigest
copy
uSHA512Hash.copy
T nanew
uSHA512Hash.new
a__orig_bases__
T nna_pbkdf2_hmac_assist
uCrypto\Hash\SHA512.py
u<module Crypto.Hash.SHA512>
T a__class__
T aself
data
truncate
state
result
T ainner
outer
first_digest
iterations
bfr
result
T aself
clone
result
T aself
bfr
result
T aself
T aself
data
T adata
truncate
T aself
data
result
a__spec__
.Crypto.Hash.SHAKE128
I
aVoidPointer
a_raw_keccak_lib
keccak_init
address_of
c_size_t
T l ac_ubyte
T l uError %d while instantiating SHAKE128
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
uError %d while updating SHAKE128 state
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
keccak_squeeze
uError %d while extracting from SHAKE128
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
aSHAKE128_XOF
uReturn a fresh instance of a SHAKE128 object.
Args:
data (bytes/bytearray/memoryview):
The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`update`.
Optional.
:Return: A :class:`SHAKE128_XOF` object
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
