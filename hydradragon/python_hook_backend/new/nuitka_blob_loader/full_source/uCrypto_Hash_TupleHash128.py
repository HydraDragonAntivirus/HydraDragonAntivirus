# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.TupleHash128

uA Tuple hash object.
Do not instantiate directly.
Use the :func:`new` function.
a__qualname__
a__init__
uTupleHash.__init__
uTupleHash.update
uTupleHash.digest
hexdigest
uTupleHash.hexdigest
uTupleHash.new
a__orig_bases__
uCrypto\Hash\TupleHash128.py
u<module Crypto.Hash.TupleHash128>
T a__class__
T aself
custom
cshake
digest_size
T aself
T aself
kwargs
T akwargs
digest_bytes
digest_bits
custom
T aself
data
item
a__spec__
.Crypto.Hash.TupleHash256
digest_bytes
pop
T adigest_bits
nuOnly one digest parameter must be provided
T nnl@l u'digest_bytes' must be at least 8
u'digest_bytes' must be at least 64 in steps of 8
T acustom
c
aTupleHash
cSHAKE256
uCreate a new TupleHash256 object.
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

T acSHAKE256
aTupleHash128
T aTupleHash
new
uCrypto\Hash\TupleHash256.py
u<module Crypto.Hash.TupleHash256>
T akwargs
digest_bytes
digest_bits
custom
a__spec__
.Crypto.Hash.TurboSHAKE128
T
aVoidPointer
a_raw_keccak_lib
keccak_init
address_of
c_size_t
c_ubyte
T l uError %d while instantiating TurboSHAKE
aSmartPointer
get
keccak_destroy
a_state
a_is_squeezing
a_capacity
a_domain
update
uYou cannot call 'update' after the first 'read'
keccak_absorb
c_uint8_ptr
uError %d while updating TurboSHAKE state
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
keccak_squeeze
uError %d while extracting from TurboSHAKE
get_raw_buffer

Compute the next piece of XOF output.
.. note::
You cannot use :meth:`update` anymore after the first call to
:meth:`read`.
Args:
length (integer): the amount of bytes this method must return
:return: the next piece of XOF output (of the given length)
:rtype: byte string
keccak_reset
uError %d while resetting TurboSHAKE state
domain
l l uIncorrect domain separation value (%d)
data
aTurboSHAKE
l T adata
uCreate a new TurboSHAKE128 object.
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
long_to_bytes
uCrypto.Util.py3compat
T abchr
bchr
keccak
T a_raw_keccak_lib
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
