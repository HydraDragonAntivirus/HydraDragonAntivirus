# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.KangarooTwelve

uA KangarooTwelve hash object.
Do not instantiate directly.
Use the :func:`new` function.
a__qualname__
a__init__
uK12_XOF.__init__
uK12_XOF.update
uK12_XOF.read
T nc
uK12_XOF.new
a__orig_bases__
T nnuCrypto\Hash\KangarooTwelve.py
u<module Crypto.Hash.KangarooTwelve>
T a__class__
T aself
data
custom
T wxwST adata
custom
T aself
length
custom_was_consumed
cv_i
trailer
T
self
data
next_length
data_mem
dtc
divider
index
len_data
new_index
cv_i
a__spec__
.Crypto.Hash.MD2
M
aVoidPointer
a_raw_md2_lib
md2_init
address_of
uError %d while instantiating MD2
aSmartPointer
get
md2_destroy
a_state
update
md2_update
c_uint8_ptr
c_size_t
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
digest_size
md2_digest
get_raw_buffer
uReturn the **binary** (non-printable) digest of the message that has been hashed so far.
:return: The hash digest, computed over the data processed so far.
Binary form.
:rtype: byte string

digest
u%02x
bord
uReturn the **printable** digest of the message that has been hashed so far.
:return: The hash digest, computed over the data processed so far.
Hexadecimal encoded.
:rtype: string
aMD2Hash
md2_copy
uError %d while copying MD2
uReturn a copy ("clone") of the hash object.
The copy will have the same internal state as the original hash
object.
This can be used to efficiently compute the digests of strings that
share a common initial substring.
:return: A hash object of the same type
new
uCreate a new hash object.
:parameter data:
Optional. The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`MD2Hash.update`.
:type data: bytes/bytearray/memoryview
:Return: A :class:`MD2Hash` hash object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T abord
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
create_string_buffer
get_raw_buffer
c_size_t
c_uint8_ptr
load_pycryptodome_raw_lib
T uCrypto.Hash._MD2

int md2_init(void **shaState);
int md2_destroy(void *shaState);
int md2_update(void *hs,
const uint8_t *buf,
size_t len);
int md2_digest(const void *shaState,
uint8_t digest[20]);
int md2_copy(const void *src, void *dst);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
