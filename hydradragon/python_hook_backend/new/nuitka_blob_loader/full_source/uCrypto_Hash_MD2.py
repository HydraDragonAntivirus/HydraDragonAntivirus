# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.MD2

uAn MD2 hash object.
Do not instantiate directly. Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
:ivar block_size: the size in bytes of the internal message block,
input to the compression function
:vartype block_size: integer
:ivar digest_size: the size in bytes of the resulting hash
:vartype digest_size: integer
a__qualname__
l ablock_size
u1.2.840.113549.2.2
oid
T na__init__
uMD2Hash.__init__
uMD2Hash.update
uMD2Hash.digest
hexdigest
uMD2Hash.hexdigest
copy
uMD2Hash.copy
uMD2Hash.new
a__orig_bases__
uCrypto\Hash\MD2.py
u<module Crypto.Hash.MD2>
T a__class__
T aself
data
state
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
T aself
data
result
a__spec__
.Crypto.Hash.MD4
n
O
aVoidPointer
a_raw_md4_lib
md4_init
address_of
uError %d while instantiating MD4
aSmartPointer
get
md4_destroy
a_state
update
md4_update
c_uint8_ptr
c_size_t
uContinue hashing of a message by consuming the next chunk of data.
Repeated calls are equivalent to a single call with the concatenation
of all the arguments. In other words:
>>> m.update(a); m.update(b)
is equivalent to:
>>> m.update(a+b)
:Parameters:
data : byte string/byte array/memoryview
The next chunk of the message being hashed.
create_string_buffer
digest_size
md4_digest
get_raw_buffer
uReturn the **binary** (non-printable) digest of the message that
has been hashed so far.
This method does not change the state of the hash object.
You can continue updating the object after calling this function.
:Return: A byte string of `digest_size` bytes. It may contain non-ASCII
characters, including null bytes.

digest
u%02x
bord
uReturn the **printable** digest of the message that has been
hashed so far.
This method does not change the state of the hash object.
:Return: A string of 2* `digest_size` characters. It contains only
hexadecimal ASCII digits.
aMD4Hash
md4_copy
uError %d while copying MD4
uReturn a copy ("clone") of the hash object.
The copy will have the same internal state as the original hash
object.
This can be used to efficiently compute the digests of strings that
share a common initial substring.
:Return: A hash object of the same type
new
uReturn a fresh instance of the hash object.
:Parameters:
data : byte string/byte array/memoryview
The very first chunk of the message to hash.
It is equivalent to an early call to `MD4Hash.update()`.
Optional.
:Return: A `MD4Hash` object

MD4 is specified in RFC1320_ and produces the 128 bit digest of a message.
>>> from Crypto.Hash import MD4
>>>
>>> h = MD4.new()
>>> h.update(b'Hello')
>>> print h.hexdigest()
MD4 stand for Message Digest version 4, and it was invented by Rivest in 1990.
This algorithm is insecure. Do not use it for new designs.
.. _RFC1320: http://tools.ietf.org/html/rfc1320
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
T uCrypto.Hash._MD4

int md4_init(void **shaState);
int md4_destroy(void *shaState);
int md4_update(void *hs,
const uint8_t *buf,
size_t len);
int md4_digest(const void *shaState,
uint8_t digest[20]);
int md4_copy(const void *src, void *dst);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
