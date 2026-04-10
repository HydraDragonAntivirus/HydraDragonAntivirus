# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.Poly1305

uAn Poly1305 MAC object.
Do not instantiate directly. Use the :func:`new` function.
:ivar digest_size: the size in bytes of the resulting MAC tag
:vartype digest_size: integer
a__qualname__
l adigest_size
a__init__
uPoly1305_MAC.__init__
uPoly1305_MAC.update
copy
uPoly1305_MAC.copy
uPoly1305_MAC.digest
hexdigest
uPoly1305_MAC.hexdigest
uPoly1305_MAC.verify
hexverify
uPoly1305_MAC.hexverify
a__orig_bases__
uCrypto\Hash\Poly1305.py
u<module Crypto.Hash.Poly1305>
T a__class__
T aself
wrwsadata
state
result
T aself
T aself
bfr
result
T aself
hex_mac_tag
T akwargs
cipher
cipher_key
nonce
data
wrwsanew_mac
T aself
data
result
T aself
mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Hash.RIPEMD
uDeprecated alias for `Crypto.Hash.RIPEMD160`
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Hash.RIPEMD160
T anew
block_size
digest_size
new
block_size
digest_size
uCrypto\Hash\RIPEMD.py
u<module Crypto.Hash.RIPEMD>

a__spec__
.Crypto.Hash.RIPEMD160
P
aVoidPointer
a_raw_ripemd160_lib
ripemd160_init
address_of
uError %d while instantiating RIPEMD160
aSmartPointer
get
ripemd160_destroy
a_state
update
ripemd160_update
c_uint8_ptr
c_size_t
uError %d while instantiating ripemd160
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
digest_size
ripemd160_digest
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
aRIPEMD160Hash
ripemd160_copy
uError %d while copying ripemd160
uReturn a copy ("clone") of the hash object.
The copy will have the same internal state as the original hash
object.
This can be used to efficiently compute the digests of strings that
share a common initial substring.
:return: A hash object of the same type
uCreate a fresh RIPEMD-160 hash object.
new
uCreate a new hash object.
:parameter data:
Optional. The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`RIPEMD160Hash.update`.
:type data: byte string/byte array/memoryview
:Return: A :class:`RIPEMD160Hash` hash object
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
T uCrypto.Hash._RIPEMD160

int ripemd160_init(void **shaState);
int ripemd160_destroy(void *shaState);
int ripemd160_update(void *hs,
const uint8_t *buf,
size_t len);
int ripemd160_digest(const void *shaState,
uint8_t digest[20]);
int ripemd160_copy(const void *src, void *dst);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
