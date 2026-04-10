# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.SHA1

uA SHA-1 hash object.
Do not instantiate directly.
Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
:ivar block_size: the size in bytes of the internal message block,
input to the compression function
:vartype block_size: integer
:ivar digest_size: the size in bytes of the resulting hash
:vartype digest_size: integer
a__qualname__
l l@ablock_size
u1.3.14.3.2.26
oid
T na__init__
uSHA1Hash.__init__
uSHA1Hash.update
uSHA1Hash.digest
hexdigest
uSHA1Hash.hexdigest
copy
uSHA1Hash.copy
uSHA1Hash.new
a__orig_bases__
a_pbkdf2_hmac_assist
uCrypto\Hash\SHA1.py
u<module Crypto.Hash.SHA1>
T a__class__
T aself
data
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
T aself
data
result
a__spec__
.Crypto.Hash.SHA224
V
aVoidPointer
a_raw_sha224_lib
aSHA224_init
address_of
uError %d while instantiating SHA224
aSmartPointer
get
aSHA224_destroy
a_state
update
aSHA224_update
c_uint8_ptr
c_size_t
uError %d while hashing data with SHA224
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
digest_size
aSHA224_digest
uError %d while making SHA224 digest
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
aSHA224Hash
aSHA224_copy
uError %d while copying SHA224
uReturn a copy ("clone") of the hash object.
The copy will have the same internal state as the original hash
object.
This can be used to efficiently compute the digests of strings that
share a common initial substring.
:return: A hash object of the same type
uCreate a fresh SHA-224 hash object.
new
uCreate a new hash object.
:parameter data:
Optional. The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`SHA224Hash.update`.
:type data: byte string/byte array/memoryview
:Return: A :class:`SHA224Hash` hash object
aSHA224_pbkdf2_hmac_assist
uError %d with PBKDF2-HMAC assist for SHA224
uCompute the expensive inner loop in PBKDF-HMAC.
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
T uCrypto.Hash._SHA224

int SHA224_init(void **shaState);
int SHA224_destroy(void *shaState);
int SHA224_update(void *hs,
const uint8_t *buf,
size_t len);
int SHA224_digest(const void *shaState,
uint8_t *digest,
size_t digest_size);
int SHA224_copy(const void *src, void *dst);
int SHA224_pbkdf2_hmac_assist(const void *inner,
const void *outer,
const uint8_t *first_digest,
uint8_t *final_digest,
size_t iterations,
size_t digest_size);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
