# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.RIPEMD160

uA RIPEMD-160 hash object.
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
u1.3.36.3.2.1
oid
T na__init__
uRIPEMD160Hash.__init__
uRIPEMD160Hash.update
uRIPEMD160Hash.digest
hexdigest
uRIPEMD160Hash.hexdigest
copy
uRIPEMD160Hash.copy
uRIPEMD160Hash.new
a__orig_bases__
uCrypto\Hash\RIPEMD160.py
u<module Crypto.Hash.RIPEMD160>
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
.Crypto.Hash.SHA
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Hash.SHA1
T a__doc__
new
block_size
digest_size
new
block_size
digest_size
uCrypto\Hash\SHA.py
u<module Crypto.Hash.SHA>

a__spec__
.Crypto.Hash.SHA1
h
V
aVoidPointer
a_raw_sha1_lib
aSHA1_init
address_of
aValueError
uError %d while instantiating SHA1
aSmartPointer
get
aSHA1_destroy
a_state
update
aSHA1_update
c_uint8_ptr
c_size_t
len
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
digest_size
aSHA1_digest
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
aSHA1Hash
aSHA1_copy
uError %d while copying SHA1
uReturn a copy ("clone") of the hash object.
The copy will have the same internal state as the original hash
object.
This can be used to efficiently compute the digests of strings that
share a common initial substring.
:return: A hash object of the same type
uCreate a fresh SHA-1 hash object.
new
uCreate a new hash object.
:parameter data:
Optional. The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`SHA1Hash.update`.
:type data: byte string/byte array/memoryview
:Return: A :class:`SHA1Hash` hash object
aSHA1_pbkdf2_hmac_assist
uError %d with PBKDF2-HMAC assis for SHA1
uCompute the expensive inner loop in PBKDF-HMAC.
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T w*uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
create_string_buffer
get_raw_buffer
c_size_t
c_uint8_ptr
load_pycryptodome_raw_lib
T uCrypto.Hash._SHA1

#define SHA1_DIGEST_SIZE 20
int SHA1_init(void **shaState);
int SHA1_destroy(void *shaState);
int SHA1_update(void *hs,
const uint8_t *buf,
size_t len);
int SHA1_digest(const void *shaState,
uint8_t digest[SHA1_DIGEST_SIZE]);
int SHA1_copy(const void *src, void *dst);
int SHA1_pbkdf2_hmac_assist(const void *inner,
const void *outer,
const uint8_t first_digest[SHA1_DIGEST_SIZE],
uint8_t final_digest[SHA1_DIGEST_SIZE],
size_t iterations);
object
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
