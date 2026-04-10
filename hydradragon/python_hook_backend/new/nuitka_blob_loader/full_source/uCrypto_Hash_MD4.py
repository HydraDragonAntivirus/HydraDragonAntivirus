# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.MD4

uClass that implements an MD4 hash
a__qualname__
l l@ablock_size
u1.2.840.113549.2.4
oid
T na__init__
uMD4Hash.__init__
uMD4Hash.update
uMD4Hash.digest
hexdigest
uMD4Hash.hexdigest
copy
uMD4Hash.copy
uMD4Hash.new
a__orig_bases__
uCrypto\Hash\MD4.py
u<module Crypto.Hash.MD4>
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
.Crypto.Hash.MD5
J
V
aVoidPointer
a_raw_md5_lib
aMD5_init
address_of
aValueError
uError %d while instantiating MD5
aSmartPointer
get
aMD5_destroy
a_state
update
aMD5_update
c_uint8_ptr
c_size_t
len
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
digest_size
aMD5_digest
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
aMD5Hash
aMD5_copy
uError %d while copying MD5
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
It is equivalent to an early call to :meth:`MD5Hash.update`.
:type data: byte string/byte array/memoryview
:Return: A :class:`MD5Hash` hash object
aMD5_pbkdf2_hmac_assist
uError %d with PBKDF2-HMAC assis for MD5
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
T uCrypto.Hash._MD5

#define MD5_DIGEST_SIZE 16
int MD5_init(void **shaState);
int MD5_destroy(void *shaState);
int MD5_update(void *hs,
const uint8_t *buf,
size_t len);
int MD5_digest(const void *shaState,
uint8_t digest[MD5_DIGEST_SIZE]);
int MD5_copy(const void *src, void *dst);
int MD5_pbkdf2_hmac_assist(const void *inner,
const void *outer,
const uint8_t first_digest[MD5_DIGEST_SIZE],
uint8_t final_digest[MD5_DIGEST_SIZE],
size_t iterations);
object
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
