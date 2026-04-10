# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.SHA256

uA SHA-256 hash object.
Do not instantiate directly. Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
:ivar block_size: the size in bytes of the internal message block,
input to the compression function
:vartype block_size: integer
:ivar digest_size: the size in bytes of the resulting hash
:vartype digest_size: integer
a__qualname__
l l@ablock_size
u2.16.840.1.101.3.4.2.1
oid
T na__init__
uSHA256Hash.__init__
uSHA256Hash.update
uSHA256Hash.digest
hexdigest
uSHA256Hash.hexdigest
copy
uSHA256Hash.copy
uSHA256Hash.new
a__orig_bases__
a_pbkdf2_hmac_assist
uCrypto\Hash\SHA256.py
u<module Crypto.Hash.SHA256>
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
.Crypto.Hash.SHA384
V
aVoidPointer
a_raw_sha384_lib
aSHA384_init
address_of
uError %d while instantiating SHA384
aSmartPointer
get
aSHA384_destroy
a_state
update
aSHA384_update
c_uint8_ptr
c_size_t
uError %d while hashing data with SHA384
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
digest_size
aSHA384_digest
uError %d while making SHA384 digest
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
aSHA384Hash
aSHA384_copy
uError %d while copying SHA384
uReturn a copy ("clone") of the hash object.
The copy will have the same internal state as the original hash
object.
This can be used to efficiently compute the digests of strings that
share a common initial substring.
:return: A hash object of the same type
uCreate a fresh SHA-384 hash object.
new
uCreate a new hash object.
:parameter data:
Optional. The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`SHA384Hash.update`.
:type data: byte string/byte array/memoryview
:Return: A :class:`SHA384Hash` hash object
aSHA384_pbkdf2_hmac_assist
uError %d with PBKDF2-HMAC assist for SHA384
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
T uCrypto.Hash._SHA384

int SHA384_init(void **shaState);
int SHA384_destroy(void *shaState);
int SHA384_update(void *hs,
const uint8_t *buf,
size_t len);
int SHA384_digest(const void *shaState,
uint8_t *digest,
size_t digest_size);
int SHA384_copy(const void *src, void *dst);
int SHA384_pbkdf2_hmac_assist(const void *inner,
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
