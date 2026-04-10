# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.SHA3_512

uA SHA3-512 hash object.
Do not instantiate directly.
Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
:ivar digest_size: the size in bytes of the resulting hash
:vartype digest_size: integer
a__qualname__
l@u2.16.840.1.101.3.4.2.10
oid
lHablock_size
a__init__
uSHA3_512_Hash.__init__
uSHA3_512_Hash.update
uSHA3_512_Hash.digest
hexdigest
uSHA3_512_Hash.hexdigest
copy
uSHA3_512_Hash.copy
T nuSHA3_512_Hash.new
a__orig_bases__
uCrypto\Hash\SHA3_512.py
u<module Crypto.Hash.SHA3_512>
T a__class__
T aself
data
update_after_digest
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
T aargs
kwargs
data
update_after_digest
T aself
data
result
a__spec__
.Crypto.Hash.SHA512
_
a_truncate
u2.16.840.1.101.3.4.2.3
oid
l@adigest_size
u224
u2.16.840.1.101.3.4.2.5
l u256
u2.16.840.1.101.3.4.2.6
l uIncorrect truncation length. It must be '224' or '256'.
aVoidPointer
a_raw_sha512_lib
aSHA512_init
address_of
c_size_t
uError %d while instantiating SHA-512
aSmartPointer
get
aSHA512_destroy
a_state
update
aSHA512_update
c_uint8_ptr
uError %d while hashing data with SHA512
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
aSHA512_digest
uError %d while making SHA512 digest
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
aSHA512Hash
aSHA512_copy
uError %d while copying SHA512
uReturn a copy ("clone") of the hash object.
The copy will have the same internal state as the original hash
object.
This can be used to efficiently compute the digests of strings that
share a common initial substring.
:return: A hash object of the same type
uCreate a fresh SHA-512 hash object.
uCreate a new hash object.
Args:
data (bytes/bytearray/memoryview):
Optional. The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`SHA512Hash.update`.
truncate (string):
Optional. The desired length of the digest. It can be either "224" or
"256". If not present, the digest is 512 bits long.
Passing this parameter is **not** equivalent to simply truncating
the output digest.
:Return: A :class:`SHA512Hash` hash object
aSHA512_pbkdf2_hmac_assist
uError %d with PBKDF2-HMAC assist for SHA512
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
T uCrypto.Hash._SHA512

int SHA512_init(void **shaState,
size_t digest_size);
int SHA512_destroy(void *shaState);
int SHA512_update(void *hs,
const uint8_t *buf,
size_t len);
int SHA512_digest(const void *shaState,
uint8_t *digest,
size_t digest_size);
int SHA512_copy(const void *src, void *dst);
int SHA512_pbkdf2_hmac_assist(const void *inner,
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
