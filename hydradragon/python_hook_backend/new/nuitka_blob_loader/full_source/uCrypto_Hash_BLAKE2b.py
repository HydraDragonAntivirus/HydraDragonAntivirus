# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.BLAKE2b

uA BLAKE2b hash object.
Do not instantiate directly. Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
:ivar block_size: the size in bytes of the internal message block,
input to the compression function
:vartype block_size: integer
:ivar digest_size: the size in bytes of the resulting hash
:vartype digest_size: integer
a__qualname__
block_size
a__init__
uBLAKE2b_Hash.__init__
uBLAKE2b_Hash.update
uBLAKE2b_Hash.digest
hexdigest
uBLAKE2b_Hash.hexdigest
uBLAKE2b_Hash.verify
hexverify
uBLAKE2b_Hash.hexverify
uBLAKE2b_Hash.new
a__orig_bases__
uCrypto\Hash\BLAKE2b.py
u<module Crypto.Hash.BLAKE2b>
T a__class__
T aself
data
key
digest_bytes
update_after_digest
state
result
T aself
bfr
result
T aself
T aself
hex_mac_tag
T aself
kwargs
T akwargs
data
update_after_digest
digest_bytes
digest_bits
key
T aself
data
result
T aself
mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Hash.BLAKE2s
x
q
digest_size
a_update_after_digest
a_digest_done
T l l l l u1.3.6.1.4.1.1722.12.2.2.
oid
aVoidPointer
a_raw_blake2s_lib
blake2s_init
address_of
c_uint8_ptr
c_size_t
uError %d while instantiating BLAKE2s
aSmartPointer
get
blake2s_destroy
a_state
update
uYou can only call 'digest' or 'hexdigest' on this object
blake2s_update
uError %d while hashing BLAKE2s data
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
T l ablake2s_digest
uError %d while creating BLAKE2s digest
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
get_random_bytes
T l anew
l  T adigest_bits
key
data
uMAC check failed
uVerify that a given **binary** MAC (computed by another party)
is valid.
Args:
mac_tag (byte string/byte array/memoryview): the expected MAC of the message.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.
verify
unhexlify
tobytes
uVerify that a given **printable** MAC (computed by another party)
is valid.
Args:
hex_mac_tag (string): the expected MAC of the message, as a hexadecimal string.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.
digest_bytes
digest_bits
uReturn a new instance of a BLAKE2s hash object.
See :func:`new`.
data
pop
T aupdate_after_digest
FT adigest_bytes
nT adigest_bits
nuOnly one digest parameter must be provided
T nnl u'digest_bytes' not in range 1..32
l l  u'digest_bits' not in range 8..256, with steps of 8
T akey
c
uBLAKE2s key cannot exceed 32 bytes
uUnknown parameters:
aBLAKE2s_Hash
uCreate a new hash object.
Args:
data (byte string/byte array/memoryview):
Optional. The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`BLAKE2s_Hash.update`.
digest_bytes (integer):
Optional. The size of the digest, in bytes (1 to 32). Default is 32.
digest_bits (integer):
Optional and alternative to ``digest_bytes``.
The size of the digest, in bits (8 to 256, in steps of 8).
Default is 256.
key (byte string):
Optional. The key to use to compute the MAC (1 to 64 bytes).
If not specified, no key will be used.
update_after_digest (boolean):
Optional. By default, a hash object cannot be updated anymore after
the digest is computed. When this flag is ``True``, such check
is no longer enforced.
Returns:
A :class:`BLAKE2s_Hash` hash object
a__doc__
a__file__
origin
has_location
a__cached__
binascii
T aunhexlify
uCrypto.Util.py3compat
T abord
tobytes
uCrypto.Random
T aget_random_bytes
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
create_string_buffer
get_raw_buffer
c_size_t
c_uint8_ptr
load_pycryptodome_raw_lib
T uCrypto.Hash._BLAKE2s

int blake2s_init(void **state,
const uint8_t *key,
size_t key_size,
size_t digest_size);
int blake2s_destroy(void *state);
int blake2s_update(void *state,
const uint8_t *buf,
size_t len);
int blake2s_digest(const void *state,
uint8_t digest[32]);
int blake2s_copy(const void *src, void *dst);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
