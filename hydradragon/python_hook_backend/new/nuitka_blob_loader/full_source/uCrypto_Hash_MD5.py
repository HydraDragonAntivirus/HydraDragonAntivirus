# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.MD5

uA MD5 hash object.
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
u1.2.840.113549.2.5
oid
T na__init__
uMD5Hash.__init__
uMD5Hash.update
uMD5Hash.digest
hexdigest
uMD5Hash.hexdigest
copy
uMD5Hash.copy
uMD5Hash.new
a__orig_bases__
a_pbkdf2_hmac_assist
uCrypto\Hash\MD5.py
u<module Crypto.Hash.MD5>
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
.Crypto.Hash.Poly1305
j
uParameter r is not 16 bytes long
uParameter s is not 16 bytes long
a_mac_tag
aVoidPointer
a_raw_poly1305
poly1305_init
address_of
c_uint8_ptr
c_size_t
uError %d while instantiating Poly1305
aSmartPointer
get
poly1305_destroy
a_state
update
uYou can only call 'digest' or 'hexdigest' on this object
poly1305_update
uError %d while hashing Poly1305 data
uAuthenticate the next chunk of message.
Args:
data (byte string/byte array/memoryview): The next chunk of data
create_string_buffer
T l apoly1305_digest
uError %d while creating Poly1305 digest
get_raw_buffer
uReturn the **binary** (non-printable) MAC tag of the message
uthenticated so far.
:return: The MAC tag digest, computed over the data processed so far.
Binary form.
:rtype: byte string

digest
u%02x
bord
uReturn the **printable** MAC tag of the message authenticated so far.
:return: The MAC tag, computed over the data processed so far.
Hexadecimal encoded.
:rtype: string
get_random_bytes
aBLAKE2s
new
l  T adigest_bits
key
data
uMAC check failed
uVerify that a given **binary** MAC (computed by another party)
is valid.
Args:
mac_tag (byte string/byte string/memoryview): the expected MAC of the message.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.
verify
unhexlify
tobytes
uVerify that a given **printable** MAC (computed by another party)
is valid.
Args:
hex_mac_tag (string): the expected MAC of the message,
s a hexadecimal string.
Raises:
ValueError: if the MAC does not match. It means that the message
has been tampered with or that the MAC key is incorrect.
cipher
a_derive_Poly1305_key_pair
uParameter 'cipher' must be AES or ChaCha20
pop
T akey
nuYou must pass a parameter 'key'
T anonce
nT adata
nuUnknown parameters:
aPoly1305_MAC
a_copy_bytes
nonce
uCreate a new Poly1305 MAC object.
Args:
key (bytes/bytearray/memoryview):
The 32-byte key for the Poly1305 object.
cipher (module from ``Crypto.Cipher``):
The cipher algorithm to use for deriving the Poly1305
key pair *(r, s)*.
It can only be ``Crypto.Cipher.AES`` or ``Crypto.Cipher.ChaCha20``.
nonce (bytes/bytearray/memoryview):
Optional. The non-repeatable value to use for the MAC of this message.
It must be 16 bytes long for ``AES`` and 8 or 12 bytes for ``ChaCha20``.
If not passed, a random nonce is created; you will find it in the
``nonce`` attribute of the new object.
data (bytes/bytearray/memoryview):
Optional. The very first chunk of the message to authenticate.
It is equivalent to an early call to ``update()``.
Returns:
A :class:`Poly1305_MAC` object
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
a_copy_bytes
uCrypto.Hash
T aBLAKE2s
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
T uCrypto.Hash._poly1305

int poly1305_init(void **state,
const uint8_t *r,
size_t r_len,
const uint8_t *s,
size_t s_len);
int poly1305_destroy(void *state);
int poly1305_update(void *state,
const uint8_t *in,
size_t len);
int poly1305_digest(const void *state,
uint8_t *digest,
size_t len);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
