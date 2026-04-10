# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.cSHAKE128

uA cSHAKE hash object.
Do not instantiate directly.
Use the :func:`new` function.
a__qualname__
a__init__
ucSHAKE_XOF.__init__
ucSHAKE_XOF.update
read
ucSHAKE_XOF.read
a__orig_bases__
a_new
T nnanew
uCrypto\Hash\cSHAKE128.py
u<module Crypto.Hash.cSHAKE128>
T	aself
data
custom
capacity
function
state
prefix_unpad
prefix
result
T wxalength
to_pad
npad
T wxabitlen
T wxanum
T adata
custom
function
T a__class__
T adata
custom
T aself
length
bfr
result
T aself
data
result

a__spec__
.Crypto.Hash.cSHAKE256
cSHAKE_XOF
l  c
uReturn a fresh instance of a cSHAKE256 object.
Args:
data (bytes/bytearray/memoryview):
The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`update`.
Optional.
custom (bytes):
Optional.
A customization bytestring (``S`` in SP 800-185).
:Return: A :class:`cSHAKE_XOF` object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util._raw_api
T ac_size_t
c_size_t
uCrypto.Hash.cSHAKE128
T acSHAKE_XOF
a_new
T nnanew
uCrypto\Hash\cSHAKE256.py
u<module Crypto.Hash.cSHAKE256>
T adata
custom
function
T adata
custom

a__spec__
.Crypto.Hash
:
upper
T u1.3.14.3.2.26
aSHA1
uSHA-1

T aSHA1
aSHA1
new
T u2.16.840.1.101.3.4.2.4
aSHA224
uSHA-224
T aSHA224
aSHA224
T u2.16.840.1.101.3.4.2.1
aSHA256
uSHA-256
T aSHA256
aSHA256
T u2.16.840.1.101.3.4.2.2
aSHA384
uSHA-384
T aSHA384
aSHA384
T u2.16.840.1.101.3.4.2.3
aSHA512
uSHA-512
T aSHA512
aSHA512
T u2.16.840.1.101.3.4.2.5
uSHA512-224
uSHA-512-224
T u224
T atruncate
T u2.16.840.1.101.3.4.2.6
uSHA512-256
uSHA-512-256
T u256
T u2.16.840.1.101.3.4.2.7
uSHA3-224
uSHA-3-224
T aSHA3_224
aSHA3_224
T u2.16.840.1.101.3.4.2.8
uSHA3-256
uSHA-3-256
T aSHA3_256
aSHA3_256
T u2.16.840.1.101.3.4.2.9
uSHA3-384
uSHA-3-384
T aSHA3_384
aSHA3_384
T u2.16.840.1.101.3.4.2.10
uSHA3-512
uSHA-3-512
T aSHA3_512
aSHA3_512
uUnknown hash %s
uReturn a new hash instance, based on its name or
on its ASN.1 Object ID
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
aHash
T aNUITKA_PACKAGE_Crypto_Hash
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
L aHMAC
aMD2
aMD4
aMD5
aRIPEMD160
aSHA1
aSHA224
aSHA256
aSHA384
aSHA512
aSHA3_224
aSHA3_256
aSHA3_384
aSHA3_512
aCMAC
aPoly1305
cSHAKE128
cSHAKE256
aKMAC128
aKMAC256
aTupleHash128
aTupleHash256
aKangarooTwelve
aTurboSHAKE128
aTurboSHAKE256
a__all__
uCrypto\Hash\__init__.py
u<module Crypto.Hash>
T
name
aSHA1
aSHA224
aSHA256
aSHA384
aSHA512
aSHA3_224
aSHA3_256
aSHA3_384
aSHA3_512
a__spec__
.Crypto.Hash.keccak
9
\
digest_size
a_update_after_digest
a_digest_done
a_padding
aVoidPointer
a_raw_keccak_lib
keccak_init
address_of
c_size_t
l ac_ubyte
T l uError %d while instantiating keccak
aSmartPointer
get
keccak_destroy
a_state
update
uYou can only call 'digest' or 'hexdigest' on this object
keccak_absorb
c_uint8_ptr
uError %d while updating keccak
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
keccak_digest
uError %d while squeezing keccak
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
digest_bytes
digest_bits
new
uCreate a fresh Keccak hash object.
data
pop
T aupdate_after_digest
FT adigest_bytes
nT adigest_bits
nuOnly one digest parameter must be provided
T nnuDigest size (bits, bytes) not provided
T l l l0l@u'digest_bytes' must be: 28, 32, 48 or 64
T l  l  l  l  u'digest_bytes' must be: 224, 256, 384 or 512
l uUnknown parameters:
aKeccak_Hash
uCreate a new hash object.
Args:
data (bytes/bytearray/memoryview):
The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`Keccak_Hash.update`.
digest_bytes (integer):
The size of the digest, in bytes (28, 32, 48, 64).
digest_bits (integer):
The size of the digest, in bits (224, 256, 384, 512).
update_after_digest (boolean):
Whether :meth:`Keccak.digest` can be followed by another
:meth:`Keccak.update` (default: ``False``).
:Return: A :class:`Keccak_Hash` hash object
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
c_ubyte
load_pycryptodome_raw_lib
T uCrypto.Hash._keccak

int keccak_init(void **state,
size_t capacity_bytes,
uint8_t rounds);
int keccak_destroy(void *state);
int keccak_absorb(void *state,
const uint8_t *in,
size_t len);
int keccak_squeeze(const void *state,
uint8_t *out,
size_t len,
uint8_t padding);
int keccak_digest(void *state,
uint8_t *digest,
size_t len,
uint8_t padding);
int keccak_copy(const void *src, void *dst);
int keccak_reset(void *state);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
