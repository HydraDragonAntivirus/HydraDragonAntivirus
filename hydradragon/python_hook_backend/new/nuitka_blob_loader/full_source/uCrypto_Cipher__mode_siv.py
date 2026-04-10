# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher._mode_siv

uSynthetic Initialization Vector (SIV).
This is an Authenticated Encryption with Associated Data (`AEAD`_) mode.
It provides both confidentiality and authenticity.
The header of the message may be left in the clear, if needed, and it will
still be subject to authentication. The decryption step tells the receiver
if the message comes from a source that really knowns the secret key.
Additionally, decryption detects if any part of the message - including the
header - has been modified or corrupted.
Unlike other AEAD modes such as CCM, EAX or GCM, accidental reuse of a
nonce is not catastrophic for the confidentiality of the message. The only
effect is that an attacker can tell when the same plaintext (and same
ssociated data) is protected with the same key.
The length of the MAC is fixed to the block size of the underlying cipher.
The key size is twice the length of the key of the underlying cipher.
This mode is only available for AES ciphers.
+--------------------+---------------+-------------------+
|      Cipher        | SIV MAC size  |   SIV key length  |
|                    |    (bytes)    |     (bytes)       |
+====================+===============+===================+
|    AES-128         |      16       |        32         |
+--------------------+---------------+-------------------+
|    AES-192         |      16       |        48         |
+--------------------+---------------+-------------------+
|    AES-256         |      16       |        64         |
+--------------------+---------------+-------------------+
See `RFC5297`_ and the `original paper`__.
.. _RFC5297: https://tools.ietf.org/html/rfc5297
.. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
.. __: http://www.cs.ucdavis.edu/~rogaway/papers/keywrap.pdf
:undocumented: __init__
a__qualname__
a__init__
uSivMode.__init__
uSivMode._create_ctr_cipher
uSivMode.update
uSivMode.encrypt
uSivMode.decrypt
uSivMode.digest
hexdigest
uSivMode.hexdigest
uSivMode.verify
hexverify
uSivMode.hexverify
T naencrypt_and_digest
uSivMode.encrypt_and_digest
decrypt_and_verify
uSivMode.decrypt_and_verify
a__orig_bases__
a_create_siv_cipher
uCrypto\Cipher\_mode_siv.py
u<module Crypto.Cipher._mode_siv>
T a__class__
T aself
factory
key
nonce
kwargs
subkey_size
T aself
wvav_int
wqT afactory
kwargs
key
weanonce
T aself
ciphertext
T aself
ciphertext
mac_tag
output
plaintext
T aself
T aself
plaintext
T aself
plaintext
output
cipher
T aself
hex_mac_tag
T aself
component
T aself
received_mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Cipher._pkcs1_oaep_decode
L
uIncorrect output length
a_raw_pkcs1_decode
pkcs1_decode
c_uint8_ptr
c_size_t
oaep_decode
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
c_size_t
c_uint8_ptr
load_pycryptodome_raw_lib
T uCrypto.Cipher._pkcs1_decode

int pkcs1_decode(const uint8_t *em, size_t len_em,
const uint8_t *sentinel, size_t len_sentinel,
size_t expected_pt_len,
uint8_t *output);
int oaep_decode(const uint8_t *em,
size_t em_len,
const uint8_t *lHash,
size_t hLen,
const uint8_t *db,
size_t db_len);
uCrypto\Cipher\_pkcs1_oaep_decode.py
u<module Crypto.Cipher._pkcs1_oaep_decode>
T aem
lHash
db
ret
T aem
sentinel
expected_pt_len
output
ret

a__spec__
.Crypto.Cipher
M
key
a_modes
pop
T aadd_aes_modes
Fa_extra_modes
uMode not supported
T l l	l
l l uToo many arguments for this mode
nonce
T l l l l aIV
l uIV is not meaningful for the ECB mode
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
aCipher
T aNUITKA_PACKAGE_Crypto_Cipher
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
os
uCrypto.Cipher._mode_ecb
T a_create_ecb_cipher
a_create_ecb_cipher
uCrypto.Cipher._mode_cbc
T a_create_cbc_cipher
a_create_cbc_cipher
uCrypto.Cipher._mode_cfb
T a_create_cfb_cipher
a_create_cfb_cipher
uCrypto.Cipher._mode_ofb
T a_create_ofb_cipher
a_create_ofb_cipher
uCrypto.Cipher._mode_ctr
T a_create_ctr_cipher
a_create_ctr_cipher
uCrypto.Cipher._mode_openpgp
T a_create_openpgp_cipher
a_create_openpgp_cipher
uCrypto.Cipher._mode_ccm
T a_create_ccm_cipher
a_create_ccm_cipher
uCrypto.Cipher._mode_eax
T a_create_eax_cipher
a_create_eax_cipher
uCrypto.Cipher._mode_siv
T a_create_siv_cipher
a_create_siv_cipher
uCrypto.Cipher._mode_gcm
T a_create_gcm_cipher
a_create_gcm_cipher
uCrypto.Cipher._mode_ocb
T a_create_ocb_cipher
a_create_ocb_cipher
l l l l l	l l
l l a_create_cipher
uCrypto\Cipher\__init__.py
u<module Crypto.Cipher>
T afactory
key
mode
args
kwargs
modes

a__spec__
.Crypto.Hash.BLAKE2b
r
q
digest_size
a_update_after_digest
a_digest_done
T l l l0l@u1.3.6.1.4.1.1722.12.2.1.
oid
aVoidPointer
a_raw_blake2b_lib
blake2b_init
address_of
c_uint8_ptr
c_size_t
uError %d while instantiating BLAKE2b
aSmartPointer
get
blake2b_destroy
a_state
update
uYou can only call 'digest' or 'hexdigest' on this object
blake2b_update
uError %d while hashing BLAKE2b data
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (bytes/bytearray/memoryview): The next chunk of the message being hashed.
create_string_buffer
T l@ablake2b_digest
uError %d while creating BLAKE2b digest
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
mac_tag (bytes/bytearray/memoryview): the expected MAC of the message.
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
uReturn a new instance of a BLAKE2b hash object.
See :func:`new`.
data
pop
T aupdate_after_digest
FT adigest_bytes
nT adigest_bits
nuOnly one digest parameter must be provided
T nnl@u'digest_bytes' not in range 1..64
l l  u'digest_bits' not in range 8..512, with steps of 8
T akey
c
uBLAKE2b key cannot exceed 64 bytes
uUnknown parameters:
aBLAKE2b_Hash
uCreate a new hash object.
Args:
data (bytes/bytearray/memoryview):
Optional. The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`BLAKE2b_Hash.update`.
digest_bytes (integer):
Optional. The size of the digest, in bytes (1 to 64). Default is 64.
digest_bits (integer):
Optional and alternative to ``digest_bytes``.
The size of the digest, in bits (8 to 512, in steps of 8).
Default is 512.
key (bytes/bytearray/memoryview):
Optional. The key to use to compute the MAC (1 to 64 bytes).
If not specified, no key will be used.
update_after_digest (boolean):
Optional. By default, a hash object cannot be updated anymore after
the digest is computed. When this flag is ``True``, such check
is no longer enforced.
Returns:
A :class:`BLAKE2b_Hash` hash object
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
T uCrypto.Hash._BLAKE2b

int blake2b_init(void **state,
const uint8_t *key,
size_t key_size,
size_t digest_size);
int blake2b_destroy(void *state);
int blake2b_update(void *state,
const uint8_t *buf,
size_t len);
int blake2b_digest(const void *state,
uint8_t digest[64]);
int blake2b_copy(const void *src, void *dst);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
