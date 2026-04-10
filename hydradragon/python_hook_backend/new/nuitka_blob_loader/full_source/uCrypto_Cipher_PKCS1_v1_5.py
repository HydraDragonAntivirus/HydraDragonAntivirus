# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher.PKCS1_v1_5

uThis cipher can perform PKCS#1 v1.5 RSA encryption or decryption.
Do not instantiate directly. Use :func:`Crypto.Cipher.PKCS1_v1_5.new` instead.
a__qualname__
a__init__
uPKCS115_Cipher.__init__
uPKCS115_Cipher.can_encrypt
uPKCS115_Cipher.can_decrypt
encrypt
uPKCS115_Cipher.encrypt
T l
decrypt
uPKCS115_Cipher.decrypt
T nuCrypto\Cipher\PKCS1_v1_5.py
u<module Crypto.Cipher.PKCS1_v1_5>
T aself
key
randfunc
T aself
T	aself
ciphertext
sentinel
expected_pt_len
wkact_int
em
output
size
T
self
message
wkamLen
ps
new_byte
em
em_int
m_int
wcT akey
randfunc

a__spec__
.Crypto.Cipher.Salsa20
E
key_size
uIncorrect key length for Salsa20 (%d bytes)
uIncorrect nonce length for Salsa20 (%d bytes)
a_copy_bytes
nonce
aVoidPointer
a_state
a_raw_salsa20_lib
aSalsa20_stream_init
c_uint8_ptr
c_size_t
address_of
uError %d instantiating a Salsa20 cipher
aSmartPointer
get
aSalsa20_stream_destroy
block_size
uInitialize a Salsa20 cipher object
See also `new()` at the module level.
create_string_buffer
is_writeable_buffer
uoutput must be a bytearray or a writeable memoryview
uoutput must have the same length as the input  (%d bytes)
aSalsa20_stream_encrypt
plaintext
uError %d while encrypting with Salsa20
get_raw_buffer
uEncrypt a piece of data.
Args:
plaintext(bytes/bytearray/memoryview): The data to encrypt, of any size.
Keyword Args:
output(bytes/bytearray/memoryview): The location where the ciphertext
is written to. If ``None``, the ciphertext is returned.
Returns:
If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
Otherwise, ``None``.
encrypt
T aoutput
replace
T aenc
dec
uDecrypt a piece of data.
Args:
ciphertext(bytes/bytearray/memoryview): The data to decrypt, of any size.
Keyword Args:
output(bytes/bytearray/memoryview): The location where the plaintext
is written to. If ``None``, the plaintext is returned.
Returns:
If ``output`` is ``None``, the plaintext is returned as ``bytes``.
Otherwise, ``None``.
get_random_bytes
T l aSalsa20Cipher
uCreate a new Salsa20 cipher
:keyword key: The secret key to use. It must be 16 or 32 bytes long.
:type key: bytes/bytearray/memoryview
:keyword nonce:
A value that must never be reused for any other encryption
done with this key. It must be 8 bytes long.
If not provided, a random byte string will be generated (you can read
it back via the ``nonce`` attribute of the returned object).
:type nonce: bytes/bytearray/memoryview
:Return: a :class:`Crypto.Cipher.Salsa20.Salsa20Cipher` object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T a_copy_bytes
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
create_string_buffer
get_raw_buffer
aVoidPointer
aSmartPointer
c_size_t
c_uint8_ptr
is_writeable_buffer
load_pycryptodome_raw_lib
uCrypto.Random
T aget_random_bytes
T uCrypto.Cipher._Salsa20

int Salsa20_stream_init(uint8_t *key, size_t keylen,
uint8_t *nonce, size_t nonce_len,
void **pSalsaState);
int Salsa20_stream_destroy(void *salsaState);
int Salsa20_stream_encrypt(void *salsaState,
const uint8_t in[],
uint8_t out[], size_t len);
