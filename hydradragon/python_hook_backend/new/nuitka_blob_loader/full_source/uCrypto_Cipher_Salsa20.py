# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher.Salsa20

uSalsa20 cipher object. Do not create it directly. Use :py:func:`new`
instead.
:var nonce: The nonce with length 8
:vartype nonce: byte string
a__qualname__
a__init__
uSalsa20Cipher.__init__
T nuSalsa20Cipher.encrypt
decrypt
uSalsa20Cipher.decrypt
new
T l l uCrypto\Cipher\Salsa20.py
u<module Crypto.Cipher.Salsa20>
T aself
key
nonce
result
T aself
ciphertext
output
weT aself
plaintext
output
ciphertext
result
T akey
nonce

a__spec__
.Crypto.Cipher._EKSBlowfish
3
pop
T akey
T asalt
T acost
uMissing EKSBlowfish parameter:
T ainvert
takey_size
uIncorrect EKSBlowfish key length (%d bytes)
a_raw_blowfish_lib
aEKSBlowfish_start_operation
aEKSBlowfish_stop_operation
aVoidPointer
c_uint8_ptr
c_size_t
c_uint
address_of
uError %X while instantiating the EKSBlowfish cipher
aSmartPointer
get
uThis method instantiates and returns a smart pointer to
a low-level base cipher. It will absorb named parameters in
the process.
salt
cost
invert
a_create_cipher
modules
uCrypto.Cipher._EKSBlowfish
uCreate a new EKSBlowfish cipher
Args:
key (bytes, bytearray, memoryview):
The secret key to use in the symmetric cipher.
Its length can vary from 0 to 72 bytes.
mode (one of the supported ``MODE_*`` constants):
The chaining mode to use for encryption or decryption.
salt (bytes, bytearray, memoryview):
The salt that bcrypt uses to thwart rainbow table attacks
cost (integer):
The complexity factor in bcrypt
invert (bool):
If ``False``, in the inner loop use ``ExpandKey`` first over the salt
nd then over the key, as defined in
the `original bcrypt specification <https://www.usenix.org/legacy/events/usenix99/provos/provos_html/node4.html>`_.
If ``True``, reverse the order, as in the first implementation of
`bcrypt` in OpenBSD.
:Return: an EKSBlowfish object
a__doc__
a__file__
origin
has_location
a__cached__
sys
uCrypto.Cipher
T a_create_cipher
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
c_size_t
c_uint8_ptr
c_uint
load_pycryptodome_raw_lib
T uCrypto.Cipher._raw_eksblowfish

int EKSBlowfish_start_operation(const uint8_t key[],
size_t key_len,
const uint8_t salt[16],
size_t salt_len,
unsigned cost,
unsigned invert,
void **pResult);
int EKSBlowfish_encrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int EKSBlowfish_decrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int EKSBlowfish_stop_operation(void *state);
a_create_base_cipher
new
aMODE_ECB
l ablock_size
;l
lIl uCrypto\Cipher\_EKSBlowfish.py
u<module Crypto.Cipher._EKSBlowfish>
T
dict_parameters
key
salt
cost
weainvert
start_operation
stop_operation
void_p
result
T akey
mode
salt
cost
invert
kwargs

a__spec__
.Crypto.Cipher._mode_cbc
Y
aVoidPointer
a_state
raw_cbc_lib
aCBC_start_operation
get
c_uint8_ptr
c_size_t
address_of
uError %d while instantiating the CBC mode
aSmartPointer
aCBC_stop_operation
release
block_size
a_copy_bytes
iv
aIV
encrypt
decrypt
a_next
uCreate a new block cipher, configured in CBC mode.
:Parameters:
block_cipher : C pointer
A smart pointer to the low-level block cipher instance.
iv : bytes/bytearray/memoryview
The initialization vector to use for encryption or decryption.
It is as long as the cipher block.
**The IV must be unpredictable**. Ideally it is picked randomly.
Reusing the *IV* for encryptions performed with the same key
compromises confidentiality.
uencrypt() cannot be called after decrypt()
create_string_buffer
is_writeable_buffer
uoutput must be a bytearray or a writeable memoryview
uoutput must have the same length as the input  (%d bytes)
aCBC_encrypt
plaintext
l uData must be padded to %d byte boundary in CBC mode
uError %d while encrypting in CBC mode
get_raw_buffer
uEncrypt data with the key and the parameters set at initialization.
A cipher object is stateful: once you have encrypted a message
you cannot encrypt (or decrypt) another message using the same
object.
The data to encrypt can be broken up in two or
more pieces and `encrypt` can be called multiple times.
That is, the statement:
>>> c.encrypt(a) + c.encrypt(b)
is equivalent to:
>>> c.encrypt(a+b)
That also means that you cannot reuse an object for encrypting
or decrypting other data with the same key.
This function does not add any padding to the plaintext.
:Parameters:
plaintext : bytes/bytearray/memoryview
The piece of data to encrypt.
Its lenght must be multiple of the cipher block size.
:Keywords:
output : bytearray/memoryview
The location where the ciphertext must be written to.
If ``None``, the ciphertext is returned.
:Return:
If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
Otherwise, ``None``.
udecrypt() cannot be called after encrypt()
aCBC_decrypt
ciphertext
uError %d while decrypting in CBC mode
uDecrypt data with the key and the parameters set at initialization.
A cipher object is stateful: once you have decrypted a message
you cannot decrypt (or encrypt) another message with the same
object.
The data to decrypt can be broken up in two or
more pieces and `decrypt` can be called multiple times.
That is, the statement:
>>> c.decrypt(a) + c.decrypt(b)
is equivalent to:
>>> c.decrypt(a+b)
This function does not remove any padding from the plaintext.
:Parameters:
ciphertext : bytes/bytearray/memoryview
The piece of data to decrypt.
Its length must be multiple of the cipher block size.
:Keywords:
output : bytearray/memoryview
The location where the plaintext must be written to.
If ``None``, the plaintext is returned.
:Return:
If ``output`` is ``None``, the plaintext is returned as ``bytes``.
Otherwise, ``None``.
a_create_base_cipher
pop
T aIV
nT aiv
nT nnaget_random_bytes
uYou must either use 'iv' or 'IV', not both
uIncorrect IV length (it must be %d bytes long)
uUnknown parameters for CBC: %s
aCbcMode
uInstantiate a cipher object that performs CBC encryption/decryption.
:Parameters:
factory : module
The underlying block cipher, a module from ``Crypto.Cipher``.
:Keywords:
iv : bytes/bytearray/memoryview
The IV to use for CBC.
IV : bytes/bytearray/memoryview
Alias for ``iv``.
Any other keyword will be passed to the underlying block cipher.
See the relevant documentation for details (at least ``key`` will need
to be present).

Ciphertext Block Chaining (CBC) mode.
a__doc__
a__file__
origin
has_location
a__cached__
a__all__
uCrypto.Util.py3compat
T a_copy_bytes
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
create_string_buffer
get_raw_buffer
aSmartPointer
c_size_t
c_uint8_ptr
is_writeable_buffer
load_pycryptodome_raw_lib
uCrypto.Random
T aget_random_bytes
T uCrypto.Cipher._raw_cbc

int CBC_start_operation(void *cipher,
const uint8_t iv[],
size_t iv_len,
void **pResult);
int CBC_encrypt(void *cbcState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int CBC_decrypt(void *cbcState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int CBC_stop_operation(void *state);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
