# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher.ARC4

uARC4 cipher object. Do not create it directly. Use
:func:`Crypto.Cipher.ARC4.new` instead.
a__qualname__
a__init__
uARC4Cipher.__init__
uARC4Cipher.encrypt
decrypt
uARC4Cipher.decrypt
new
;l l  l uCrypto\Cipher\ARC4.py
u<module Crypto.Cipher.ARC4>
T aself
key
args
kwargs
ndrop
result
T aself
ciphertext
weT aself
plaintext
ciphertext
result
T akey
args
kwargs

a__spec__
.Crypto.Cipher.Blowfish
9
pop
T akey
uMissing 'key' parameter
key_size
uIncorrect Blowfish key length (%d bytes)
a_raw_blowfish_lib
aBlowfish_start_operation
aBlowfish_stop_operation
aVoidPointer
c_uint8_ptr
c_size_t
address_of
uError %X while instantiating the Blowfish cipher
aSmartPointer
get
uThis method instantiates and returns a smart pointer to
a low-level base cipher. It will absorb named parameters in
the process.
a_create_cipher
modules
uCrypto.Cipher.Blowfish
uCreate a new Blowfish cipher
:param key:
The secret key to use in the symmetric cipher.
Its length can vary from 5 to 56 bytes.
:type key: bytes, bytearray, memoryview
:param mode:
The chaining mode to use for encryption or decryption.
:type mode: One of the supported ``MODE_*`` constants
:Keyword Arguments:
*   **iv** (*bytes*, *bytearray*, *memoryview*) --
(Only applicable for ``MODE_CBC``, ``MODE_CFB``, ``MODE_OFB``,
nd ``MODE_OPENPGP`` modes).
The initialization vector to use for encryption or decryption.
For ``MODE_CBC``, ``MODE_CFB``, and ``MODE_OFB`` it must be 8 bytes long.
For ``MODE_OPENPGP`` mode only,
it must be 8 bytes long for encryption
nd 10 bytes for decryption (in the latter case, it is
ctually the *encrypted* IV which was prefixed to the ciphertext).
If not provided, a random byte string is generated (you must then
read its value with the :attr:`iv` attribute).
*   **nonce** (*bytes*, *bytearray*, *memoryview*) --
(Only applicable for ``MODE_EAX`` and ``MODE_CTR``).
A value that must never be reused for any other encryption done
with this key.
For ``MODE_EAX`` there are no
restrictions on its length (recommended: **16** bytes).
For ``MODE_CTR``, its length must be in the range **[0..7]**.
If not provided for ``MODE_EAX``, a random byte string is generated (you
can read it back via the ``nonce`` attribute).
*   **segment_size** (*integer*) --
(Only ``MODE_CFB``).The number of **bits** the plaintext and ciphertext
re segmented in. It must be a multiple of 8.
If not specified, it will be assumed to be 8.
*   **mac_len** : (*integer*) --
(Only ``MODE_EAX``)
Length of the authentication tag, in bytes.
It must be no longer than 8 (default).
*   **initial_value** : (*integer*) --
(Only ``MODE_CTR``). The initial value for the counter within
the counter block. By default it is **0**.
:Return: a Blowfish object, of the applicable mode.

Module's constants for the modes of operation supported with Blowfish:
:var MODE_ECB: :ref:`Electronic Code Book (ECB) <ecb_mode>`
:var MODE_CBC: :ref:`Cipher-Block Chaining (CBC) <cbc_mode>`
:var MODE_CFB: :ref:`Cipher FeedBack (CFB) <cfb_mode>`
:var MODE_OFB: :ref:`Output FeedBack (OFB) <ofb_mode>`
:var MODE_CTR: :ref:`CounTer Mode (CTR) <ctr_mode>`
:var MODE_OPENPGP:  :ref:`OpenPGP Mode <openpgp_mode>`
:var MODE_EAX: :ref:`EAX Mode <eax_mode>`
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
load_pycryptodome_raw_lib
T uCrypto.Cipher._raw_blowfish

int Blowfish_start_operation(const uint8_t key[],
size_t key_len,
void **pResult);
int Blowfish_encrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int Blowfish_decrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int Blowfish_stop_operation(void *state);
a_create_base_cipher
new
aMODE_ECB
l aMODE_CBC
l aMODE_CFB
l aMODE_OFB
l aMODE_CTR
l aMODE_OPENPGP
l	aMODE_EAX
l ablock_size
;l l9l uCrypto\Cipher\Blowfish.py
u<module Crypto.Cipher.Blowfish>
T adict_parameters
key
start_operation
stop_operation
void_p
result
T akey
mode
args
kwargs

a__spec__
.Crypto.Cipher.CAST
~
<
pop
T akey
uMissing 'key' parameter
key_size
uIncorrect CAST key length (%d bytes)
a_raw_cast_lib
aCAST_start_operation
aCAST_stop_operation
aVoidPointer
c_uint8_ptr
c_size_t
address_of
uError %X while instantiating the CAST cipher
aSmartPointer
get
uThis method instantiates and returns a handle to a low-level
base cipher. It will absorb named parameters in the process.
a_create_cipher
modules
uCrypto.Cipher.CAST
uCreate a new CAST cipher
:param key:
The secret key to use in the symmetric cipher.
Its length can vary from 5 to 16 bytes.
:type key: bytes, bytearray, memoryview
:param mode:
The chaining mode to use for encryption or decryption.
:type mode: One of the supported ``MODE_*`` constants
:Keyword Arguments:
*   **iv** (*bytes*, *bytearray*, *memoryview*) --
(Only applicable for ``MODE_CBC``, ``MODE_CFB``, ``MODE_OFB``,
nd ``MODE_OPENPGP`` modes).
The initialization vector to use for encryption or decryption.
For ``MODE_CBC``, ``MODE_CFB``, and ``MODE_OFB`` it must be 8 bytes long.
For ``MODE_OPENPGP`` mode only,
it must be 8 bytes long for encryption
nd 10 bytes for decryption (in the latter case, it is
ctually the *encrypted* IV which was prefixed to the ciphertext).
If not provided, a random byte string is generated (you must then
read its value with the :attr:`iv` attribute).
*   **nonce** (*bytes*, *bytearray*, *memoryview*) --
(Only applicable for ``MODE_EAX`` and ``MODE_CTR``).
A value that must never be reused for any other encryption done
with this key.
For ``MODE_EAX`` there are no
restrictions on its length (recommended: **16** bytes).
For ``MODE_CTR``, its length must be in the range **[0..7]**.
If not provided for ``MODE_EAX``, a random byte string is generated (you
can read it back via the ``nonce`` attribute).
*   **segment_size** (*integer*) --
(Only ``MODE_CFB``).The number of **bits** the plaintext and ciphertext
re segmented in. It must be a multiple of 8.
If not specified, it will be assumed to be 8.
*   **mac_len** : (*integer*) --
(Only ``MODE_EAX``)
Length of the authentication tag, in bytes.
It must be no longer than 8 (default).
*   **initial_value** : (*integer*) --
(Only ``MODE_CTR``). The initial value for the counter within
the counter block. By default it is **0**.
:Return: a CAST object, of the applicable mode.

Module's constants for the modes of operation supported with CAST:
:var MODE_ECB: :ref:`Electronic Code Book (ECB) <ecb_mode>`
:var MODE_CBC: :ref:`Cipher-Block Chaining (CBC) <cbc_mode>`
:var MODE_CFB: :ref:`Cipher FeedBack (CFB) <cfb_mode>`
:var MODE_OFB: :ref:`Output FeedBack (OFB) <ofb_mode>`
:var MODE_CTR: :ref:`CounTer Mode (CTR) <ctr_mode>`
:var MODE_OPENPGP:  :ref:`OpenPGP Mode <openpgp_mode>`
:var MODE_EAX: :ref:`EAX Mode <eax_mode>`
a__doc__
a__file__
origin
has_location
a__cached__
sys
uCrypto.Cipher
T a_create_cipher
uCrypto.Util.py3compat
T abyte_string
byte_string
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
c_size_t
c_uint8_ptr
load_pycryptodome_raw_lib
T uCrypto.Cipher._raw_cast

int CAST_start_operation(const uint8_t key[],
size_t key_len,
void **pResult);
int CAST_encrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int CAST_decrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int CAST_stop_operation(void *state);
a_create_base_cipher
new
aMODE_ECB
l aMODE_CBC
l aMODE_CFB
l aMODE_OFB
l aMODE_CTR
l aMODE_OPENPGP
l	aMODE_EAX
l ablock_size
;l l l uCrypto\Cipher\CAST.py
u<module Crypto.Cipher.CAST>
T adict_parameters
key
start_operation
stop_operation
cipher
result
T akey
mode
args
kwargs

a__spec__
.Crypto.Cipher.ChaCha20
x
B
a_raw_chacha20_lib
hchacha20
c_uint8_ptr
uError %d when deriving subkey with HChaCha20
a_copy_bytes
nonce
a_HChaCha20
:nl nb
:l nnaXChaCha20
a_name
aChaCha20
T aencrypt
decrypt
a_next
aVoidPointer
a_state
chacha20_init
address_of
c_size_t
uError %d instantiating a %s cipher
aSmartPointer
get
chacha20_destroy
uInitialize a ChaCha20/XChaCha20 cipher object
See also `new()` at the module level.
encrypt
uCipher object can only be used for decryption
T aencrypt
a_encrypt
uEncrypt a piece of data.
Args:
plaintext(bytes/bytearray/memoryview): The data to encrypt, of any size.
Keyword Args:
output(bytes/bytearray/memoryview): The location where the ciphertext
is written to. If ``None``, the ciphertext is returned.
Returns:
If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
Otherwise, ``None``.
create_string_buffer
is_writeable_buffer
uoutput must be a bytearray or a writeable memoryview
uoutput must have the same length as the input  (%d bytes)
chacha20_encrypt
plaintext
uError %d while encrypting with %s
get_raw_buffer
uEncrypt without FSM checks
decrypt
uCipher object can only be used for encryption
T adecrypt
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
l@g       l achacha20_seek
c_ulong
uError %d while seeking with %s
uSeek to a certain position in the key stream.
Args:
position (integer):
The absolute position within the key stream, in bytes.
uPoly1305 with ChaCha20 requires a 32-byte key
get_random_bytes
T l uPoly1305 with ChaCha20 requires an 8- or 12-byte nonce
new
T akey
nonce
T b
uDerive a tuple (r, s, nonce) for a Poly1305 MAC.
If nonce is ``None``, a new 12-byte nonce is generated.
key
uMissing parameter %s
pop
T anonce
nT l uChaCha20/XChaCha20 key must be 32 bytes long
T l l l uNonce must be 8/12 bytes(ChaCha20) or 24 bytes (XChaCha20)
uUnknown parameters:
aChaCha20Cipher
uCreate a new ChaCha20 or XChaCha20 cipher
Keyword Args:
key (bytes/bytearray/memoryview): The secret key to use.
It must be 32 bytes long.
nonce (bytes/bytearray/memoryview): A mandatory value that
must never be reused for any other encryption
done with this key.
For ChaCha20, it must be 8 or 12 bytes long.
For XChaCha20, it must be 24 bytes long.
If not provided, 8 bytes will be randomly generated
(you can find them back in the ``nonce`` attribute).
:Return: a :class:`Crypto.Cipher.ChaCha20.ChaCha20Cipher` object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Random
T aget_random_bytes
uCrypto.Util.py3compat
T a_copy_bytes
uCrypto.Util._raw_api
T	aload_pycryptodome_raw_lib
create_string_buffer
get_raw_buffer
aVoidPointer
aSmartPointer
c_size_t
c_uint8_ptr
c_ulong
is_writeable_buffer
load_pycryptodome_raw_lib
T uCrypto.Cipher._chacha20

int chacha20_init(void **pState,
const uint8_t *key,
size_t keySize,
const uint8_t *nonce,
size_t nonceSize);
int chacha20_destroy(void *state);
int chacha20_encrypt(void *state,
const uint8_t in[],
uint8_t out[],
size_t len);
int chacha20_seek(void *state,
unsigned long block_high,
unsigned long block_low,
unsigned offset);
int hchacha20(  const uint8_t key[32],
const uint8_t nonce16[16],
uint8_t subkey[32]);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
