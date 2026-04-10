# Reconstructed from integrated Nuitka blob
# Module: u<metaclass>

uChaCha20-Poly1305 and XChaCha20-Poly1305 cipher object.
Do not create it directly. Use :py:func:`new` instead.
:var nonce: The nonce with length 8, 12 or 24 bytes
:vartype nonce: byte string
a__qualname__
a__init__
uChaCha20Poly1305Cipher.__init__
uChaCha20Poly1305Cipher.update
uChaCha20Poly1305Cipher._pad_aad
T nuChaCha20Poly1305Cipher.encrypt
uChaCha20Poly1305Cipher.decrypt
uChaCha20Poly1305Cipher._compute_mac
uChaCha20Poly1305Cipher.digest
hexdigest
uChaCha20Poly1305Cipher.hexdigest
uChaCha20Poly1305Cipher.verify
hexverify
uChaCha20Poly1305Cipher.hexverify
encrypt_and_digest
uChaCha20Poly1305Cipher.encrypt_and_digest
decrypt_and_verify
uChaCha20Poly1305Cipher.decrypt_and_verify
a__orig_bases__
l akey_size
uCrypto\Cipher\ChaCha20_Poly1305.py
u<module Crypto.Cipher.ChaCha20_Poly1305>
T a__class__
T aself
key
nonce
T aself
T aenums
T aself
ciphertext
output
T aself
ciphertext
received_mac_tag
plaintext
T aself
plaintext
output
result
T aself
plaintext
T aself
hex_mac_tag
T akwargs
key
weanonce
chacha20_poly1305_nonce
cipher
T aself
data
T aself
received_mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Cipher.DES
;
pop
T akey
uMissing 'key' parameter
key_size
uIncorrect DES key length (%d bytes)
a_raw_des_lib
aDES_start_operation
aDES_stop_operation
aVoidPointer
c_uint8_ptr
c_size_t
address_of
uError %X while instantiating the DES cipher
aSmartPointer
get
uThis method instantiates and returns a handle to a low-level
base cipher. It will absorb named parameters in the process.
a_create_cipher
modules
uCrypto.Cipher.DES
uCreate a new DES cipher.
:param key:
The secret key to use in the symmetric cipher.
It must be 8 byte long. The parity bits will be ignored.
:type key: bytes/bytearray/memoryview
:param mode:
The chaining mode to use for encryption or decryption.
:type mode: One of the supported ``MODE_*`` constants
:Keyword Arguments:
*   **iv** (*byte string*) --
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
*   **nonce** (*byte string*) --
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
:Return: a DES object, of the applicable mode.

Module's constants for the modes of operation supported with Single DES:
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
T uCrypto.Cipher._raw_des

int DES_start_operation(const uint8_t key[],
size_t key_len,
void **pResult);
int DES_encrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int DES_decrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int DES_stop_operation(void *state);
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
uCrypto\Cipher\DES.py
u<module Crypto.Cipher.DES>
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
.Crypto.Cipher.DES3
N
parity_byte
uadjust_key_parity.<locals>.parity_byte
key_size
uNot a valid TDES key
c
bchr
bord
:nl n:l l n:q q n:q nnuTriple DES key degenerates to single DES
uSet the parity bits in a TDES key.
:param key_in: the TDES key whose bits need to be adjusted
:type key_in: byte string
:returns: a copy of ``key_in``, with the parity bits correctly set
:rtype: byte string
:raises ValueError: if the TDES key is not 16 or 24 bytes long
:raises ValueError: if the TDES key degenerates into Single DES
;l l l aparity
key_byte
l  apop
T akey
uMissing 'key' parameter
adjust_key_parity
bstr
a_raw_des3_lib
aDES3_start_operation
aDES3_stop_operation
aVoidPointer
c_size_t
address_of
uError %X while instantiating the TDES cipher
aSmartPointer
get
uThis method instantiates and returns a handle to a low-level base cipher.
It will absorb named parameters in the process.
a_create_cipher
modules
uCrypto.Cipher.DES3
uCreate a new Triple DES cipher.
:param key:
The secret key to use in the symmetric cipher.
It must be 16 or 24 byte long. The parity bits will be ignored.
:type key: bytes/bytearray/memoryview
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
:Return: a Triple DES object, of the applicable mode.

Module's constants for the modes of operation supported with Triple DES:
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
bchr
bord
bstr
byte_string
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
c_size_t
load_pycryptodome_raw_lib
T uCrypto.Cipher._raw_des3

int DES3_start_operation(const uint8_t key[],
size_t key_len,
void **pResult);
int DES3_encrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int DES3_decrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int DES3_stop_operation(void *state);
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
T l l uCrypto\Cipher\DES3.py
u<module Crypto.Cipher.DES3>
T adict_parameters
key_in
key
start_operation
stop_operation
cipher
result
T akey_in
parity_byte
key_out
T akey
mode
args
kwargs
T akey_byte
parity
wiu
a__spec__
.Crypto.Cipher.PKCS1_OAEP
U
a_key
a_hashObj
aCrypto
aHash
aSHA1
a_mgf
u<lambda>
uPKCS1OAEP_Cipher.__init__.<locals>.<lambda>
a_copy_bytes
a_label
a_randfunc
uInitialize this PKCS#1 OAEP cipher object.
:Parameters:
key : an RSA key object
If a private half is given, both encryption and decryption are possible.
If a public half is given, only encryption is possible.
hashAlgo : hash object
The hash function to use. This can be a module under `Crypto.Hash`
or an existing hash object created from any of such modules. If not specified,
`Crypto.Hash.SHA1` is used.
mgfunc : callable
A mask generation function that accepts two parameters: a string to
use as seed, and the lenth of the mask to generate, in bytes.
If not specified, the standard MGF1 consistent with ``hashAlgo`` is used (a safe choice).
label : bytes/bytearray/memoryview
A label to apply to this particular encryption. If not specified,
n empty string is used. Specifying a label does not improve
security.
randfunc : callable
A function that returns random bytes.
:attention: Modify the mask generation function only if you know what you are doing.
Sender and receiver must use the same one.
aMGF1
self
can_encrypt
uLegacy function to check if you can call :meth:`encrypt`.
.. deprecated:: 3.0
can_decrypt
uLegacy function to check if you can call :meth:`decrypt`.
.. deprecated:: 3.0
aUtil
number
size
wnaceil_div
l adigest_size
l uPlaintext is too long.
new
digest
d
d astrxor
bytes_to_long
a_encrypt
long_to_bytes
uEncrypt a message with PKCS#1 OAEP.
:param message:
The message to encrypt, also known as plaintext. It can be of
variable length, but not longer than the RSA modulus (in bytes)
minus 2, minus twice the hash output size.
For instance, if you use RSA 2048 and SHA-256, the longest message
you can encrypt is 190 byte long.
:type message: bytes/bytearray/memoryview
:returns: The ciphertext, as large as the RSA modulus.
:rtype: bytes
:raises ValueError:
if the message is too long.
uCiphertext with incorrect length.
a_decrypt_to_bytes
oaep_decode
uIncorrect decryption.
uDecrypt a message with PKCS#1 OAEP.
:param ciphertext: The encrypted message.
:type ciphertext: bytes/bytearray/memoryview
:returns: The original message (plaintext).
:rtype: bytes
:raises ValueError:
if the ciphertext has the wrong length, or if decryption
fails the integrity check (in which case, the decryption
key is probably wrong).
:raises TypeError:
if the RSA key has no private half (i.e. you are trying
to decrypt using a public key).
aRandom
get_random_bytes
aPKCS1OAEP_Cipher
uReturn a cipher object :class:`PKCS1OAEP_Cipher`
that can be used to perform PKCS#1 OAEP encryption or decryption.
:param key:
The key object to use to encrypt or decrypt the message.
Decryption is only possible with a private RSA key.
:type key: RSA key object
:param hashAlgo:
The hash function to use. This can be a module under `Crypto.Hash`
or an existing hash object created from any of such modules.
If not specified, `Crypto.Hash.SHA1` is used.
:type hashAlgo: hash object
:param mgfunc:
A mask generation function that accepts two parameters: a string to
use as seed, and the lenth of the mask to generate, in bytes.
If not specified, the standard MGF1 consistent with ``hashAlgo`` is used (a safe choice).
:type mgfunc: callable
:param label:
A label to apply to this particular encryption. If not specified,
n empty string is used. Specifying a label does not improve
security.
:type label: bytes/bytearray/memoryview
:param randfunc:
A function that returns random bytes.
The default is `Random.get_random_bytes`.
:type randfunc: callable
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Signature.pss
T aMGF1
uCrypto.Hash.SHA1
uCrypto.Util.py3compat
T a_copy_bytes
uCrypto.Util.number
T aceil_div
bytes_to_long
long_to_bytes
uCrypto.Util.strxor
T astrxor
T aRandom
a_pkcs1_oaep_decode
T aoaep_decode
uCounter with CBC-MAC (CCM).
This is an Authenticated Encryption with Associated Data (`AEAD`_) mode.
It provides both confidentiality and authenticity.
The header of the message may be left in the clear, if needed, and it will
still be subject to authentication. The decryption step tells the receiver
if the message comes from a source that really knowns the secret key.
Additionally, decryption detects if any part of the message - including the
header - has been modified or corrupted.
This mode requires a nonce. The nonce shall never repeat for two
different messages encrypted with the same key, but it does not need
to be random.
Note that there is a trade-off between the size of the nonce and the
maximum size of a single message you can encrypt.
It is important to use a large nonce if the key is reused across several
messages and the nonce is chosen randomly.
It is acceptable to us a short nonce if the key is only used a few times or
if the nonce is taken from a counter.
The following table shows the trade-off when the nonce is chosen at
random. The column on the left shows how many messages it takes
for the keystream to repeat **on average**. In practice, you will want to
stop using the key way before that.
+--------------------+---------------+-------------------+
| Avg. # of messages |    nonce      |     Max. message  |
| before keystream   |    size       |     size          |
| repeats            |    (bytes)    |     (bytes)       |
+====================+===============+===================+
|       2^52         |      13       |        64K        |
+--------------------+---------------+-------------------+
|       2^48         |      12       |        16M        |
+--------------------+---------------+-------------------+
|       2^44         |      11       |         4G        |
+--------------------+---------------+-------------------+
|       2^40         |      10       |         1T        |
+--------------------+---------------+-------------------+
|       2^36         |       9       |        64P        |
+--------------------+---------------+-------------------+
|       2^32         |       8       |        16E        |
+--------------------+---------------+-------------------+
This mode is only available for ciphers that operate on 128 bits blocks
(e.g. AES but not TDES).
See `NIST SP800-38C`_ or RFC3610_.
.. _`NIST SP800-38C`: http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C.pdf
.. _RFC3610: https://tools.ietf.org/html/rfc3610
.. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
:undocumented: __init__
a__qualname__
a__init__
uCcmMode.__init__
uCcmMode._start_mac
uCcmMode._pad_cache_and_update
uCcmMode.update
T c
uCcmMode._update
T nuCcmMode.encrypt
uCcmMode.decrypt
uCcmMode.digest
uCcmMode._digest
hexdigest
uCcmMode.hexdigest
uCcmMode.verify
hexverify
uCcmMode.hexverify
encrypt_and_digest
uCcmMode.encrypt_and_digest
decrypt_and_verify
uCcmMode.decrypt_and_verify
a__orig_bases__
a_create_ccm_cipher
uCrypto\Cipher\_mode_ccm.py
u<module Crypto.Cipher._mode_ccm>
T a__class__
T	aself
factory
key
nonce
mac_len
msg_len
assoc_len
cipher_params
wqT	afactory
kwargs
key
weanonce
mac_len
msg_len
assoc_len
cipher_params
T aself
T aself
len_cache
T aself
wqaflags
b_0
assoc_len_encoded
enc_size
first_data_to_mac
T aself
assoc_data_pt
filler
update_len
T aself
ciphertext
output
plaintext
T aself
ciphertext
received_mac_tag
output
plaintext
T aself
plaintext
output
T aenums
T aself
hex_mac_tag
T aself
assoc_data
T aself
received_mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Cipher._mode_cfb
;
Z
aVoidPointer
a_state
raw_cfb_lib
aCFB_start_operation
get
c_uint8_ptr
c_size_t
address_of
uError %d while instantiating the CFB mode
aSmartPointer
aCFB_stop_operation
release
block_size
a_copy_bytes
iv
aIV
encrypt
decrypt
a_next
uCreate a new block cipher, configured in CFB mode.
:Parameters:
block_cipher : C pointer
A smart pointer to the low-level block cipher instance.
iv : bytes/bytearray/memoryview
The initialization vector to use for encryption or decryption.
It is as long as the cipher block.
**The IV must be unpredictable**. Ideally it is picked randomly.
Reusing the *IV* for encryptions performed with the same key
compromises confidentiality.
segment_size : integer
The number of bytes the plaintext and ciphertext are segmented in.
uencrypt() cannot be called after decrypt()
create_string_buffer
is_writeable_buffer
uoutput must be a bytearray or a writeable memoryview
uoutput must have the same length as the input  (%d bytes)
aCFB_encrypt
plaintext
uError %d while encrypting in CFB mode
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
This function does not add any padding to the plaintext.
:Parameters:
plaintext : bytes/bytearray/memoryview
The piece of data to encrypt.
It can be of any length.
:Keywords:
output : bytearray/memoryview
The location where the ciphertext must be written to.
If ``None``, the ciphertext is returned.
:Return:
If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
Otherwise, ``None``.
udecrypt() cannot be called after encrypt()
aCFB_decrypt
ciphertext
uError %d while decrypting in CFB mode
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
It can be of any length.
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
T asegment_size
l l u'segment_size' must be positive and multiple of 8 bits
uUnknown parameters for CFB: %s
aCfbMode
uInstantiate a cipher object that performs CFB encryption/decryption.
:Parameters:
factory : module
The underlying block cipher, a module from ``Crypto.Cipher``.
:Keywords:
iv : bytes/bytearray/memoryview
The IV to use for CFB.
IV : bytes/bytearray/memoryview
Alias for ``iv``.
segment_size : integer
The number of bit the plaintext and ciphertext are segmented in.
If not present, the default is 8.
Any other keyword will be passed to the underlying block cipher.
See the relevant documentation for details (at least ``key`` will need
to be present).

Counter Feedback (CFB) mode.
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
T uCrypto.Cipher._raw_cfb

int CFB_start_operation(void *cipher,
const uint8_t iv[],
size_t iv_len,
size_t segment_len, /* In bytes */
void **pResult);
int CFB_encrypt(void *cfbState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int CFB_decrypt(void *cfbState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int CFB_stop_operation(void *state);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
uGHASH function defined in NIST SP 800-38D, Algorithm 2.
If X_1, X_2, .. X_m are the blocks of input data, the function
computes:
X_1*H^{m} + X_2*H^{m-1} + ... + X_m*H
in the Galois field GF(2^256) using the reducing polynomial
(x^128 + x^7 + x^2 + x + 1).
a__qualname__
a__init__
u_GHASH.__init__
u_GHASH.update
u_GHASH.digest
a__orig_bases__
enum
T l l T aPROCESSING_AUTH_DATA
aPROCESSING_CIPHERTEXT
uGalois Counter Mode (GCM).
This is an Authenticated Encryption with Associated Data (`AEAD`_) mode.
It provides both confidentiality and authenticity.
The header of the message may be left in the clear, if needed, and it will
still be subject to authentication. The decryption step tells the receiver
if the message comes from a source that really knowns the secret key.
Additionally, decryption detects if any part of the message - including the
header - has been modified or corrupted.
This mode requires a *nonce*.
This mode is only available for ciphers that operate on 128 bits blocks
(e.g. AES but not TDES).
See `NIST SP800-38D`_.
.. _`NIST SP800-38D`: http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
.. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
:undocumented: __init__
uGcmMode.__init__
uGcmMode.update
uGcmMode._update
uGcmMode._pad_cache_and_update
T nuGcmMode.encrypt
uGcmMode.decrypt
uGcmMode.digest
uGcmMode._compute_mac
hexdigest
uGcmMode.hexdigest
uGcmMode.verify
hexverify
uGcmMode.hexverify
encrypt_and_digest
uGcmMode.encrypt_and_digest
decrypt_and_verify
uGcmMode.decrypt_and_verify
a_create_gcm_cipher
uCrypto\Cipher\_mode_gcm.py
u<module Crypto.Cipher._mode_gcm>
T a__class__
Taself
factory
key
nonce
mac_len
cipher_params
ghash_c
hash_subkey
j0
fill
ghash_in
nonce_ctr
iv_ctr
T aself
subkey
ghash_c
result
T alib
postfix
namedtuple
funcs
aGHASH_Imp
imp_funcs
params
T aself
s_tag
T afactory
kwargs
key
weanonce
mac_len
use_clmul
ghash_c
T aapi
lib
result
T aself
len_cache
T aself
data
filler
update_len
T aself
ciphertext
output
T aself
ciphertext
received_mac_tag
output
plaintext
T aself
T aself
plaintext
output
ciphertext
T aself
plaintext
output
T aenums
T aself
hex_mac_tag
T aself
assoc_data
T aself
block_data
result
T aself
received_mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Cipher._mode_ocb
*
block_size
l uOCB mode is only available for ciphers that operate on 128 bits blocks
a_copy_bytes
nonce
;l l l uNonce must be at most 15 bytes long
is_buffer
uNonce must be bytes, bytearray or memoryview
a_mac_len
l uMAC tag must be between 8 and 16 bytes long
a_mac_tag
c
a_cache_A
a_cache_P
L aupdate
encrypt
decrypt
digest
verify
a_next
key
l  abchr
d
d abord
l l?l  anew
aMODE_ECB
encrypt
struct
pack
u15sB
:nl nastrxor
:nl n:l l	nalong_to_bytes
bytes_to_long
l@l :l nna_create_base_cipher
uUnknown keywords:
aVoidPointer
a_state
a_raw_ocb_lib
aOCB_start_operation
get
c_size_t
address_of
uError %d while instantiating the OCB mode
aSmartPointer
aOCB_stop_operation
release
aOCB_update
c_uint8_ptr
uError %d while computing MAC in OCB mode
update
uupdate() can only be called immediately after initialization
L aencrypt
decrypt
digest
verify
update
min
a_update
uProcess the associated data.
If there is any associated data, the caller has to invoke
this method one or more times, before using
``decrypt`` or ``encrypt``.
By *associated data* it is meant any data (e.g. packet headers) that
will not be encrypted and will be transmitted in the clear.
However, the receiver shall still able to detect modifications.
If there is no associated data, this method must not be called.
The caller may split associated data in segments of any size, and
invoke this method multiple times, each time with the next segment.
:Parameters:
ssoc_data : bytes/bytearray/memoryview
A piece of associated data.
create_string_buffer
uError %d while %sing in OCB mode
get_raw_buffer
a_transcrypt_aligned
uencrypt() can only be called after initialization or an update()
digest
a_transcrypt
aOCB_encrypt
uEncrypt the next piece of plaintext.
After the entire plaintext has been passed (but before `digest`),
you **must** call this method one last time with no arguments to collect
the final piece of ciphertext.
If possible, use the method `encrypt_and_digest` instead.
:Parameters:
plaintext : bytes/bytearray/memoryview
The next piece of data to encrypt or ``None`` to signify
that encryption has finished and that any remaining ciphertext
has to be produced.
:Return:
the ciphertext, as a byte string.
Its length may not match the length of the *plaintext*.
decrypt
udecrypt() can only be called after initialization or an update()
verify
aOCB_decrypt
uDecrypt the next piece of ciphertext.
After the entire ciphertext has been passed (but before `verify`),
you **must** call this method one last time with no arguments to collect
the remaining piece of plaintext.
If possible, use the method `decrypt_and_verify` instead.
:Parameters:
ciphertext : bytes/bytearray/memoryview
The next piece of data to decrypt or ``None`` to signify
that decryption has finished and that any remaining plaintext
has to be produced.
:Return:
the plaintext, as a byte string.
Its length may not match the length of the *ciphertext*.
T l aOCB_digest
uError %d while computing digest in OCB mode
udigest() cannot be called now for this cipher
a_compute_mac_tag
uCompute the *binary* MAC tag.
Call this method after the final `encrypt` (the one with no arguments)
to obtain the MAC tag.
The MAC tag is needed by the receiver to determine authenticity
of the message.
:Return: the MAC, as a byte string.

u%02x
uCompute the *printable* MAC tag.
This method is like `digest`.
:Return: the MAC, as a hexadecimal string.
uverify() cannot be called now for this cipher
get_random_bytes
aBLAKE2s
l  T adigest_bits
key
data
uMAC check failed
uValidate the *binary* MAC tag.
Call this method after the final `decrypt` (the one with no arguments)
to check if the message is authentic and valid.
:Parameters:
received_mac_tag : bytes/bytearray/memoryview
This is the *binary* MAC, as received from the sender.
:Raises ValueError:
if the MAC does not match. The message has been tampered with
or the key is incorrect.
unhexlify
uValidate the *printable* MAC tag.
This method is like `verify`.
:Parameters:
hex_mac_tag : string
This is the *printable* MAC, as received from the sender.
:Raises ValueError:
if the MAC does not match. The message has been tampered with
or the key is incorrect.
uEncrypt the message and create the MAC tag in one step.
:Parameters:
plaintext : bytes/bytearray/memoryview
The entire message to encrypt.
:Return:
a tuple with two byte strings:
- the encrypted data
- the MAC
uDecrypted the message and verify its authenticity in one step.
:Parameters:
ciphertext : bytes/bytearray/memoryview
The entire message to decrypt.
received_mac_tag : byte string
This is the *binary* MAC, as received from the sender.
:Return: the decrypted data (byte string).
:Raises ValueError:
if the MAC does not match. The message has been tampered with
or the key is incorrect.
T l apop
T amac_len
l uKeyword missing:
aOcbMode
uCreate a new block cipher, configured in OCB mode.
:Parameters:
factory : module
A symmetric cipher module from `Crypto.Cipher`
(like `Crypto.Cipher.AES`).
:Keywords:
nonce : bytes/bytearray/memoryview
A  value that must never be reused for any other encryption.
Its length can vary from 1 to 15 bytes.
If not specified, a random 15 bytes long nonce is generated.
mac_len : integer
Length of the MAC, in bytes.
It must be in the range ``[8..16]``.
The default is 16 (128 bits).
Any other keyword will be passed to the underlying block cipher.
See the relevant documentation for details (at least ``key`` will need
to be present).

Offset Codebook (OCB) mode.
OCB is Authenticated Encryption with Associated Data (AEAD) cipher mode
designed by Prof. Phillip Rogaway and specified in `RFC7253`_.
The algorithm provides both authenticity and privacy, it is very efficient,
it uses only one key and it can be used in online mode (so that encryption
or decryption can start before the end of the message is available).
This module implements the third and last variant of OCB (OCB3) and it only
works in combination with a 128-bit block symmetric cipher, like AES.
OCB is patented in US but `free licenses`_ exist for software implementations
meant for non-military purposes.
Example:
>>> from Crypto.Cipher import AES
>>> from Crypto.Random import get_random_bytes
>>>
>>> key = get_random_bytes(32)
>>> cipher = AES.new(key, AES.MODE_OCB)
>>> plaintext = b"Attack at dawn"
>>> ciphertext, mac = cipher.encrypt_and_digest(plaintext)
>>> # Deliver cipher.nonce, ciphertext and mac
...
>>> cipher = AES.new(key, AES.MODE_OCB, nonce=nonce)
>>> try:
>>>     plaintext = cipher.decrypt_and_verify(ciphertext, mac)
>>> except ValueError:
>>>     print "Invalid message"
>>> else:
>>>     print plaintext
:undocumented: __package__
.. _RFC7253: http://www.rfc-editor.org/info/rfc7253
.. _free licenses: http://web.cs.ucdavis.edu/~rogaway/ocb/license.htm
a__doc__
a__file__
origin
has_location
a__cached__
binascii
T aunhexlify
uCrypto.Util.py3compat
T abord
a_copy_bytes
bchr
uCrypto.Util.number
T along_to_bytes
bytes_to_long
uCrypto.Util.strxor
T astrxor
uCrypto.Hash
T aBLAKE2s
uCrypto.Random
T aget_random_bytes
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
create_string_buffer
get_raw_buffer
aSmartPointer
c_size_t
c_uint8_ptr
is_buffer
load_pycryptodome_raw_lib
T uCrypto.Cipher._raw_ocb

int OCB_start_operation(void *cipher,
const uint8_t *offset_0,
size_t offset_0_len,
void **pState);
int OCB_encrypt(void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int OCB_decrypt(void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int OCB_update(void *state,
const uint8_t *in,
size_t data_len);
int OCB_digest(void *state,
uint8_t *tag,
size_t tag_len);
int OCB_stop_operation(void *state);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
a__qualname__
a__orig_bases__
aNothingType
L"aNOTHING
aAttribute
aAttrsInstance
aConverter
aFactory
aNothingType
asdict
assoc
astuple
attr
attrib
attributes
attrs
cmp_using
converters
define
evolve
exceptions
field
fields
fields_dict
filters
frozen
get_run_validators
has
ib
make_class
mutable
resolve_types
wsaset_run_validators
setters
validate
validators
a__all__
return
a_make_getattr
T aattr
uattr\__init__.py
u<module attr>
T aname
msg
metadata
meta
mod_name
T amod_name
T amod_name
a__getattr__
a__spec__
.attr.converters
b
:
aConverter
optional_converter
uoptional.<locals>.optional_converter
a_AnnotationExtractor
get_first_param_type
aOptional
a__annotations__
val
get_return_type
return
D atakes_self
takes_field
tpu
A converter that allows an attribute to be optional. An optional attribute
is one which can be set to `None`.
Type annotations will be inferred from the wrapped converter's, if it has
ny.
Args:
converter (typing.Callable):
the converter that is used for non-`None` values.
.. versionadded:: 17.1.0
converter
aNOTHING
uMust pass either `default` or `factory`.
uMust pass either `default` or `factory` but not both.
aFactory
takes_self
u`takes_self` is not supported by default_if_none.
default_if_none_converter
udefault_if_none.<locals>.default_if_none_converter

A converter that allows to replace `None` values by *default* or the result
of *factory*.
Args:
default:
Value to be used if `None` is passed. Passing an instance of
`attrs.Factory` is supported, however the ``takes_self`` option is
*not*.
factory (typing.Callable):
A callable that takes no parameters whose result is used if `None`
is passed.
Raises:
TypeError: If **neither** *default* or *factory* is passed.
TypeError: If **both** *default* and *factory* are passed.
ValueError:
If an instance of `attrs.Factory` is passed with
``takes_self=True``.
.. versionadded:: 18.2.0
default
factory
lower
T tatrue
wtayes
wyaon
w1l T Fafalse
wfano
wnaoff
w0l
uCannot convert value to bool:


Convert "boolean" strings (for example, from environment variables) to real
booleans.
Values mapping to `True`:
- ``True``
- ``"true"`` / ``"t"``
- ``"yes"`` / ``"y"``
- ``"on"``
- ``"1"``
- ``1``
Values mapping to `False`:
- ``False``
- ``"false"`` / ``"f"``
- ``"no"`` / ``"n"``
- ``"off"``
- ``"0"``
- ``0``
Raises:
ValueError: For any other value.
.. versionadded:: 21.3.0

Commonly useful converters.
a__doc__
a__file__
origin
has_location
a__cached__
typing
a_compat
T a_AnnotationExtractor
a_make
T aNOTHING
aConverter
aFactory
pipe
pipe
L adefault_if_none
optional
pipe
to_bool
a__all__
optional
default_if_none
to_bool
uattr\converters.py
u<module attr.converters>
T adefault
factory
msg
default_if_none_converter
T aval
default
T adefault
T aconverter
optional_converter
xtr
wtart
T aval
converter
T aconverter
T aval
inst
field
converter
T aval
msg
a__spec__
.attr.exceptions
m
7
a__init__
msg
value
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aClassVar
T EAttributeError
a__prepare__
aFrozenError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
ufrozenbitarray(initializer=0, /, endian='big', buffer=None) -> frozenbitarray
Return a `frozenbitarray` object.  Initialized the same way a `bitarray`
object is initialized.  A `frozenbitarray` is immutable and hashable,
nd may therefore be used as a dictionary key.
a__qualname__
a__init__
ufrozenbitarray.__init__
ufrozenbitarray.__repr__
a__hash__
ufrozenbitarray.__hash__
a__delitem__
ufrozenbitarray.__delitem__
append
bytereverse
clear
extend
encode
fill
frombytes
fromfile
insert
invert
pack
pop
remove
reverse
setall
sort
a__setitem__
a__iadd__
a__iand__
a__imul__
a__ior__
a__ixor__
a__ilshift__
a__irshift__
a__orig_bases__
bits2bytes
T l atest
ubitarray\__init__.py
u<module bitarray>
T aself
args
kwargs
T aself
waT aself
T a__n
T a__class__
T averbosity
a__spec__
.bitarray.util
bitarray
frombytes
urandom
bits2bytes
uurandom(length, /, endian=None) -> bitarray
Return a bitarray of `length` random bits (uses `os.urandom`).
stdout
pprint
T astream
indent
width
ugroup must be >= 1
uindent must be >= 0
uwidth must be > %d (indent)
l a__name__
u'''
w'u
write
u%s(%s
epl
stream

%s
indent
w agroup
T w T w
u%s)
flush
upprint(bitarray, /, stream=None, group=8, indent=4, width=80)
Prints the formatted representation of object on `stream` (which defaults
to `sys.stdout`).  By default, elements are grouped in bytes (8 elements),
nd 8 bytes (64 elements) per line.
Non-bitarray objects are printed by the standard library
function `pprint.pprint()`.
ustr expected for mode, got '%s'
T aleft
right
both
umode must be 'left', 'right' or 'both', got %r
right
find
T l :nl
naleft
T l pT aright
ustrip(bitarray, /, mode='right') -> bitarray
Return a new bitarray with zeros stripped from left, right or both ends.
Allowed values for mode are the strings: `left`, `right`, `both`
uintervals(bitarray, /) -> iterator
Compute all uninterrupted intervals of 1s and 0s, and return an
iterator over tuples `(value, start, stop)`.  The intervals are guaranteed
to be in order, and their size is always non-zero (`stop - start > 0`).
a__a
stop
wnaindex
value
intervals
ubitarray expected, got '%s'
unon-empty bitarray expected
endian
little
padbits
zeros
from_bytes
tobytes
T abyteorder
uba2int(bitarray, /, signed=False) -> int
Convert the given bitarray to an integer.
The bit-endianness of the bitarray is respected.
`signed` indicates whether two's complement is used to represent the integer.
uint expected, got '%s'
uint expected for length
ulength must be > 0
usigned requires length
usigned integer not in range(%d, %d), got %d
uunsigned integer not positive, got %d
uunsigned integer not in range(0, %d), got %d
a__i
to_bytes
bit_length
length
strip
wauint2ba(int, /, length=None, endian=None, signed=False) -> bitarray
Convert the given integer to a bitarray (with given bit-endianness,
nd no leading (big-endian) / trailing (little-endian) zeros), unless
the `length` of the bitarray is provided.  An `OverflowError` is raised
if the integer is not representable with the given number of bits.
`signed` determines whether two's complement is used to represent the integer,
nd requires `length` to be provided.
heapq
T aheappush
heappop
heappush
heappop
T Oobject
a__prepare__
aNode
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
uA way of looking up TreeBuilder subclasses by their name or by desired
features.
a__qualname__
uDict[str, List[Type[TreeBuilder]]]
uList[Type[TreeBuilder]]
D areturn
aNone
uTreeBuilderRegistry.__init__
D atreebuilder_class
return
utype[TreeBuilder]
aNone
uTreeBuilderRegistry.register
D afeatures
return
str
uOptional[Type[TreeBuilder]]
lookup
uTreeBuilderRegistry.lookup
a__orig_bases__
uTurn a textual document into a Beautiful Soup object tree.
This is an abstract superclass which smooths out the behavior of
different parser libraries into a single, unified interface.
:param multi_valued_attributes: If this is set to None, the
TreeBuilder will not turn any values for attributes like
'class' into lists. Setting this to a dictionary will
customize this behavior; look at :py:attr:`bs4.builder.HTMLTreeBuilder.DEFAULT_CDATA_LIST_ATTRIBUTES`
for an example.
Internally, these are called "CDATA list attributes", but that
probably doesn't make sense to an end-user, so the argument name
is ``multi_valued_attributes``.
:param preserve_whitespace_tags: A set of tags to treat
the way <pre> tags are treated in HTML. Tags in this set
re immune from pretty-printing; their contents will always be
output as-is.
:param string_containers: A dictionary mapping tag names to
the classes that should be instantiated to contain the textual
contents of those tags. The default is to use NavigableString
for every tag, no matter what the name. You can override the
default by changing :py:attr:`DEFAULT_STRING_CONTAINERS`.
:param store_line_numbers: If the parser keeps track of the line
numbers and positions of the original markup, that information
will, by default, be stored in each corresponding
:py:class:`bs4.element.Tag` object. You can turn this off by
passing store_line_numbers=False; then Tag.sourcepos and
Tag.sourceline will always be None. If the parser you're using
doesn't keep track of this information, then store_line_numbers
is irrelevant.
:param attribute_dict_class: The value of a multi-valued attribute
(such as HTML's 'class') willl be stored in an instance of this
class.  The default is Beautiful Soup's built-in
`AttributeValueList`, which is a normal Python list, and you
will probably never need to change it.
object
D amulti_valued_attributes
preserve_whitespace_tags
store_line_numbers
string_containers
empty_element_tags
attribute_dict_class
attribute_value_list_class
uDict[str, Set[str]]
uSet[str]
bool
uDict[str, Type[NavigableString]]
uSet[str]
uType[AttributeDict]
uType[AttributeValueList]
uTreeBuilder.__init__
u[Unknown tree builder]
aNAME
str
aALTERNATE_NAMES
uIterable[str]
is_xml
bool
picklable
uOptional[BeautifulSoup]
uOptional[Set[str]]
uDict[str, Set[str]]
uSet[str]
uDict[str, Type[NavigableString]]
tracks_line_numbers
set
uDict[str, Type[bs4.element.NavigableString]]
D asoup
return
aBeautifulSoup
aNone
initialize_soup
uTreeBuilder.initialize_soup
uDo any work necessary to reset the underlying parser
for a new document.
By default, this does nothing.
reset
uTreeBuilder.reset
D atag_name
return
str
bool
can_be_empty_element
uTreeBuilder.can_be_empty_element
D amarkup
return
a_RawMarkup
aNone
feed
uTreeBuilder.feed
T nnnD amarkup
user_specified_encoding
document_declared_encoding
exclude_encodings
return
a_RawMarkup
uOptional[_Encoding]
uOptional[_Encoding]
uOptional[_Encodings]
uIterable[Tuple[_RawMarkup, Optional[_Encoding], Optional[_Encoding], bool]]
D afragment
return
str
patest_fragment_to_document
uTreeBuilder.test_fragment_to_document
D atag
return
aTag
bool
uSet up any substitutions that will need to be performed on
a `Tag` when it's output as a string.
By default, this does nothing. See `HTMLTreeBuilder` for a
case where this is used.
:return: Whether or not a substitution was performed.
:meta private:
set_up_substitutions
uTreeBuilder.set_up_substitutions
D atag_name
attrs
return
str
a_RawOrProcessedAttributeValues
a_AttributeValues
a_replace_cdata_list_attribute_values
uTreeBuilder._replace_cdata_list_attribute_values
uA Beautiful Soup treebuilder that listens for SAX events.
This is not currently used for anything, and it will be removed
soon. It was a good idea, but it wasn't properly integrated into the
rest of Beautiful Soup, so there have been long stretches where it
hasn't worked properly.
D aargs
kwargs
return
aAny
paNone
uSAXTreeBuilder.__init__
uSAXTreeBuilder.feed
close
uSAXTreeBuilder.close
D aname
attrs
return
str
uDict[str, str]
aNone
uSAXTreeBuilder.startElement
D aname
return
str
aNone
uSAXTreeBuilder.endElement
D ansTuple
nodeName
attrs
return
uTuple[str, str]
str
uDict[str, str]
aNone
startElementNS
uSAXTreeBuilder.startElementNS
D ansTuple
nodeName
return
uTuple[str, str]
str
aNone
endElementNS
uSAXTreeBuilder.endElementNS
D aprefix
nodeValue
return
str
paNone
startPrefixMapping
uSAXTreeBuilder.startPrefixMapping
D aprefix
return
str
aNone
endPrefixMapping
uSAXTreeBuilder.endPrefixMapping
D acontent
return
str
aNone
characters
uSAXTreeBuilder.characters
startDocument
uSAXTreeBuilder.startDocument
endDocument
uSAXTreeBuilder.endDocument
aHTMLTreeBuilder
uThis TreeBuilder knows facts about HTML, such as which tags are treated
specially by the HTML standard.
L aarea
base
br
col
embed
hr
img
input
keygen
link
menuitem
meta
param
source
track
wbr
basefont
bgsound
command
frame
image
isindex
nextid
spacer
S asource
img
meta
input
param
keygen
col
hr
isindex
spacer
command
frame
embed
link
menuitem
image
basefont
wbr
track
area
br
nextid
bgsound
base
L#aaddress
article
aside
blockquote
canvas
dd
div
dl
dt
fieldset
figcaption
figure
footer
form
h1
h2
h3
h4
h5
h6
header
hr
li
main
nav
noscript
ol
output
wpapre
section
table
tfoot
ul
video
S#amain
h2
wpanav
form
h5
noscript
ul
li
div
dt
hr
tfoot
blockquote
h3
video
footer
aside
figure
figcaption
h4
h6
header
fieldset
dl
h1
pre
section
article
output
address
dd
table
canvas
ol
aDEFAULT_BLOCK_ELEMENTS
rt
rp
style
script
template
D w*waalink
td
th
form
object
area
icon
iframe
output
S adropzone
class
accesskey
S arel
rev
S arel
rev
S aheaders
S aheaders
S uaccept-charset
S aarchive
S arel
S asizes
S asandbox
S afor
pre
textarea
S apre
textarea
uset[str]
uHTMLTreeBuilder.set_up_substitutions
aDetectsXMLParsedAsHTML
uA mixin class for any class (a TreeBuilder, or some class used by a
TreeBuilder) that's in a position to detect whether an XML
document is being incorrectly parsed as HTML, and issue an
ppropriate warning.
This requires being able to observe an incoming processing
instruction that might be an XML declaration, and also able to
observe tags as they're opened. If you can't do that for a given
`TreeBuilder`, there's a less reliable implementation based on
examining the raw markup.
compile
u<[^ +]html
wIuPattern[str]
c<[^ +]html
uPattern[bytes]
u<?xml
c<?xml
bytes
uOptional[str]
classmethod
T l D amarkup
stacklevel
return
uOptional[_RawMarkup]
int
bool
warn_if_markup_looks_like_xml
uDetectsXMLParsedAsHTML.warn_if_markup_looks_like_xml
T l D astacklevel
return
int
aNone
uDetectsXMLParsedAsHTML._warn
a_initialize_xml_detector
uDetectsXMLParsedAsHTML._initialize_xml_detector
D aprocessing_instruction
return
str
aNone
a_document_might_be_xml
uDetectsXMLParsedAsHTML._document_might_be_xml
a_root_tag_encountered
uDetectsXMLParsedAsHTML._root_tag_encountered
D amodule
return
aModuleType
aNone
register_treebuilders_from

T a_htmlparser
a_htmlparser
T a_html5lib
a_html5lib
T a_lxml
a_lxml
ubs4\builder\__init__.py
T a.0
wxT a.0
key
value
u<module bs4.builder>
T a__class__
T aself
args
kwargs
a__class__
T aself
multi_valued_attributes
preserve_whitespace_tags
store_line_numbers
string_containers
empty_element_tags
attribute_dict_class
attribute_value_list_class
T aself
T aself
processing_instruction
T	aself
tag_name
attrs
universal
modified_value
original_value
modified_attrs
tag_specific
attr
T aself
name
T acls
stacklevel
T aself
tag_name
T aself
content
T aself
nsTuple
nodeName
T aself
prefix
T aself
markup
T aself
soup
T aself
features
feature_list
candidates
candidate_set
feature
we_have_the_feature
candidate
T aself
markup
user_specified_encoding
document_declared_encoding
exclude_encodings
T aself
treebuilder_class
feature
T amodule
this_module
name
obj
T aself
tag
content
charset
http_equiv
substituted
T aself
tag
T aself
name
attrs
T aself
nsTuple
nodeName
attrs
T aself
prefix
nodeValue
T aself
fragment
T acls
markup
stacklevel
markup_b
markup_s
looks_like_xml
a__spec__
.bs4
K
convertEntities
warnings
warn
T uBS4 does not respect the convertEntities argument to the BeautifulSoup constructor. Entities are always converted to Unicode characters.
markupMassage
T uBS4 does not respect the markupMassage argument to the BeautifulSoup constructor. The tree builder is responsible for any necessary markup massage.
smartQuotesTo
T uBS4 does not respect the smartQuotesTo argument to the BeautifulSoup constructor. Smart quotes are always converted to Unicode characters.
selfClosingTags
T uBeautiful Soup 4 does not respect the selfClosingTags argument to the BeautifulSoup constructor. The tree builder is responsible for understanding self-closing tags.
isHTML
T uBeautiful Soup 4 does not respect the isHTML argument to the BeautifulSoup constructor. Suggest you use features='lxml' for HTML and features='lxml-xml' for XML.
old_name
new_name
return
aOptional
aAny
deprecated_argument
uBeautifulSoup.__init__.<locals>.deprecated_argument
T aparseOnlyThese
parse_only
excludes_everything
uThe given value for parse_only will exclude everything:

aUserWarning
D astacklevel
l T afromEncoding
from_encoding
T uYou provided Unicode markup but also provided a value for from_encoding. Your from_encoding will be ignored.
element_classes
features
aDEFAULT_BUILDER_FEATURES
builder_registry
lookup
aFeatureNotFound
uCouldn't find a tree builder with the features you requested: %s. Do you need to install a parser library?
w,abuilder
builder_class
aNAME
aALTERNATE_NAMES
is_xml
aXML
aHTML
a_getframe
T l af_globals
f_lineno
get
T a__file__
lower
endswith
T T u.pyc
u.pyo
:nq nafilename
line_number
parser
markup_type
aGuessedAtParserWarning
aMESSAGE
D astacklevel
l T uKeyword arguments to the BeautifulSoup constructor will be ignored. These would normally be passed into the TreeBuilder constructor, but a TreeBuilder instance was passed in as `builder`.
known_xml
a_namespaces
parse_only
read
T Obytes
Ostr
a__len__
uIncoming markup is of an invalid type:
u. Markup must be a string, a bytestring, or an open filehandle.
d<d
w<w
a_markup_is_url
a_markup_resembles_filename
cast
a_RawMarkup
markup
prepare_markup
T aexclude_encodings
self
original_encoding
declared_html_encoding
contains_replacement_characters
reset
initialize_soup
a_feed
aParserRejectedMarkup
rejections
uThe markup you provided was rejected by the parser. Trying a different parser or a different encoding may help.
Original exception(s) from parser:

soup
uConstructor.
:param markup: A string or a file-like object representing
markup to be parsed.
:param features: Desirable features of the parser to be
used. This may be the name of a specific parser ("lxml",
"lxml-xml", "html.parser", or "html5lib") or it may be the
type of markup to be used ("html", "html5", "xml"). It's
recommended that you name a specific parser, so that
Beautiful Soup gives you the same results across platforms
nd virtual environments.
:param builder: A TreeBuilder subclass to instantiate (or
instance to use) instead of looking one up based on
`features`. You only need to use this if you've implemented a
custom TreeBuilder.
:param parse_only: A SoupStrainer. Only parts of the document
matching the SoupStrainer will be considered. This is useful
when parsing part of a document that would otherwise be too
large to fit into memory.
:param from_encoding: A string indicating the encoding of the
document to be parsed. Pass this in if Beautiful Soup is
guessing wrongly about the document's encoding.
:param exclude_encodings: A list of strings indicating
encodings known to be wrong. Pass this in if you don't know
the document's encoding but you know Beautiful Soup's guess is
wrong.
:param element_classes: A dictionary mapping BeautifulSoup
classes like Tag and NavigableString, to other classes you'd
like to be instantiated instead as the parse tree is
built. This is useful for subclassing Tag or NavigableString
to modify default behavior.
:param kwargs: For backwards compatibility purposes, the
constructor accepts certain keyword arguments used in
Beautiful Soup 3. None of these arguments do anything in
Beautiful Soup 4; they will result in a warning and then be
ignored.
Apart from this, any keyword arguments passed into the
BeautifulSoup constructor are propagated to the TreeBuilder
constructor. This makes it possible to configure a
TreeBuilder by passing in arguments, not just by saying which
one to use.
kwargs
uThe "%s" argument to the BeautifulSoup constructor was renamed to "%s" in Beautiful Soup 4.0.0
aDeprecationWarning
pop
uCreate a new BeautifulSoup object with the same TreeBuilder,
but not associated with any markup.
This is the first step of the deepcopy process.
picklable
contents
decode
a_most_recent_element
aHTMLParserTreeBuilder
T uutf-8
replace
uEnsure `markup` is Unicode so it's safe to send into warnings.warn.
warnings.warn had this problem back in 2010 but fortunately
not anymore. This has not been used for a long time; I just
noticed that fact while working on 4.13.0.
T chttp:
chttps:
d T uhttp:
uhttps:
w aMarkupResemblesLocatorWarning
aURL_MESSAGE
D awhat
aURL
uError-handling method to raise a warning if incoming markup looks
like a URL.
:param markup: A string of markup.
:return: Whether or not the markup resembled a URL
closely enough to justify issuing a warning.
startswith
u<genexpr>
uBeautifulSoup._markup_is_url.<locals>.<genexpr>
encode
T autf8
L c.html
c.htm
c.xml
c.xhtml
c.txt
c?*#&;>$|
c//
c
T d:arfind
T q l aFILENAME_MESSAGE
D awhat
filename
uError-handling method to issue a warning if incoming markup
resembles a filename.
:param markup: A string of markup.
:return: Whether or not the markup resembled a filename
closely enough to justify issuing a warning.
uBeautifulSoup._markup_resembles_filename.<locals>.<genexpr>
feed
endData
currentTag
name
aROOT_TAG_NAME
popTag
uInternal method that parses previously set markup, creating a large
number of Tag and NavigableString objects.
aTag
a__init__
hidden
current_data
tagStack
aCounter
open_tag_counter
preserve_whitespace_tag_stack
string_container_stack
pushTag
uReset this object to a state as though it had never parsed any
markup.
attribute_dict_class
update
aType
T asourceline
sourcepos
string
uCreate a new Tag associated with this BeautifulSoup object.
:param name: The name of the new Tag.
:param namespace: The URI of the new Tag's XML namespace, if any.
:param prefix: The prefix for the new Tag's XML namespace, if any.
:param attrs: A dictionary of this Tag's attribute values; can
be used instead of ``kwattrs`` for attributes like 'class'
that are reserved words in Python.
:param sourceline: The line number where this tag was
(purportedly) found in its source document.
:param sourcepos: The character position within ``sourceline`` where this
tag was (purportedly) found.
:param string: String content for the new Tag, if any.
:param kwattrs: Keyword arguments for the new Tag's attribute values.
aNavigableString
string_containers
uFind the class that should be instantiated to hold a given kind of
string.
This may be a built-in Beautiful Soup class or a custom class passed
in to the BeautifulSoup constructor.
string_container
uCreate a new `NavigableString` associated with this `BeautifulSoup`
object.
:param s: The string content of the `NavigableString`
:param subclass: The subclass of `NavigableString`, if any, to
use. If a document is being processed, an appropriate
subclass for the current location in the document will
be determined automatically.
uBeautifulSoup objects don't support insert_before().
uThis method is part of the PageElement API, but `BeautifulSoup` doesn't implement
it because there is nothing before or after it in the parse tree.
uBeautifulSoup objects don't support insert_after().
uInternal method called by _popToTag when a tag is closed.
:meta private:
append
preserve_whitespace_tags
uInternal method called by handle_starttag when a tag is opened.
:meta private:
aASCII_SPACES
allow_string_creation
object_was_parsed
uMethod called by the TreeBuilder when the end of a data segment
occurs.
:param containerClass: The class to use when incorporating the
data segment into the parse tree.
:meta private:
next_element
next_sibling
previous_sibling
previous_element
setup
a_linkage_fixer
uMethod called by the TreeBuilder to integrate an object into the
parse tree.
:meta private:
parent
aPageElement
a_last_descendant
T Fatarget
uMake sure linkage of this fragment is sound.
prefix
most_recently_popped
uPops the tag stack up to and including the most recent
instance of the given tag.
If there are no open tags with the given name, nothing will be
popped.
:param name: Pop up to the most recent tag with this name.
:param nsprefix: The namespace prefix that goes with `name`.
:param inclusivePop: It this is false, pops the tag stack up
to but *not* including the most recent instqance of the
given tag.
:meta private:
allow_tag_creation
T asourceline
sourcepos
namespaces
uCalled by the tree builder when a new tag is encountered.
:param name: Name of the tag.
:param nsprefix: Namespace prefix for the tag.
:param attrs: A dictionary of attribute values. Note that
ttribute values are expected to be simple strings; processing
of multi-valued attributes such as "class" comes later.
:param sourceline: The line number where this tag was found in its
source document.
:param sourcepos: The character position within `sourceline` where this
tag was found.
:param namespaces: A dictionary of all namespace prefix mappings
currently in scope in the document.
If this method returns None, the tag was rejected by an active
`ElementFilter`. You should proceed as if the tag had not occurred
in the document. For instance, if this was a self-closing tag,
don't call handle_endtag.
:meta private:
a_popToTag
uCalled by the tree builder when an ending tag is encountered.
:param name: Name of the tag.
:param nsprefix: Namespace prefix for the tag.
:meta private:
uCalled by the tree builder when a chunk of textual data is
encountered.
:meta private:
aPYTHON_SPECIFIC_ENCODINGS
u encoding="%s"
u<?xml version="1.0"%s?>
uAs of 4.13.0, the first argument to BeautifulSoup.decode has been changed from bool to int, to match Tag.decode. Pass in a value of
u instead.
pretty_print
uAs of 4.13.0, the pretty_print argument to BeautifulSoup.decode has been removed, to match Tag.decode. Pass in a value of indent_level=
aBeautifulSoup
uReturns a string representation of the parse tree
s a full HTML or XML document.
:param indent_level: Each line of the rendering will be
indented this many levels. (The ``formatter`` decides what a
'level' means, in terms of spaces or other characters
output.) This is used internally in recursive calls while
pretty-printing.
:param eventual_encoding: The encoding of the final document.
If this is None, the document will be a Unicode string.
:param formatter: Either a `Formatter` object, or a string naming one of
the standard formatters.
:param iterator: The iterator to use when navigating over the
parse tree. This is only used by `Tag.decode_contents` and
you probably won't need to use it.
xml
uThe BeautifulStoneSoup class was deprecated in version 4.0.0. Instead of using it, pass features="xml" into the BeautifulSoup constructor.
aBeautifulStoneSoup
uBeautiful Soup Elixir and Tonic - "The Screen-Scraper's Friend".
http://www.crummy.com/software/BeautifulSoup/
Beautiful Soup uses a pluggable XML or HTML parser to parse a
(possibly invalid) document into a tree representation. Beautiful Soup
provides methods and Pythonic idioms that make it easy to navigate,
search, and modify the parse tree.
Beautiful Soup works with Python 3.7 and up. It works better if lxml
nd/or html5lib is installed, but they are not required.
For more than you ever wanted to know about Beautiful Soup, see the
documentation: http://www.crummy.com/software/BeautifulSoup/bs4/doc/
a__doc__
a__file__
path
dirname
environ
T aNUITKA_PACKAGE_bs4
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uLeonard Richardson (leonardr@segfault.org)
a__author__
u4.13.3
a__version__
uCopyright (c) 2004-2025 Leonard Richardson
a__copyright__
aMIT
a__license__
L aAttributeResemblesVariableWarning
aBeautifulSoup
aComment
aDeclaration
aProcessingInstruction
aResultSet
aCSS
aScript
aStylesheet
aTag
aTemplateString
aElementFilter
aUnicodeDammit
aCData
aDoctype
aFeatureNotFound
aParserRejectedMarkup
aStopParsing
aAttributeResemblesVariableWarning
aGuessedAtParserWarning
aMarkupResemblesLocatorWarning
aUnusualUsageWarning
aXMLParsedAsHTMLWarning
a__all__
collections
T aCounter
sys
T abuilder_registry
aTreeBuilder
aTreeBuilder
ubuilder._htmlparser
T aHTMLParserTreeBuilder
dammit
T aUnicodeDammit
aUnicodeDammit
css
T aCSS
aCSS
a_deprecation
T a_deprecated
a_deprecated
element
T aCData
aComment
aDEFAULT_OUTPUT_ENCODING
aDeclaration
aDoctype
aNavigableString
aPageElement
aProcessingInstruction
aPYTHON_SPECIFIC_ENCODINGS
aResultSet
aScript
aStylesheet
aTag
aTemplateString
aCData
aComment
aDEFAULT_OUTPUT_ENCODING
aDeclaration
aDoctype
aProcessingInstruction
aResultSet
aScript
aStylesheet
aTemplateString
formatter
T aFormatter
aFormatter
filter
T aElementFilter
aSoupStrainer
aElementFilter
aSoupStrainer
aCounterType
aDict
aIterator
aList
aSequence
aUnion
ubs4._typing
T a_Encoding
a_Encodings
a_IncomingMarkup
a_InsertableElement
a_RawAttributeValue
a_RawAttributeValues
a_RawMarkup
a_Encoding
a_Encodings
a_IncomingMarkup
a_InsertableElement
a_RawAttributeValue
a_RawAttributeValues
ubs4.exceptions
T aFeatureNotFound
aParserRejectedMarkup
aStopParsing
aStopParsing
ubs4._warnings
T aAttributeResemblesVariableWarning
aGuessedAtParserWarning
aMarkupResemblesLocatorWarning
aUnusualUsageWarning
aXMLParsedAsHTMLWarning
aAttributeResemblesVariableWarning
aUnusualUsageWarning
aXMLParsedAsHTMLWarning
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>

Logging class that can be used for lower level debug logging.
return
bool
uExtendedDebugLogger.show_debug2
message
str
args
kwargs
uExtendedDebugLogger.debug2
a__reduce__
uExtendedDebugLogger.__reduce__
a__orig_bases__
D areturn
nasetup_DEBUG2_logging
contextmanager
T nT aTHasLoggerMeta
aHasLoggerMeta
aTHasLoggerMeta
T Otype
aHasLoggerMeta

Assigns a logger instance to a class, derived from the import path and name.
This metaclass uses `__qualname__` to identify a unique and meaningful name
to use when creating the associated logger for a given class.
mcls
bases
namespace
uHasLoggerMeta.__new__
classmethod
value
replace_logger_class
uHasLoggerMeta.replace_logger_class
other
type
meta_compat
uHasLoggerMeta.meta_compat
metaclass
T aHasLogger
T
aHasLogger
a__annotations__
aHasExtendedDebugLoggerMeta
T aHasExtendedDebugLogger
T
aHasExtendedDebugLogger
ueth_utils\logging.py
T amessage
args
kwargs
u<module eth_utils.logging>
T a__class__
T amcls
name
bases
namespace
logger
a__class__
T aself
T alogger_class
original_logger_class
T aself
message
args
kwargs
T aname
T aname
logger_class
manager
T amcls
other
T amcls
value

a__spec__
.eth_utils.module_loading
o
rsplit
T w.l u
u doesn't look like a module path
import_module
uModule "
u" does not define a "
u" attribute/class

Import a variable using its path and name.
:param dotted_path: dotted module path and variable/class name
:return: the attribute/class designated by the last name in the path
:raise: ImportError, if the import failed
Source: django.utils.module_loading
a__doc__
a__file__
origin
has_location
a__cached__
aAny
dotted_path
return
import_string
ueth_utils\module_loading.py
u<module eth_utils.module_loading>
T adotted_path
module_path
class_name
msg
module
a__spec__
.eth_utils.network
K
8
join
a__file__
a__json
ueth_networks.json
uUTF-8
a__enter__
a__exit__
json
load
T nnnanetwork_data
aNetwork
chainId
name
shortName
aChainId
T achain_id
name
shortName
symbol
networks_obj
networks_by_id
aValidationError
uchain_id is not recognized:

network_names_by_id
network_short_names_by_id
a__doc__
origin
has_location
a__cached__
dataclasses
T adataclass
dataclass
os
aList
eth_typing
T aChainId
eth_utils
T aValidationError
a__qualname__
a__orig_bases__
T Ostr
Obytes
Oint
T Ostr
Oint
aNetworkType
L aAnyUrl
aAnyHttpUrl
aFileUrl
aHttpUrl
stricturl
aEmailStr
aNameEmail
aIPvAnyAddress
aIPvAnyInterface
aIPvAnyNetwork
aPostgresDsn
aCockroachDsn
aAmqpDsn
aRedisDsn
aMongoDsn
aKafkaDsn
validate_email
a__all__
u(?:(?P<ipv4>(?:\d{1,3}\.){3}\d{1,3})(?=$|[/:#?])|(?P<ipv6>\[[A-F0-9]*:[A-F0-9:]+\])(?=$|[/:#?])|(?P<domain>[^\s/:?#]+))?(?::(?P<port>\d+))?
u(?:(?P<scheme>[a-z][a-z0-9+\-.]+)://)?
u(?:(?P<user>[^\s:/]*)(?::(?P<password>[^\s/]*))?@)?
u(?P<path>/[^\s?#]*)?
u(?:\?(?P<query>[^\s#]*))?
u(?:#(?P<fragment>[^\s#]*))?
return
T Ostr
a__annotations__
l   astr
bool
set
url
object
uAnyUrl.__new__
D	auser
password
host
tld
host_type
port
path
query
fragment
nnnnadomain
nnnnuAnyUrl.__init__
classmethod
D auser
password
port
path
query
fragment
nnnnnna_kwargs
uAnyUrl.build
field_schema
a__modify_schema__
uAnyUrl.__modify_schema__
D areturn
aCallableGenerator
field
aModelField
config
aBaseConfig
uAnyUrl.validate
wmuAnyUrl._build_url
staticmethod
uAnyUrl._match_url
uAnyUrl._validate_port
T tavalidate_port
uAnyUrl.validate_parts
uAnyUrl.validate_host
D aparts
return
aParts
aParts
uAnyUrl.get_default_parts
uAnyUrl.apply_default_parts
uAnyUrl.__repr__
aAnyHttpUrl
S ahttps
http
aHttpUrl
l  S aport
uHttpUrl.get_default_parts
aFileUrl
S afile
aMultiHostDsn
T ahosts
D ahosts
naHostParts
args
kwargs
uMultiHostDsn.__init__
uMultiHostDsn._match_url
uMultiHostDsn.validate_parts
uMultiHostDsn._build_url
aPostgresDsn
S	apostgresql
upostgresql+pg8000
upostgresql+asyncpg
postgres
upostgresql+psycopg
upostgresql+psycopg2
upostgresql+py-postgresql
upostgresql+psycopg2cffi
upostgresql+pygresql
aCockroachDsn
S acockroachdb
ucockroachdb+asyncpg
ucockroachdb+psycopg2
aAmqpDsn
S aamqps
amqp
aRedisDsn
S arediss
redis
uRedisDsn.get_default_parts
aMongoDsn
S amongodb
uMongoDsn.get_default_parts
aKafkaDsn
S akafka
uKafkaDsn.get_default_parts
D astrip_whitespace
min_length
max_length
tld_required
host_required
allowed_schemes
tl l   tpnastricturl
D areturn
naEmailStr
uEmailStr.__modify_schema__
uEmailStr.validate
T aname
email
uNameEmail.__init__
other
a__eq__
uNameEmail.__eq__
uNameEmail.__modify_schema__
uNameEmail.validate
a__str__
uNameEmail.__str__
aIPvAnyAddress
uIPvAnyAddress.__modify_schema__
bytes
int
uIPvAnyAddress.validate
aIPvAnyInterface
uIPvAnyInterface.__modify_schema__
uIPvAnyInterface.validate
aIPvAnyNetwork
uIPvAnyNetwork.__modify_schema__
uIPvAnyNetwork.validate
T u([\w ]*?) *<(.*)> *
l  T Ostr
pupydantic\v1\networks.py
T a.0
wnaself
T a__class__
u<module pydantic.v1.networks>
T aself
other
T acls
T aself
url
scheme
user
password
host
tld
host_type
port
path
query
fragment
T aself
hosts
args
kwargs
a__class__
T aself
name
email
T acls
field_schema
T acls
url
kwargs
T aself
extra
a__class__
T aself
T acls
wmaurl
parts
host
tld
host_type
rebuild
Tacls
wmaurl
parts
hosts_parts
wdahost_re
host
tld
host_type
rebuild
port
host_part
T aurl
T acls
parts
key
value
T aascii_chunk
ascii_domain_ending
T acls
scheme
user
password
host
port
path
query
fragment
a_kwargs
parts
url
T aparts
T weT aint_chunk
int_domain_ending
T astrip_whitespace
min_length
max_length
tld_required
host_required
allowed_schemes
namespace
T acls
value
field
config
url
wmaoriginal_parts
parts
T acls
value
T	avalue
name
wmaemail
parts
weaat_index
local_part
global_part
T	acls
parts
tld
host_type
rebuild
wfahost
is_international
wdT acls
parts
validate_port
scheme
user
T acls
parts
validate_port
a__class__
a__spec__
.pydantic.v1.parse
=
endswith
T T ajson
javascript
T apickle
aProtocol
pickle
uUnknown content-type:

json
decode
uTrying to decode with pickle with allow_pickle=False
encode
loads
uUnknown protocol:
aPath
read_bytes
suffix
T u.js
u.json
u.pkl
load_str_bytes
T aproto
content_type
encoding
allow_pickle
json_loads
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aEnum
aEnum
pathlib
T aPath
aAny
aCallable
aUnion
upydantic.v1.types
T aStrBytes
aStrBytes
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
a__qualname__
name
str
bases
dct
uConstrainedNumberMeta.__new__
a__orig_bases__
T Oint
aStrictBool

StrictBool to allow for bools which are not type-coerced.
classmethod
field_schema
a__modify_schema__
uStrictBool.__modify_schema__
D areturn
aCallableGenerator
bool
uStrictBool.validate
metaclass
uConstrainedInt.__modify_schema__
D astrict
gt
ge
lt
le
multiple_of
Fnnnnnaconint
aPositiveInt
aNegativeInt
aNonPositiveInt
aNonNegativeInt
aStrictInt
T Ofloat
uConstrainedFloat.__modify_schema__
D astrict
gt
ge
lt
le
multiple_of
allow_inf_nan
Fnnnnnnaconfloat
aPositiveFloat
aNegativeFloat
aNonPositiveFloat
aNonNegativeFloat
aStrictFloat
aFiniteFloat
T Obytes
uConstrainedBytes.__modify_schema__
D astrip_whitespace
to_upper
to_lower
min_length
max_length
strict
FppnnFaconbytes
aStrictBytes
T Ostr
uConstrainedStr.__modify_schema__
uConstrainedStr.validate
staticmethod
uConstrainedStr._get_pattern
D astrip_whitespace
to_upper
to_lower
strict
min_length
max_length
curtail_length
regex
Fpppnnnnaconstr
aStrictStr
T Oset
set
a__origin__
int
uConstrainedSet.__modify_schema__
D wvareturn
uOptional[Set[T]]
uOptional[Set[T]]
uConstrainedSet.set_length_validator
D amin_items
max_items
nnaconset
T Ofrozenset
frozenset
uConstrainedFrozenSet.__modify_schema__
D wvareturn
uOptional[FrozenSet[T]]
uOptional[FrozenSet[T]]
uConstrainedFrozenSet.frozenset_length_validator
confrozenset
T Olist
list
uConstrainedList.__modify_schema__
D wvareturn
uOptional[List[T]]
uOptional[List[T]]
uConstrainedList.list_length_validator
uConstrainedList.unique_items_validator
D amin_items
max_items
unique_items
nnnaconlist
aPyObject
validate_always
uPyObject.validate
uConstrainedDecimal.__modify_schema__
uConstrainedDecimal.validate
D agt
ge
lt
le
max_digits
decimal_places
multiple_of
nnnnnnnacondecimal
aUUID1
uUUID1.__modify_schema__
aUUID3
l aUUID4
l aUUID5
l aFilePath
uFilePath.__modify_schema__
uFilePath.validate
aDirectoryPath
uDirectoryPath.__modify_schema__
uDirectoryPath.validate
aJsonMeta
wtuJsonMeta.__getitem__
T aJson
T
uJson.__modify_schema__
aABC
aSecretField

Note: this should be implemented as a generic like `SecretField(ABC, Generic[T])`,
the `__init__()` should be part of the abstract class and the
`get_secret_value()` method should use the generic `T` type.
However Cython doesn't support very well generics at the moment and
the generated code fails to be imported (see
https://github.com/cython/cython/issues/2753).
a__eq__
uSecretField.__eq__
a__str__
uSecretField.__str__
a__hash__
uSecretField.__hash__
abstractmethod
uSecretField.get_secret_value
aSecretStr
uSecretStr.__modify_schema__
uSecretStr.validate
a__init__
uSecretStr.__init__
a__repr__
uSecretStr.__repr__
a__len__
uSecretStr.__len__
display
uSecretStr.display
uSecretStr.get_secret_value
aSecretBytes
uSecretBytes.__modify_schema__
uSecretBytes.validate
bytes
uSecretBytes.__init__
uSecretBytes.__repr__
uSecretBytes.__len__
uSecretBytes.display
uSecretBytes.get_secret_value
uAmerican Express
aMastercard
aVisa
uPaymentCardBrand.__str__
aPaymentCardNumber

Based on: https://en.wikipedia.org/wiki/Payment_card_number
l l acard_number
uPaymentCardNumber.__init__
property
masked
uPaymentCardNumber.masked
uPaymentCardNumber.validate_digits
uPaymentCardNumber.validate_luhn_check_digit
D acard_number
return
aPaymentCardNumber
aPaymentCardNumber
uPaymentCardNumber.validate_length_for_brand
uPaymentCardNumber._get_brand
Dwbakb
mb
gb
tb
pb
eb
kib
mib
gib
tib
pib
eib
l l  l  =l     g        g         g           l  l  @l     g
g
g
wiu^\s*(\d*\.?\d+)\s*(\w+)?
aIGNORECASE
aByteSize
wvuByteSize.validate
T Fahuman_readable
uByteSize.human_readable
unit
float
to
uByteSize.to
aPastDate
uPastDate.validate
aFutureDate
uFutureDate.validate
uConstrainedDate.__modify_schema__
D agt
ge
lt
le
nnnnacondate
upydantic\v1\types.py
T ans
namespace
T anamespace
u<module pydantic.v1.types>
T a__class__
T aself
other
T acls
T aself
wtT aself
T aself
card_number
T aself
value
T acls
field_schema
T acls
name
bases
dct
new_cls
T acard_number
brand
T aregex
T atyp
T astrip_whitespace
to_upper
to_lower
min_length
max_length
strict
namespace
T agt
ge
lt
le
namespace
T agt
ge
lt
le
max_digits
decimal_places
multiple_of
namespace
T astrict
gt
ge
lt
le
multiple_of
allow_inf_nan
namespace
T aitem_type
min_items
max_items
namespace
T astrict
gt
ge
lt
le
multiple_of
namespace
T aitem_type
min_items
max_items
unique_items
namespace
T	astrip_whitespace
to_upper
to_lower
strict
min_length
max_length
curtail_length
regex
namespace
T acls
wvav_len
T aself
decimal
divisor
units
final_unit
num
unit
T aself
num_masked
T aself
unit
unit_div
T acls
wvwiavalue
T acls
wvastr_match
scalar
unit
unit_mult
T	acls
value
normalized_value
digit_tuple
exponent
digits
decimals
whole_digits
expected
T acls
value
T acls
value
weT acls
card_number
T acls
card_number
required_length
valid
T acls
card_number
sum_
length
parity
wiadigit
valid
a__spec__
.pydantic.v1.typing
;
cast
aAny
a_evaluate
D arecursive_guard
S
get_type_hints
D ainclude_extras
ta__name__
aAnnotatedTypeNames
aType
aAnnotated
a_typing_get_origin
a__origin__

We can't directly use `typing.get_origin` since we need a fallback to support
custom generic classes like `ConstrainedList`
It should be useless once https://github.com/cython/cython/issues/3537 is
solved and https://github.com/pydantic/pydantic/pull/1753 is merged.
a_nparams
aTuple
T T

In python 3.9, `typing.Dict`, `typing.List`, ...
do have an empty `__args__` by default (instead of the generic ~T for example).
In order to still support `Dict` for example and consider it as `Dict[Any, Any]`,
we retrieve the `_nparams` value that tells us how many parameters it needs.
a__args__
a__metadata__
a_typing_get_args
a_generic_get_args
uGet type arguments with all substitutions performed.
For unions, basic simplifications used by Union constructor are performed.
Examples::
get_args(Dict[str, int]) == (str, int)
get_args(int) == ()
get_args(Union[int, Union[T, int], str][int]) == (int, str)
get_args(Union[int, Tuple[T, int]][str]) == (int, Tuple[str, int])
get_args(Callable[[], T][int]) == ([], int)
get_origin
get_args
a_AnnotatedAlias
convert_generics
:l nnaTypingGenericAlias
aTypesUnionType
a_UnionGenericAlias

Recursively searches for `str` type hints and replaces them with ForwardRef.
Examples::
convert_generics(list['Hero']) == list[ForwardRef('Hero')]
convert_generics(dict['Hero', 'Team']) == dict[ForwardRef('Hero'), ForwardRef('Team')]
convert_generics(typing.Dict['Hero', 'Team']) == typing.Dict[ForwardRef('Hero'), ForwardRef('Team')]
convert_generics(list[str | 'Hero'] | int) == list[str | ForwardRef('Hero')] | int
tp
aForwardRef
u<genexpr>
uconvert_generics.<locals>.<genexpr>
aUnion
aUnionType
aNONE_TYPES
typing_base
aWithArgsTypes
is_union
uUnion[
u,
display_as_type
w]u
replace
T utyping.

modules
module
items
D ais_argument
is_class
Fta_eval_type
base_globals
value
annotations

Partially taken from typing.get_type_hints.
Resolve string or ForwardRef annotations into type objects if possible.
aCallable
aLiteral
aLITERAL_TYPES
is_literal_type
literal_values

This method is used to retrieve all Literal values as
Literal can be used recursively (see https://www.python.org/dev/peps/pep-0586)
e.g. `Literal[Literal[Literal[1, 2, 3], "foo"], 5, None]`
all_literal_values
uall_literal_values.<locals>.<genexpr>
upydantic.v1.utils
T alenient_issubclass
lenient_issubclass
a_fields

Check if a given class is a named tuple.
It can be either a `typing.NamedTuple` or `collections.namedtuple`
a__total__

Check if a given class is a typed dict (from `typing` or `typing_extensions`)
In 3.10, there will be a public method (https://docs.python.org/3.10/library/typing.html#typing.is_typeddict)
aTypedDictRequired
aTypedDictNotRequired
a_check_typeddict_special

Check if type is a TypedDict special form (Required or NotRequired).
test_type
a__supertype__

Check whether type_ was created using typing.NewType
type_
aClassVar
a_name
aFinal

Check if a given type is a `typing.Final` type.
a_check_classvar
a__forward_arg__
startswith
T uClassVar[
a_check_finalvar
evaluate_forwardref
outer_type_
prepare
sub_fields
update_field_forward_refs
globalns
localns
T aglobalns
localns
discriminator_key
prepare_discriminated_union_sub_fields

uProvide for graceful degradation of objects which
re currently dictionaries (and therefore accessed via
`.keys`, `.items`, etc.) into lists. Wraps an existing
`dict` and allows it to be addressed as a `dict` or as a
`list` during an interregnum, issuing a `DeprecationWarning`
if accessed as a `dict`.
a__qualname__
dir
difference
uSelfDeprecatingDict.__init__
uSelfDeprecatingDict.__getattr__
a__iter__
uSelfDeprecatingDict.__iter__
a__str__
uSelfDeprecatingDict.__str__
a__repr__
uSelfDeprecatingDict.__repr__
uSelfDeprecatingDict.__getitem__
a__orig_bases__
aProvideConstants
uWhen called on a ``win32com.client.Dispatch`` object,
provides lazy access to constants defined in the typelib.
They can then be accessed as attributes of the :attr:`_constants`
property. (From Thomas Heller on c.l.py).
uProvideConstants.__init__
uProvideConstants.__getattr__
T uwinmgmts:
wbemErrInvalidQuery
wbemErrTimedout
T EException
uAncestor of all wmi-related exceptions. Keeps track of
n info message and the underlying COM error if any, exposed
s the :attr:`com_error` attribute.
T u
nux_wmi.__init__
ux_wmi.__str__
x_wmi_invalid_query
uRaised when a WMI returns `wbemErrInvalidQuery`
x_wmi_timed_out
uRaised when a watcher times out
uRaised when an attempt is made to query or watch
from a class without a namespace.
x_access_denied
uRaised when WMI raises 80070005
uRaised when an invalid combination of authentication properties is attempted when connecting
uRaised when WMI returns 800401E4 on connection, usually
indicating that no COM threading model has been initialised
g     g     g     T nT l  l pT nnnnnnnnafrom_time
to_time
uA currying sort of wrapper around a WMI method name. It
bstract's the method's parameters and can be called like
a normal Python object passing in the parameter values.
Output parameters are returned from the call as a tuple.
In addition, the docstring is set up as the method's
signature, including an indication as to whether any
given parameter is expecting an array, and what
special privileges are required to call the method.
u_wmi_method.__init__
a__call__
u_wmi_method.__call__
u_wmi_method.__repr__
u_wmi_property.__init__
u_wmi_property.set
u_wmi_property.__repr__
u_wmi_property.__getattr__
uThe heart of the WMI module: wraps the objects returned by COM
ISWbemObject interface and provide readier access to their properties
nd methods resulting in a more Pythonic interface. Not usually
instantiated directly, rather as a result of calling a :class:`_wmi_class`
on the parent :class:`_wmi_namespace`.
If you get hold of a WMI-related COM object from some other
source than this module, you can wrap it in one of these objects
to get the benefits of the module::
import win32com.client
import wmi
wmiobj = win32com.client.GetObject("winmgmts:Win32_LogicalDisk.DeviceID='C:'")
c_drive = wmi._wmi_object(wmiobj)
print(c_drive)
u_wmi_object.__init__
a__lt__
u_wmi_object.__lt__
u_wmi_object.__str__
u_wmi_object.__repr__
u_wmi_object._cached_properties
u_wmi_object._cached_methods
u_wmi_object.__getattr__
a__setattr__
u_wmi_object.__setattr__
a__eq__
u_wmi_object.__eq__
a__hash__
u_wmi_object.__hash__
a_getAttributeNames
u_wmi_object._getAttributeNames
a_get_keys
u_wmi_object._get_keys
wmi_property
u_wmi_object.wmi_property
put
u_wmi_object.put
u_wmi_object.set
path
u_wmi_object.path
u_wmi_object.derivation
a_cached_associated_classes
u_wmi_object._cached_associated_classes
associated_classes
T u
paassociators
u_wmi_object.associators
T u
references
u_wmi_object.references
uSlight extension of the _wmi_object class to allow
objects which are the result of events firing to return
extra information such as the type of event.
compile
T u__Instance(Creation|Modification|Deletion)Event
u_wmi_event.__init__
uCurrying class to assist in issuing queries against
a WMI namespace. The idea is that when someone issues
n otherwise unknown method against the WMI object, if
it matches a known WMI class a query object will be
returned which may then be called with one or more params
which will form the WHERE clause::
c = wmi.WMI()
c_drives = c.Win32_LogicalDisk(Name='C:')
u_wmi_class.__init__
u_wmi_class.__getattr__
to_csv
u_wmi_class.to_csv
u_wmi_class.query
operation
u_wmi_class.watch_for
instances
u_wmi_class.instances
u_wmi_class.new
uSimple, data only result for targeted WMI queries which request
data only result classes via fetch_as_classes.
u_wmi_result.__init__
uA WMI root of a computer system. The classes attribute holds a list
of the classes on offer. This means you can explore a bit with
things like this::
c = wmi.WMI()
for i in c.classes:
if "user" in i.lower():
print(i)
u_wmi_namespace.__init__
u_wmi_namespace.__repr__
u_wmi_namespace.__str__
a_get_classes
u_wmi_namespace._get_classes
u_wmi_namespace.get
handle
u_wmi_namespace.handle
T u
u.*
u_wmi_namespace.subclasses_of
u_wmi_namespace.instances
u_wmi_namespace.new
new_instance_of
u_wmi_namespace._raw_query
u_wmi_namespace.query
T T
fetch_as_classes
u_wmi_namespace.fetch_as_classes
fetch_as_lists
u_wmi_namespace.fetch_as_lists
u_wmi_namespace.watch_for
u_wmi_namespace.__getattr__
u_wmi_namespace._cached_classes
u_wmi_namespace._getAttributeNames
uHelper class for WMI.watch_for below(qv)
u_wmi_watcher.__init__
T q u_wmi_watcher.__call__
uwinmgmts:
Tu
pppppnu
pppFpaconnect
T nnnnnnnT	u
ppppppl  nT naImpersonate
aDefault
nnnaRegistry
uwmi.py
T a.0
wpT a.0
wcaregex
T a.0
wqT a.0
assoc
self
T wxu<module wmi>
T a__class__
T acomputer
impersonation_level
authentication_level
authority
privileges
moniker
T aself
args
kwargs
parameter_names
name
is_array
parameters
n_arg
arg
parameter
wkwvaresult
results
value
T aself
timeout_ms
event
T aself
other
T aself
name
result
T aself
attribute
T aself
attribute
property
factory
value
T aself
attr
T aself
item
T aself
T aself
comobj
T aself
dictlike
T aself
namespace
wmi_class
class_moniker
winmgmts
namespace_moniker
class_name
T aself
event
event_info
fields
event_type
T aself
ole_object
method_name
parameter_names
wqadoc
privileges
T aself
namespace
find_classes
w_T aself
ole_object
instance_of
fields
property_map
field
wpwmT aself
property
T aself
obj
attributes
attr
wpT aself
wmi_event
is_extrinsic
fields
T aself
info
com_error
T aself
attribute
value
T aself
obj
associated_classes
T aself
class_name
T aself
attribs
T aself
property
qualifier
T aself
wql
flags
T aobj
attribute
value
T aitem
T aself
wmi_association_class
wmi_result_class
T acomputer
impersonation_level
authentication_level
authority
privileges
moniker
wmi
namespace
suffix
user
password
find_classes
debug
obj
wmi_type
T aserver
namespace
user
password
locale
authority
impersonation_level
authentication_level
security_flags
named_value_set
impersonation
authentication
T
computer
impersonation_level
authentication_level
authority
privileges
namespace
suffix
security
moniker
parts
T aself
wmi_classname
fields
where_clause
wql
T aself
wmi_classname
fields
where_clause
wql
results
obj
T ans100
T
year
month
day
hours
minutes
seconds
microseconds
timezone
str_or_stars
wmi_time
T aself
moniker
T aobj
path
T aerr
w_ahresult_code
hresult_name
additional_info
parameter_in_error
exception_string
scode
wcode
source_of_error
error_description
whlp_file
whlp_context
error_code
klass
T wsastart
end
T aself
kwargs
obj
T aself
wmi_class
kwargs
T amethod_parameters
parameter_names
param
name
is_array
datatype
bitmap
qualifier
T aself
fields
where_clause
field_list
wql
T aself
wql
instance_of
fields
T aself
wmi_class
T aself
kwargs
attribute
value
T aself
value
T asigned
unsigned
T wialength
T aself
root
regex
aSubclassesOf
T aself
filepath
a_to_utf8
fields
wfawriter
instance
T
wmi_time
int_or_none
year
month
day
hours
minutes
seconds
microseconds
timezone
T aself
notification_type
delay_secs
fields
where_clause
valid_notification_types
T aself
raw_wql
notification_type
wmi_class
delay_secs
fields
where_clause
wql
is_extrinsic
class_name
field_list
where
T aself
property_name
a__spec__
.xrpl.account
uMethods for interacting with XRPL accounts.
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_xrpl
u\not_existing
account
T aNUITKA_PACKAGE_xrpl_account
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uxrpl.account.main
T adoes_account_exist
get_account_root
get_balance
get_next_valid_seq_number
does_account_exist
get_account_root
get_balance
get_next_valid_seq_number
uxrpl.account.transaction_history
T aget_latest_transaction
get_latest_transaction
L aget_next_valid_seq_number
get_balance
get_account_root
does_account_exist
get_latest_transaction
a__all__
uxrpl\account\__init__.py
u<module xrpl.account>

a__spec__
.xrpl.account.main
%
asyncio
run
main
does_account_exist

Query the ledger for whether the account exists.
Args:
ddress: the account to query.
client: the network client used to make network calls.
ledger_index: The ledger index to use for the request. Must be an integer
ledger value or "current" (the current working version), "closed" (for the
closed-and-proposed version), or "validated" (the most recent version
validated by consensus). The default is "validated".
Returns:
Whether the account exists on the ledger.
Raises:
XRPLRequestFailureException: if the transaction fails.
get_next_valid_seq_number

Query the ledger for the next available sequence number for an account.
Args:
ddress: the account to query.
client: the network client used to make network calls.
ledger_index: The ledger index to use for the request. Must be an integer
ledger value or "current" (the current working version), "closed" (for the
closed-and-proposed version), or "validated" (the most recent version
validated by consensus). The default is "current".
Returns:
The next valid sequence number for the address.
get_balance

Query the ledger for the balance of the given account.
Args:
ddress: the account to query.
client: the network client used to make network calls.
ledger_index: The ledger index to use for the request. Must be an integer
ledger value or "current" (the current working version), "closed" (for the
closed-and-proposed version), or "validated" (the most recent version
validated by consensus). The default is "validated".
Returns:
The balance of the address.
get_account_root

Query the ledger for the AccountRoot object associated with a given address.
Args:
ddress: the account to query.
client: the network client used to make network calls.
ledger_index: The ledger index to use for the request. Must be an integer
ledger value or "current" (the current working version), "closed" (for the
closed-and-proposed version), or "validated" (the most recent version
validated by consensus). The default is "validated".
Returns:
The AccountRoot dictionary for the address.
uHigh-level methods to obtain information about accounts.
a__doc__
a__file__
origin
has_location
a__cached__
aDict
aUnion
uxrpl.asyncio.account
T amain
uxrpl.clients.sync_client
T aSyncClient
aSyncClient
T avalidated
address
client
ledger_index
T Ostr
Oint
return
T acurrent
T Oint
Ostr
uxrpl\account\main.py
u<module xrpl.account.main>
T aaddress
client
ledger_index

a__spec__
.xrpl.account.transaction_history
C
asyncio
run
transaction_history
get_latest_transaction

Fetches the most recent transaction on the ledger associated with an account.
Args:
ccount: the account to query.
client: the network client used to communicate with a rippled node.
Returns:
The Response object containing the transaction info.
Raises:
XRPLRequestFailureException: if the transaction fails.
uHigh-level methods to obtain information about account transaction history.
a__doc__
a__file__
origin
has_location
a__cached__
uxrpl.asyncio.account
T atransaction_history
uxrpl.clients.sync_client
T aSyncClient
aSyncClient
uxrpl.models.response
T aResponse
aResponse
account
client
return
uxrpl\account\transaction_history.py
u<module xrpl.account.transaction_history>
T aaccount
client

a__spec__
.xrpl.asyncio.account
+
!
uAsync methods for interacting with XRPL accounts.
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_xrpl
u\not_existing
uasyncio\account
T aNUITKA_PACKAGE_xrpl_asyncio
u\not_existing
account
T aNUITKA_PACKAGE_xrpl_asyncio_account
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
uxrpl.asyncio.account.main
T adoes_account_exist
get_account_root
get_balance
get_next_valid_seq_number
does_account_exist
get_account_root
get_balance
get_next_valid_seq_number
uxrpl.asyncio.account.transaction_history
T aget_latest_transaction
get_latest_transaction
L aget_next_valid_seq_number
get_balance
get_account_root
does_account_exist
get_latest_transaction
a__all__
uxrpl\asyncio\account\__init__.py
u<module xrpl.asyncio.account>

a__spec__
.xrpl.asyncio.account.main
5

Query the ledger for whether the account exists.
Args:
ddress: the account to query.
client: the network client used to make network calls.
ledger_index: The ledger index to use for the request. Must be an integer
ledger value or "current" (the current working version), "closed" (for the
closed-and-proposed version), or "validated" (the most recent version
validated by consensus). The default is "validated".
Returns:
Whether the account exists on the ledger.
Raises:
XRPLRequestFailureException: if the transaction fails.
get_account_root
address
client
ledger_index
T aledger_index
aXRPLRequestFailureException
error
actNotFound
does_account_exist

Query the ledger for the next available sequence number for an account.
Args:
ddress: the account to query.
client: the network client used to make network calls.
ledger_index: The ledger index to use for the request. Must be an integer
ledger value or "current" (the current working version), "closed" (for the
closed-and-proposed version), or "validated" (the most recent version
validated by consensus). The default is "current".
Returns:
The next valid sequence number for the address.
cast
aSequence
get_next_valid_seq_number

Query the ledger for the balance of the given account.
Args:
ddress: the account to query.
client: the network client used to make network calls.
ledger_index: The ledger index to use for the request. Must be an integer
ledger value or "current" (the current working version), "closed" (for the
closed-and-proposed version), or "validated" (the most recent version
validated by consensus). The default is "validated".
Returns:
The balance of the address.
aBalance
get_balance

Query the ledger for the AccountRoot object associated with a given address.
Args:
ddress: the account to query.
client: the network client used to make network calls.
ledger_index: The ledger index to use for the request. Must be an integer
ledger value or "current" (the current working version), "closed" (for the
closed-and-proposed version), or "validated" (the most recent version
validated by consensus). The default is "validated".
Returns:
The AccountRoot dictionary for the address.
Raises:
XRPLRequestFailureException: if the rippled API call fails.
is_valid_xaddress
xaddress_to_classic_address
a_request_impl
aAccountInfo
T aaccount
ledger_index
is_successful
result
aDict
aUnion
T Oint
Ostr
account_data
uHigh-level methods to obtain information about accounts.
a__doc__
a__file__
origin
has_location
a__cached__
uxrpl.asyncio.clients
T aClient
aXRPLRequestFailureException
aClient
uxrpl.core.addresscodec
T ais_valid_xaddress
xaddress_to_classic_address
uxrpl.models.requests
T aAccountInfo
T avalidated
T Ostr
Oint
return
T acurrent
uxrpl\asyncio\account\main.py
u<module xrpl.asyncio.account.main>
T aaddress
client
ledger_index
weT aaddress
client
ledger_index
classic_address
w_aaccount_info
T aaddress
client
ledger_index

a__spec__
.xrpl.asyncio.account.transaction_history
/
"

Fetches the most recent transaction on the ledger associated with an account.
Args:
ccount: the account to query.
client: the network client used to communicate with a rippled node.
Returns:
The Response object containing the transaction info.
Raises:
XRPLRequestFailureException: if the transaction fails.
is_valid_xaddress
account
xaddress_to_classic_address
client
a_request_impl
aAccountTx
T aaccount
ledger_index_max
limit
is_successful
aXRPLRequestFailureException
result
get_latest_transaction
uHigh-level methods to obtain information about account transaction history.
a__doc__
a__file__
origin
has_location
a__cached__
uxrpl.asyncio.clients
T aClient
aXRPLRequestFailureException
aClient
uxrpl.core.addresscodec
T ais_valid_xaddress
xaddress_to_classic_address
uxrpl.models.requests
T aAccountTx
uxrpl.models.response
T aResponse
aResponse
return
uxrpl\asyncio\account\transaction_history.py
u<module xrpl.asyncio.account.transaction_history>
T aaccount
client
w_aresponse

a__spec__
.xrpl.asyncio.clients.async_client
*

Makes a request with this client and returns the response.
Arguments:
request: The Request to send.
Returns:
The Response for the given Request.
self
a_request_impl
request
uAsyncClient.request
uInterface for all async network clients to follow.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
typing_extensions
T aSelf
aSelf
uxrpl.asyncio.clients.client
T aClient
aClient
uxrpl.models.requests.request
T aRequest
aRequest
uxrpl.models.response
T aResponse
aResponse
a__prepare__
aAsyncClient
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
