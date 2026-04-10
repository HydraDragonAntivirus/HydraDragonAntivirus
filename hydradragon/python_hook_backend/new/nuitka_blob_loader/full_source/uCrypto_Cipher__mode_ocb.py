# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher._mode_ocb

uOffset Codebook (OCB) mode.
:undocumented: __init__
a__qualname__
a__init__
uOcbMode.__init__
uOcbMode._update
uOcbMode.update
uOcbMode._transcrypt_aligned
uOcbMode._transcrypt
T nuOcbMode.encrypt
uOcbMode.decrypt
uOcbMode._compute_mac_tag
uOcbMode.digest
hexdigest
uOcbMode.hexdigest
uOcbMode.verify
hexverify
uOcbMode.hexverify
encrypt_and_digest
uOcbMode.encrypt_and_digest
decrypt_and_verify
uOcbMode.decrypt_and_verify
a__orig_bases__
a_create_ocb_cipher
uCrypto\Cipher\_mode_ocb.py
u<module Crypto.Cipher._mode_ocb>
T a__class__
T aself
factory
nonce
mac_len
cipher_params
params_without_key
key
taglen_mod128
bottom_bits
top_bits
ktop_cipher
ktop
stretch
offset_0
raw_cipher
result
T aself
mac_tag
result
T afactory
kwargs
nonce
mac_len
weT	aself
in_data
trans_func
trans_desc
out_data
prefix
filler
trans_len
result
T aself
in_data
in_data_len
trans_func
trans_desc
out_data
result
T aself
assoc_data
assoc_data_len
result
T aself
ciphertext
T aself
ciphertext
received_mac_tag
plaintext
T aself
T aself
plaintext
T aself
hex_mac_tag
T aself
assoc_data
filler
seg
update_len
T aself
received_mac_tag
secret
mac1
mac2
a__spec__
.Crypto.Cipher._mode_ofb
W
aVoidPointer
a_state
raw_ofb_lib
aOFB_start_operation
get
c_uint8_ptr
c_size_t
address_of
uError %d while instantiating the OFB mode
aSmartPointer
aOFB_stop_operation
release
block_size
a_copy_bytes
iv
aIV
encrypt
decrypt
a_next
uCreate a new block cipher, configured in OFB mode.
:Parameters:
block_cipher : C pointer
A smart pointer to the low-level block cipher instance.
iv : bytes/bytearray/memoryview
The initialization vector to use for encryption or decryption.
It is as long as the cipher block.
**The IV must be a nonce, to to be reused for any other
message**. It shall be a nonce or a random value.
Reusing the *IV* for encryptions performed with the same key
compromises confidentiality.
uencrypt() cannot be called after decrypt()
create_string_buffer
is_writeable_buffer
uoutput must be a bytearray or a writeable memoryview
uoutput must have the same length as the input  (%d bytes)
aOFB_encrypt
plaintext
uError %d while encrypting in OFB mode
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
aOFB_decrypt
ciphertext
uError %d while decrypting in OFB mode
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
The location where the plaintext is written to.
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
uUnknown parameters for OFB: %s
aOfbMode
uInstantiate a cipher object that performs OFB encryption/decryption.
:Parameters:
factory : module
The underlying block cipher, a module from ``Crypto.Cipher``.
:Keywords:
iv : bytes/bytearray/memoryview
The IV to use for OFB.
IV : bytes/bytearray/memoryview
Alias for ``iv``.
Any other keyword will be passed to the underlying block cipher.
See the relevant documentation for details (at least ``key`` will need
to be present).

Output Feedback (CFB) mode.
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
T uCrypto.Cipher._raw_ofb

int OFB_start_operation(void *cipher,
const uint8_t iv[],
size_t iv_len,
void **pResult);
int OFB_encrypt(void *ofbState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int OFB_decrypt(void *ofbState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int OFB_stop_operation(void *state);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
