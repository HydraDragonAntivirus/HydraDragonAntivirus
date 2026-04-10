# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher._mode_eax

u*EAX* mode.
This is an Authenticated Encryption with Associated Data
(`AEAD`_) mode. It provides both confidentiality and authenticity.
The header of the message may be left in the clear, if needed,
nd it will still be subject to authentication.
The decryption step tells the receiver if the message comes
from a source that really knowns the secret key.
Additionally, decryption detects if any part of the message -
including the header - has been modified or corrupted.
This mode requires a *nonce*.
This mode is only available for ciphers that operate on 64 or
128 bits blocks.
There are no official standards defining EAX.
The implementation is based on `a proposal`__ that
was presented to NIST.
.. _AEAD: http://blog.cryptographyengineering.com/2012/05/how-to-choose-authenticated-encryption.html
.. __: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/eax/eax-spec.pdf
:undocumented: __init__
a__qualname__
a__init__
uEaxMode.__init__
uEaxMode.update
T nuEaxMode.encrypt
uEaxMode.decrypt
uEaxMode.digest
hexdigest
uEaxMode.hexdigest
uEaxMode.verify
hexverify
uEaxMode.hexverify
encrypt_and_digest
uEaxMode.encrypt_and_digest
decrypt_and_verify
uEaxMode.decrypt_and_verify
a__orig_bases__
a_create_eax_cipher
uCrypto\Cipher\_mode_eax.py
u<module Crypto.Cipher._mode_eax>
T a__class__
T aself
factory
key
nonce
mac_len
cipher_params
counter_int
T afactory
kwargs
key
nonce
mac_len
weT aself
ciphertext
output
T aself
ciphertext
received_mac_tag
output
pt
T aself
tag
wiT aself
plaintext
output
ct
T aself
plaintext
output
T aself
T aself
hex_mac_tag
T aself
assoc_data
T aself
received_mac_tag
tag
wiasecret
mac1
mac2
a__spec__
.Crypto.Cipher._mode_ecb
H
block_size
aVoidPointer
a_state
raw_ecb_lib
aECB_start_operation
get
address_of
uError %d while instantiating the ECB mode
aSmartPointer
aECB_stop_operation
release
uCreate a new block cipher, configured in ECB mode.
:Parameters:
block_cipher : C pointer
A smart pointer to the low-level block cipher instance.
create_string_buffer
is_writeable_buffer
uoutput must be a bytearray or a writeable memoryview
uoutput must have the same length as the input  (%d bytes)
aECB_encrypt
c_uint8_ptr
plaintext
c_size_t
l uData must be aligned to block boundary in ECB mode
uError %d while encrypting in ECB mode
get_raw_buffer
uEncrypt data with the key set at initialization.
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
The length must be multiple of the cipher block length.
:Keywords:
output : bytearray/memoryview
The location where the ciphertext must be written to.
If ``None``, the ciphertext is returned.
:Return:
If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
Otherwise, ``None``.
aECB_decrypt
ciphertext
uError %d while decrypting in ECB mode
uDecrypt data with the key set at initialization.
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
The length must be multiple of the cipher block length.
:Keywords:
output : bytearray/memoryview
The location where the plaintext must be written to.
If ``None``, the plaintext is returned.
:Return:
If ``output`` is ``None``, the plaintext is returned as ``bytes``.
Otherwise, ``None``.
a_create_base_cipher
uUnknown parameters for ECB: %s
aEcbMode
uInstantiate a cipher object that performs ECB encryption/decryption.
:Parameters:
factory : module
The underlying block cipher, a module from ``Crypto.Cipher``.
All keywords are passed to the underlying block cipher.
See the relevant documentation for details (at least ``key`` will need
to be present

Electronic Code Book (ECB) mode.
a__doc__
a__file__
origin
has_location
a__cached__
a__all__
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
T uCrypto.Cipher._raw_ecb

int ECB_start_operation(void *cipher,
void **pResult);
int ECB_encrypt(void *ecbState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int ECB_decrypt(void *ecbState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int ECB_stop_operation(void *state);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
