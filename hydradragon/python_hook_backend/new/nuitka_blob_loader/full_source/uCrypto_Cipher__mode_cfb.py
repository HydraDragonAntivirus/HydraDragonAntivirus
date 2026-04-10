# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher._mode_cfb

u*Cipher FeedBack (CFB)*.
This mode is similar to CFB, but it transforms
the underlying block cipher into a stream cipher.
Plaintext and ciphertext are processed in *segments*
of **s** bits. The mode is therefore sometimes
labelled **s**-bit CFB.
An Initialization Vector (*IV*) is required.
See `NIST SP800-38A`_ , Section 6.3.
.. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
:undocumented: __init__
a__qualname__
a__init__
uCfbMode.__init__
T nuCfbMode.encrypt
uCfbMode.decrypt
a__orig_bases__
a_create_cfb_cipher
uCrypto\Cipher\_mode_cfb.py
u<module Crypto.Cipher._mode_cfb>
T a__class__
T aself
block_cipher
iv
segment_size
result
T afactory
kwargs
cipher_state
iv
aIV
segment_size_bytes
rem
T aself
ciphertext
output
plaintext
result
T aself
plaintext
output
ciphertext
result

a__spec__
.Crypto.Cipher._mode_ctr
#
s
a_copy_bytes
nonce
aVoidPointer
a_state
raw_ctr_lib
aCTR_start_operation
get
c_uint8_ptr
c_size_t
address_of
uError %X while instantiating the CTR mode
aSmartPointer
aCTR_stop_operation
release
block_size
encrypt
decrypt
a_next
uCreate a new block cipher, configured in CTR mode.
:Parameters:
block_cipher : C pointer
A smart pointer to the low-level block cipher instance.
initial_counter_block : bytes/bytearray/memoryview
The initial plaintext to use to generate the key stream.
It is as large as the cipher block, and it embeds
the initial value of the counter.
This value must not be reused.
It shall contain a nonce or a random component.
Reusing the *initial counter block* for encryptions
performed with the same key compromises confidentiality.
prefix_len : integer
The amount of bytes at the beginning of the counter block
that never change.
counter_len : integer
The length in bytes of the counter embedded in the counter
block.
little_endian : boolean
True if the counter in the counter block is an integer encoded
in little endian mode. If False, it is big endian.
uencrypt() cannot be called after decrypt()
create_string_buffer
is_writeable_buffer
uoutput must be a bytearray or a writeable memoryview
uoutput must have the same length as the input  (%d bytes)
aCTR_encrypt
plaintext
l   uThe counter has wrapped around in CTR mode
uError %X while encrypting in CTR mode
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
aCTR_decrypt
ciphertext
uError %X while decrypting in CTR mode
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
T acounter
nT anonce
nT ainitial_value
nuInvalid parameters for CTR mode: %s
T nnu'counter' and 'nonce'/'initial_value' are mutually exclusive
l uImpossible to create a safe nonce for short block sizes
get_random_bytes
l uNonce is too long
is_native_int
l uInitial counter value is too large
long_to_bytes
uIncorrect length for counter byte string (%d bytes, expected %d)
aCtrMode
counter_len
prefix
suffix
initial_value
little_endian
uIncorrect counter object (use Crypto.Util.Counter.new)
words
struct
pack
wBl  d
max
reverse
c
uSize of the counter block (%d bytes) must match block size (%d)
uInstantiate a cipher object that performs CTR encryption/decryption.
:Parameters:
factory : module
The underlying block cipher, a module from ``Crypto.Cipher``.
:Keywords:
nonce : bytes/bytearray/memoryview
The fixed part at the beginning of the counter block - the rest is
the counter number that gets increased when processing the next block.
The nonce must be such that no two messages are encrypted under the
same key and the same nonce.
The nonce must be shorter than the block size (it can have
zero length; the counter is then as long as the block).
If this parameter is not present, a random nonce will be created with
length equal to half the block size. No random nonce shorter than
64 bits will be created though - you must really think through all
security consequences of using such a short block size.
initial_value : posive integer or bytes/bytearray/memoryview
The initial value for the counter. If not present, the cipher will
start counting from 0. The value is incremented by one for each block.
The counter number is encoded in big endian mode.
counter : object
Instance of ``Crypto.Util.Counter``, which allows full customization
of the counter block. This parameter is incompatible to both ``nonce``
nd ``initial_value``.
Any other keyword will be passed to the underlying block cipher.
See the relevant documentation for details (at least ``key`` will need
to be present).

Counter (CTR) mode.
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
uCrypto.Random
T aget_random_bytes
uCrypto.Util.py3compat
T a_copy_bytes
is_native_int
uCrypto.Util.number
T along_to_bytes
T uCrypto.Cipher._raw_ctr

int CTR_start_operation(void *cipher,
uint8_t   initialCounterBlock[],
size_t    initialCounterBlock_len,
size_t    prefix_len,
unsigned  counter_len,
unsigned  littleEndian,
void **pResult);
int CTR_encrypt(void *ctrState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int CTR_decrypt(void *ctrState,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int CTR_stop_operation(void *ctrState);
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
