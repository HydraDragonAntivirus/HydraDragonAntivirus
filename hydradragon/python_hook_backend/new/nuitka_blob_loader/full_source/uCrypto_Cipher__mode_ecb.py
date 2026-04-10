# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher._mode_ecb

u*Electronic Code Book (ECB)*.
This is the simplest encryption mode. Each of the plaintext blocks
is directly encrypted into a ciphertext block, independently of
ny other block.
This mode is dangerous because it exposes frequency of symbols
in your plaintext. Other modes (e.g. *CBC*) should be used instead.
See `NIST SP800-38A`_ , Section 6.1.
.. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
:undocumented: __init__
a__qualname__
a__init__
uEcbMode.__init__
T naencrypt
uEcbMode.encrypt
decrypt
uEcbMode.decrypt
a__orig_bases__
a_create_ecb_cipher
uCrypto\Cipher\_mode_ecb.py
u<module Crypto.Cipher._mode_ecb>
T a__class__
T aself
block_cipher
result
T afactory
kwargs
cipher_state
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
.Crypto.Cipher._mode_gcm
/
collections
T anamedtuple
namedtuple
T a_GHash_Imp
T aghash
ghash_expand
ghash_destroy
T aghash
ghash_expand
ghash_destroy
w_apostfix
a_ghash_api_template
replace
T u%imp%
portable
load_pycryptodome_raw_lib
uCrypto.Hash._ghash_portable
a_build_impl
portable
a_cpu_features
have_clmul
T u%imp%
clmul
uCrypto.Hash._ghash_clmul
clmul
uReturn None if CLMUL implementation is not available
ghash_c
aVoidPointer
a_exp_key
ghash_expand
c_uint8_ptr
address_of
uError %d while expanding the GHASH key
aSmartPointer
get
ghash_destroy
create_string_buffer
T l a_last_y
l aghash
c_size_t
uError %d while updating GHASH
get_raw_buffer
aEnum
uCrypto.Cipher._mode_gcm
block_size
uGCM mode is only available for ciphers that operate on 128 bits blocks
uNonce cannot be empty
is_buffer
uNonce must be bytes, bytearray or memoryview
g            uNonce exceeds maximum length
a_copy_bytes
nonce
a_factory
a_key
a_tag
a_mac_len
l uParameter 'mac_len' must be in the range 4..16
L aupdate
encrypt
decrypt
digest
verify
a_next
a_no_more_assoc_data
a_auth_len
a_msg_len
new
aMODE_ECB
encrypt
T b
b
d
long_to_bytes
l a_GHASH
update
digest
:nl nabytes_to_long
g       aMODE_CTR
initial_value
a_cipher
a_signer
c
a_tag_cipher
a_cache
aMacStatus
aPROCESSING_AUTH_DATA
a_status
uupdate() can only be called immediately after initialization
a_update
uAdditional Authenticated Data exceeds maximum length
uProtect associated data
If there is any associated data, the caller has to invoke
this function one or more times, before using
``decrypt`` or ``encrypt``.
By *associated data* it is meant any data (e.g. packet headers) that
will not be encrypted and will be transmitted in the clear.
However, the receiver is still able to detect any modification to it.
In GCM, the *associated data* is also called
*additional authenticated data* (AAD).
If there is no associated data, this method must not be called.
The caller may split associated data in segments of any size, and
invoke this method multiple times, each time with the next segment.
:Parameters:
ssoc_data : bytes/bytearray/memoryview
A piece of associated data. There are no restrictions on its size.
min
uencrypt() can only be called after initialization or an update()
T aoutput
a_pad_cache_and_update
aPROCESSING_CIPHERTEXT
g        uPlaintext exceeds maximum length
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
If ``output`` is ``None``, the ciphertext as ``bytes``.
Otherwise, ``None``.
decrypt
udecrypt() can only be called after initialization or an update()
verify
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
If ``output`` is ``None``, the plaintext as ``bytes``.
Otherwise, ``None``.
udigest() cannot be called when decrypting or validating a message
a_compute_mac
uCompute the *binary* MAC tag in an AEAD mode.
The caller invokes this function at the very end.
This method returns the MAC that shall be sent to the receiver,
together with the ciphertext.
:Return: the MAC, as a byte string.
uCompute MAC without any FSM checks.

u%02x
bord
uCompute the *printable* MAC tag.
This method is like `digest`.
:Return: the MAC, as a hexadecimal string.
uverify() cannot be called when encrypting a message
get_random_bytes
aBLAKE2s
l  T adigest_bits
key
data
uMAC check failed
uValidate the *binary* MAC tag.
The caller invokes this function at the very end.
This method checks if the decrypted message is indeed valid
(that is, if the key is correct) and it has not been
tampered with while in transit.
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
uPerform encrypt() and digest() in one step.
:Parameters:
plaintext : bytes/bytearray/memoryview
The piece of data to encrypt.
:Keywords:
output : bytearray/memoryview
The location where the ciphertext must be written to.
If ``None``, the ciphertext is returned.
:Return:
a tuple with two items:
- the ciphertext, as ``bytes``
- the MAC tag, as ``bytes``
The first item becomes ``None`` when the ``output`` parameter
specified a location for the result.
uPerform decrypt() and verify() in one step.
:Parameters:
ciphertext : bytes/bytearray/memoryview
The piece of data to decrypt.
received_mac_tag : byte string
This is the *binary* MAC, as received from the sender.
:Keywords:
output : bytearray/memoryview
The location where the plaintext must be written to.
If ``None``, the plaintext is returned.
:Return: the plaintext as ``bytes`` or ``None`` when the ``output``
parameter specified a location for the result.
:Raises ValueError:
if the MAC does not match. The message has been tampered with
or the key is incorrect.
key
uMissing parameter:
pop
T anonce
nT amac_len
l T ause_clmul
ta_ghash_clmul
a_ghash_portable
aGcmMode
uCreate a new block cipher, configured in Galois Counter Mode (GCM).
:Parameters:
factory : module
A block cipher module, taken from `Crypto.Cipher`.
The cipher must have block length of 16 bytes.
GCM has been only defined for `Crypto.Cipher.AES`.
:Keywords:
key : bytes/bytearray/memoryview
The secret key to use in the symmetric cipher.
It must be 16 (e.g. *AES-128*), 24 (e.g. *AES-192*)
or 32 (e.g. *AES-256*) bytes long.
nonce : bytes/bytearray/memoryview
A value that must never be reused for any other encryption.
There are no restrictions on its length,
but it is recommended to use at least 16 bytes.
The nonce shall never repeat for two
different messages encrypted with the same key,
but it does not need to be random.
If not provided, a 16 byte nonce will be randomly created.
mac_len : integer
Length of the MAC, in bytes.
It must be no larger than 16 bytes (which is the default).

Galois/Counter Mode (GCM).
a__doc__
a__file__
origin
has_location
a__cached__
a__all__
binascii
T aunhexlify
uCrypto.Util.py3compat
T abord
a_copy_bytes
uCrypto.Util._raw_api
T ais_buffer
uCrypto.Util.number
T along_to_bytes
bytes_to_long
uCrypto.Hash
T aBLAKE2s
uCrypto.Random
T aget_random_bytes
T aload_pycryptodome_raw_lib
aVoidPointer
create_string_buffer
get_raw_buffer
aSmartPointer
c_size_t
c_uint8_ptr
uCrypto.Util
T a_cpu_features

int ghash_%imp%(uint8_t y_out[16],
const uint8_t block_data[],
size_t len,
const uint8_t y_in[16],
const void *exp_key);
int ghash_expand_%imp%(const uint8_t h[16],
void **ghash_tables);
int ghash_destroy_%imp%(void *ghash_tables);
a_get_ghash_portable
a_get_ghash_clmul
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
