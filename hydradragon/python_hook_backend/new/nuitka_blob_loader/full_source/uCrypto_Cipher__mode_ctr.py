# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher._mode_ctr

u*CounTeR (CTR)* mode.
This mode is very similar to ECB, in that
encryption of one block is done independently of all other blocks.
Unlike ECB, the block *position* contributes to the encryption
nd no information leaks about symbol frequency.
Each message block is associated to a *counter* which
must be unique across all messages that get encrypted
with the same key (not just within the same message).
The counter is as big as the block size.
Counters can be generated in several ways. The most
straightword one is to choose an *initial counter block*
(which can be made public, similarly to the *IV* for the
other modes) and increment its lowest **m** bits by one
(modulo *2^m*) for each block. In most cases, **m** is
chosen to be half the block size.
See `NIST SP800-38A`_, Section 6.5 (for the mode) and
Appendix B (for how to manage the *initial counter block*).
.. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
:undocumented: __init__
a__qualname__
a__init__
uCtrMode.__init__
T nuCtrMode.encrypt
uCtrMode.decrypt
a__orig_bases__
a_create_ctr_cipher
uCrypto\Cipher\_mode_ctr.py
u<module Crypto.Cipher._mode_ctr>
T a__class__
T aself
block_cipher
initial_counter_block
prefix_len
counter_len
little_endian
result
Tafactory
kwargs
cipher_state
counter
nonce
initial_value
counter_len
initial_counter_block
a_counter
prefix
suffix
little_endian
words
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
.Crypto.Cipher._mode_eax
U%
block_size
a_copy_bytes
nonce
a_mac_len
a_mac_tag
L aupdate
encrypt
decrypt
digest
verify
a_next
l u'mac_len' must be at least 2 and not larger than %d
uNonce cannot be empty in EAX mode
is_buffer
unonce must be bytes, bytearray or memoryview
;l
l l aCMAC
new
key
d
self
struct
pack
wBafactory
cipher_params
T aciphermod
cipher_params
a_omac
update
a_signer
bytes_to_long
digest
aMODE_CTR
initial_value
c
a_cipher
uEAX cipher mode
uupdate() can only be called immediately after initialization
uProtect associated data
If there is any associated data, the caller has to invoke
this function one or more times, before using
``decrypt`` or ``encrypt``.
By *associated data* it is meant any data (e.g. packet headers) that
will not be encrypted and will be transmitted in the clear.
However, the receiver is still able to detect any modification to it.
If there is no associated data, this method must not be called.
The caller may split associated data in segments of any size, and
invoke this method multiple times, each time with the next segment.
:Parameters:
ssoc_data : bytes/bytearray/memoryview
A piece of associated data. There are no restrictions on its size.
encrypt
uencrypt() can only be called after initialization or an update()
T aoutput
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
strxor
tag
uCompute the *binary* MAC tag.
The caller invokes this function at the very end.
This method returns the MAC that shall be sent to the receiver,
together with the ciphertext.
:Return: the MAC, as a byte string.

u%02x
bord
uCompute the *printable* MAC tag.
This method is like `digest`.
:Return: the MAC, as a hexadecimal string.
uverify() cannot be called when encrypting a message
get_random_bytes
T l aBLAKE2s
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
:Raises MacMismatchError:
if the MAC does not match. The message has been tampered with
or the key is incorrect.
unhexlify
uValidate the *printable* MAC tag.
This method is like `verify`.
:Parameters:
hex_mac_tag : string
This is the *printable* MAC, as received from the sender.
:Raises MacMismatchError:
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
received_mac_tag : bytes/bytearray/memoryview
This is the *binary* MAC, as received from the sender.
:Keywords:
output : bytearray/memoryview
The location where the plaintext must be written to.
If ``None``, the plaintext is returned.
:Return: the plaintext as ``bytes`` or ``None`` when the ``output``
parameter specified a location for the result.
:Raises MacMismatchError:
if the MAC does not match. The message has been tampered with
or the key is incorrect.
pop
T anonce
namac_len
uMissing parameter:
aEaxMode
uCreate a new block cipher, configured in EAX mode.
:Parameters:
factory : module
A symmetric cipher module from `Crypto.Cipher` (like
`Crypto.Cipher.AES`).
:Keywords:
key : bytes/bytearray/memoryview
The secret key to use in the symmetric cipher.
nonce : bytes/bytearray/memoryview
A value that must never be reused for any other encryption.
There are no restrictions on its length, but it is recommended to use
t least 16 bytes.
The nonce shall never repeat for two different messages encrypted with
the same key, but it does not need to be random.
If not specified, a 16 byte long random string is used.
mac_len : integer
Length of the MAC, in bytes. It must be no larger than the cipher
block bytes (which is the default).

EAX mode.
a__doc__
a__file__
origin
has_location
a__cached__
a__all__
binascii
T aunhexlify
uCrypto.Util.py3compat
T abyte_string
bord
a_copy_bytes
byte_string
uCrypto.Util._raw_api
T ais_buffer
uCrypto.Util.strxor
T astrxor
uCrypto.Util.number
T along_to_bytes
bytes_to_long
long_to_bytes
uCrypto.Hash
T aCMAC
aBLAKE2s
uCrypto.Random
T aget_random_bytes
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
