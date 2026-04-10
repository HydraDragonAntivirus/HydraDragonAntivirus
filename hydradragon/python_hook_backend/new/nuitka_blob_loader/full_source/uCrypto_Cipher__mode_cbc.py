# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher._mode_cbc

u*Cipher-Block Chaining (CBC)*.
Each of the ciphertext blocks depends on the current
nd all previous plaintext blocks.
An Initialization Vector (*IV*) is required.
See `NIST SP800-38A`_ , Section 6.2 .
.. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
:undocumented: __init__
a__qualname__
a__init__
uCbcMode.__init__
T nuCbcMode.encrypt
uCbcMode.decrypt
a__orig_bases__
a_create_cbc_cipher
uCrypto\Cipher\_mode_cbc.py
u<module Crypto.Cipher._mode_cbc>
T a__class__
T aself
block_cipher
iv
result
T afactory
kwargs
cipher_state
iv
aIV
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
.Crypto.Cipher._mode_ccm
2
aEnum
uCrypto.Cipher._mode_ccm
block_size
a_copy_bytes
nonce
a_factory
a_key
a_mac_len
a_msg_len
a_assoc_len
a_cipher_params
a_mac_tag
l uCCM mode is only available for ciphers that operate on 128 bits blocks
T l l l l
l l l uParameter 'mac_len' must be even and in the range 4..16 (not %d)
uLength of parameter 'nonce' must be in the range 7..13 bytes
new
aMODE_CBC
D aiv
b
a_mac
aMacStatus
aNOT_STARTED
a_mac_status
a_t
L aupdate
encrypt
decrypt
digest
verify
a_next
a_cumul_assoc_len
a_cumul_msg_len
a_cache
aMODE_CTR
struct
pack
wBa_cipher
encrypt
T b
a_s_0
a_start_mac
l@l l along_to_bytes
c
l   g
c
l c
insert
aPROCESSING_AUTH_DATA
a_update
d
update
uupdate() can only be called immediately after initialization
uAssociated data is too long
uProtect associated data
If there is any associated data, the caller has to invoke
this function one or more times, before using
``decrypt`` or ``encrypt``.
By *associated data* it is meant any data (e.g. packet headers) that
will not be encrypted and will be transmitted in the clear.
However, the receiver is still able to detect any modification to it.
In CCM, the *associated data* is also called
*additional authenticated data* (AAD).
If there is no associated data, this method must not be called.
The caller may split associated data in segments of any size, and
invoke this method multiple times, each time with the next segment.
:Parameters:
ssoc_data : bytes/bytearray/memoryview
A piece of associated data. There are no restrictions on its size.
is_writeable_buffer
append
assoc_data_pt
min
:q nnuUpdate the MAC with associated data or plaintext
(without FSM checks)
uencrypt() can only be called after initialization or an update()
digest
uAssociated data is too short
uMessage is too long
a_pad_cache_and_update
aPROCESSING_PLAINTEXT
T aoutput
uEncrypt data with the key set at initialization.
A cipher object is stateful: once you have encrypted a message
you cannot encrypt (or decrypt) another message using the same
object.
This method can be called only **once** if ``msg_len`` was
not passed at initialization.
If ``msg_len`` was given, the data to encrypt can be broken
up in two or more pieces and `encrypt` can be called
multiple times.
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
uDecrypt data with the key set at initialization.
A cipher object is stateful: once you have decrypted a message
you cannot decrypt (or encrypt) another message with the same
object.
This method can be called only **once** if ``msg_len`` was
not passed at initialization.
If ``msg_len`` was given, the data to decrypt can be
broken up in two or more pieces and `decrypt` can be
called multiple times.
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
a_digest
uCompute the *binary* MAC tag.
The caller invokes this function at the very end.
This method returns the MAC that shall be sent to the receiver,
together with the ciphertext.
:Return: the MAC, as a byte string.
uMessage is too short
strxor

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
received_mac_tag : bytes/bytearray/memoryview
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
nT l amac_len
T amsg_len
nT aassoc_len
naCcmMode
uCreate a new block cipher, configured in CCM mode.
:Parameters:
factory : module
A symmetric cipher module from `Crypto.Cipher` (like
`Crypto.Cipher.AES`).
:Keywords:
key : bytes/bytearray/memoryview
The secret key to use in the symmetric cipher.
nonce : bytes/bytearray/memoryview
A value that must never be reused for any other encryption.
Its length must be in the range ``[7..13]``.
11 or 12 bytes are reasonable values in general. Bear in
mind that with CCM there is a trade-off between nonce length and
maximum message size.
If not specified, a 11 byte long random string is used.
mac_len : integer
Length of the MAC, in bytes. It must be even and in
the range ``[4..16]``. The default is 16.
msg_len : integer
Length of the message to (de)cipher.
If not specified, ``encrypt`` or ``decrypt`` may only be called once.
ssoc_len : integer
Length of the associated data.
If not specified, all data is internally buffered.

Counter with CBC-MAC (CCM) mode.
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
T ais_writeable_buffer
uCrypto.Util.strxor
T astrxor
uCrypto.Util.number
T along_to_bytes
uCrypto.Hash
T aBLAKE2s
uCrypto.Random
T aget_random_bytes
enum
T l
l l T aNOT_STARTED
aPROCESSING_AUTH_DATA
aPROCESSING_PLAINTEXT
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
