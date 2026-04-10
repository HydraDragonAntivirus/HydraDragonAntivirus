# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher.ChaCha20

uChaCha20 (or XChaCha20) cipher object.
Do not create it directly. Use :py:func:`new` instead.
:var nonce: The nonce with length 8, 12 or 24 bytes
:vartype nonce: bytes
a__qualname__
block_size
a__init__
uChaCha20Cipher.__init__
T nuChaCha20Cipher.encrypt
uChaCha20Cipher._encrypt
uChaCha20Cipher.decrypt
seek
uChaCha20Cipher.seek
a__orig_bases__
a_derive_Poly1305_key_pair
key_size
uCrypto\Cipher\ChaCha20.py
u<module Crypto.Cipher.ChaCha20>
T a__class__
T akey
nonce
subkey
result
T aself
key
nonce
result
T akey
nonce
padded_nonce
rs
T aself
plaintext
output
ciphertext
result
T aself
ciphertext
output
weT aself
plaintext
output
T akwargs
key
weanonce
T aself
position
offset
block_low
block_high
result

a__spec__
.Crypto.Cipher.ChaCha20_Poly1305
aEnum
uCrypto.Cipher.ChaCha20_Poly1305
T aupdate
encrypt
decrypt
digest
verify
a_next
aPoly1305
new
aChaCha20
T akey
nonce
cipher
a_authenticator
T akey
nonce
a_cipher
seek
T l@a_len_aad
a_len_ct
a_mac_tag
a_CipherStatus
aPROCESSING_AUTH_DATA
a_status
uInitialize a ChaCha20-Poly1305 AEAD cipher object
See also `new()` at the module level.
update
uupdate() method cannot be called
uProtect the associated data.
Associated data (also known as *additional authenticated data* - AAD)
is the piece of the message that must stay in the clear, while
still allowing the receiver to verify its integrity.
An example is packet headers.
The associated data (possibly split into multiple segments) is
fed into :meth:`update` before any call to :meth:`decrypt` or :meth:`encrypt`.
If there is no associated data, :meth:`update` is not called.
:param bytes/bytearray/memoryview assoc_data:
A piece of associated data. There are no restrictions on its size.
l d
l aPROCESSING_CIPHERTEXT
encrypt
uencrypt() method cannot be called
a_pad_aad
T aencrypt
digest
T aoutput
uEncrypt a piece of data.
Args:
plaintext(bytes/bytearray/memoryview): The data to encrypt, of any size.
Keyword Args:
output(bytes/bytearray/memoryview): The location where the ciphertext
is written to. If ``None``, the ciphertext is returned.
Returns:
If ``output`` is ``None``, the ciphertext is returned as ``bytes``.
Otherwise, ``None``.
decrypt
udecrypt() method cannot be called
T adecrypt
verify
uDecrypt a piece of data.
Args:
ciphertext(bytes/bytearray/memoryview): The data to decrypt, of any size.
Keyword Args:
output(bytes/bytearray/memoryview): The location where the plaintext
is written to. If ``None``, the plaintext is returned.
Returns:
If ``output`` is ``None``, the plaintext is returned as ``bytes``.
Otherwise, ``None``.
aPROCESSING_DONE
long_to_bytes
l :nnq adigest
uFinalize the cipher (if not done already) and return the MAC.
udigest() method cannot be called
T adigest
a_compute_mac
uCompute the *binary* authentication tag (MAC).
:Return: the MAC tag, as 16 ``bytes``.

u%02x
bord
uCompute the *printable* authentication tag (MAC).
This method is like :meth:`digest`.
:Return: the MAC tag, as a hexadecimal string.
verify
uverify() cannot be called when encrypting a message
T averify
get_random_bytes
T l aBLAKE2s
l  T adigest_bits
key
data
uMAC check failed
uValidate the *binary* authentication tag (MAC).
The receiver invokes this method at the very end, to
check if the associated data (if any) and the decrypted
messages are valid.
:param bytes/bytearray/memoryview received_mac_tag:
This is the 16-byte *binary* MAC, as received from the sender.
:Raises ValueError:
if the MAC does not match. The message has been tampered with
or the key is incorrect.
unhexlify
uValidate the *printable* authentication tag (MAC).
This method is like :meth:`verify`.
:param string hex_mac_tag:
This is the *printable* MAC.
:Raises ValueError:
if the MAC does not match. The message has been tampered with
or the key is incorrect.
uPerform :meth:`encrypt` and :meth:`digest` in one step.
:param plaintext: The data to encrypt, of any size.
:type plaintext: bytes/bytearray/memoryview
:return: a tuple with two ``bytes`` objects:
- the ciphertext, of equal length as the plaintext
- the 16-byte MAC tag
uPerform :meth:`decrypt` and :meth:`verify` in one step.
:param ciphertext: The piece of data to decrypt.
:type ciphertext: bytes/bytearray/memoryview
:param bytes received_mac_tag:
This is the 16-byte *binary* MAC, as received from the sender.
:return: the decrypted data (as ``bytes``)
:raises ValueError:
if the MAC does not match. The message has been tampered with
or the key is incorrect.
key
uMissing parameter %s
uKey must be 32 bytes long
pop
T anonce
nT l T l l a_HChaCha20
:nl nb
:l nnuNonce must be 8, 12 or 24 bytes long
is_buffer
unonce must be bytes, bytearray or memoryview
uUnknown parameters:
aChaCha20Poly1305Cipher
a_copy_bytes
nonce
uCreate a new ChaCha20-Poly1305 or XChaCha20-Poly1305 AEAD cipher.
:keyword key: The secret key to use. It must be 32 bytes long.
:type key: byte string
:keyword nonce:
A value that must never be reused for any other encryption
done with this key.
For ChaCha20-Poly1305, it must be 8 or 12 bytes long.
For XChaCha20-Poly1305, it must be 24 bytes long.
If not provided, 12 ``bytes`` will be generated randomly
(you can find them back in the ``nonce`` attribute).
:type nonce: bytes, bytearray, memoryview
:Return: a :class:`Crypto.Cipher.ChaCha20.ChaCha20Poly1305Cipher` object
a__doc__
a__file__
origin
has_location
a__cached__
binascii
T aunhexlify
uCrypto.Cipher
T aChaCha20
uCrypto.Cipher.ChaCha20
T a_HChaCha20
uCrypto.Hash
T aPoly1305
aBLAKE2s
uCrypto.Random
T aget_random_bytes
uCrypto.Util.number
T along_to_bytes
uCrypto.Util.py3compat
T a_copy_bytes
bord
uCrypto.Util._raw_api
T ais_buffer
a_enum
T l l l T aPROCESSING_AUTH_DATA
aPROCESSING_CIPHERTEXT
aPROCESSING_DONE
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
