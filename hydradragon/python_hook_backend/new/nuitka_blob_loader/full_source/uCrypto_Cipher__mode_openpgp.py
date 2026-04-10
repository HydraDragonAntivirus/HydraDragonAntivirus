# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher._mode_openpgp

uOpenPGP mode.
This mode is a variant of CFB, and it is only used in PGP and
OpenPGP_ applications. If in doubt, use another mode.
An Initialization Vector (*IV*) is required.
Unlike CFB, the *encrypted* IV (not the IV itself) is
transmitted to the receiver.
The IV is a random data block. For legacy reasons, two of its bytes are
duplicated to act as a checksum for the correctness of the key, which is now
known to be insecure and is ignored. The encrypted IV is therefore 2 bytes
longer than the clean IV.
.. _OpenPGP: http://tools.ietf.org/html/rfc4880
:undocumented: __init__
a__qualname__
a__init__
uOpenPgpMode.__init__
uOpenPgpMode.encrypt
uOpenPgpMode.decrypt
a__orig_bases__
a_create_openpgp_cipher
uCrypto\Cipher\_mode_openpgp.py
u<module Crypto.Cipher._mode_openpgp>
T a__class__
T aself
factory
key
iv
cipher_params
aIV_cipher
T afactory
kwargs
iv
aIV
key
weT aself
ciphertext
T aself
plaintext
res

a__spec__
.Crypto.Cipher._mode_siv
q$
block_size
a_factory
a_cipher_params
T l l0l@uIncorrect key length (%d bytes)
is_buffer
uWhen provided, the nonce must be bytes, bytearray or memoryview
uWhen provided, the nonce must be non-empty
a_copy_bytes
nonce
l a_mac_tag
a_S2V
T aciphermod
cipher_params
a_kdf
a_subkey_cipher
new
aMODE_ECB
L aupdate
encrypt
decrypt
digest
verify
a_next
bytes_to_long
g                      aMODE_CTR
initial_value
c
uCreate a new CTR cipher from V in SIV mode
update
uupdate() can only be called immediately after initialization
uProtect one associated data component
For SIV, the associated data is a sequence (*vector*) of non-empty
byte strings (*components*).
This method consumes the next component. It must be called
once for each of the components that constitue the associated data.
Note that the components have clear boundaries, so that:
>>> cipher.update(b"builtin")
>>> cipher.update(b"securely")
is not equivalent to:
>>> cipher.update(b"built")
>>> cipher.update(b"insecurely")
If there is no associated data, this method must not be called.
:Parameters:
component : bytes/bytearray/memoryview
The next associated data component.
uencrypt() not allowed for SIV mode. Use encrypt_and_digest() instead.

For SIV, encryption and MAC authentication must take place at the same
point. This method shall not be used.
Use `encrypt_and_digest` instead.
udecrypt() not allowed for SIV mode. Use decrypt_and_verify() instead.

For SIV, decryption and verification must take place at the same
point. This method shall not be used.
Use `decrypt_and_verify` instead.
digest
udigest() cannot be called when decrypting or validating a message
derive
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
verify
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
encrypt
uencrypt() can only be called after initialization or an update()
a_create_ctr_cipher
T aoutput
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
decrypt
udecrypt() can only be called after initialization or an update()
a_cipher
uPerform decryption and verification in one step.
A cipher object is stateful: once you have decrypted a message
you cannot decrypt (or encrypt) another message with the same
object.
You cannot reuse an object for encrypting
or decrypting other data with the same key.
This function does not remove any padding from the plaintext.
:Parameters:
ciphertext : bytes/bytearray/memoryview
The piece of data to decrypt.
It can be of any length.
mac_tag : bytes/bytearray/memoryview
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
naSivMode
uCreate a new block cipher, configured in
Synthetic Initializaton Vector (SIV) mode.
:Parameters:
factory : object
A symmetric cipher module from `Crypto.Cipher`
(like `Crypto.Cipher.AES`).
:Keywords:
key : bytes/bytearray/memoryview
The secret key to use in the symmetric cipher.
It must be 32, 48 or 64 bytes long.
If AES is the chosen cipher, the variants *AES-128*,
*AES-192* and or *AES-256* will be used internally.
nonce : bytes/bytearray/memoryview
For deterministic encryption, it is not present.
Otherwise, it is a value that must never be reused
for encrypting message under this key.
There are no restrictions on its length,
but it is recommended to use at least 16 bytes.

Synthetic Initialization Vector (SIV) mode.
a__doc__
a__file__
origin
has_location
a__cached__
a__all__
binascii
T ahexlify
unhexlify
hexlify
uCrypto.Util.py3compat
T abord
a_copy_bytes
uCrypto.Util._raw_api
T ais_buffer
uCrypto.Util.number
T along_to_bytes
bytes_to_long
long_to_bytes
uCrypto.Protocol.KDF
T a_S2V
uCrypto.Hash
T aBLAKE2s
uCrypto.Random
T aget_random_bytes
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
