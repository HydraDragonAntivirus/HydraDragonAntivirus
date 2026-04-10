# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher._mode_ofb

u*Output FeedBack (OFB)*.
This mode is very similar to CBC, but it
transforms the underlying block cipher into a stream cipher.
The keystream is the iterated block encryption of the
previous ciphertext block.
An Initialization Vector (*IV*) is required.
See `NIST SP800-38A`_ , Section 6.4.
.. _`NIST SP800-38A` : http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
:undocumented: __init__
a__qualname__
a__init__
uOfbMode.__init__
T nuOfbMode.encrypt
uOfbMode.decrypt
a__orig_bases__
a_create_ofb_cipher
uCrypto\Cipher\_mode_ofb.py
u<module Crypto.Cipher._mode_ofb>
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
.Crypto.Cipher._mode_openpgp
A
block_size
a_done_first_block
new
aMODE_CFB
aIV
d
segment_size
l a_copy_bytes
encrypt
:q nna_encrypted_IV
l adecrypt
:nq nuLength of IV must be %d or %d bytes for MODE_OPENPGP
iv
a_cipher
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
:Return:
the encrypted data, as a byte string.
It is as long as *plaintext* with one exception:
when encrypting the first message chunk,
the encypted IV is prepended to the returned ciphertext.
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
:Return: the decrypted data (byte string).
pop
T aiv
nT nnaget_random_bytes
uYou must either use 'iv' or 'IV', not both
T akey
uMissing component:
aOpenPgpMode
uCreate a new block cipher, configured in OpenPGP mode.
:Parameters:
factory : module
The module.
:Keywords:
key : bytes/bytearray/memoryview
The secret key to use in the symmetric cipher.
IV : bytes/bytearray/memoryview
The initialization vector to use for encryption or decryption.
For encryption, the IV must be as long as the cipher block size.
For decryption, it must be 2 bytes longer (it is actually the
*encrypted* IV which was prefixed to the ciphertext).

OpenPGP mode.
a__doc__
a__file__
origin
has_location
a__cached__
a__all__
uCrypto.Util.py3compat
T a_copy_bytes
uCrypto.Random
T aget_random_bytes
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
