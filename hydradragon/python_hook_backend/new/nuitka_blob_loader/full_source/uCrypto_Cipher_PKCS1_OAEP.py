# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Cipher.PKCS1_OAEP

uCipher object for PKCS#1 v1.5 OAEP.
Do not create directly: use :func:`new` instead.
a__qualname__
a__init__
uPKCS1OAEP_Cipher.__init__
uPKCS1OAEP_Cipher.can_encrypt
uPKCS1OAEP_Cipher.can_decrypt
encrypt
uPKCS1OAEP_Cipher.encrypt
decrypt
uPKCS1OAEP_Cipher.decrypt
T nnc
nuCrypto\Cipher\PKCS1_OAEP.py
T wxwyaself
T aself
u<module Crypto.Cipher.PKCS1_OAEP>
T aself
key
hashAlgo
mgfunc
label
randfunc
T aself
ciphertext
modBits
wkahLen
ct_int
em
lHash
maskedSeed
maskedDB
seedMask
seed
dbMask
db
res
T aself
message
modBits
wkahLen
mLen
ps_len
lHash
ps
db
ros
dbMask
maskedDB
seedMask
maskedSeed
em
em_int
m_int
wcT akey
hashAlgo
mgfunc
label
randfunc

a__spec__
.Crypto.Cipher.PKCS1_v1_5
H
a_key
a_randfunc
uInitialize this PKCS#1 v1.5 cipher object.
:Parameters:
key : an RSA key object
If a private half is given, both encryption and decryption are possible.
If a public half is given, only encryption is possible.
randfunc : callable
Function that returns random bytes.
can_encrypt
uReturn True if this cipher object can be used for encryption.
can_decrypt
uReturn True if this cipher object can be used for decryption.
size_in_bytes
l uPlaintext is too long.
ps
wkamLen
l aself
T l abord
c
b
d
a_copy_bytes
bytes_to_long
a_encrypt
long_to_bytes
uProduce the PKCS#1 v1.5 encryption of a message.
This function is named ``RSAES-PKCS1-V1_5-ENCRYPT``, and it is specified in
`section 7.2.1 of RFC8017
<https://tools.ietf.org/html/rfc8017#page-28>`_.
:param message:
The message to encrypt, also known as plaintext. It can be of
variable length, but not longer than the RSA modulus (in bytes) minus 11.
:type message: bytes/bytearray/memoryview
:Returns: A byte string, the ciphertext in which the message is encrypted.
It is as long as the RSA modulus (in bytes).
:Raises ValueError:
If the RSA key length is not sufficiently long to deal with the given
message.
uCiphertext with incorrect length (not %d bytes)
a_decrypt_to_bytes
is_bytes
pkcs1_decode
uDecrypt a PKCS#1 v1.5 ciphertext.
This is the function ``RSAES-PKCS1-V1_5-DECRYPT`` specified in
`section 7.2.2 of RFC8017
<https://tools.ietf.org/html/rfc8017#page-29>`_.
Args:
ciphertext (bytes/bytearray/memoryview):
The ciphertext that contains the message to recover.
sentinel (any type):
The object to return whenever an error is detected.
expected_pt_len (integer):
The length the plaintext is known to have, or 0 if unknown.
Returns (byte string):
It is either the original message or the ``sentinel`` (in case of an error).
.. warning::
PKCS#1 v1.5 decryption is intrinsically vulnerable to timing
ttacks (see `Bleichenbacher's`__ attack).
**Use PKCS#1 OAEP instead**.
This implementation attempts to mitigate the risk
with some constant-time constructs.
However, they are not sufficient by themselves: the type of protocol you
implement and the way you handle errors make a big difference.
Specifically, you should make it very hard for the (malicious)
party that submitted the ciphertext to quickly understand if decryption
succeeded or not.
To this end, it is recommended that your protocol only encrypts
plaintexts of fixed length (``expected_pt_len``),
that ``sentinel`` is a random byte string of the same length,
nd that processing continues for as long
s possible even if ``sentinel`` is returned (i.e. in case of
incorrect decryption).
.. __: https://dx.doi.org/10.1007/BFb0055716
aRandom
get_random_bytes
aPKCS115_Cipher
uCreate a cipher for performing PKCS#1 v1.5 encryption or decryption.
:param key:
The key to use to encrypt or decrypt the message. This is a `Crypto.PublicKey.RSA` object.
Decryption is only possible if *key* is a private RSA key.
:type key: RSA key object
:param randfunc:
Function that return random bytes.
The default is :func:`Crypto.Random.get_random_bytes`.
:type randfunc: callable
:returns: A cipher object `PKCS115_Cipher`.
a__doc__
a__file__
origin
has_location
a__cached__
new
a__all__
aCrypto
T aRandom
uCrypto.Util.number
T abytes_to_long
long_to_bytes
uCrypto.Util.py3compat
T abord
is_bytes
a_copy_bytes
a_pkcs1_oaep_decode
T apkcs1_decode
