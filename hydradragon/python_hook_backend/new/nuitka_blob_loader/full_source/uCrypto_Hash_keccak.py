# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.keccak

uA Keccak hash object.
Do not instantiate directly.
Use the :func:`new` function.
:ivar digest_size: the size in bytes of the resulting hash
:vartype digest_size: integer
a__qualname__
a__init__
uKeccak_Hash.__init__
uKeccak_Hash.update
uKeccak_Hash.digest
hexdigest
uKeccak_Hash.hexdigest
uKeccak_Hash.new
a__orig_bases__
uCrypto\Hash\keccak.py
u<module Crypto.Hash.keccak>
T a__class__
T aself
data
digest_bytes
update_after_digest
state
result
T aself
bfr
result
T aself
T aself
kwargs
T akwargs
data
update_after_digest
digest_bytes
digest_bits
T aself
data
result
a__spec__
.Crypto.IO.PEM
i
get_random_bytes
u-----BEGIN %s-----
T l aPBKDF1
l aMD5
l aDES3
new
aMODE_CBC
uProc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,%s
tostr
hexlify
upper
encrypt
pad
block_size
uEmpty password
l0ab2a_base64

u-----END %s-----
uEncode a piece of binary data into PEM format.
Args:
data (byte string):
The piece of binary data to encode.
marker (string):
The marker for the PEM block (e.g. "PUBLIC KEY").
Note that there is no official master list for all allowed markers.
Still, you can refer to the OpenSSL_ source code.
passphrase (byte string):
If given, the PEM block will be encrypted. The key is derived from
the passphrase.
randfunc (callable):
Random number generation function; it accepts an integer N and returns
a byte string of random data, N bytes long. If not given, a new one is
instantiated.
Returns:
The PEM block, as a string.
.. _OpenSSL: https://github.com/openssl/openssl/blob/master/include/openssl/pem.h
c
l wdadata
salt
digest
re
compile
T u\s*-----BEGIN (.*)-----\s+
match
uNot a valid PEM pre boundary
group
T l T u-----END (.*)-----\s*$
search
uNot a valid PEM post boundary
replace
T w u
split
startswith
T uProc-Type:4,ENCRYPTED
uPEM is encrypted, but no passphrase available
l T w:uDEK-Info
uPEM encryption format not supported.
T w,aunhexlify
tobytes
uDES-CBC
a_EVP_BytesToKey
aDES
uDES-EDE3-CBC
l uAES-128-CBC
:nl naAES
uAES-192-CBC
uAES-256-CBC
l alower
uid-aes256-gcm
aMODE_GCM
T anonce
uUnsupport PEM encryption algorithm (%s).
:l nnaa2b_base64
:l q napadding
unpad
decrypt
uDecode a PEM block into binary.
Args:
pem_data (string):
The PEM block.
passphrase (byte string):
If given and the PEM block is encrypted,
the key will be derived from the passphrase.
Returns:
A tuple with the binary data, the marker string, and a boolean to
indicate if decryption was performed.
Raises:
ValueError: if decoding fails, if the PEM file is encrypted and no passphrase has
been provided or if the passphrase is incorrect.
a__doc__
a__file__
origin
has_location
a__cached__
encode
decode
a__all__
binascii
T aa2b_base64
b2a_base64
hexlify
unhexlify
uCrypto.Hash
T aMD5
uCrypto.Util.Padding
T apad
unpad
uCrypto.Cipher
T aDES
aDES3
aAES
uCrypto.Protocol.KDF
T aPBKDF1
uCrypto.Random
T aget_random_bytes
uCrypto.Util.py3compat
T atobytes
tostr
T nnT nuCrypto\IO\PEM.py
u<module Crypto.IO.PEM>
T adata
salt
key_len
wdwmw_and
T apem_data
passphrase
wrwmamarker
lines
aDEK
algo
salt
padding
key
objdec
data
enc_flag
T	adata
marker
passphrase
randfunc
out
salt
key
objenc
chunks
a__spec__
.Crypto.IO.PKCS8
k
9
aDerSequence
aDerObjectId
aDerOctetString
encode
aValueError
T uEmpty passphrase
tobytes
uPBKDF2WithHMAC-SHA1AndDES-EDE3-CBC
aPBES2
encrypt
uWrap a private key into a PKCS#8 blob (clear or encrypted).
Args:
private_key (bytes):
The private key encoded in binary form. The actual encoding is
lgorithm specific. In most cases, it is DER.
key_oid (string):
The object identifier (OID) of the private key to wrap.
It is a dotted string, like ``'1.2.840.113549.1.1.1'`` (for RSA keys)
or ``'1.2.840.10045.2.1'`` (for ECC keys).
Keyword Args:
passphrase (bytes or string):
The secret passphrase from which the wrapping key is derived.
Set it only if encryption is required.
protection (string):
The identifier of the algorithm to use for securely wrapping the key.
Refer to :ref:`the encryption parameters<enc_params>` .
The default value is ``'PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC'``.
prot_params (dictionary):
Parameters for the key derivation function (KDF).
Refer to :ref:`the encryption parameters<enc_params>` .
key_params (DER object or None):
The ``parameters`` field to use in the ``AlgorithmIdentifier``
SEQUENCE. If ``None``, no ``parameters`` field will be added.
By default, the ASN.1 type ``NULL`` is used.
randfunc (callable):
Random number generation function; it should accept a single integer
N and return a string of random data, N bytes long.
If not specified, a new RNG will be instantiated
from :mod:`Crypto.Random`.
Returns:
bytes: The PKCS#8-wrapped private key (possibly encrypted).
aPBES1
decrypt
aPbesError
uPBES1[%s]
str
uPBES1[Invalid]
p8_private_key
error_str
u,PBES2[%s]
u,PBES2[Invalid]
uError decoding PKCS#8 (%s)
decode
D anr_elements
T l l l l alen
l apassphrase
T uNot a valid clear PKCS#8 structure (maybe it is encrypted?)
T l l T uNot a valid PrivateKeyInfo SEQUENCE
T l l l D anr_elements
T l l avalue
aDerNull
payload
uUnwrap a private key from a PKCS#8 blob (clear or encrypted).
Args:
p8_private_key (bytes):
The private key wrapped into a PKCS#8 container, DER encoded.
Keyword Args:
passphrase (byte string or string):
The passphrase to use to decrypt the blob (if it is encrypted).
Return:
A tuple containing
#. the algorithm identifier of the wrapped key (OID, dotted string)
#. the private key (bytes, DER encoded)
#. the associated parameters (bytes, DER encoded) or ``None``
Raises:
ValueError : if decoding fails
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T w*uCrypto.Util.asn1
T aDerNull
aDerSequence
aDerObjectId
aDerOctetString
uCrypto.IO._PBES
T aPBES1
aPBES2
aPbesError
wrap
unwrap
a__all__
T nuCrypto\IO\PKCS8.py
u<module Crypto.IO.PKCS8>
T
p8_private_key
passphrase
found
weaerror_str
pk_info
algo
algo_oid
algo_params
private_key
T
private_key
key_oid
passphrase
protection
prot_params
key_params
randfunc
algorithm
pk_info
pk_info_der

a__spec__
.Crypto.IO._PBES
9
aDerSequence
decode
aDerOctetString
payload
aDerObjectId
value
a_OID_PBE_WITH_MD5_AND_DES_CBC
uCrypto.Hash
T aMD5
aMD5
uCrypto.Cipher
T aDES
aDES
a_OID_PBE_WITH_MD5_AND_RC2_CBC
T aARC2
aARC2
l@aeffective_keylen
a_OID_PBE_WITH_SHA1_AND_DES_CBC
T aSHA1
aSHA1
a_OID_PBE_WITH_SHA1_AND_RC2_CBC
aPbesError
T uUnknown OID for PBES1
D anr_elements
l aPBKDF1
l :nl n:l nnanew
aMODE_CBC
cipher_params
decrypt
unpad
block_size
uDecrypt a piece of data using a passphrase and *PBES1*.
The algorithm to use is automatically detected.
:Parameters:
data : byte string
The piece of data to decrypt.
passphrase : byte string
The passphrase to use for decrypting the data.
:Returns:
The decrypted data, as a binary string.
aRandom
read
re
compile
T u^(PBKDF2WithHMAC-([0-9A-Z-]+)|scrypt)And([0-9A-Z-]+)$
match
uUnknown protection %s
startswith
T aPBKDF
pbkdf2
group
T l T l ascrypt
uDES-EDE3-CBC
T aDES3
aDES3
l a_OID_DES_EDE3_CBC
iv
T l uAES128-CBC
aAES
a_OID_AES128_CBC
T l uAES192-CBC
a_OID_AES192_CBC
uAES256-CBC
l a_OID_AES256_CBC
uAES128-GCM
aMODE_GCM
a_OID_AES128_GCM
nonce
T l uAES192-GCM
a_OID_AES192_GCM
uAES256-GCM
a_OID_AES256_GCM
uUnknown encryption mode '%s'
randfunc
get
T asalt_size
l T aiteration_count
l  aHash
pbkdf2_hmac_algo
aPBKDF2
T ahmac_hash_module
aDerInteger
aHMAC
T c
T adigestmod
oid
uNo OID for HMAC hash algorithm
append
a_OID_PBKDF2
T aiteration_count
l   T ablock_size
l T aparallelization
l a_OID_SCRYPT
uUnknown KDF
res
T l aencrypt_and_digest
encrypt
pad
a_OID_PBES2
encode
uEncrypt a piece of data using a passphrase and *PBES2*.
:Parameters:
data : byte string
The piece of data to encrypt.
passphrase : byte string
The passphrase to use for encrypting the data.
protection : string
The identifier of the encryption algorithm to use.
The default value is '``PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC``'.
prot_params : dictionary
Parameters of the protection algorithm.
+------------------+-----------------------------------------------+
| Key              | Description                                   |
+==================+===============================================+
| iteration_count  | The KDF algorithm is repeated several times to|
|                  | slow down brute force attacks on passwords    |
|                  | (called *N* or CPU/memory cost in scrypt).    |
|                  |                                               |
|                  | The default value for PBKDF2 is 1 000.        |
|                  | The default value for scrypt is 16 384.       |
+------------------+-----------------------------------------------+
| salt_size        | Salt is used to thwart dictionary and rainbow |
|                  | attacks on passwords. The default value is 8  |
|                  | bytes.                                        |
+------------------+-----------------------------------------------+
| block_size       | *(scrypt only)* Memory-cost (r). The default  |
|                  | value is 8.                                   |
+------------------+-----------------------------------------------+
| parallelization  | *(scrypt only)* CPU-cost (p). The default     |
|                  | value is 1.                                   |
+------------------+-----------------------------------------------+
randfunc : callable
Random number generation function; it should accept
a single integer N and return a string of random data,
N bytes long. If not specified, a new RNG will be
instantiated from ``Crypto.Random``.
:Returns:
The encrypted data, as a binary string.
T uNot a PBES2 object
D anr_elements
T l l l l a_OID_HMAC_SHA1
D anr_elements
T l l T l l l l T uUnsupported PBES2 KDF
uUnsupported PBES2 cipher
T uMismatch between PBES2 KDF parameters and selected cipher
a_hmac2hash_oid
pbkdf2_prf_oid
uUnsupported HMAC %s
scrypt_r
scrypt_p
uToo little data to decrypt
decrypt_and_verify
uDecrypt a piece of data using a passphrase and *PBES2*.
The algorithm to use is automatically detected.
:Parameters:
data : byte string
The piece of data to decrypt.
passphrase : byte string
The passphrase to use for decrypting the data.
:Returns:
The decrypted data, as a binary string.
a__doc__
a__file__
origin
has_location
a__cached__
aCrypto
T aHash
T aRandom
uCrypto.Util.asn1
T aDerSequence
aDerOctetString
aDerObjectId
aDerInteger
T aAES
uCrypto.Util.Padding
T apad
unpad
uCrypto.Protocol.KDF
T aPBKDF1
aPBKDF2
scrypt
u1.2.840.113549.1.5.3
u1.2.840.113549.1.5.6
u1.2.840.113549.1.5.10
u1.2.840.113549.1.5.11
u1.2.840.113549.1.5.13
u1.2.840.113549.1.5.12
u1.3.6.1.4.1.11591.4.11
u1.2.840.113549.2.7
u1.2.840.113549.3.7
u2.16.840.1.101.3.4.1.2
u2.16.840.1.101.3.4.1.22
u2.16.840.1.101.3.4.1.42
u2.16.840.1.101.3.4.1.6
u2.16.840.1.101.3.4.1.26
u2.16.840.1.101.3.4.1.46
T EValueError
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
