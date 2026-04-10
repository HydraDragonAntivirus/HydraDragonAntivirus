# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Signature.pkcs1_15

uA signature object for ``RSASSA-PKCS1-v1_5``.
Do not instantiate directly.
Use :func:`Crypto.Signature.pkcs1_15.new`.
a__qualname__
a__init__
uPKCS115_SigScheme.__init__
can_sign
uPKCS115_SigScheme.can_sign
sign
uPKCS115_SigScheme.sign
verify
uPKCS115_SigScheme.verify
T tanew
uCrypto\Signature\pkcs1_15.py
u<module Crypto.Signature.pkcs1_15>
T amsg_hash
emLen
with_hash_parameters
digestAlgo
digest
digestInfo
aPS
T aself
rsa_key
T aself
T arsa_key
T aself
msg_hash
modBits
wkaem
em_int
signature
T
self
msg_hash
signature
modBits
wkasignature_int
em_int
em1
possible_em1
algorithm_is_md

a__spec__
.Crypto.Signature.pss
j
a_key
a_saltLen
a_mgfunc
a_randfunc
uInitialize this PKCS#1 PSS signature scheme object.
:Parameters:
key : an RSA key object
If a private half is given, both signature and
verification are possible.
If a public half is given, only verification is possible.
mgfunc : callable
A mask generation function that accepts two parameters:
a string to use as seed, and the lenth of the mask to
generate, in bytes.
saltLen : integer
Length of the salt, in bytes.
randfunc : callable
A function that returns random bytes.
has_private
uReturn ``True`` if this object can be used to sign messages.
digest_size
u<lambda>
uPSS_SigScheme.sign.<locals>.<lambda>
aCrypto
aUtil
number
size
wnaceil_div
l a_EMSA_PSS_ENCODE
bytes_to_long
a_decrypt_to_bytes
pow
weuFault detected in RSA private key operation
uCreate the PKCS#1 PSS signature of a message.
This function is also called ``RSASSA-PSS-SIGN`` and
it is specified in
`section 8.1.1 of RFC8017 <https://tools.ietf.org/html/rfc8017#section-8.1.1>`_.
:parameter msg_hash:
This is an object from the :mod:`Crypto.Hash` package.
It has been used to digest the message to sign.
:type msg_hash: hash object
:return: the signature encoded as a *byte string*.
:raise ValueError: if the RSA key is not long enough for the given hash algorithm.
:raise TypeError: if the RSA key has no private half.
aMGF1
msg_hash
uPSS_SigScheme.verify.<locals>.<lambda>
uIncorrect signature
a_encrypt
long_to_bytes
a_EMSA_PSS_VERIFY
uCheck if the  PKCS#1 PSS signature over a message is valid.
This function is also called ``RSASSA-PSS-VERIFY`` and
it is specified in
`section 8.1.2 of RFC8037 <https://tools.ietf.org/html/rfc8017#section-8.1.2>`_.
:parameter msg_hash:
The hash that was carried out over the message. This is an object
belonging to the :mod:`Crypto.Hash` module.
:type parameter: hash object
:parameter signature:
The signature that needs to be validated.
:type signature: bytes
:raise ValueError: if the signature is not valid.
c
iter_range
l ahash_gen
new
update
mgfSeed
wTadigest
uMask Generation Function, described in `B.2.1 of RFC8017
<https://tools.ietf.org/html/rfc8017>`_.
:param mfgSeed:
seed from which the mask is generated
:type mfgSeed: byte string
:param maskLen:
intended length in bytes of the mask
:type maskLen: integer
:param hash_gen:
A module or a hash object from :mod:`Crypto.Hash`
:type hash_object:
:return: the mask, as a *byte string*
lmask
l  l uDigest or salt length are too long for given key size.
bchr
T l
T l astrxor
bord
:l nnT l  u
Implement the ``EMSA-PSS-ENCODE`` function, as defined
in PKCS#1 v2.1 (RFC3447, 9.1.1).
The original ``EMSA-PSS-ENCODE`` actually accepts the message ``M``
s input, and hash it internally. Here, we expect that the message
has already been hashed instead.
:Parameters:
mhash : hash object
The hash object that holds the digest of the message being signed.
emBits : int
Maximum length of the final encoding, in bits.
randFunc : callable
An RNG function that accepts as only parameter an int, and returns
a string of random bytes, to be used as salt.
mgf : callable
A mask generation function that accepts two parameters: a string to
use as seed, and the lenth of the mask to generate, in bytes.
sLen : int
Length of the salt, in bytes.
:Return: An ``emLen`` byte long string that encodes the hash
(with ``emLen = \ceil(emBits/8)``).
:Raise ValueError:
When digest or salt length are too big.
:q nnl  astartswith

Implement the ``EMSA-PSS-VERIFY`` function, as defined
in PKCS#1 v2.1 (RFC3447, 9.1.2).
``EMSA-PSS-VERIFY`` actually accepts the message ``M`` as input,
nd hash it internally. Here, we expect that the message has already
been hashed instead.
:Parameters:
mhash : hash object
The hash object that holds the digest of the message to be verified.
em : string
The signature to verify, therefore proving that the sender really
signed the message that was received.
emBits : int
Length of the final encoding (em), in bits.
mgf : callable
A mask generation function that accepts two parameters: a string to
use as seed, and the lenth of the mask to generate, in bytes.
sLen : int
Length of the salt, in bytes.
:Raise ValueError:
When the encoding is inconsistent, or the digest or salt lengths
re too big.
mask_func
pop
T asalt_bytes
nT arand_func
naRandom
get_random_bytes
uUnknown keywords:
keys
aPSS_SigScheme
uCreate an object for making or verifying PKCS#1 PSS signatures.
:parameter rsa_key:
The RSA key to use for signing or verifying the message.
This is a :class:`Crypto.PublicKey.RSA` object.
Signing is only possible when ``rsa_key`` is a **private** RSA key.
:type rsa_key: RSA object
:Keyword Arguments:
*   *mask_func* (``callable``) --
A function that returns the mask (as `bytes`).
It must accept two parameters: a seed (as `bytes`)
nd the length of the data to return.
If not specified, it will be the function :func:`MGF1` defined in
`RFC8017 <https://tools.ietf.org/html/rfc8017#page-67>`_ and
combined with the same hash algorithm applied to the
message to sign or verify.
If you want to use a different function, for instance still :func:`MGF1`
but together with another hash, you can do::
from Crypto.Hash import SHA256
from Crypto.Signature.pss import MGF1
mgf = lambda x, y: MGF1(x, y, SHA256)
*   *salt_bytes* (``integer``) --
Length of the salt, in bytes.
It is a value between 0 and ``emLen - hLen - 2``, where ``emLen``
is the size of the RSA modulus and ``hLen`` is the size of the digest
pplied to the message to sign or verify.
The salt is generated internally, you don't need to provide it.
If not specified, the salt length will be ``hLen``.
If it is zero, the signature scheme becomes deterministic.
Note that in some implementations such as OpenSSL the default
salt length is ``emLen - hLen - 2`` (even though it is not more
secure than ``hLen``).
*   *rand_func* (``callable``) --
A function that returns random ``bytes``, of the desired length.
The default is :func:`Crypto.Random.get_random_bytes`.
:return: a :class:`PSS_SigScheme` signature object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T abchr
bord
iter_range
uCrypto.Util.number
T aceil_div
long_to_bytes
bytes_to_long
uCrypto.Util.strxor
T astrxor
T aRandom
