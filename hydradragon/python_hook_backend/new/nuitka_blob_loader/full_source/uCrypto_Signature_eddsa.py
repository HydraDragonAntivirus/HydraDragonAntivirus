# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Signature.eddsa

uAn EdDSA signature object.
Do not instantiate directly.
Use :func:`Crypto.Signature.eddsa.new`.
a__qualname__
a__init__
uEdDSASigScheme.__init__
can_sign
uEdDSASigScheme.can_sign
sign
uEdDSASigScheme.sign
uEdDSASigScheme._sign_ed25519
uEdDSASigScheme._sign_ed448
verify
uEdDSASigScheme.verify
uEdDSASigScheme._verify_ed25519
uEdDSASigScheme._verify_ed448
a__orig_bases__
T nuCrypto\Signature\eddsa.py
u<module Crypto.Signature.eddsa>
T a__class__
T aself
key
context
T aself
msg_or_hash
ph
flag
dom2
aPHM
r_hash
wraR_pk
k_hash
wkwsT aself
msg_or_hash
ph
flag
dom4
aPHM
r_hash
wraR_pk
k_hash
wkwsTaself
msg_or_hash
signature
ph
flag
dom2
aPHM
wRwsak_hash
wkapoint1
point2
Taself
msg_or_hash
signature
ph
flag
dom4
aPHM
wRwsak_hash
wkapoint1
point2
T aself
T aencoded
curve_name
T aencoded
wxwyacurve_name
T akey
mode
context
T aself
msg_or_hash
ph
eddsa_sign_method
T aself
msg_or_hash
signature
ph
eddsa_verify_method

a__spec__
.Crypto.Signature.pkcs1_15
I
a_key
uInitialize this PKCS#1 v1.5 signature scheme object.
:Parameters:
rsa_key : an RSA key object
Creation of signatures is only possible if this is a *private*
RSA key. Verification of signatures is always possible.
has_private
uReturn ``True`` if this object can be used to sign messages.
aCrypto
aUtil
number
size
wnaceil_div
l a_EMSA_PKCS1_V1_5_ENCODE
bytes_to_long
a_decrypt_to_bytes
pow
weuFault detected in RSA private key operation
uCreate the PKCS#1 v1.5 signature of a message.
This function is also called ``RSASSA-PKCS1-V1_5-SIGN`` and
it is specified in
`section 8.2.1 of RFC8017 <https://tools.ietf.org/html/rfc8017#page-36>`_.
:parameter msg_hash:
This is an object from the :mod:`Crypto.Hash` package.
It has been used to digest the message to sign.
:type msg_hash: hash object
:return: the signature encoded as a *byte string*.
:raise ValueError: if the RSA key is not long enough for the given hash algorithm.
:raise TypeError: if the RSA key has no private half.
uInvalid signature
a_encrypt
long_to_bytes
oid
startswith
T u1.2.840.113549.2.
uCheck if the  PKCS#1 v1.5 signature over a message is valid.
This function is also called ``RSASSA-PKCS1-V1_5-VERIFY`` and
it is specified in
`section 8.2.2 of RFC8037 <https://tools.ietf.org/html/rfc8017#page-37>`_.
:parameter msg_hash:
The hash that was carried out over the message. This is an object
belonging to the :mod:`Crypto.Hash` module.
:type parameter: hash object
:parameter signature:
The signature that needs to be validated.
:type signature: byte string
:raise ValueError: if the signature is not valid.
aDerSequence
aDerObjectId
encode
append
aDerNull
aDerOctetString
digest
uDigestInfo is too long for this RSA key (%d bytes).
d l b
d

Implement the ``EMSA-PKCS1-V1_5-ENCODE`` function, as defined
in PKCS#1 v2.1 (RFC3447, 9.2).
``_EMSA-PKCS1-V1_5-ENCODE`` actually accepts the message ``M`` as input,
nd hash it internally. Here, we expect that the message has already
been hashed instead.
:Parameters:
msg_hash : hash object
The hash object that holds the digest of the message being signed.
emLen : int
The length the final encoding must have, in bytes.
with_hash_parameters : bool
If True (default), include NULL parameters for the hash
lgorithm in the ``digestAlgorithm`` SEQUENCE.
:attention: the early standard (RFC2313) stated that ``DigestInfo``
had to be BER-encoded. This means that old signatures
might have length tags in indefinite form, which
is not supported in DER. Such encoding cannot be
reproduced by this function.
:Return: An ``emLen`` byte long string that encodes the hash.
aPKCS115_SigScheme
uCreate a signature object for creating
or verifying PKCS#1 v1.5 signatures.
:parameter rsa_key:
The RSA key to use for signing or verifying the message.
This is a :class:`Crypto.PublicKey.RSA` object.
Signing is only possible when ``rsa_key`` is a **private** RSA key.
:type rsa_key: RSA object
:return: a :class:`PKCS115_SigScheme` signature object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.number
T aceil_div
bytes_to_long
long_to_bytes
uCrypto.Util.asn1
T aDerSequence
aDerNull
aDerOctetString
aDerObjectId
