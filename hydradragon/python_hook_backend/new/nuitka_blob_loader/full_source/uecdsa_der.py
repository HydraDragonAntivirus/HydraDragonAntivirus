# Reconstructed from integrated Nuitka blob
# Module: uecdsa.der

a__qualname__
a__orig_bases__
encode_constructed
encode_integer
encode_bitstring
encode_octet_string
encode_oid
encode_sequence
is_sequence
remove_constructed
remove_sequence
remove_octet_string
remove_object
remove_integer
remove_bitstring
unpem
topem
uecdsa\der.py
T a.0
wpu<module ecdsa.der>
T wsaunused
encoded_unused
len_extra
last
T atag
value
T wrwhwsanum
T wlwsallen
T wnab128_digits
T wsT afirst
second
pieces
body
T aencoded_pieces
total_len
T astring
T astring
num
llen
msb
T astring
number
llen
wdT	astring
expect_unused
num
length
llen
body
rest
unused
last
T astring
s0
tag
length
llen
body
rest
T astring
wnalength
llen
numberbytes
rest
msb
smsb
T astring
wnalength
lengthlength
body
rest
numbers
all
n0
first
second
T astring
wnalength
llen
body
rest
T astring
wnalength
lengthlength
endseq
T ader
name
b64
lines
T apem
wdu
a__spec__
.ecdsa.ecdh
"
{
curve
private_key
public_key
load_private_key
load_received_public_key

ECDH init.
Call can be initialised without parameters, then the first operation
(loading either key) will set the used curve.
All parameters must be ultimately set before shared secret
calculation will be allowed.
:param curve: curve for operations
:type curve: Curve
:param private_key: `my` private key for ECDH
:type private_key: SigningKey
:param public_key:  `their` public key for ECDH
:type public_key: VerifyingKey
aNoKeyError
T uPrivate key needs to be set to create shared secret
T uPublic key needs to be set to create shared secret
aInvalidCurveError
T uCurves for public key and private key is not equal.
pubkey
point
privkey
secret_multiplier
aINFINITY
aInvalidSharedSecretError
T uInvalid shared secret (INFINITY).
wxu
Set the working curve for ecdh operations.
:param key_curve: curve from `curves` module
:type key_curve: Curve
aNoCurveError
T uCurve must be set prior to key generation.
aSigningKey
generate
T acurve

Generate local private key for ecdh operation with curve that was set.
:raises NoCurveError: Curve must be set before key generation.
:return: public (verifying) key from this private key.
:rtype: VerifyingKey
T uCurve mismatch.
get_verifying_key

Load private key from SigningKey (keys.py) object.
Needs to have the same curve as was set with set_curve method.
If curve is not set - it sets from this SigningKey
:param private_key: Initialised SigningKey class
:type private_key: SigningKey
:raises InvalidCurveError: private_key curve not the same as self.curve
:return: public (verifying) key from this private key.
:rtype: VerifyingKey
T uCurve must be set prior to key load.
from_string

Load private key from byte string.
Uses current curve and checks if the provided key matches
the curve of ECDH key agreement.
Key loads via from_string method of SigningKey class
:param private_key: private key in bytes string format
:type private_key: :term:`bytes-like object`
:raises NoCurveError: Curve must be set before loading.
:return: public (verifying) key from this private key.
:rtype: VerifyingKey
from_der

Load private key from DER byte string.
Compares the curve of the DER-encoded key with the ECDH set curve,
uses the former if unset.
Note, the only DER format supported is the RFC5915
Look at keys.py:SigningKey.from_der()
:param private_key_der: string with the DER encoding of private ECDSA
key
:type private_key_der: string
:raises InvalidCurveError: private_key curve not the same as self.curve
:return: public (verifying) key from this private key.
:rtype: VerifyingKey
from_pem

Load private key from PEM string.
Compares the curve of the DER-encoded key with the ECDH set curve,
uses the former if unset.
Note, the only PEM format supported is the RFC5915
Look at keys.py:SigningKey.from_pem()
it needs to have `EC PRIVATE KEY` section
:param private_key_pem: string with PEM-encoded private ECDSA key
:type private_key_pem: string
:raises InvalidCurveError: private_key curve not the same as self.curve
:return: public (verifying) key from this private key.
:rtype: VerifyingKey

Provides a public key that matches the local private key.
Needs to be sent to the remote party.
:return: public (verifying) key from local private key.
:rtype: VerifyingKey

Load public key from VerifyingKey (keys.py) object.
Needs to have the same curve as set as current for ecdh operation.
If curve is not set - it sets it from VerifyingKey.
:param public_key: Initialised VerifyingKey class
:type public_key: VerifyingKey
:raises InvalidCurveError: public_key curve not the same as self.curve
aVerifyingKey

Load public key from byte string.
Uses current curve and checks if key length corresponds to
the current curve.
Key loads via from_string method of VerifyingKey class
:param public_key_str: public key in bytes string format
:type public_key_str: :term:`bytes-like object`
:param valid_encodings: list of acceptable point encoding formats,
supported ones are: :term:`uncompressed`, :term:`compressed`,
:term:`hybrid`, and :term:`raw encoding` (specified with ``raw``
name). All formats by default (specified with ``None``).
:type valid_encodings: :term:`set-like object`

Load public key from DER byte string.
Compares the curve of the DER-encoded key with the ECDH set curve,
uses the former if unset.
Note, the only DER format supported is the RFC5912
Look at keys.py:VerifyingKey.from_der()
:param public_key_der: string with the DER encoding of public ECDSA key
:type public_key_der: string
:raises InvalidCurveError: public_key curve not the same as self.curve

Load public key from PEM string.
Compares the curve of the PEM-encoded key with the ECDH set curve,
uses the former if unset.
Note, the only PEM format supported is the RFC5912
Look at keys.py:VerifyingKey.from_pem()
:param public_key_pem: string with PEM-encoded public ECDSA key
:type public_key_pem: string
:raises InvalidCurveError: public_key curve not the same as self.curve
number_to_string
generate_sharedsecret
wpu
Generate shared secret from local private key and remote public key.
The objects needs to have both private key and received public key
before generation is allowed.
:raises InvalidCurveError: public_key curve not the same as self.curve
:raises NoKeyError: public_key or private_key is not set
:return: shared secret
:rtype: bytes
a_get_shared_secret

Generate shared secret from local private key and remote public key.
The objects needs to have both private key and received public key
before generation is allowed.
It's the same for local and remote party,
shared secret(local private key, remote public key) ==
shared secret(local public key, remote private key)
:raises InvalidCurveError: public_key curve not the same as self.curve
:raises NoKeyError: public_key or private_key is not set
:return: shared secret
:rtype: int

Class for performing Elliptic-curve Diffie-Hellman (ECDH) operations.
a__doc__
a__file__
origin
has_location
a__cached__
util
T anumber_to_string
ellipticcurve
T aINFINITY
keys
T aSigningKey
aVerifyingKey
L aECDH
aNoKeyError
aNoCurveError
aInvalidCurveError
aInvalidSharedSecretError
a__all__
T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
