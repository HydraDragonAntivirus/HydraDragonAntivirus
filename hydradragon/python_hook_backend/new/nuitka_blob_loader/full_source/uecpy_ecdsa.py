# Reconstructed from integrated Nuitka blob
# Module: uecpy.ecdsa

uECDSA signer.
Args:
fmt (str) : in/out signature format. See :mod:`ecpy.formatters`
aECDSA
a__qualname__
T aDER
a__init__
uECDSA.__init__
T Fasign
uECDSA.sign
sign_rfc6979
uECDSA.sign_rfc6979
sign_k
uECDSA.sign_k
uECDSA._do_sign
verify
uECDSA.verify
uecpy\ecdsa.py
u<module ecpy.ecdsa>
T aself
fmt
T aself
msg
pv_key
wkacanonical
curve
wnwGamsg_len
wQakinv
wrwsasig
T aself
msg
pv_key
canonical
order
wiwkasig
T aself
msg
pv_key
wkacanonical
T
self
msg
pv_key
hasher
canonical
order
wVwiwkasig
T aself
msg
sig
pu_key
curve
wnwGwrwsamsg_len
whwcau1
u2
u1G
u2Q
aGQ
wxu
a__spec__
.ecpy.ecrand
;
?
bit_length
random
getrandbits
nbits
u Returns a random number less than q, with the same bits length than q
Args:
q (int)         : field/modulo
Returns:
int : random

bs(bytes): binary value
bits2int
urnd_rfc6979.<locals>.bits2int
int2octets
urnd_rfc6979.<locals>.int2octets
bits2octets
urnd_rfc6979.<locals>.bits2octets
digest_size
d d
hmac
new
digest
c
wqwTl wKwVahasher
u Generates a deterministic `value` according  to RF6979.
See https://tools.ietf.org/html/rfc6979#section-3.2
if V == None, this is the first try, so compute the initial value for V.
Else it means the previous value has been rejected by the caller, so
generate the next one!
Warning: the `hashmsg` parameter is the message hash, not the message
itself. In other words, `hashmsg` is equal to `h1` in the  *rfc6979, section-3.2,
step a*.
Args:
hasher (hashlib): hasher
hashmsg (bytes) : message hash
secret (int)    : secret
q (int)         : field/modulo
V               : previous value for continuation
The function returns a couple `(k,V)` with `k` the expected value and `V` is the
continuation value to pass to next cal if k is rejected.
Returns:
tuple: (k,V)
int
from_bytes
big
l q ato_bytes
a__doc__
a__file__
origin
has_location
a__cached__
uecpy.curves
T aCurve
aPoint
aCurve
aPoint
uecpy.keys
T aECPublicKey
aECPrivateKey
aECPublicKey
aECPrivateKey
uecpy.formatters
T adecode_sig
encode_sig
decode_sig
encode_sig
rnd
T narnd_rfc6979
uecpy\ecrand.py
u<module ecpy.ecrand>
T abs
wiablen
qlen
wqT wqT abs
z1
z2
woabits2int
wqaint2octets
T abits2int
int2octets
wqT wiarlen
wowqT wqanbits
wkT ahashmsg
secret
wqahasher
aVK
bits2int
int2octets
bits2octets
hsize
h1
wVwKwTaqlen
a_i
wku
a__spec__
.ecpy.eddsa
\
a_hasher
a_hash_len
fmt
aEDDSA
a_get_materials
aECPublicKey
u Returns the public key corresponding to this private key
This method compute the public key according to draft-irtf-cfrg-eddsa-05.
The hash parameter shall be the same as the one used for signing and
verifying.
Args:
hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
pv_key (ecpy.keys.ECPrivateKey): key to use for signing
Returns:
ECPublicKey : public key
curve
generator
order
a_coord_size
wdato_bytes
big
update
digest
name
aEd25519
:nl n:l nnl  l l l@aEd448
:nl9n:l9nnl  l8l7l  u%s not supported
waaint
from_bytes
little
u Returns the internal private scalar a(int), the public point A(ECPoint) = a.B and the
signature prefix h(bytes)
The hash parameter shall be the same as the one used for signing and
verifying.
Args:
hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
pv_key (ecpy.keys.ECPrivateKey): key to use for signing
Returns:
ECPrivateKey : internal private key
a_do_sign
u Signs a message.
Args:
msg (bytes)                    : the message to sign
pv_key (ecpy.keys.ECPrivateKey): key to use for signing
encode_point
T b
SigEd448
msg
eR
encode_sig
decode_sig
decode_point
wWu Verifies a message signature.
Args:
msg (bytes)                   : the message to verify the signature
sig (bytes)                   : signature to verify
pu_key (ecpy.keys.ECPublicKey): key to use for verifying
a__doc__
a__file__
origin
has_location
a__cached__
pow
binascii
uecpy.curves
T aCurve
aPoint
aCurve
aPoint
uecpy.keys
T aECPublicKey
aECPrivateKey
aECPrivateKey
uecpy.formatters
T adecode_sig
encode_sig
hashlib
