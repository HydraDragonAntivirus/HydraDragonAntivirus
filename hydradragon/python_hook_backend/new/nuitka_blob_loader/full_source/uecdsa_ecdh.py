# Reconstructed from integrated Nuitka blob
# Module: uecdsa.ecdh

uECDH. Key not found but it is needed for operation.
a__qualname__
a__orig_bases__
uECDH. Curve not set but it is needed for operation.

ECDH. Raised in case the public and private keys use different curves.
uECDH. Raised in case the shared secret we obtained is an INFINITY.
T Oobject
aECDH

Elliptic-curve Diffie-Hellman (ECDH). A key agreement protocol.
Allows two parties, each having an elliptic-curve public-private key
pair, to establish a shared secret over an insecure channel
T nnna__init__
uECDH.__init__
uECDH._get_shared_secret
set_curve
uECDH.set_curve
generate_private_key
uECDH.generate_private_key
uECDH.load_private_key
load_private_key_bytes
uECDH.load_private_key_bytes
load_private_key_der
uECDH.load_private_key_der
load_private_key_pem
uECDH.load_private_key_pem
get_public_key
uECDH.get_public_key
uECDH.load_received_public_key
T naload_received_public_key_bytes
uECDH.load_received_public_key_bytes
load_received_public_key_der
uECDH.load_received_public_key_der
load_received_public_key_pem
uECDH.load_received_public_key_pem
generate_sharedsecret_bytes
uECDH.generate_sharedsecret_bytes
uECDH.generate_sharedsecret
uecdsa\ecdh.py
u<module ecdsa.ecdh>
T a__class__
T aself
curve
private_key
public_key
T aself
remote_public_key
result
T aself
T aself
private_key
T aself
private_key_der
T aself
private_key_pem
T aself
public_key
T aself
public_key_str
valid_encodings
T aself
public_key_der
T aself
public_key_pem
T aself
key_curve

a__spec__
.ecdsa.ecdsa
p=
; wrwsacurve
order
pow
l wpwawbanumbertheory
square_root_mod_prime
l aellipticcurve
aPointJacobi
inverse_mod
aPublic_key

Returns two public keys for which the signature is valid
:param int hash: signed hash
:param AbstractPoint generator: is the generator used in creation
of the signature
:rtype: tuple(Public_key, Public_key)
:return: a pair of public keys that can validate the signature
generator
point
wxwyaInvalidPointError
T uThe public point has x or y out of range.
contains_point
T uPoint does not lay on the curve
T uGenerator point must have order.
cofactor
aINFINITY
T uGenerator point order is bad.
uLow level ECDSA public key object.
:param generator: the Point that generates the group (the base point)
:param point: the Point that defines the public key
:param bool verify: if True check if point is valid point on curve
:raises InvalidPointError: if the point parameters are invalid or
point does not lay on the curve
uReturn True if the keys are identical, False otherwise.
Note: for comparison, only placement on the same curve and point
equality is considered, use of the same generator point is not
considered.
uReturn False if the keys are identical, True otherwise.
mul_add
uVerify that signature is a valid signature of hash.
Return True if the signature is valid.
public_key
secret_multiplier
upublic_key is of class Public_key;
secret_multiplier is a large integer.
aPrivate_key
uReturn True if the points are identical, False otherwise.
uReturn False if the points are identical, True otherwise.
bit_length
aRSZeroError
T uamazingly unlucky random number r
T uamazingly unlucky random number s
aSignature
uReturn a signature for the provided hash, using the provided
random nonce.  It is absolutely vital that random_k be an unpredictable
number in the range [1, self.public_key.point.order()-1].  If
n attacker can guess random_k, he can compute our private key from a
single signature.  Also, if an attacker knows a few high-order
bits (or a few low-order bits) of random_k, he can compute our private
key from many signatures.  The generation of nonces with adequate
cryptographic strength is very difficult and far beyond the scope
of this comment.
May raise RuntimeError, in which case retrying with a new
random value k is in order.
warnings
warn
uFunction is unused in library code. If you use this code, change to util.string_to_number.
aDeprecationWarning
d
l  aresult
int2byte
l c
uConvert integer x into a string of bytes, as per X9.62.
uFunction is unused in library code. If you use this code, change to util.number_to_string.
l  uConvert a string of bytes into an integer, as per X9.62.
uFunction is unused in library code. If you use this code, change to a one-liner with util.number_to_string and util.string_to_number methods.
hashlib
T asha1
sha1
string_to_int
int_to_string
digest
uConvert an integer into a string of bytes, compute
its SHA-1 hash, and convert the result to an integer.
uIs (x,y) a valid public key based on the specified generator?

Low level implementation of Elliptic-Curve Digital Signatures.
.. note ::
You're most likely looking for the :py:class:`~ecdsa.keys` module.
This is a low-level implementation of the ECDSA that operates on
integers, not byte strings.
NOTE: This a low level implementation of ECDSA, for normal applications
you should be looking at the keys.py module.
Classes and methods for elliptic-curve signatures:
private keys, public keys, signatures,
nd definitions of prime-modulus curves.
Example:
.. code-block:: python
# (In real-life applications, you would probably want to
# protect against defects in SystemRandom.)
from random import SystemRandom
randrange = SystemRandom().randrange
# Generate a public/private key pair using the NIST Curve P-192:
g = generator_192
n = g.order()
secret = randrange( 1, n )
pubkey = Public_key( g, g * secret )
privkey = Private_key( pubkey, secret )
# Signing a hash value:
hash = randrange( 1, n )
signature = privkey.sign( hash, randrange( 1, n ) )
# Verifying a signature for a hash value:
if pubkey.verifies( hash, signature ):
print_("Demo verification succeeded.")
else:
print_("*** Demo verification failed.")
# Verification fails if the hash value is modified:
if pubkey.verifies( hash-1, signature ):
print_("**** Demo verification failed to reject tampered hash.")
else:
print_("Demo verification correctly rejected tampered hash.")
Revision history:
2005.12.31 - Initial version.
2008.11.25 - Substantial revisions introducing new classes.
2009.05.16 - Warn against using random.randrange in real applications.
2009.05.17 - Use random.SystemRandom by default.
Originally written in 2005 by Peter Pearson and placed in the public domain,
modified as part of the python-ecdsa package.
a__doc__
a__file__
origin
has_location
a__cached__
six
T aint2byte

T aellipticcurve
T anumbertheory
util
T abit_length
a_compat
T aremove_whitespace
remove_whitespace
T ERuntimeError
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
