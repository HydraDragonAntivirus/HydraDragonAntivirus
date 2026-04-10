# Reconstructed from integrated Nuitka blob
# Module: uecdsa.keys


Raised when verification of signature failed.
Will be raised irrespective of reason of the failure:
* the calculated or provided hash does not match the signature
* the signature does not match the curve/public key
* the encoding of the signature is malformed
* the size of the signature does not match the curve of the VerifyingKey
a__qualname__
a__orig_bases__
uRaised in case the selected hash is too large for the curve.
T Oobject

Class for handling keys that can verify signatures (public keys).
:ivar `~ecdsa.curves.Curve` ~.curve: The Curve over which all the
cryptographic operations will take place
:ivar default_hashfunc: the function that will be used for hashing the
data. Should implement the same API as hashlib.sha1
:vartype default_hashfunc: callable
:ivar pubkey: the actual public key
:vartype pubkey: ~ecdsa.ecdsa.Public_key
T na__init__
uVerifyingKey.__init__
a__repr__
uVerifyingKey.__repr__
a__eq__
uVerifyingKey.__eq__
a__ne__
uVerifyingKey.__ne__
classmethod
uVerifyingKey.from_public_point
T Faprecompute
uVerifyingKey.precompute
uVerifyingKey.from_string
from_pem
uVerifyingKey.from_pem
uVerifyingKey.from_der
from_public_key_recovery
uVerifyingKey.from_public_key_recovery
uVerifyingKey.from_public_key_recovery_with_digest
T araw
uVerifyingKey.to_string
T auncompressed
nato_pem
uVerifyingKey.to_pem
uVerifyingKey.to_der
to_ssh
uVerifyingKey.to_ssh
uVerifyingKey.verify
uVerifyingKey.verify_digest

Class for handling keys that can create signatures (private keys).
:ivar `~ecdsa.curves.Curve` curve: The Curve over which all the
cryptographic operations will take place
:ivar default_hashfunc: the function that will be used for hashing the
data. Should implement the same API as :py:class:`hashlib.sha1`
:ivar int baselen: the length of a :term:`raw encoding` of private key
:ivar `~ecdsa.keys.VerifyingKey` verifying_key: the public key
ssociated with this private key
:ivar `~ecdsa.ecdsa.Private_key` privkey: the actual private key
uSigningKey.__init__
uSigningKey.__eq__
uSigningKey.__ne__
uSigningKey._twisted_edwards_keygen
uSigningKey._weierstrass_keygen
generate
uSigningKey.generate
uSigningKey.from_secret_exponent
uSigningKey.from_string
uSigningKey.from_pem
uSigningKey.from_der
uSigningKey.to_string
T auncompressed
ssleay
nuSigningKey.to_pem
uSigningKey._encode_eddsa
uSigningKey.to_der
uSigningKey.to_ssh
uSigningKey.get_verifying_key
uSigningKey.sign_deterministic
uSigningKey.sign_digest_deterministic
uSigningKey.sign
uSigningKey.sign_digest
T nnuSigningKey.sign_number
uecdsa\keys.py
u<module ecdsa.keys>
T a__class__
T aself
other
T aself
a_error__please_use_generate
T aself
pub_key
hash_name
T aself
ec_private_key
T adigest
curve
allow_truncate
number
max_length
length
T acls
curve
entropy
random
private_key
public_key
verifying_key
self
T acls
curve
entropy
hashfunc
secexp
T acls
string
hashfunc
valid_curve_encodings
wsacurve
empty
version
sequence
algorithm_oid
algorithm_identifier
key_str_der
key_str
w_aprivkey_str
tag
curve_oid_str
Tacls
string
hashfunc
valid_encodings
valid_curve_encodings
s1
empty
s2
point_str_bitstring
oid_pk
rest
curve
point_str
T acls
string
hashfunc
valid_curve_encodings
private_key_index
T acls
string
hashfunc
valid_encodings
valid_curve_encodings
T acls
signature
data
curve
hashfunc
sigdecode
allow_truncate
digest
T acls
signature
digest
curve
hashfunc
sigdecode
allow_truncate
generator
wrwsasig
digest_as_number
pks
verifying_keys
T acls
point
curve
hashfunc
validate_point
self
T acls
secexp
curve
hashfunc
self
wnapubkey_point
pubkey
T acls
string
curve
hashfunc
self
secexp
T acls
string
curve
hashfunc
validate_point
valid_encodings
self
point
T acls
curve
entropy
hashfunc
T aself
T aself
lazy
pt
T aself
data
entropy
hashfunc
sigencode
wkaallow_truncate
whT aself
data
hashfunc
sigencode
extra_entropy
digest
T	aself
digest
entropy
sigencode
wkaallow_truncate
number
wrwsTaself
digest
hashfunc
sigencode
extra_entropy
allow_truncate
secexp
simple_r_s
retry_gen
wkwrwsaorder
T aself
number
entropy
wkaorder
a_k
sig
T wrwsaorder
T aself
point_encoding
format
curve_parameters_encoding
encoded_vk
priv_key_elems
ec_private_key
T aself
point_encoding
curve_parameters_encoding
point_str
T aself
point_encoding
format
curve_parameters_encoding
header
T aself
point_encoding
curve_parameters_encoding
T aself
secexp
wsT aself
encoding
T aself
signature
data
hashfunc
sigdecode
allow_truncate
weadigest
T
self
signature
digest
sigdecode
allow_truncate
number
wrwsweasig
a__spec__
.ecdsa.numbertheory
:
warnings
warn
uFunction is unused in library code. If you use this code, change to pow() builtin.
aDeprecationWarning
aNegativeExponentError
uNegative exponents (%d) not allowed
pow
uRaise base to exponent, reducing by modulus
poly
polymod
xrange
l wp:l
q nuReduce poly by polymod, integer arithmetic modulo p.
Polynomials are represented as lists of coefficients
of increasing powers of x.
m2
prod
wiapolynomial_reduce_mod
uPolynomial multiplication modulo a polynomial over ints mod p.
Polynomials are represented as lists of coefficients
of increasing powers of x.
wkapolynomial_multiply_mod
wGwsuPolynomial exponentiation modulo a polynomial over ints mod p.
Polynomials are represented as lists of coefficients
of increasing powers of x.
l aJacobiError
T un must be larger than 2
T un must be odd
a1
wel l l ajacobi
uJacobi symbol
aSquareRootError
u%d has no square root modulo %d
l aPY2
min
g      waapolynomial_exp_mod
T l
l T up is not prime
uNo b found.
uModular square root of a, mod p, p prime.
powmod
uInverse of a mod m.
mpz
T l T l
low
high
hm
lm
wbuGreatest common divisor using Euclid's algorithm.
reduce
gcd2
a__iter__
uGreatest common divisor.
Usage: gcd([ 2, 4, 6 ])
or:    gcd(2, 4, 6)
gcd
uLeast common multiple of two integers.
lcm2
uLeast common multiple.
Usage: lcm([ 3, 4, 5 ])
or:    lcm(3, 4, 5)
integer_types
smallprimes
wnwqacount
result
is_prime
wduDecompose n into a list of (prime,exponent) pairs.
uFunction is unused by library code. If you use this code, please open an issue in https://github.com/tlsfuzzer/python-ecdsa
factorization
uReturn the Euler totient function of n.
carmichael_of_factorized
uReturn Carmichael function of n.
Carmichael(n) is the smallest integer x such that
m**x = 1 mod n for all m relatively prime to n.
carmichael_of_ppower
lcm
uReturn the Carmichael function of a number that is
represented as a list of (prime,exponent) pairs.
uCarmichael function of the given power of the given prime.
wzwxwmuReturn the order of x in the multiplicative group mod m.
uReturn the largest factor of a relatively prime to b.
order_mod
largest_factor_relatively_prime
uReturn the order of x in the multiplicative group mod m',
where m' is the largest factor of m relatively prime to x.
miller_rabin_test_count
l  l(abit_length
l l   T T ldl T l  l T l  l T l  l T l  l	T l  l T l  l T l  l T l  l T l  l T l  l T l
l wrwtarandom
choice
wjwyuReturn True if x is prime, False otherwise.
We use the Miller-Rabin test, as given in Menezes et al. p. 138.
This test is not exact: there are composite values n for which
it returns True.
In testing the odd numbers from 10000001 to 19999999,
bout 66 composites got past the first test,
5 got past the second test, and none got past the third.
Since factors of 2, 3, 5, 7, and 11 were detected during
preliminary screening, the number of numbers tested by
Miller-Rabin was (19999999 - 10000001)*(2/3)*(4/5)*(6/7)
= 4.57 million.
uReturn the smallest prime larger than the starting value.
a__doc__
a__file__
origin
has_location
a__cached__
division
sys
six
T ainteger_types
aPY2
usix.moves
T areduce
gmpy2
T apowmod
mpz
aGMPY2
aGMPY
gmpy
T ampz
math
util
T abit_length
T EException
a__prepare__
aError
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
