# Reconstructed from integrated Nuitka blob
# Module: uCrypto.PublicKey.ECC

a__qualname__
a__orig_bases__
T Oobject
uClass defining an ECC key.
Do not instantiate directly.
Use :func:`generate`, :func:`construct` or :func:`import_key` instead.
:ivar curve: The **canonical** name of the curve as defined in the `ECC table`_.
:vartype curve: string
:ivar pointQ: an ECC point representating the public component.
:vartype pointQ: :class:`EccPoint` or :class:`EccXPoint`
:ivar d: A scalar that represents the private component
in NIST P curves. It is smaller than the
order of the generator point.
:vartype d: integer
:ivar seed: A seed that representats the private component
in Ed22519 (32 bytes), Curve25519 (32 bytes),
Curve448 (56 bytes), Ed448 (57 bytes).
:vartype seed: bytes
a__init__
uEccKey.__init__
a__eq__
uEccKey.__eq__
a__repr__
uEccKey.__repr__
uEccKey.has_private
a_sign
uEccKey._sign
a_verify
uEccKey._verify
property
uEccKey.d
uEccKey.seed
uEccKey.pointQ
public_key
uEccKey.public_key
uEccKey._export_SEC1
uEccKey._export_eddsa_public
uEccKey._export_montgomery_public
uEccKey._export_subjectPublicKeyInfo
T tuEccKey._export_rfc5915_private_der
uEccKey._export_pkcs8
uEccKey._export_public_pem
uEccKey._export_private_pem
uEccKey._export_private_clear_pkcs8_in_clear_pem
uEccKey._export_private_encrypted_pkcs8_in_clear_pem
uEccKey._export_openssh
export_key
uEccKey.export_key
generate
T nnT naimport_key
uCrypto\PublicKey\ECC.py
u<module Crypto.PublicKey.ECC>
T a__class__
T aself
other
T aself
kwargs
kwargs_
curve_name
count
seed_hash
tmp
T aself
extra
wxaresult
wyT aself
compress
modulus_bytes
first_byte
public_key
T aself
wxwyaresult
T aself
wxafield_size
result
T	aself
compress
desc
public_key
comps
modulus_bytes
first_byte
middle
blob
T aself
kwargs
aPKCS8
oid
private_key
params
result
T aself
aPEM
encoded_der
T aself
passphrase
kwargs
aPEM
encoded_der
T aself
compress
aPEM
encoded_der
T aself
include_ec_params
modulus_bytes
public_key
seq
T aself
compress
oid
public_key
params
T aencoded
wxapoint_x
T aencoded
point_x
T aencoded
passphrase
err
T aencoded
wpwdwyax_lsb
point_y
wuwvav_inv
x2
point_x
T adata
password
import_openssh_private_generic
read_bytes
read_string
check_padding
key_type
decrypted
eddsa_keys
ecdsa_curve_name
curve
modulus_bytes
public_key
point_x
point_y
private_key
wdaparams
curve_name
import_eddsa_public_key
seed_len
private_public_key
seed
w_apadded
T aencoded
parts
keystring
keyparts
lk
curve_name
curve
middle
ecc_key
wxwyT aencoded
passphrase
aPKCS8
algo_oid
private_key
params
nist_p_oids
eddsa_oids
xdh_oids
curve_oid
seed
curve_name
T	aec_point
curve_oid
curve_name
a_curve_name
curve
modulus_bytes
point_type
wxwyT aencoded
passphrase
curve_oid
ec_private_key
scalar_bytes
next_element
parameters
curve_name
curve
modulus_bytes
point_x
point_y
public_key_enc
public_key
wdT aencoded
kwargs
oid
ec_point
params
nist_p_oids
eddsa_oids
xdh_oids
curve_oid
curve_name
import_eddsa_public_key
wxwyaimport_xdh_public_key
T aencoded
kwargs
sp_info
T	aself
wzwkaorder
blind
blind_d
inv_blind_k
wrwsT aself
wzars
order
sinv
point1
point2
T akwargs
curve_name
curve
point_x
point_y
new_key
pub_key
T aself
T aself
kwargs
args
ext_format
compress
passphrase
use_pkcs8
T akwargs
curve_name
curve
randfunc
seed
new_key
wdTaencoded
passphrase
curve_name
aPEM
text_encoded
openssh_encoded
marker
enc_flag
result
ecparams_start
ecparams_end
der_encoded
uef
a__spec__
.Crypto.PublicKey.ElGamal
"
aElGamalKey
generate_probable_safe_prime
T aexact_bits
randfunc
wpapow
aInteger
random_range
l aobj
randfunc
T amin_inclusive
max_exclusive
randfunc
wgT l l ainverse
wxwyuRandomly generate a fresh, new ElGamal key.
The key will be safe for use for both encryption and signature
(although it should be used for **only one** purpose).
Args:
bits (int):
Key length, or size (in bits) of the modulus *p*.
The recommended value is 2048.
randfunc (callable):
Random number generation function; it should accept
a single integer *N* and return a string of random
*N* random bytes.
Return:
n :class:`ElGamalKey` object
T l l uargument for construct() wrong length
a_keydata
test_probable_prime
aCOMPOSITE
uInvalid ElGamal key components
uConstruct an ElGamal key from a tuple of valid ElGamal components.
The modulus *p* must be a prime.
The following conditions must apply:
.. math::
\begin{align}
&1 < g < p-1 \\
&g^{p-1} = 1 \text{ mod } 1 \\
&1 < x < p-1 \\
&g^x = y \text{ mod } p
\end{align}
Args:
tup (tuple):
A tuple with either 3 or 4 integers,
in the following order:
1. Modulus (*p*).
2. Generator (*g*).
3. Public key (*y*).
4. Private key (*x*). Optional.
Raises:
ValueError: when the key being imported fails the most basic ElGamal validity checks.
Returns:
n :class:`ElGamalKey` object
aRandom
new
read
a_randfunc
uPrivate key not available in this object
gcd
uBad K value: GCD(K,p-1)!=1
wtap1
uWhether this is an ElGamal private key
construct
uA matching ElGamal public key.
Returns:
a new :class:`ElGamalKey` object
has_private
result
self
key
other
a__eq__
pickle
T aPicklingError
aPicklingError
a__doc__
a__file__
origin
has_location
a__cached__
generate
a__all__
aCrypto
T aRandom
uCrypto.Math.Primality
T agenerate_probable_safe_prime
test_probable_prime
aCOMPOSITE
uCrypto.Math.Numbers
T aInteger
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
