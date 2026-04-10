# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Protocol.KDF

uString-to-vector PRF as defined in `RFC5297`_.
This class implements a pseudorandom function family
based on CMAC that takes as input a vector of strings.
.. _RFC5297: http://tools.ietf.org/html/rfc5297
a__qualname__
T na__init__
u_S2V.__init__
staticmethod
u_S2V.new
u_S2V._double
u_S2V.update
derive
u_S2V.derive
a__orig_bases__
T l naHKDF
scrypt
bcrypt_check
T nc
paSP800_108_Counter
uCrypto\Protocol\KDF.py
T a.0
wjalink
wsT wpwsahmac_hash_module
T ahmac_hash_module
T wpwsu<module Crypto.Protocol.KDF>
T amaster
key_len
salt
hashmod
num_keys
context
output_len
hmac
prk
wtwnatlen
derived_output
kol
T apassword
salt
dkLen
count
hashAlgo
pHash
digest
wiT apassword
salt
dkLen
count
prf
hmac_hash_module
link
key
wiwsabase
first_digest
T amaster
key_len
prf
num_keys
label
context
key_len_enc
output_len
wiadk
info
kol
T a__class__
T aself
key
ciphermod
cipher_params
T
data
wsabits
wcaidx
bits6
modulo4
bits8
result
wgT	adata
wsabits
wcabits_c
bits6
result
wgaidx
T	apassword
cost
salt
constant
invert
a_EKSBlowfish
cipher
ctext
w_T aself
abs
doubled
T apassword
cost
salt
ctext
cost_enc
salt_enc
hash_enc
T
password
bcrypt_hash
wpwracost
salt
bcrypt_hash2
secret
mac1
mac2
T aself
final
padded
mac
T wsaprf
password
T apassword
prf
T akey
ciphermod
T apassword
salt
key_len
wNwrwpanum_keys
prf_hmac_sha256
stage_1
scryptROMix
core
data_out
flow
idx
buffer_out
result
dk
kol
T aself
item
mac
a__spec__
.Crypto.Protocol.SecretSharing
f2
wzaf1
uMultiply two polynomials in GF(2)
number
size
deg
wrwdwqa_mult_gf2
wbu
Compute division of polynomials over GF(2).
Given a and b, it finds two polynomials q and r such that:
a = b*q + r with deg(r)<deg(b)
is_native_int
a_value
bytes_to_long
uThe encoded value must be an integer or a 16 byte string
uInitialize the element to a certain value.
The value passed as parameter is internally encoded as
a 128-bit integer, where each bit represents a polynomial
coefficient. The LSB is the constant coefficient.
uReturn the field element, encoded as a 128-bit integer.
long_to_bytes
l uReturn the field element, encoded as a 16 byte string.
irr_poly
a_Element
T l
l l  :l nnwvamask1
self
uInversion of zero
T l l
r1
a_div_gf2
r0
s1
s0
uReturn the inverse of this element in GF(2^128).
result
rng
T l aappend
make_share
uShamir.split.<locals>.make_share
coeffs
ssss
uSplit a secret into ``n`` shares.
The secret can be reconstructed later using just ``k`` shares
out of the original ``n``.
Each share must be kept confidential to the person it was
ssigned to.
Each share is associated to an index (starting from 1).
Args:
k (integer):
The sufficient number of shares to reconstruct the secret (``k < n``).
n (integer):
The number of shares that this method will create.
secret (byte string):
A byte string of 16 bytes (e.g. the AES 128 key).
ssss (bool):
If ``True``, the shares can be used with the ``ssss`` utility.
Default: ``False``.
Return (tuples):
``n`` tuples. A tuple is meant for each participant and it contains two items:
1. the unique index (an integer)
2. the share (a byte string, 16 bytes)
idx
share
encode
gf_shares
uDuplicate share
wkT l anumerator
denominator
x_j
inverse
uRecombine a secret, if enough shares are presented.
Args:
shares (tuples):
The *k* tuples, each containin the index (an integer) and
the share (a byte string, 16 bytes long) that were assigned to
a participant.
ssss (bool):
If ``True``, the shares were produced by the ``ssss`` utility.
Default: ``False``.
Return:
The original secret, as a byte string (16 bytes long).
u<genexpr>
uShamir.combine.<locals>.<genexpr>
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T ais_native_int
uCrypto.Util
T anumber
uCrypto.Util.number
T along_to_bytes
bytes_to_long
uCrypto.Random
T aget_random_bytes
get_random_bytes
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
