# Reconstructed from integrated Nuitka blob
# Module: uecdsa.numbertheory

uBase class for exceptions in this module.
a__qualname__
a__orig_bases__
modular_exp
square_root_mod_prime
inverse_mod
phi
carmichael
kinda_order_mod
next_prime
L  l l l l l ll l l l l l%l)l+l/l5l;l=lClGlIlOlSlYlalelglklmlql l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l  l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	l 	uecdsa\numbertheory.py
u<module ecdsa.numbertheory>
T wnT af_list
result
wiT app
wpwaT wnaresult
wdwqwracount
T waT wawbT wawmT wawmalm
hm
low
high
wrT wnwtan_bits
wkatt
wswrwiwawywjT wawnaa1
wewsT wxwmT wawbwdwqwrT abase
exponent
modulus
T astarting_value
result
T wxwmwzaresult
T wnaresult
ff
wfweT abase
exponent
polymod
wpwGwkwsT am1
m2
polymod
wpaprod
wiwjT apoly
polymod
wpwiT wawpajac
wdarange_top
wbwfaff

a__spec__
.ecdsa.rfc6979
1
hexlify
l l abits2int
bit_length
number_to_string_crop
digest_size
l ahmac_compat
number_to_string
bits2octets
d d
hmac
new
T adigestmod
update
wkadigest
c
wtwvahash_func
qlen
retry_gen

Generate the ``k`` value - the nonce for DSA.
:param int order: order of the DSA generator used in the signature
:param int secexp: secure exponent (private key) in numeric form
:param hash_func: reference to the same hash function used for generating
hash, like :py:class:`hashlib.sha1`
:param bytes data: hash in binary form of the signing data
:param int retry_gen: how many good 'k' values to skip before returning
:param bytes extra_entropy: additional added data in binary form as per
section-3.6 of rfc6979
:rtype: int

RFC 6979:
Deterministic Usage of the Digital Signature Algorithm (DSA) and
Elliptic Curve Digital Signature Algorithm (ECDSA)
http://tools.ietf.org/html/rfc6979
Many thanks to Coda Hale for his implementation in Go language:
https://github.com/codahale/rfc6979
a__doc__
a__file__
origin
has_location
a__cached__
binascii
T ahexlify
util
T anumber_to_string
number_to_string_crop
bit_length
a_compat
T ahmac_compat
L abit_length
bits2int
bits2octets
generate_k
a__all__
T l
c
generate_k
uecdsa\rfc6979.py
u<module ecdsa.rfc6979>
T adata
qlen
wxwlT adata
order
z1
z2
T aorder
secexp
hash_func
data
retry_gen
extra_entropy
qlen
holen
rolen
bx
wvwkwiwtasecret

a__spec__
.ecdsa.ssh
?
aEd25519
a_SSH_ED25519
uUnsupported key type
c
bytes
int_to_bytes
D alength
byteorder
l abig
put_u32
put_raw
binascii
b2a_base64
compat26_str
der
topem
uOPENSSH PRIVATE KEY
a_Serializer
a_get_key_type
put_str
d aencode
T l
tobytes
T c
put_pad
a_SK_MAGIC
a_NONE
T l a__doc__
a__file__
origin
has_location
a__cached__

T ader
a_compat
T acompat26_str
int_to_bytes
cssh-ed25519
b openssh-key-v1
cnone
