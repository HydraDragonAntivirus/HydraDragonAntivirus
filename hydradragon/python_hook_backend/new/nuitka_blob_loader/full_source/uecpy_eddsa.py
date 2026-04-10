# Reconstructed from integrated Nuitka blob
# Module: uecpy.eddsa

uEDDSA signer implemenation according to:
- IETF `draft-irtf-cfrg-eddsa-05 <https://tools.ietf.org/html/draft-irtf-cfrg-eddsa-05>`_.
Args:
hasher (hashlib): callable constructor returning an object with update(), digest() interface. Example: hashlib.sha256,  hashlib.sha512...
fmt (str): in/out signature format. See  :mod:`ecpy.formatters`.
a__qualname__
T naEDDSA
a__init__
uEDDSA.__init__
sha512
get_public_key
uEDDSA.get_public_key
uEDDSA._get_materials
sign
uEDDSA.sign
uEDDSA._do_sign
verify
uEDDSA.verify
uecpy\eddsa.py
u<module ecpy.eddsa>
T a__class__
T aself
hasher
hash_len
fmt
T aself
msg
pv_key
curve
wBwnasize
wawAaprefix
eA
hasher
wrwRaeR
aH_eR_eA_m
wiwSasig
T apv_key
hasher
hash_len
curve
wBwnasize
wkwhwawAT apv_key
hasher
hash_len
wawAwhT aself
msg
pv_key
T aself
msg
sig
pu_key
curve
wnasize
eR
wSwRahasher
eA
whwAaleft
right

a__spec__
.ecpy.formatters
G
T na_int2bin
uencode_sig.<locals>._int2bin
aDER
a_strip_leading_zero
uencode_sig.<locals>._strip_leading_zero

t(bin),v(bin) ->  tlv(bin)
a_tlv
uencode_sig.<locals>._tlv
d d0aBTUPLE
aITUPLE
aRAW
aECPyException
T usize must be specified when encoding in RAW
aEDDSA
T usize must be specified when encoding in EDDSA
to_bytes
little
u encore signature according format
Args:
r (int):   r value
s (int):   s value
fmt (str): 'DER'|'BTUPLE'|'ITUPLE'|'RAW'|'EDDSA
Returns:
bytes:  TLV   for DER encoding
Returns:
bytes:  (r,s) for BTUPLE encoding
Returns:
ints:   (r,s) for ITUPLE encoding
Returns:
bytes:  r|s   for RAW encoding
bit_length
l l abig
wx:l nnl  d
a_untlv
udecode_sig.<locals>._untlv
l0T nnl aint
from_bytes
u encore signature according format
Args:
rs (bytes,ints,tuple) : r,s value
fmt (str): 'DER'|'BTUPLE'|'ITUPLES'|'RAW'|'EDDSA'
Returns:
ints:   (r,s)
:l nnl l l :l nnl l :l nnT nnnnatlv
wla__doc__
a__file__
origin
has_location
a__cached__
pow
T aDER
aBTUPLE
aITUPLE
aRAW
aEDDSA
list_formats
T aDER
l
encode_sig
T aDER
decode_sig
uecpy\formatters.py
u<module ecpy.formatters>
T wxasize
T wxT wtwvwla_int2bin
T a_int2bin
T atlv
wtwlwvT asig
fmt
a_untlv
wtwlwvatail
tr
lr
vr
ts
ls
vs
wrwsT wrwsafmt
size
a_int2bin
a_strip_leading_zero
a_tlv
sig

a__spec__
.ecpy.keys
*
wWacurve
uECPublicKey:
x: %x
y: %x
wxwyaint
wdagenerator
aECPublicKey
u Returns the public key corresponding to this private key
This method considers the private key the generator multiplier and
return pv*Generator in all cases.
For specific derivation such as in EdDSA, see ecpy.eddsa.get_public_key
Returns:
ECPublicKey : public key
uECPrivateKey:
d: %x
a__doc__
a__file__
origin
has_location
a__cached__
pow
uecpy.curves
ecpy
