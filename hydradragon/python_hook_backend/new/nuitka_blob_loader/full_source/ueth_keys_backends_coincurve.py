# Reconstructed from integrated Nuitka blob
# Module: ueth_keys.backends.coincurve

a__qualname__
D areturn
nuCoinCurveECCBackend.__init__
msg_hash
bytes
private_key
return
ecdsa_sign
uCoinCurveECCBackend.ecdsa_sign
ecdsa_sign_non_recoverable
uCoinCurveECCBackend.ecdsa_sign_non_recoverable
signature
bool
ecdsa_verify
uCoinCurveECCBackend.ecdsa_verify
ecdsa_recover
uCoinCurveECCBackend.ecdsa_recover
private_key_to_public_key
uCoinCurveECCBackend.private_key_to_public_key
compressed_public_key_bytes
decompress_public_key_bytes
uCoinCurveECCBackend.decompress_public_key_bytes
uncompressed_public_key_bytes
compress_public_key_bytes
uCoinCurveECCBackend.compress_public_key_bytes
a__orig_bases__
ueth_keys\backends\coincurve.py
u<module eth_keys.backends.coincurve>
T a__class__
T aself
coincurve
a__class__
T aself
uncompressed_public_key_bytes
point
public_key
T aself
compressed_public_key_bytes
public_key
T aself
msg_hash
signature
signature_bytes
public_key_bytes
err
public_key
T aself
msg_hash
private_key
private_key_bytes
signature_bytes
signature
T aself
msg_hash
private_key
private_key_bytes
der_encoded_signature
rs
signature
T aself
msg_hash
signature
public_key
low_s
der_encoded_signature
coincurve_public_key
T acoincurve
T aself
private_key
public_key_bytes

a__spec__
.eth_keys.backends
"
.
is_coincurve_available
ueth_keys.backends.CoinCurveECCBackend
ueth_keys.backends.NativeECCBackend
environ
get
aECC_BACKEND_CLASS
get_default_backend_class
import_string
get_backend_class
a__doc__
a__file__
path
dirname
join
T aNUITKA_PACKAGE_eth_keys
u\not_existing
backends
T aNUITKA_PACKAGE_eth_keys_backends
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
os
aType
ueth_keys.utils.module_loading
T aimport_string
base
T aBaseECCBackend
aBaseECCBackend
coincurve
T aCoinCurveECCBackend
is_coincurve_available
aCoinCurveECCBackend
native
T aNativeECCBackend
aNativeECCBackend
D areturn
Ostr
T naimport_path
return
get_backend
ueth_keys\backends\__init__.py
u<module eth_keys.backends>
T aimport_path
backend_class
T aimport_path

a__spec__
.eth_keys.backends.native
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_eth_keys
u\not_existing
ubackends\native
T aNUITKA_PACKAGE_eth_keys_backends
u\not_existing
native
T aNUITKA_PACKAGE_eth_keys_backends_native
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
main
T aNativeECCBackend
aNativeECCBackend
ueth_keys\backends\native\__init__.py
u<module eth_keys.backends.native>

a__spec__
.eth_keys.backends.native.ecdsa
k
big_endian_to_int
:l
l n:l l@nc
pad32
int_to_big_endian
wNuInvalid privkey
fast_multiply
wGaencode_raw_public_key
decode_public_key
l d d uInvalid compressed public key
T l l :l nnl wAwBwPapow
l ahmac
new
b
b!
digest
c
d adeterministic_generate_k
inv
l afast_add
T l
l aBadSignature
uvalue of v, aka y-parity, was

u, must be either 0 or 1
T uInvalid signature
jacobian_multiply
aGx
aGy
jacobian_add
is_identity
T aInvalidSignature
from_jacobian

Functions lifted from https://github.com/vbuterin/pybitcointools
a__doc__
a__file__
origin
has_location
a__cached__
hashlib
aAny
aCallable
aTuple
eth_utils
T abig_endian_to_int
int_to_big_endian
ueth_keys.constants
T aSECPK1_A
aSECPK1_B
aSECPK1_G
aSECPK1_N
aSECPK1_P
aSECPK1_Gx
aSECPK1_Gy
aSECPK1_A
aSECPK1_B
aSECPK1_G
aSECPK1_N
aSECPK1_P
aSECPK1_Gx
aSECPK1_Gy
ueth_keys.exceptions
T aBadSignature
ueth_keys.utils.padding
T apad32
jacobian
T afast_add
fast_multiply
from_jacobian
inv
is_identity
jacobian_add
jacobian_multiply
public_key_bytes
return
T Oint
paraw_public_key
D aprivate_key_bytes
return
Obytes
paprivate_key_to_public_key
D auncompressed_public_key_bytes
return
Obytes
pacompress_public_key
D acompressed_public_key_bytes
return
Obytes
padecompress_public_key
sha256
msg_hash
private_key_bytes
digest_fn
T Oint
ppaecdsa_raw_sign
rs
ecdsa_raw_verify
vrs
ecdsa_raw_recover
ueth_keys\backends\native\ecdsa.py
u<module eth_keys.backends.native.ecdsa>
T auncompressed_public_key_bytes
wxwyaprefix
T apublic_key_bytes
left
right
T acompressed_public_key_bytes
prefix
wxay_squared
y_abs
wyT amsg_hash
private_key_bytes
digest_fn
v_0
k_0
k_1
v_1
k_2
v_2
kb
wkT amsg_hash
vrs
wvwrwswxaxcubedaxb
beta
wywzaGz
aXY
aQr
wQaraw_public_key
T	amsg_hash
private_key_bytes
wzwkwrwyas_raw
wvwsT amsg_hash
rs
public_key_bytes
raw_public_key
wrwswwwzau1
u2
wxwyT araw_public_key
left
right
T aprivate_key_bytes
private_key_as_num
raw_public_key
public_key_bytes
a__spec__
.eth_keys.backends.native.jacobian
9
T l l
low
high
hm
lm
T l
ppl wPl l wAl T l
pl ajacobian_double
inv
wNajacobian_multiply
jacobian_add
uInvariant: Unreachable code path
from_jacobian
to_jacobian
aIDENTITY_POINTS
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
ueth_keys.constants
T aIDENTITY_POINTS
aSECPK1_A
aSECPK1_N
aSECPK1_P
aSECPK1_A
aSECPK1_N
aSECPK1_P
D wawnareturn
Oint
ppwpT Oint
pareturn
T Oint
ppwqwawnafast_multiply
wbafast_add
is_identity
ueth_keys\backends\native\jacobian.py
u<module eth_keys.backends.native.jacobian>
T wawbT wawnT wpwzT	wawnalm
hm
low
high
wranm
new
T wpT wpwqaU1
aU2
aS1
aS2
wHwRaH2
aH3
aU1H2
nx
any
nz
T wpaysq
wSwManx
any
nz
T wpwou
a__spec__
.eth_keys.backends.native.main
I
ecdsa_raw_sign
to_bytes
aSignature
T avrs
backend
aNonRecoverableSignature
T ars
backend
ecdsa_raw_verify
rs
ecdsa_raw_recover
vrs
aPublicKey
T abackend
private_key_to_public_key
decompress_public_key
compress_public_key
a__doc__
a__file__
origin
has_location
a__cached__
ueth_keys.backends.base
T aBaseECCBackend
aBaseECCBackend
ueth_keys.datatypes
T aBaseSignature
aNonRecoverableSignature
aPrivateKey
aPublicKey
aSignature
aBaseSignature
aPrivateKey
ecdsa
T acompress_public_key
decompress_public_key
ecdsa_raw_recover
ecdsa_raw_sign
ecdsa_raw_verify
private_key_to_public_key
a__prepare__
aNativeECCBackend
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
