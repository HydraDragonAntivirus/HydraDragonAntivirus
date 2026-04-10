# Reconstructed from integrated Nuitka blob
# Module: ucoincurve.keys

a__qualname__
a__init__
uPrivateKey.__init__
message
hasher
custom_nonce
return
sign
uPrivateKey.sign
T c
D amessage
aux_randomness
return
Obytes
ppasign_schnorr
uPrivateKey.sign_schnorr
sign_recoverable
uPrivateKey.sign_recoverable
D apublic_key
return
Obytes
paecdh
uPrivateKey.ecdh
D ascalar
update
Obytes
Obool
add
uPrivateKey.add
multiply
uPrivateKey.multiply
D areturn
Ostr
to_hex
uPrivateKey.to_hex
D areturn
Oint
uPrivateKey.to_int
D areturn
Obytes
to_pem
uPrivateKey.to_pem
uPrivateKey.to_der
hexed
from_hex
uPrivateKey.from_hex
num
from_int
uPrivateKey.from_int
pem
from_pem
uPrivateKey.from_pem
der
from_der
uPrivateKey.from_der
uPrivateKey._update_public_key
D areturn
Obool
a__eq__
uPrivateKey.__eq__
uPublicKey.__init__
from_secret
uPublicKey.from_secret
uPublicKey.from_valid_secret
wxwyafrom_point
uPublicKey.from_point
signature
from_signature_and_message
uPublicKey.from_signature_and_message
combine_keys
uPublicKey.combine_keys
T tD acompressed
return
Obool
Obytes
uPublicKey.format
T Oint
papoint
uPublicKey.point
verify
uPublicKey.verify
uPublicKey.add
uPublicKey.multiply
D aupdate
Obool
combine
uPublicKey.combine
uPublicKey.__eq__
uPublicKeyXOnly.__init__
uPublicKeyXOnly.from_secret
uPublicKeyXOnly.from_valid_secret
uPublicKeyXOnly.format
D asignature
message
return
Obytes
pObool
uPublicKeyXOnly.verify
D ascalar
Obytes
tweak_add
uPublicKeyXOnly.tweak_add
uPublicKeyXOnly.__eq__
ucoincurve\keys.py
u<module coincurve.keys>
T a__class__
T aself
other
T aself
other
res
T aself
secret
context
T aself
data
context
public_key
parsed
T aself
data
parity
context
public_key
parsed
T aself
created
T aself
scalar
update
secret
success
T aself
scalar
update
new_key
success
T aself
public_keys
update
new_key
combined
T acls
public_keys
context
public_key
combined
T aself
public_key
secret
T aself
compressed
length
serialized
output_len
T aself
output32
res
T acls
der
context
T acls
hexed
context
T acls
num
context
T acls
pem
context
T acls
wxwyacontext
T acls
secret
context
public_key
created
T acls
secret
context
keypair
res
xonly_pubkey
pk_parity
T acls
signature
message
hasher
context
T aself
scalar
update
secret
T aself
scalar
update
new_key
T aself
public_key
T	aself
message
hasher
custom_nonce
msg_hash
signature
nonce_fn
nonce_data
signed
T aself
message
aux_randomness
keypair
res
signature
T aself
pk
T aself
T aself
scalar
out_pubkey
res
pk_parity
T aself
signature
message
hasher
msg_hash
verified
T aself
signature
message

a__spec__
.coincurve.types
a__doc__
a__file__
origin
has_location
a__cached__
sys
aOptional
aTuple
a_libsecp256k1
T affi
ffi
ucollections.abc
T aCallable
aCallable
T L Obytes
Obytes
aHasher
aCData
aNonce
ucoincurve\types.py
u<module coincurve.types>

a__spec__
.coincurve.utils
a_sha256
digest
w0u
from_bytes
big
to_bytes
bit_length
l l apad_scalar
fromhex
pad_hex
data
size
u<genexpr>
uchunk_data.<locals>.<genexpr>
c
aPEM_HEADER
d
chunk_data
b64encode
l@aPEM_FOOTER
b64decode
strip
splitlines
:l q naurandom
aKEY_SIZE
aZERO
aGROUP_ORDER
bytes_to_int
aGROUP_ORDER_INT
uSecret scalar must be greater than 0 and less than
w.affi
new
T usecp256k1_pubkey *
lib
secp256k1_ec_pubkey_parse
ctx
uThe public key could not be parsed or is invalid.
uMessage hash must be 32 bytes long.
T usecp256k1_ecdsa_signature *
secp256k1_ecdsa_signature_parse_der
uThe DER-encoded signature could not be parsed.
secp256k1_ecdsa_verify

:param signature: The ECDSA signature.
:param message: The message that was supposedly signed.
:param public_key: The formatted public key.
:param hasher: The hash function to use, which must return 32 bytes. By default,
the `sha256` algorithm is used. If `None`, no hashing occurs.
:param context:
:return: A boolean indicating whether or not the signature is correct.
:raises ValueError: If the public key could not be parsed or was invalid, the message hash was
not 32 bytes long, or the DER-encoded signature could not be parsed.
a__doc__
a__file__
origin
has_location
a__cached__
base64
T ab64decode
b64encode
hashlib
T asha256
sha256
environ
aGenerator
ucoincurve.context
T aGLOBAL_CONTEXT
aContext
aGLOBAL_CONTEXT
aContext
ucoincurve.types
T aHasher
aHasher
a_libsecp256k1
T affi
lib
c                     H ;  ^  6AA
g	                                          l d
c-----BEGIN PRIVATE KEY-----
c-----END PRIVATE KEY-----
get
T aCOINCURVE_BUILDING_DOCS
true
aNULL
aDEFAULT_NONCE
D abytestr
return
Obytes
pT Otuple
a__prepare__
a__Nonce
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
