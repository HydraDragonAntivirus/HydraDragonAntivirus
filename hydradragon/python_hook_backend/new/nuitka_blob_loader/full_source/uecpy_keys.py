# Reconstructed from integrated Nuitka blob
# Module: uecpy.keys

u Public EC key.
Can be used for both ECDSA and EDDSA signature
Attributes:
W (Point): public key point
Args:
W (Point): public key value
a__qualname__
a__init__
uECPublicKey.__init__
uECPublicKey.curve
a__str__
uECPublicKey.__str__
u Public EC key.
Can be used for both ECDSA and EDDSA signature
Attributes
d (int)       : private key scalar
curve (Curve) : curve
Args:
d (int):        private key value
curve (Curve) : curve
aECPrivateKey
uECPrivateKey.__init__
get_public_key
uECPrivateKey.get_public_key
uECPrivateKey.__str__
uecpy\keys.py
u<module ecpy.keys>
T a__class__
T aself
wdacurve
T aself
wWT aself

a__spec__
.ed25519_blake2b._version
.
json
loads
version_json
a__doc__
a__file__
origin
has_location
a__cached__
sys

{
"dirty": false,
"error": null,
"full-revisionid": "bbc52046755dff306100b03609ff14b27e490277",
"version": "1.4.1"
}
get_versions
ued25519_blake2b\_version.py
u<module ed25519_blake2b._version>

a__spec__
.ed25519_blake2b
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_ed25519_blake2b
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
keys
T aBadSignatureError
aBadPrefixError
create_keypair
aSigningKey
aVerifyingKey
remove_prefix
to_ascii
from_ascii
aBadSignatureError
aBadPrefixError
create_keypair
aSigningKey
aVerifyingKey
remove_prefix
to_ascii
from_ascii
a_version
T aget_versions
get_versions
version
a__version__
ued25519_blake2b\__init__.py
u<module ed25519_blake2b>

a__spec__
.ed25519_blake2b.keys
p
a_ed25519
aSECRETKEYBYTES
l aSigningKey
get_verifying_key
aBadPrefixError
udid not see expected '%s' prefix
encode
T aascii
base64
b64encode
decode
rstrip
T w=abase32
b32encode
lower
T abase16
hex
b16encode
uReturn a version-prefixed ASCII representation of the given binary
string. 'encoding' indicates how to do the encoding, and can be one of:
* base64
* base32
* base16 (or hex)
This function handles bytes, not bits, so it does not append any trailing
'=' (unlike standard base64.b64encode). It also lowercases the base32
output.
'prefix' will be prepended to the encoded form, and is useful for
distinguishing the purpose and version of the binary string. E.g. you
could prepend 'pub0-' to a VerifyingKey string to allow the receiving
code to raise a useful error if someone pasted in a signature string by
mistake.
remove_prefix
strip
w=l ab64decode
l ab32decode
upper
b16decode
uThis is the opposite of to_ascii. It will throw BadPrefixError if
the prefix is not found.
from_ascii
T aencoding
derive_public_from_secret
uSigningKey takes 32-byte seed or 64-byte string
:nl n:l nnask_s
vk_s
to_ascii
to_seed
aVerifyingKey
sign
:l
l n:l l@n:l@nnaopen
T cpriv0-sQHl0NVcrc/O6lsHe2DXb71pq1NjMFAG7Q/I74VGnIk=
upriv0-
base64
T aprefix
encoding
T cpub0-QM20hii2QB4EfChxfvzxgCPDnIpU5u/ZTgXUvr0oyVg=
upub0-
base64
T ccrypto libraries should always test themselves at powerup
usig0-
base64
csig0-OO3brWHJzzl6JGkNl/4l63pOiEYhQugdd3Q4hK4QftJbCwV7lTKN8J1hDDXGMOr6Q2vz7Zksu+TWu6ABNDJfBA
verify
ccrypto libraries should always test themselves at powerup
D aprefix
encoding
usig0-
base64
a__doc__
a__file__
origin
has_location
a__cached__
os

T a_ed25519
aBadSignatureError
urandom
create_keypair
T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
