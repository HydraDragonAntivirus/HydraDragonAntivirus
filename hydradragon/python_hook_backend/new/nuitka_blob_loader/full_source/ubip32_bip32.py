# Reconstructed from integrated Nuitka blob
# Module: ubip32.bip32


Tried to use a derivation requiring private keys, without private keys.
a__qualname__
a__orig_bases__
a__init__
uInvalidInputError.__init__
uParsingError.__init__
T nnb
l
pamain
uBIP32.__init__
uBIP32.get_extended_privkey_from_path
get_privkey_from_path
uBIP32.get_privkey_from_path
uBIP32.get_extended_pubkey_from_path
uBIP32.get_pubkey_from_path
get_xpriv_from_path
uBIP32.get_xpriv_from_path
get_xpub_from_path
uBIP32.get_xpub_from_path
uBIP32.get_xpriv
uBIP32.get_xpriv_bytes
uBIP32.get_xpub
uBIP32.get_xpub_bytes
get_fingerprint
uBIP32.get_fingerprint
from_xpriv
uBIP32.from_xpriv
from_xpub
uBIP32.from_xpub
T amain
from_seed
uBIP32.from_seed
ubip32\bip32.py
u<module bip32.bip32>
T a__class__
T aself
chaincode
privkey
pubkey
fingerprint
depth
index
network
T aself
message
T acls
seed
network
secret
T
cls
xpriv
extended_key
network
depth
fingerprint
index
chaincode
key
weT
cls
xpub
extended_key
network
depth
fingerprint
index
chaincode
key
weT aself
path
chaincode
privkey
index
T aself
path
chaincode
key
pubkey
index
T aself
T aself
path
T aself
path
parent_pubkey
chaincode
privkey
extended_key
T aself
path
parent_pubkey
chaincode
pubkey
extended_key
a__spec__
.bip32
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_bip32
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
bip32
T aBIP32
aPrivateDerivationError
aInvalidInputError
aBIP32
aPrivateDerivationError
aInvalidInputError
utils
T aBIP32DerivationError
aHARDENED_INDEX
aBIP32DerivationError
aHARDENED_INDEX
u4.0
a__version__
L aBIP32
aBIP32DerivationError
aPrivateDerivationError
aInvalidInputError
aHARDENED_INDEX
a__all__
ubip32\__init__.py
u<module bip32>

a__spec__
.bip32.ripemd160
F
l l l uThe f1, f2, f3, f4, and f5 functions from the specification.
g       l uRotate the bottom 32 bits of x left by i bits.
;l
l l afrom_bytes
little
;l
lPl arol
al
fi
bl
cl
dl
aML
aKL
aRL
el
l
ar
br
cr
dr
aMR
aKR
aRR
er
uCompress state (h0, h1, h2, h3, h4) with block.
T l     g       g       l     g       l acompress
state
l@d d
l?q@l ato_bytes
T l alittle
c
uCompute the RIPEMD-160 hash of data.
T l alittle
u<genexpr>
uripemd160.<locals>.<genexpr>

Pure Python RIPEMD160 implementation.
WARNING: This implementation is NOT constant-time.
Do not use without understanding the implications.
a__doc__
a__file__
origin
has_location
a__cached__
LPl
l l l l l l l l l	l
l l ll l l l ll l
l l l l l
l	l l l l l l l
l l l	l l l l l l
l ll l l l l	l l
l
l l l ll l l l l l l l l
l l	l l l l
l l l l l l l lLPl l l l
l	l l l ll l l l l
l l l l l l l
ll l
l l l l l l	l l l l l l l l l l	l l l l l
l
l ll l l l l l l l
l l l ll	l l
l l l l
l l l l l l l ll l
l l	l LPl l l l l l l l	l ll l l l l	l l l l ll l	l l l l l l	l l ll l ll l l l	ll l l ll l l l l l l l l l l l	l l	l l l l l l l l	l l l l l ll l l ll l l l l LPl l	pl ll pl l pl l l pl l l	ll l l l l	l l pl l l l ll l	l l l l l pl l ll l lpl l l l l l l pl l l l	l l	l l l l pl l l	l l l l l ll l l ll pL l
l     l     g     xg       L l     l     l     l     l
ripemd160
ubip32\ripemd160.py
T a.0
whu<module bip32.ripemd160>
T ah0
h1
h2
h3
h4
block
al
bl
cl
dl
el
ar
br
cr
dr
er
wxwjarnd
T wxwywzwiT adata
state
wbapad
fin
T wxwiu
a__spec__
.bip32.utils
z
q
coincurve
aPrivateKey
uTakes bytes and returns True if it's a valid secp256k1 privkey
aPublicKey
uTakes bytes and returns True if it's a valid secp256k1 pubkey
from_secret
format
uTakes a 32 bytes privkey and returns a 33 bytes secp256k1 pubkey
aHARDENED_INDEX
a_privkey_to_pubkey
hmac
new
to_bytes
T l abig
hashlib
sha512
digest
:nl naadd
aBIP32DerivationError
uInvalid private key at index {}, try the next one!
secret
:l nnuA.k.a CKDpriv, in bip-0032
:param privkey: The parent's private key, as bytes
:param chaincode: The parent's chaincode, as bytes
:param index: The index of the node to derive, as int
:return: (child_privatekey, child_chaincode)
d
uA.k.a CKDpriv, in bip-0032, but the hardened way
:param privkey: The parent's private key, as bytes
:param chaincode: The parent's chaincode, as bytes
:param index: The index of the node to derive, as int
:return: (child_privatekey, child_chaincode)
combine_keys
uInvalid public key at index {}, try the next one!
uA.k.a CKDpub, in bip-0032.
:param pubkey: The parent's (compressed) public key, as bytes
:param chaincode: The parent's chaincode, as bytes
:param index: The index of the node to derive, as int
:return: (child_pubkey, child_chaincode)
T aripemd160
update

ripemd160
a_ripemd160
sha256
:nl na_pubkey_to_fingerprint
uBad parent, a fingerprint or a pubkey is required
b
P l l!P amain
test
uUnsupported network
aENCODING_PREFIX
private
public
T l abig
uSerialize an extended private *OR* public key, as spec by bip-0032.
:param key: The public or private key to serialize. Note that if this is
a public key it MUST be compressed.
:param depth: 0x00 for master nodes, 0x01 for level-1 derived keys, etc..
:param parent: The parent pubkey used to derive the fingerprint, or the
fingerprint itself None if master.
:param index: The index of the key being serialized. 0x00000000 if master.
:param chaincode: The chain code (not the labs !!).
:return: The serialized extended key.
from_bytes
big
main
values
test
l :l l	n:l	ln:ll-n:l-nnuUnserialize an extended private *OR* public key, as spec by bip-0032.
:param extended_key: The extended key to unserialize __as bytes__
:return: network (str), depth (int), fingerprint (bytes), index (int),
chaincode (bytes), key (bytes)
aREGEX_DERIVATION_PATH
match
uinvalid format
split
T w/:l nn:q nnT w'whwHalist_path
:nq nuConverts a derivation path as string to a list of integers
(index of each depth)
:param strpath: Derivation path as string with "m/x/x'/x" notation.
(e.g. m/0'/1/2'/2 or m/0H/1/2H/2 or m/0h/1/2h/2)
:return: Derivation path as a list of integers (index of each depth)
a__doc__
a__file__
origin
has_location
a__cached__
re
compile
T u^m(/[0-9]+['hH]?)*$
g
D amain
test
D aprivate
public
l   $l   $D aprivate
public
l   !l   !T EException
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
