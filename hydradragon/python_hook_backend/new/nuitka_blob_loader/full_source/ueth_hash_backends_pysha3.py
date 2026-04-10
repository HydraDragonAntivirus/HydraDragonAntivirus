# Reconstructed from integrated Nuitka blob
# Module: ueth_hash.backends.pysha3

a__qualname__
prehash
bytes
return
a__init__
uPysha3Preimage.__init__
uPysha3Preimage.update
uPysha3Preimage.digest
D areturn
aPysha3Preimage
uPysha3Preimage.copy
a__orig_bases__
aPySha3Backend
bytearray
keccak256
uPySha3Backend.keccak256
preimage
uPySha3Backend.preimage
backend
ueth_hash\backends\pysha3.py
u<module eth_hash.backends.pysha3>
T a__class__
T aself
prehash
T aself
dup
T aself

a__spec__
.eth_hash
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_eth_hash
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
version
a__version
main
T aKeccak256
aKeccak256
u0.7.1
a__version__
ueth_hash\__init__.py
u<module eth_hash>

a__spec__
.eth_hash.main
-
a_backend
a_hasher_first_run
hasher
a_preimage_first_run
preimage
keccak256
T c
b   F   #< ~}
S  ';{   ]  pu
Validate, on first-run, that the hasher backend is valid.
After first run, replace this with the new hasher method.
This is a bit of a hacky way to minimize overhead on hash calls after
this first one.
T Obytearray
Obytes
uCan only compute the hash of `bytes` or `bytearray` values, not

a__doc__
a__file__
origin
has_location
a__cached__
aUnion
abc
T aBackendAPI
aPreImageAPI
aBackendAPI
aPreImageAPI
