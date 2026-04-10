# Reconstructed from integrated Nuitka blob
# Module: ucryptography.hazmat.primitives.kdf

aKeyDerivationFunction
a__qualname__
abstractmethod
derive
uKeyDerivationFunction.derive
verify
uKeyDerivationFunction.verify
ucryptography\hazmat\primitives\kdf\__init__.py
u<module cryptography.hazmat.primitives.kdf>
T a__class__
T aself
key_material
T aself
key_material
expected_key

.cryptography.hazmat.primitives.kdf.hkdf

a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
annotations
ucryptography.hazmat.bindings._rust
T aopenssl
l
openssl
rust_openssl
ucryptography.hazmat.primitives.kdf
T aKeyDerivationFunction
aKeyDerivationFunction
kdf
aHKDF
aHKDFExpand
register
a__all__
ucryptography\hazmat\primitives\kdf\hkdf.py
u<module cryptography.hazmat.primitives.kdf.hkdf>

.cryptography.hazmat.primitives.kdf.kbkdf
aMode
umode must be of type Mode
aCounterLocation
ulocation must be of type CounterLocation
aMiddleFixed
uPlease specify a break_location
ubreak_location is ignored when location is not CounterLocation.MiddleFixed
ubreak_location must be an integer
l
ubreak_location must be a positive integer
uWhen supplying fixed data, label and context are ignored.
a_valid_byte_length
urlen must be between 1 and 4
uPlease specify an llen
ullen must be an integer
ullen must be non-zero
c
utils
a_check_bytes
label
context
a_prf
a_mode
a_length
a_rlen
a_llen
a_location
a_break_location
a_label
a_context
a_used
a_fixed_data
uvalue must be of type int
int_to_bytes
l aAlreadyFinalized
a_check_byteslike
key_material
pow
l l uThere are too many iterations.
a_generate_fixed_input
aBeforeFixed
aAfterFixed
ubreak_location offset > len(fixed)
self
data_before_ctr
data_after_ctr
update
output
finalize
d
hashes
aHashAlgorithm
aUnsupportedAlgorithm
uAlgorithm supplied is not a supported hash algorithm.
a_Reasons
aUNSUPPORTED_HASH
ucryptography.hazmat.backends.openssl.backend
T abackend
backend
hmac_supported
uAlgorithm supplied is not a supported hmac algorithm.
a_algorithm
a_KBKDFDeriver
a_deriver
hmac
aHMAC
derive
digest_size
constant_time
bytes_eq
aInvalidKey
ciphers
aBlockCipherAlgorithm
aCipherAlgorithm
uAlgorithm supplied is not a supported cipher algorithm.
aUNSUPPORTED_CIPHER
a_cipher
cmac
aCMAC
cmac_algorithm_supported
block_size
a__doc__
a__file__
a__spec__
origin
has_location
a__cached__
annotations
typing
ucollections.abc
T aCallable
aCallable
cryptography
T autils
ucryptography.exceptions
T aAlreadyFinalized
aInvalidKey
aUnsupportedAlgorithm
a_Reasons
ucryptography.hazmat.primitives
T aciphers
cmac
constant_time
hashes
hmac
ucryptography.hazmat.primitives.kdf
T aKeyDerivationFunction
aKeyDerivationFunction
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
