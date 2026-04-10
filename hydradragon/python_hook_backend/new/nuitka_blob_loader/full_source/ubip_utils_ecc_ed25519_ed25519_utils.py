# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.ecc.ed25519.ed25519_utils

uClass container for ed25519 utility functions.
aEd25519Utils
a__qualname__
D aint_bytes
return
Obytes
Oint
aIntDecode
uEd25519Utils.IntDecode
D aint_val
return
Oint
Obytes
aIntEncode
uEd25519Utils.IntEncode
scalar
T Obytes
Oint
return
aScalarReduce
uEd25519Utils.ScalarReduce
ubip_utils\ecc\ed25519\ed25519_utils.py
u<module bip_utils.ecc.ed25519.ed25519_utils>
T a__class__
T aint_bytes
T aint_val
T ascalar

a__spec__
.bip_utils.ecc.ed25519.lib
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uecc\ed25519\lib
T aNUITKA_PACKAGE_bip_utils_ecc
u\not_existing
ued25519\lib
T aNUITKA_PACKAGE_bip_utils_ecc_ed25519
u\not_existing
lib
T aNUITKA_PACKAGE_bip_utils_ecc_ed25519_lib
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils\ecc\ed25519\lib\__init__.py
u<module bip_utils.ecc.ed25519.lib>

a__spec__
.bip_utils.ecc.ed25519.lib.ed25519_lib
y
pow
a_Q
l a_inv
a_D
l l a_I
wxaBytesUtils
aToInteger
D aendianness
little

Decode int from bytes.
Args:
int_bytes (bytes): Integer bytes
Returns:
int: Decoded integer
aIntegerUtils
aToBytes
a_COORD_BYTE_LEN

Encode int to bytes.
Args:
int_val (int): Integer value
Returns:
bytes: Encoded integer

Get if point bytes are in decoded format.
Args:
point_bytes (bytes): Point bytes
Returns:
bool: True if in decoded format, false otherwise

Get if point bytes are in encoded format.
Args:
point_bytes (bytes): Point bytes
Returns:
bool: True if in encoded format, false otherwise
point_is_decoded_bytes
point_is_encoded_bytes

Get if point bytes are valid.
Args:
point_bytes (bytes): Point bytes
Returns:
bool: True if valid, false otherwise
int_decode
point_decode_no_check
uInvalid point bytes

Convert point bytes to coordinates.
Args:
point_bytes (bytes): Point bytes
Returns:
tuple[int, int]: Point coordinates
Raises:
ValueError: If point bytes are not valid
int_encode

Convert point coordinates to bytes.
Args:
point_coord (tuple[int, int]): Point coordinates
Returns:
bytes: Point bytes
l  a_x_recover

Decode point bytes to coordinates without checking if it lies on the ed25519 curve.
Args:
point_bytes (bytes): Point bytes
Returns:
tuple[int, int]: Point coordinates
Raises:
ValueError: If point bytes are not valid
point_is_on_curve
uDecoded point does not lie on the curve

Decode point bytes to coordinates by checking if it lies on the ed25519 curve.
Args:
point_bytes (bytes): Point bytes
Returns:
tuple[int, int]: Point coordinates
Raises:
ValueError: If the point bytes are not valid or the decoded point doesn't lie on the curve
point_coord_to_bytes
l  u
Encode point coordinates to bytes.
Args:
point_coord (tuple[int, int]): Point coordinates
Returns:
bytes: Point bytes
a_G_ENC_BYTES
a_G_DEC_BYTES
a_G

Get if the point is the generator of the ed25519 curve.
Args:
point (bytes or tuple[int, int]): Point
Returns:
bool: True if generator, false otherwise
Raises:
ValueError: If point bytes are not valid
point_bytes_to_coord

Get if the point lies on the ed25519 curve.
This method is used because nacl.bindings.crypto_core_ed25519_is_valid_point performs more strict checks,
which results in points (i.e. public keys) that are considered not valid even if they are accepted by wallets.
Args:
point (bytes or tuple[int, int]): Point
Returns:
bool: True if it lies on the curve, false otherwise
Raises:
ValueError: If point bytes are not valid
bindings
crypto_core_ed25519_add
point_encode

Add two points on the ed25519 curve.
Args:
point_1 (bytes or tuple[int, int]): Point 1
point_2 (bytes or tuple[int, int]): Point 2
Returns:
bytes: New point resulting from the addition
crypto_scalarmult_ed25519_noclamp

Multiply a point on the ed25519 curve with a scalar.
Args:
scalar (bytes or int)           : Scalar
point (bytes or tuple[int, int]): Point
Returns:
bytes: New point resulting from the multiplication
crypto_scalarmult_ed25519_base_noclamp

Multiply the base (i.e. generator) point of the ed25519 curve with a scalar.
Args:
scalar (bytes or int): Scalar
Returns:
bytes: New point resulting from the multiplication
crypto_core_ed25519_scalar_reduce
ljust
d

Convert the specified bytes to integer and return its lowest 32-bytes modulo ed25519 curve order.
Args:
scalar (bytes or int): Scalar
Returns:
bytes: Lowest 32-bytes modulo ed25519-order
a_L

Get if the specified scalar is valid (i.e. less than the ed25519 curve order).
Args:
scalar (bytes or int): Scalar
Returns:
bool: True if lower, false otherwise

Helper library for ed25519 point encoding/decoding, which cannot be done with pynacl APIs.
Encode/Decode operations copied from: https://github.com/warner/python-pure25519/blob/master/pure25519/basic.py
a__doc__
a__file__
origin
has_location
a__cached__
binascii
aTuple
aUnion
nacl
T abindings
ubip_utils.utils.misc
T aBytesUtils
aIntegerUtils
l l  g          ^          T g	!                                      yg	f                                        aunhexlify
T u1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd33669215866666666666666666666666666666666666666666666666666666666666666
T u5866666666666666666666666666666666666666666666666666666666666666
l D wxareturn
Oint
pq   T l   l D wyareturn
Oint
pD aint_bytes
return
Obytes
Oint
D aint_val
return
Oint
Obytes
D apoint_bytes
return
Obytes
Obool
point_is_valid_bytes
point_bytes
return
T Oint
papoint_coord
point_decode
point
point_is_generator
point_1
point_2
point_add
scalar
T Obytes
Oint
point_scalar_mul
point_scalar_mul_base
scalar_reduce
scalar_is_valid
ubip_utils\ecc\ed25519\lib\ed25519_lib.py
u<module bip_utils.ecc.ed25519.lib.ed25519_lib>
T wxT wyaxx
wxT aint_bytes
T aint_val
T apoint_1
point_2
T apoint_bytes
T apoint_coord
T apoint_bytes
point_coord
T apoint_bytes
point_int
clamp
wywxT apoint_coord
point_bytes
y_bytes
T apoint
T apoint
wxwyT ascalar
point
T ascalar

a__spec__
.bip_utils.ecc.ed25519_blake2b
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_bip_utils
u\not_existing
uecc\ed25519_blake2b
T aNUITKA_PACKAGE_bip_utils_ecc
u\not_existing
ed25519_blake2b
T aNUITKA_PACKAGE_bip_utils_ecc_ed25519_blake2b
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ubip_utils\ecc\ed25519_blake2b\__init__.py
u<module bip_utils.ecc.ed25519_blake2b>

a__spec__
.bip_utils.ecc.ed25519_blake2b.ed25519_blake2b
uModule for ed25519-blake2b curve.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
ubip_utils.ecc.curve.elliptic_curve
T aEllipticCurve
aEllipticCurve
ubip_utils.ecc.ed25519_blake2b.ed25519_blake2b_const
T aEd25519Blake2bConst
aEd25519Blake2bConst
ubip_utils.ecc.ed25519_blake2b.ed25519_blake2b_keys
T aEd25519Blake2bPrivateKey
aEd25519Blake2bPublicKey
aEd25519Blake2bPrivateKey
aEd25519Blake2bPublicKey
ubip_utils.ecc.ed25519_blake2b.ed25519_blake2b_point
T aEd25519Blake2bPoint
aEd25519Blake2bPoint
aNAME
aCURVE_ORDER
aGENERATOR
aEd25519Blake2b
ubip_utils\ecc\ed25519_blake2b\ed25519_blake2b.py
u<module bip_utils.ecc.ed25519_blake2b.ed25519_blake2b>

a__spec__
.bip_utils.ecc.ed25519_blake2b.ed25519_blake2b_const
.
uModule for ed25519-blake2b constants.
a__doc__
a__file__
origin
has_location
a__cached__
ubip_utils.ecc.common.ipoint
T aIPoint
aIPoint
ubip_utils.ecc.ed25519.ed25519
T aEd25519Const
aEd25519Const
