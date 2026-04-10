# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Math._IntegerBase

a__qualname__
abstractmethod
a__int__
uIntegerBase.__int__
a__str__
uIntegerBase.__str__
a__repr__
uIntegerBase.__repr__
T l
big
to_bytes
uIntegerBase.to_bytes
staticmethod
T abig
uIntegerBase.from_bytes
a__eq__
uIntegerBase.__eq__
a__ne__
uIntegerBase.__ne__
a__lt__
uIntegerBase.__lt__
a__le__
uIntegerBase.__le__
a__gt__
uIntegerBase.__gt__
a__ge__
uIntegerBase.__ge__
a__nonzero__
uIntegerBase.__nonzero__
a__bool__
is_negative
uIntegerBase.is_negative
a__add__
uIntegerBase.__add__
a__sub__
uIntegerBase.__sub__
a__mul__
uIntegerBase.__mul__
a__floordiv__
uIntegerBase.__floordiv__
a__mod__
uIntegerBase.__mod__
T nainplace_pow
uIntegerBase.inplace_pow
a__pow__
uIntegerBase.__pow__
a__abs__
uIntegerBase.__abs__
sqrt
uIntegerBase.sqrt
a__iadd__
uIntegerBase.__iadd__
a__isub__
uIntegerBase.__isub__
a__imul__
uIntegerBase.__imul__
a__imod__
uIntegerBase.__imod__
a__and__
uIntegerBase.__and__
a__or__
uIntegerBase.__or__
a__rshift__
uIntegerBase.__rshift__
a__irshift__
uIntegerBase.__irshift__
a__lshift__
uIntegerBase.__lshift__
a__ilshift__
uIntegerBase.__ilshift__
get_bit
uIntegerBase.get_bit
is_odd
uIntegerBase.is_odd
is_even
uIntegerBase.is_even
uIntegerBase.size_in_bits
size_in_bytes
uIntegerBase.size_in_bytes
is_perfect_square
uIntegerBase.is_perfect_square
fail_if_divisible_by
uIntegerBase.fail_if_divisible_by
multiply_accumulate
uIntegerBase.multiply_accumulate
set
uIntegerBase.set
inplace_inverse
uIntegerBase.inplace_inverse
inverse
uIntegerBase.inverse
gcd
uIntegerBase.gcd
lcm
uIntegerBase.lcm
jacobi_symbol
uIntegerBase.jacobi_symbol
a_tonelli_shanks
uIntegerBase._tonelli_shanks
classmethod
uIntegerBase.random
random_range
uIntegerBase.random_range
uMultiply two integers, take the modulo, and encode as big endian.
This specialized method is used for RSA decryption.
Args:
term1 : integer
The first term of the multiplication, non-negative.
term2 : integer
The second term of the multiplication, non-negative.
modulus: integer
The modulus, a positive odd number.
:Returns:
A byte string, with the result of the modular multiplication
encoded in big endian mode.
It is as long as the modulus would be, with zero padding
on the left if needed.
a_mult_modulo_bytes
uIntegerBase._mult_modulo_bytes
a__orig_bases__
uCrypto\Math\_IntegerBase.py
u<module Crypto.Math._IntegerBase>
T a__class__
T aself
T aself
term
T aself
divisor
T aself
pos
T aself
factor
T aself
exponent
modulus
T aterm1
term2
modulus
Twnwparoot
wswqwzaeuler
wmwcwtwrwiwbT aself
small_prime
T abyte_string
byteorder
T aself
wnT aself
modulus
T wawnT aself
wawbT	acls
kwargs
exact_bits
max_bits
randfunc
bits
bytes_needed
significant_bits_msb
msb
T	acls
kwargs
min_inclusive
max_inclusive
max_exclusive
randfunc
norm_maximum
bits_needed
norm_candidate
T aself
source
T aself
block_size
byteorder

a__spec__
.Crypto.Math._IntegerCustom
_
K
big
little
reverse
uIncorrect byteorder
aIntegerCustom
bytes_to_long
byte_string
uExponent must not be negative
pow
a_value
uModulus must be positive
uModulus cannot be zero
long_to_bytes
max
create_string_buffer
a_raw_montgomery
monty_pow
c_size_t
c_ulonglong
getrandbits
T l@umonty_pow failed with error: %d
get_raw_buffer
uOdd modulus is required
monty_multiply
umonty_multiply failed with error: %d
a__doc__
a__file__
origin
has_location
a__cached__
a_IntegerNative
T aIntegerNative
aIntegerNative
uCrypto.Util.number
T along_to_bytes
bytes_to_long
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
create_string_buffer
get_raw_buffer
backend
c_size_t
c_ulonglong
load_pycryptodome_raw_lib
backend
uCrypto.Random.random
T agetrandbits

int monty_pow(uint8_t       *out,
const uint8_t *base,
const uint8_t *exp,
const uint8_t *modulus,
size_t        len,
uint64_t      seed);
int monty_multiply(uint8_t       *out,
const uint8_t *term1,
const uint8_t *term2,
const uint8_t *modulus,
size_t        len);
c_defs
uCrypto.Math._modexp
library
custom
api
implementation
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
