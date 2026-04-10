# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Math._IntegerCustom

a__qualname__
staticmethod
T abig
from_bytes
uIntegerCustom.from_bytes
T nainplace_pow
uIntegerCustom.inplace_pow
a_mult_modulo_bytes
uIntegerCustom._mult_modulo_bytes
a__orig_bases__
uCrypto\Math\_IntegerCustom.py
u<module Crypto.Math._IntegerCustom>
T a__class__
T
term1
term2
modulus
mod_value
modulus_b
numbers_len
term1_b
term2_b
out
error
T abyte_string
byteorder
T aself
exponent
modulus
exp_value
mod_value
max_len
base_b
exp_b
modulus_b
out
error
result

a__spec__
.Crypto.Math._IntegerGMP
Z
a__doc__
a__file__
origin
has_location
a__cached__
sys
struct
uCrypto.Util.py3compat
T ais_native_int
is_native_int
uCrypto.Util._raw_api
T abackend
load_lib
c_ulong
c_size_t
c_uint8_ptr
backend
load_lib
c_ulong
c_size_t
c_uint8_ptr
a_IntegerBase
T aIntegerBase
aIntegerBase
utypedef unsigned long UNIX_ULONG;
typedef struct { int a; int b; void *c; } MPZ;
typedef MPZ mpz_t[1];
typedef UNIX_ULONG mp_bitcnt_t;
void __gmpz_init (mpz_t x);
void __gmpz_init_set (mpz_t rop, const mpz_t op);
void __gmpz_init_set_ui (mpz_t rop, UNIX_ULONG op);
UNIX_ULONG __gmpz_get_ui (const mpz_t op);
void __gmpz_set (mpz_t rop, const mpz_t op);
void __gmpz_set_ui (mpz_t rop, UNIX_ULONG op);
void __gmpz_add (mpz_t rop, const mpz_t op1, const mpz_t op2);
void __gmpz_add_ui (mpz_t rop, const mpz_t op1, UNIX_ULONG op2);
void __gmpz_sub_ui (mpz_t rop, const mpz_t op1, UNIX_ULONG op2);
void __gmpz_addmul (mpz_t rop, const mpz_t op1, const mpz_t op2);
void __gmpz_addmul_ui (mpz_t rop, const mpz_t op1, UNIX_ULONG op2);
void __gmpz_submul_ui (mpz_t rop, const mpz_t op1, UNIX_ULONG op2);
void __gmpz_import (mpz_t rop, size_t count, int order, size_t size,
int endian, size_t nails, const void *op);
void * __gmpz_export (void *rop, size_t *countp, int order,
size_t size,
int endian, size_t nails, const mpz_t op);
size_t __gmpz_sizeinbase (const mpz_t op, int base);
void __gmpz_sub (mpz_t rop, const mpz_t op1, const mpz_t op2);
void __gmpz_mul (mpz_t rop, const mpz_t op1, const mpz_t op2);
void __gmpz_mul_ui (mpz_t rop, const mpz_t op1, UNIX_ULONG op2);
int __gmpz_cmp (const mpz_t op1, const mpz_t op2);
void __gmpz_powm (mpz_t rop, const mpz_t base, const mpz_t exp, const
mpz_t mod);
void __gmpz_powm_ui (mpz_t rop, const mpz_t base, UNIX_ULONG exp,
const mpz_t mod);
void __gmpz_pow_ui (mpz_t rop, const mpz_t base, UNIX_ULONG exp);
void __gmpz_sqrt(mpz_t rop, const mpz_t op);
void __gmpz_mod (mpz_t r, const mpz_t n, const mpz_t d);
void __gmpz_neg (mpz_t rop, const mpz_t op);
void __gmpz_abs (mpz_t rop, const mpz_t op);
void __gmpz_and (mpz_t rop, const mpz_t op1, const mpz_t op2);
void __gmpz_ior (mpz_t rop, const mpz_t op1, const mpz_t op2);
void __gmpz_clear (mpz_t x);
void __gmpz_tdiv_q_2exp (mpz_t q, const mpz_t n, mp_bitcnt_t b);
void __gmpz_fdiv_q (mpz_t q, const mpz_t n, const mpz_t d);
void __gmpz_mul_2exp (mpz_t rop, const mpz_t op1, mp_bitcnt_t op2);
int __gmpz_tstbit (const mpz_t op, mp_bitcnt_t bit_index);
int __gmpz_perfect_square_p (const mpz_t op);
int __gmpz_jacobi (const mpz_t a, const mpz_t b);
void __gmpz_gcd (mpz_t rop, const mpz_t op1, const mpz_t op2);
UNIX_ULONG __gmpz_gcd_ui (mpz_t rop, const mpz_t op1,
UNIX_ULONG op2);
void __gmpz_lcm (mpz_t rop, const mpz_t op1, const mpz_t op2);
int __gmpz_invert (mpz_t rop, const mpz_t op1, const mpz_t op2);
int __gmpz_divisible_p (const mpz_t n, const mpz_t d);
int __gmpz_divisible_ui_p (const mpz_t n, UNIX_ULONG d);
size_t __gmpz_size (const mpz_t op);
UNIX_ULONG __gmpz_getlimbn (const mpz_t op, size_t n);
gmp_defs
uNot using GMP on Windows
uCrypto\Math\_IntegerGMP.py
u<module Crypto.Math._IntegerGMP>

a__spec__
.Crypto.Math._IntegerNative
uA floating point type is not a natural number
a_value
uInteger(%s)
uConversion only valid for non-negative numbers
long_to_bytes
uValue too large to encode
big
little
reverse
uIncorrect byteorder
result
bytes_to_long
byte_string
a__eq__
a__lt__
a__le__
T EValueError
EAttributeError
ETypeError
uModulus must be positive
uExponent must not be negative
uModulus cannot be zero
pow
inplace_pow
uSquare root of negative value
l wywxavalue
a_tonelli_shanks
uDivision by zero
uIncorrect shift count
uno bit representation for negative values
unegative bit count
bit_length
size_in_bits
l T l
l asquare_x
self
uValue is composite
inverse
inplace_inverse
aGCD
T l
gcd
un must be a positive integer
un must be odd for the Jacobi symbol
a1
weT l l l l aIntegerNative
jacobi_symbol
uOdd modulus is required
a__doc__
a__file__
origin
has_location
a__cached__
a_IntegerBase
T aIntegerBase
aIntegerBase
uCrypto.Util.number
T along_to_bytes
bytes_to_long
inverse
aGCD
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
