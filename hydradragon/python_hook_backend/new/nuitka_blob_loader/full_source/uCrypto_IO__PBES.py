# Reconstructed from integrated Nuitka blob
# Module: uCrypto.IO._PBES

a__qualname__
a__orig_bases__
T Oobject
aPBES1
uDeprecated encryption scheme with password-based key derivation
(originally defined in PKCS#5 v1.5, but still present in `v2.0`__).
.. __: http://www.ietf.org/rfc/rfc2898.txt
staticmethod
uPBES1.decrypt
aPBES2
uEncryption scheme with password-based key derivation
(defined in `PKCS#5 v2.0`__).
.. __: http://www.ietf.org/rfc/rfc2898.txt.
T nnuPBES2.encrypt
uPBES2.decrypt
uCrypto\IO\_PBES.py
u<module Crypto.IO._PBES>
T a__class__
T adata
passphrase
enc_private_key_info
encrypted_algorithm
encrypted_data
pbe_oid
cipher_params
aMD5
aDES
hashmod
module
aARC2
aSHA1
pbe_params
salt
iterations
key_iv
key
iv
cipher
pt
T$adata
passphrase
enc_private_key_info
enc_algo
encrypted_data
pbe_oid
pbes2_params
kdf_info
kdf_oid
kdf_key_length
pbkdf2_params
salt
iteration_count
left
idx
pbkdf2_prf_oid
pbkdf2_prf_algo_id
scrypt_params
scrypt_r
scrypt_p
enc_info
enc_oid
aead
aDES3
module
cipher_mode
key_size
cipher_param
iv_nonce
hmac_hash_module_oid
hmac_hash_module
key
cipher
tag_len
pt
pt_padded
T!adata
passphrase
protection
prot_params
randfunc
pattern
res
pbkdf
pbkdf2_hmac_algo
enc_algo
aead
aDES3
key_size
module
cipher_mode
enc_oid
enc_param
iv_nonce
salt
count
digestmod
key
pbkdf2_params
hmac_oid
kdf_info
scrypt_r
scrypt_p
cipher
ct
tag
encrypted_data
enc_info
enc_private_key_info

a__spec__
.Crypto.IO
$
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_Crypto
u\not_existing
aIO
T aNUITKA_PACKAGE_Crypto_IO
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
aPEM
aPKCS8
a__all__
uCrypto\IO\__init__.py
u<module Crypto.IO>

a__spec__
.Crypto.Math.Numbers
a__doc__
a__file__
origin
has_location
a__cached__
aInteger
a__all__
os
getenv
T aPYCRYPTODOME_DISABLE_GMP
uCrypto.Math._IntegerGMP
T aIntegerGMP
aIntegerGMP
T aimplementation
implementation
a_implementation
T EImportError
EOSError
EAttributeError
uCrypto.Math._IntegerCustom
T aIntegerCustom
aIntegerCustom
T EImportError
EOSError
uCrypto.Math._IntegerNative
T aIntegerNative
aIntegerNative
uCrypto\Math\Numbers.py
u<module Crypto.Math.Numbers>

a__spec__
.Crypto.Math.Primality
c
aInteger
T l l l l aPROBABLY_PRIME
is_even
aCOMPOSITE
T l aRandom
new
read
wmwaaiter_range
base
random_range
l acandidate
randfunc
T amin_inclusive
max_inclusive
randfunc
pow
wzuPerform a Miller-Rabin primality test on an integer.
The test is specified in Section C.3.1 of `FIPS PUB 186-4`__.
:Parameters:
candidate : integer
The number to test for primality.
iterations : integer
The maximum number of iterations to perform before
declaring a candidate a probable prime.
randfunc : callable
An RNG function where bases are taken from.
:Returns:
``Primality.COMPOSITE`` or ``Primality.PROBABLY_PRIME``.
.. __: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
is_perfect_square
alternate
ulucas_test.<locals>.alternate
jacobi_symbol
size_in_bits
T l
aU_temp
set
aU_i
aV_i
aV_temp
wDamultiply_accumulate
is_odd
wKaget_bit
uPerform a Lucas primality test on an integer.
The test is specified in Section C.3.3 of `FIPS PUB 186-4`__.
:Parameters:
candidate : integer
The number to test for primality.
:Returns:
``Primality.COMPOSITE`` or ``Primality.PROBABLY_PRIME``.
.. __: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
l avalue
a_sieve_base
fail_if_divisible_by
u<lambda>
utest_probable_prime.<locals>.<lambda>
T
T l  l T l  l T l  l T l  l
T l  l T l  l T l  l T l 	l T l l T l  l amiller_rabin_test
T arandfunc
lucas_test
uTest if a number is prime.
A number is qualified as prime if it passes a certain
number of Miller-Rabin tests (dependent on the size
of the number, but such that probability of a false
positive is less than 10^-30) and a single Lucas test.
For instance, a 1024-bit candidate will need to pass
4 Miller-Rabin tests.
:Parameters:
candidate : integer
The number to test for primality.
randfunc : callable
The routine to draw random bytes from to select Miller-Rabin bases.
:Returns:
``PROBABLE_PRIME`` if the number if prime with very high probability.
``COMPOSITE`` if the number is a composite.
For efficiency reasons, ``COMPOSITE`` is also returned for small primes.
bit_size
exact_bits
pop
T arandfunc
naprime_filter
ugenerate_probable_prime.<locals>.<lambda>
uUnknown parameters:
keys
uMissing exact_bits parameter
l  uPrime number is not big enough.
result
random
T aexact_bits
randfunc
test_probable_prime
uGenerate a random probable prime.
The prime will not have any specific properties
(e.g. it will not be a *strong* prime).
Random numbers are evaluated for primality until one
passes all tests, consisting of a certain number of
Miller-Rabin tests with random bases followed by
a single Lucas test.
The number of Miller-Rabin iterations is chosen such that
the probability that the output number is a non-prime is
less than 1E-30 (roughly 2^{-100}).
This approach is compliant to `FIPS PUB 186-4`__.
:Keywords:
exact_bits : integer
The desired size in bits of the probable prime.
It must be at least 160.
randfunc : callable
An RNG function where candidate primes are taken from.
prime_filter : callable
A function that takes an Integer as parameter and returns
True if the number can be passed to further primality tests,
False if it should be immediately discarded.
:Return:
A probable prime in the range 2^exact_bits > p > 2^(exact_bits-1).
.. __: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
generate_probable_prime
uGenerate a random, probable safe prime.
Note this operation is much slower than generating a simple prime.
:Keywords:
exact_bits : integer
The desired size in bits of the probable safe prime.
randfunc : callable
An RNG function where candidate primes are taken from.
:Return:
A probable safe prime in the range
2^exact_bits > p > 2^(exact_bits-1).
uFunctions to create and test prime numbers.
:undocumented: __package__
a__doc__
a__file__
origin
has_location
a__cached__
aCrypto
T aRandom
uCrypto.Math.Numbers
T aInteger
uCrypto.Util.py3compat
T aiter_range
T nuCrypto.Util.number
T asieve_base
sieve_base
a_sieve_base_large
:nldnagenerate_probable_safe_prime
uCrypto\Math\Primality.py
T wxT wxabit_size
T abit_size
u<module Crypto.Math.Primality>
T avalue
T akwargs
exact_bits
randfunc
prime_filter
result
candidate
T akwargs
exact_bits
randfunc
result
wqacandidate
T acandidate
alternate
wDajs
wKwraU_i
aV_i
aU_temp
aV_temp
wiT acandidate
iterations
randfunc
one
minus_one
wmwawiabase
wzwjT acandidate
randfunc
mr_ranges
bit_size
mr_iterations

a__spec__
.Crypto.Math._IntegerBase
T l
l l l apow
l uCannot compute square root
wqwsT l wzwpwtaiter_range
wmwiuCannot compute square root of %d mod %d
wcwruTonelli-shanks algorithm for computing the square root
of n modulo a prime p.
n must be in the range [0..p-1].
p must be at least even.
The return value r is the square root of modulo p. If non-zero,
nother solution will also exist (p-r).
Note we cannot assume that p is really a prime: if it's not,
we can either raise an exception or return the correct value.
exact_bits
pop
T amax_bits
nT arandfunc
naRandom
new
read
uEither 'exact_bits' or 'max_bits' must be specified
u'exact_bits' and 'max_bits' are mutually exclusive
l abord
T l afrom_bytes
bchr
uGenerate a random natural integer of a certain size.
:Keywords:
exact_bits : positive integer
The length in bits of the resulting random Integer number.
The number is guaranteed to fulfil the relation:
2^bits > result >= 2^(bits - 1)
max_bits : positive integer
The maximum length in bits of the resulting random Integer number.
The number is guaranteed to fulfil the relation:
2^bits > result >=0
randfunc : callable
A function that returns a random byte string. The length of the
byte string is passed as parameter. Optional.
If not provided (or ``None``), randomness is read from the system RNG.
:Return: a Integer object
min_inclusive
T amax_inclusive
nT amax_exclusive
nuUnknown keywords:
keys
umax_inclusive and max_exclusive cannot be both specified
uMissing keyword to identify the interval
size_in_bits
norm_candidate
cls
random
bits_needed
randfunc
T amax_bits
randfunc
uGenerate a random integer within a given internal.
:Keywords:
min_inclusive : integer
The lower end of the interval (inclusive).
max_inclusive : integer
The higher end of the interval (inclusive).
max_exclusive : integer
The higher end of the interval (exclusive).
randfunc : callable
A function that returns a random byte string. The length of the
byte string is passed as parameter. Optional.
If not provided (or ``None``), randomness is read from the system RNG.
:Returns:
An Integer randomly taken in the given interval.
a__doc__
a__file__
origin
has_location
a__cached__
abc
uCrypto.Util.py3compat
T aiter_range
bord
bchr
aABC
aABC
aCrypto
T aRandom
a__prepare__
aIntegerBase
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
