# Reconstructed from integrated Nuitka blob
# Module: unacl.bindings.crypto_sign


State object wrapping the sha-512 state used in ed25519ph computation
a__qualname__
a__slots__
D areturn
na__init__
ucrypto_sign_ed25519ph_state.__init__
edph
pmsg
sk
signature
pk
unacl\bindings\crypto_sign.py
u<module nacl.bindings.crypto_sign>
T aself
rc
T amessage
sk
signed
signed_len
rc
T apublic_key_bytes
curve_public_key_len
curve_public_key
rc
T asecret_key_bytes
curve_secret_key_len
curve_secret_key
rc
T asecret_key_bytes
T aedph
sk
signature
rc
T aedph
signature
pk
rc
T aedph
pmsg
rc
T apk
sk
rc
T asigned
pk
message
message_len
T aseed
pk
sk
rc

a__spec__
.nacl.bindings.randombytes
6
"
ffi
new
uunsigned char[]
lib
randombytes
buffer
:nnnu
Returns ``size`` number of random bytes from a cryptographically secure
random source.
:param size: int
:rtype: bytes
randombytes_SEEDBYTES
exc
aTypeError
T uDeterministic random bytes must be generated from 32 bytes
randombytes_buf_deterministic

Returns ``size`` number of deterministically generated pseudorandom bytes
from a seed
:param size: int
:param seed: bytes
:rtype: bytes
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
nacl
T aexceptions
exceptions
unacl._sodium
T affi
lib
randombytes_seedbytes
D asize
return
Oint
Obytes
D asize
seed
return
Oint
Obytes
punacl\bindings\randombytes.py
u<module nacl.bindings.randombytes>
T asize
buf
T asize
seed
buf

a__spec__
.nacl.bindings.sodium_core
ensure
lib
sodium_init
uCould not initialize sodium
exc
aRuntimeError
T araising
ffi
init_once
a_sodium_init
libsodium

Initializes sodium, picking the best implementations available for this
machine.
a__doc__
a__file__
origin
has_location
a__cached__
nacl
T aexceptions
exceptions
unacl._sodium
T affi
lib
unacl.exceptions
T aensure
D areturn
nunacl\bindings\sodium_core.py
u<module nacl.bindings.sodium_core>

a__spec__
.nacl.bindings.utils
x
3
ensure
exc
aTypeError
T araising
max
ffi
new
uchar []
memmove
lib
sodium_memcmp

Compare contents of two memory regions in constant time
aValueError
uunsigned char []
T usize_t []
l asodium_pad
uPadding failure
aCryptoError
buffer
:nnnu
Pad the input bytearray ``s`` to a multiple of ``blocksize``
using the ISO/IEC 7816-4 algorithm
:param s: input bytes string
:type s: bytes
:param blocksize:
:type blocksize: int
:return: padded string
:rtype: bytes
sodium_unpad
T uUnpadding failure

Remove ISO/IEC 7816-4 padding from the input byte array ``s``
:param s: input bytes string
:type s: bytes
:param blocksize:
:type blocksize: int
:return: unpadded string
:rtype: bytes
sodium_increment

Increment the value of a byte-sequence interpreted
s the little-endian representation of a unsigned big integer.
:param inp: input bytes buffer
:type inp: bytes
:return: a byte-sequence representing, as a little-endian
unsigned big integer, the value ``to_int(inp)``
incremented by one.
:rtype: bytes
sodium_add

Given a couple of *same-sized* byte sequences, interpreted as the
little-endian representation of two unsigned integers, compute
the modular addition of the represented values, in constant time for
a given common length of the byte sequences.
:param a: input bytes buffer
:type a: bytes
:param b: input bytes buffer
:type b: bytes
:return: a byte-sequence representing, as a little-endian big integer,
the integer value of ``(to_int(a) + to_int(b)) mod 2^(8*len(a))``
:rtype: bytes
a__doc__
a__file__
origin
has_location
a__cached__
unacl.exceptions
exceptions
unacl._sodium
T affi
lib
T aensure
D ainp1
inp2
return
Obytes
pObool
D wsablocksize
return
Obytes
Oint
Obytes
D ainp
return
Obytes
pD wawbareturn
Obytes
ppunacl\bindings\utils.py
u<module nacl.bindings.utils>
T wawbaln
buf_a
buf_b
T ainp
ln
buf
T ainp1
inp2
ln
buf1
buf2
eqL
eqC
T wsablocksize
s_len
m_len
buf
p_len
rc
T wsablocksize
s_len
u_len
rc

a__spec__
.nacl
m
"
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_nacl
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
L a__title__
a__summary__
a__uri__
a__version__
a__author__
a__email__
a__license__
a__copyright__
a__all__
aPyNaCl
a__title__
uPython binding to the Networking and Cryptography (NaCl) library
a__summary__
uhttps://github.com/pyca/pynacl/
a__uri__
u1.5.0
a__version__
uThe PyNaCl developers
a__author__
ucryptography-dev@python.org
a__email__
uApache License 2.0
a__license__
uCopyright 2013-2018 {}
a__copyright__
unacl\__init__.py
u<module nacl>

a__spec__
.nacl.encoding
K
binascii
hexlify
unhexlify
base64
b16encode
b16decode
b32encode
b32decode
b64encode
b64decode
urlsafe_b64encode
urlsafe_b64decode
encode
a__doc__
a__file__
origin
has_location
a__cached__
abc
T aABCMeta
abstractmethod
aABCMeta
abstractmethod
aSupportsBytes
aType
metaclass
a__prepare__
T a_Encoder
T
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
