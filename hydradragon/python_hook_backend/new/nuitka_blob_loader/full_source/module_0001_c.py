# Reconstructed from integrated Nuitka blob
# Module: c

a__class__
a__name__
a__package__
a__metaclass__
a__abstractmethods__
a__closure__
a__dict__
a__doc__
a__file__
a__path__
a__enter__
a__exit__
a__builtins__
a__all__
a__init__
a__cmp__
a__iter__
a__loader__
a__compiled__
a__nuitka__
inspect
compile
range
open
super
sum
format
a__import__
bytearray
staticmethod
classmethod
keys
get
name
globals
locals
fromlist
level
read
rb
wrwwwbw/w\apath
basename
dirname
abspath
isabs
normpath
exists
isdir
isfile
listdir
stat
lstat
close
getattr
a__cached__
print
end
file
bytes
w.w_asend
throw
site
type
len
repr
int
aiter
a__spec__
a_initializing
parent
types
ascii
punycode
a__main__
as_file
register
a__class_getitem__
reconfigure
encoding
line_buffering
a__match_args__
fileno
upython.exe
T T aattrs
T aattr
uMetadata-Version: 2.4
Name: attrs
Version: 25.1.0
Summary: Classes Without Boilerplate
Project-URL: Documentation, https://www.attrs.org/
Project-URL: Changelog, https://www.attrs.org/en/stable/changelog.html
Project-URL: GitHub, https://github.com/python-attrs/attrs
Project-URL: Funding, https://github.com/sponsors/hynek
Project-URL: Tidelift, https://tidelift.com/subscription/pkg/pypi-attrs?utm_source=pypi-attrs&utm_medium=pypi
Author-email: Hynek Schlawack <hs@ox.cx>
License-Expression: MIT
License-File: LICENSE
Keywords: attribute,boilerplate,class
Classifier: Development Status :: 5 - Production/Stable
Classifier: Programming Language :: Python :: 3.8
Classifier: Programming Language :: Python :: 3.9
Classifier: Programming Language :: Python :: 3.10
Classifier: Programming Language :: Python :: 3.11
Classifier: Programming Language :: Python :: 3.12
Classifier: Programming Language :: Python :: 3.13
Classifier: Programming Language :: Python :: Implementation :: CPython
Classifier: Programming Language :: Python :: Implementation :: PyPy
Classifier: Typing :: Typed
Requires-Python: >=3.8
Provides-Extra: benchmark
Requires-Dist: cloudpickle; (platform_python_implementation == 'CPython') and extra == 'benchmark'
Requires-Dist: hypothesis; extra == 'benchmark'
Requires-Dist: mypy>=1.11.1; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'benchmark'
Requires-Dist: pympler; extra == 'benchmark'
Requires-Dist: pytest-codspeed; extra == 'benchmark'
Requires-Dist: pytest-mypy-plugins; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'benchmark'
Requires-Dist: pytest-xdist[psutil]; extra == 'benchmark'
Requires-Dist: pytest>=4.3.0; extra == 'benchmark'
Provides-Extra: cov
Requires-Dist: cloudpickle; (platform_python_implementation == 'CPython') and extra == 'cov'
Requires-Dist: coverage[toml]>=5.3; extra == 'cov'
Requires-Dist: hypothesis; extra == 'cov'
Requires-Dist: mypy>=1.11.1; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'cov'
Requires-Dist: pympler; extra == 'cov'
Requires-Dist: pytest-mypy-plugins; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'cov'
Requires-Dist: pytest-xdist[psutil]; extra == 'cov'
Requires-Dist: pytest>=4.3.0; extra == 'cov'
Provides-Extra: dev
Requires-Dist: cloudpickle; (platform_python_implementation == 'CPython') and extra == 'dev'
Requires-Dist: hypothesis; extra == 'dev'
Requires-Dist: mypy>=1.11.1; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'dev'
Requires-Dist: pre-commit-uv; extra == 'dev'
Requires-Dist: pympler; extra == 'dev'
Requires-Dist: pytest-mypy-plugins; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'dev'
Requires-Dist: pytest-xdist[psutil]; extra == 'dev'
Requires-Dist: pytest>=4.3.0; extra == 'dev'
Provides-Extra: docs
Requires-Dist: cogapp; extra == 'docs'
Requires-Dist: furo; extra == 'docs'
Requires-Dist: myst-parser; extra == 'docs'
Requires-Dist: sphinx; extra == 'docs'
Requires-Dist: sphinx-notfound-page; extra == 'docs'
Requires-Dist: sphinxcontrib-towncrier; extra == 'docs'
Requires-Dist: towncrier<24.7; extra == 'docs'
Provides-Extra: tests
Requires-Dist: cloudpickle; (platform_python_implementation == 'CPython') and extra == 'tests'
Requires-Dist: hypothesis; extra == 'tests'
Requires-Dist: mypy>=1.11.1; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'tests'
Requires-Dist: pympler; extra == 'tests'
Requires-Dist: pytest-mypy-plugins; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'tests'
Requires-Dist: pytest-xdist[psutil]; extra == 'tests'
Requires-Dist: pytest>=4.3.0; extra == 'tests'
Provides-Extra: tests-mypy
Requires-Dist: mypy>=1.11.1; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'tests-mypy'
Requires-Dist: pytest-mypy-plugins; (platform_python_implementation == 'CPython' and python_version >= '3.10') and extra == 'tests-mypy'
Description-Content-Type: text/markdown
<p align="center">
<a href="https://www.attrs.org/">
<img src="https://raw.githubusercontent.com/python-attrs/attrs/main/docs/_static/attrs_logo.svg" width="35%" alt="attrs" />
</a>
</p>
*attrs* is the Python package that will bring back the **joy** of **writing classes** by relieving you from the drudgery of implementing object protocols (aka [dunder methods](https://www.attrs.org/en/latest/glossary.html#term-dunder-methods)).
[Trusted by NASA](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-github-profile/customizing-your-profile/personalizing-your-profile#list-of-qualifying-repositories-for-mars-2020-helicopter-contributor-achievement) for Mars missions since 2020!
Its main goal is to help you to write **concise** and **correct** software without slowing down your code.
## Sponsors
*attrs* would not be possible without our [amazing sponsors](https://github.com/sponsors/hynek).
Especially those generously supporting us at the *The Organization* tier and higher:
<!-- sponsor-break-begin -->
<p align="center">
<!-- [[[cog
import pathlib, tomllib
for sponsor in tomllib.loads(pathlib.Path("pyproject.toml").read_text())["tool"]["sponcon"]["sponsors"]:
print(f'<a href="{sponsor["url"]}"><img title="{sponsor["title"]}" src="https://www.attrs.org/en/25.1.0/_static/sponsors/{sponsor["img"]}" width="190" /></a>')
]]] -->
<a href="https://www.variomedia.de/"><img title="Variomedia AG" src="https://www.attrs.org/en/25.1.0/_static/sponsors/Variomedia.svg" width="190" /></a>
<a href="https://tidelift.com/?utm_source=lifter&utm_medium=referral&utm_campaign=hynek"><img title="Tidelift" src="https://www.attrs.org/en/25.1.0/_static/sponsors/Tidelift.svg" width="190" /></a>
<a href="https://klaviyo.com/"><img title="Klaviyo" src="https://www.attrs.org/en/25.1.0/_static/sponsors/Klaviyo.svg" width="190" /></a>
<a href="https://www.emsys-renewables.com/"><img title="emsys renewables" src="https://www.attrs.org/en/25.1.0/_static/sponsors/emsys-renewables.svg" width="190" /></a>
<a href="https://filepreviews.io/"><img title="FilePreviews" src="https://www.attrs.org/en/25.1.0/_static/sponsors/FilePreviews.svg" width="190" /></a>
<a href="https://privacy-solutions.org/"><img title="Privacy Solutions" src="https://www.attrs.org/en/25.1.0/_static/sponsors/Privacy-Solutions.svg" width="190" /></a>
<a href="https://polar.sh/"><img title="Polar" src="https://www.attrs.org/en/25.1.0/_static/sponsors/Polar.svg" width="190" /></a>
<!-- [[[end]]] -->
</p>
<!-- sponsor-break-end -->
<p align="center">
<strong>Please consider <a href="https://github.com/sponsors/hynek">joining them</a> to help make <em>attrs</em>   s maintenance more sustainable!</strong>
</p>
<!-- teaser-end -->
## Example
*attrs* gives you a class decorator and a way to declaratively define the attributes on that class:
<!-- code-begin -->
```pycon
>>> from attrs import asdict, define, make_class, Factory
>>> @define
... class SomeClass:
...     a_number: int = 42
...     list_of_numbers: list[int] = Factory(list)
...
...     def hard_math(self, another_number):
...         return self.a_number + sum(self.list_of_numbers) * another_number
>>> sc = SomeClass(1, [1, 2, 3])
>>> sc
SomeClass(a_number=1, list_of_numbers=[1, 2, 3])
>>> sc.hard_math(3)
19
>>> sc == SomeClass(1, [1, 2, 3])
True
>>> sc != SomeClass(2, [3, 2, 1])
True
>>> asdict(sc)
{'a_number': 1, 'list_of_numbers': [1, 2, 3]}
>>> SomeClass()
SomeClass(a_number=42, list_of_numbers=[])
>>> C = make_class("C", ["a", "b"])
>>> C("foo", "bar")
C(a='foo', b='bar')
```
After *declaring* your attributes, *attrs* gives you:
- a concise and explicit overview of the class's attributes,
- a nice human-readable `__repr__`,
- equality-checking methods,
- an initializer,
- and much more,
*without* writing dull boilerplate code again and again and *without* runtime performance penalties.
---
This example uses *attrs*'s modern APIs that have been introduced in version 20.1.0, and the *attrs* package import name that has been added in version 21.3.0.
The classic APIs (`@attr.s`, `attr.ib`, plus their serious-business aliases) and the `attr` package import name will remain **indefinitely**.
Check out [*On The Core API Names*](https://www.attrs.org/en/latest/names.html) for an in-depth explanation!
### Hate Type Annotations!?
No problem!
Types are entirely **optional** with *attrs*.
Simply assign `attrs.field()` to the attributes instead of annotating them with types:
```python
from attrs import define, field
@define
class SomeClass:
a_number = field(default=42)
list_of_numbers = field(factory=list)
```
## Data Classes
On the tin, *attrs* might remind you of `dataclasses` (and indeed, `dataclasses` [are a descendant](https://hynek.me/articles/import-attrs/) of *attrs*).
In practice it does a lot more and is more flexible.
For instance, it allows you to define [special handling of NumPy arrays for equality checks](https://www.attrs.org/en/stable/comparison.html#customization), allows more ways to [plug into the initialization process](https://www.attrs.org/en/stable/init.html#hooking-yourself-into-initialization), has a replacement for `__init_subclass__`, and allows for stepping through the generated methods using a debugger.
For more details, please refer to our [comparison page](https://www.attrs.org/en/stable/why.html#data-classes), but generally speaking, we are more likely to commit crimes against nature to make things work that one would expect to work, but that are quite complicated in practice.
## Project Information
- [**Changelog**](https://www.attrs.org/en/stable/changelog.html)
- [**Documentation**](https://www.attrs.org/)
- [**PyPI**](https://pypi.org/project/attrs/)
- [**Source Code**](https://github.com/python-attrs/attrs)
- [**Contributing**](https://github.com/python-attrs/attrs/blob/main/.github/CONTRIBUTING.md)
- [**Third-party Extensions**](https://github.com/python-attrs/attrs/wiki/Extensions-to-attrs)
- **Get Help**: use the `python-attrs` tag on [Stack Overflow](https://stackoverflow.com/questions/tagged/python-attrs)
### *attrs* for Enterprise
Available as part of the [Tidelift Subscription](https://tidelift.com/?utm_source=lifter&utm_medium=referral&utm_campaign=hynek).
The maintainers of *attrs* and thousands of other packages are working with Tidelift to deliver commercial support and maintenance for the open source packages you use to build your applications.
Save time, reduce risk, and improve code health, while paying the maintainers of the exact packages you use.
## Release Information
### Changes
- This release only ensures correct PyPI licensing metadata.
[#1386](https://github.com/python-attrs/attrs/issues/1386)
---
[Full changelog    ](https://www.attrs.org/en/stable/changelog.html)

.Crypto.Cipher.AES
[
pop
T ause_aesni
tT akey
uMissing 'key' parameter
key_size
uIncorrect AES key length (%d bytes)
a_raw_aesni_lib
aAESNI_start_operation
aAESNI_stop_operation
a_raw_aes_lib
aAES_start_operation
aAES_stop_operation
aVoidPointer
c_uint8_ptr
c_size_t
address_of
uError %X while instantiating the AES cipher
aSmartPointer
get
uThis method instantiates and returns a handle to a low-level
base cipher. It will absorb named parameters in the process.
uPoly1305 with AES requires a 32-byte key
get_random_bytes
T l uPoly1305 with AES requires a 16-byte nonce
new
:nl naMODE_ECB
encrypt
nonce
:l nnuDerive a tuple (r, s, nonce) for a Poly1305 MAC.
If nonce is ``None``, a new 16-byte nonce is generated.
add_aes_modes
a_create_cipher
modules
uCrypto.Cipher.AES
uCreate a new AES cipher.
Args:
key(bytes/bytearray/memoryview):
The secret key to use in the symmetric cipher.
It must be 16 (*AES-128)*, 24 (*AES-192*) or 32 (*AES-256*) bytes long.
For ``MODE_SIV`` only, it doubles to 32, 48, or 64 bytes.
mode (a ``MODE_*`` constant):
The chaining mode to use for encryption or decryption.
If in doubt, use ``MODE_EAX``.
Keyword Args:
iv (bytes/bytearray/memoryview):
(Only applicable for ``MODE_CBC``, ``MODE_CFB``, ``MODE_OFB``,
nd ``MODE_OPENPGP`` modes).
The initialization vector to use for encryption or decryption.
For ``MODE_CBC``, ``MODE_CFB``, and ``MODE_OFB`` it must be 16 bytes long.
For ``MODE_OPENPGP`` mode only,
it must be 16 bytes long for encryption
nd 18 bytes for decryption (in the latter case, it is
ctually the *encrypted* IV which was prefixed to the ciphertext).
If not provided, a random byte string is generated (you must then
read its value with the :attr:`iv` attribute).
nonce (bytes/bytearray/memoryview):
(Only applicable for ``MODE_CCM``, ``MODE_EAX``, ``MODE_GCM``,
``MODE_SIV``, ``MODE_OCB``, and ``MODE_CTR``).
A value that must never be reused for any other encryption done
with this key (except possibly for ``MODE_SIV``, see below).
For ``MODE_EAX``, ``MODE_GCM`` and ``MODE_SIV`` there are no
restrictions on its length (recommended: **16** bytes).
For ``MODE_CCM``, its length must be in the range **[7..13]**.
Bear in mind that with CCM there is a trade-off between nonce
length and maximum message size. Recommendation: **11** bytes.
For ``MODE_OCB``, its length must be in the range **[1..15]**
(recommended: **15**).
For ``MODE_CTR``, its length must be in the range **[0..15]**
(recommended: **8**).
For ``MODE_SIV``, the nonce is optional, if it is not specified,
then no nonce is being used, which renders the encryption
deterministic.
If not provided, for modes other than ``MODE_SIV``, a random
byte string of the recommended length is used (you must then
read its value with the :attr:`nonce` attribute).
segment_size (integer):
(Only ``MODE_CFB``).The number of **bits** the plaintext and ciphertext
re segmented in. It must be a multiple of 8.
If not specified, it will be assumed to be 8.
mac_len (integer):
(Only ``MODE_EAX``, ``MODE_GCM``, ``MODE_OCB``, ``MODE_CCM``)
Length of the authentication tag, in bytes.
It must be even and in the range **[4..16]**.
The recommended value (and the default, if not specified) is **16**.
msg_len (integer):
(Only ``MODE_CCM``). Length of the message to (de)cipher.
If not specified, ``encrypt`` must be called with the entire message.
Similarly, ``decrypt`` can only be called once.
ssoc_len (integer):
(Only ``MODE_CCM``). Length of the associated data.
If not specified, all associated data is buffered internally,
which may represent a problem for very large messages.
initial_value (integer or bytes/bytearray/memoryview):
(Only ``MODE_CTR``).
The initial value for the counter. If not present, the cipher will
start counting from 0. The value is incremented by one for each block.
The counter number is encoded in big endian mode.
counter (object):
(Only ``MODE_CTR``).
Instance of ``Crypto.Util.Counter``, which allows full customization
of the counter block. This parameter is incompatible to both ``nonce``
nd ``initial_value``.
use_aesni: (boolean):
Use Intel AES-NI hardware extensions (default: use if available).
Returns:
n AES object, of the applicable mode.
a__doc__
a__file__
origin
has_location
a__cached__
sys
uCrypto.Cipher
T a_create_cipher
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
c_size_t
c_uint8_ptr
load_pycryptodome_raw_lib
uCrypto.Util
T a_cpu_features
a_cpu_features
uCrypto.Random
T aget_random_bytes
l aMODE_CBC
l aMODE_CFB
l aMODE_OFB
l aMODE_CTR
l aMODE_OPENPGP
l aMODE_CCM
l	aMODE_EAX
l
aMODE_SIV
l aMODE_GCM
l aMODE_OCB

int AES_start_operation(const uint8_t key[],
size_t key_len,
void **pResult);
int AES_encrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int AES_decrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int AES_stop_operation(void *state);
a_cproto
uCrypto.Cipher._raw_aes
have_aes_ni
uCrypto.Cipher._raw_aesni
replace
T aAES
aAESNI
a_create_base_cipher
a_derive_Poly1305_key_pair
l ablock_size
T l l l uCrypto\Cipher\AES.py
u<module Crypto.Cipher.AES>
T adict_parameters
use_aesni
key
start_operation
stop_operation
cipher
result
T akey
nonce
wsT akey
mode
args
kwargs

a__spec__
.Crypto.Cipher.ARC2
<
@
pop
T akey
uMissing 'key' parameter
T aeffective_keylen
l  akey_size
uIncorrect ARC2 key length (%d bytes)
l(l  u'effective_key_len' must be at least 40 and no larger than 1024 (not %d)
a_raw_arc2_lib
aARC2_start_operation
aARC2_stop_operation
aVoidPointer
c_uint8_ptr
c_size_t
address_of
uError %X while instantiating the ARC2 cipher
aSmartPointer
get
uThis method instantiates and returns a handle to a low-level
base cipher. It will absorb named parameters in the process.
a_create_cipher
modules
uCrypto.Cipher.ARC2
uCreate a new RC2 cipher.
:param key:
The secret key to use in the symmetric cipher.
Its length can vary from 5 to 128 bytes; the actual search space
(and the cipher strength) can be reduced with the ``effective_keylen`` parameter.
:type key: bytes, bytearray, memoryview
:param mode:
The chaining mode to use for encryption or decryption.
:type mode: One of the supported ``MODE_*`` constants
:Keyword Arguments:
*   **iv** (*bytes*, *bytearray*, *memoryview*) --
(Only applicable for ``MODE_CBC``, ``MODE_CFB``, ``MODE_OFB``,
nd ``MODE_OPENPGP`` modes).
The initialization vector to use for encryption or decryption.
For ``MODE_CBC``, ``MODE_CFB``, and ``MODE_OFB`` it must be 8 bytes long.
For ``MODE_OPENPGP`` mode only,
it must be 8 bytes long for encryption
nd 10 bytes for decryption (in the latter case, it is
ctually the *encrypted* IV which was prefixed to the ciphertext).
If not provided, a random byte string is generated (you must then
read its value with the :attr:`iv` attribute).
*   **nonce** (*bytes*, *bytearray*, *memoryview*) --
(Only applicable for ``MODE_EAX`` and ``MODE_CTR``).
A value that must never be reused for any other encryption done
with this key.
For ``MODE_EAX`` there are no
restrictions on its length (recommended: **16** bytes).
For ``MODE_CTR``, its length must be in the range **[0..7]**.
If not provided for ``MODE_EAX``, a random byte string is generated (you
can read it back via the ``nonce`` attribute).
*   **effective_keylen** (*integer*) --
Optional. Maximum strength in bits of the actual key used by the ARC2 algorithm.
If the supplied ``key`` parameter is longer (in bits) of the value specified
here, it will be weakened to match it.
If not specified, no limitation is applied.
*   **segment_size** (*integer*) --
(Only ``MODE_CFB``).The number of **bits** the plaintext and ciphertext
re segmented in. It must be a multiple of 8.
If not specified, it will be assumed to be 8.
*   **mac_len** : (*integer*) --
(Only ``MODE_EAX``)
Length of the authentication tag, in bytes.
It must be no longer than 8 (default).
*   **initial_value** : (*integer*) --
(Only ``MODE_CTR``). The initial value for the counter within
the counter block. By default it is **0**.
:Return: an ARC2 object, of the applicable mode.

Module's constants for the modes of operation supported with ARC2:
:var MODE_ECB: :ref:`Electronic Code Book (ECB) <ecb_mode>`
:var MODE_CBC: :ref:`Cipher-Block Chaining (CBC) <cbc_mode>`
:var MODE_CFB: :ref:`Cipher FeedBack (CFB) <cfb_mode>`
:var MODE_OFB: :ref:`Output FeedBack (OFB) <ofb_mode>`
:var MODE_CTR: :ref:`CounTer Mode (CTR) <ctr_mode>`
:var MODE_OPENPGP:  :ref:`OpenPGP Mode <openpgp_mode>`
:var MODE_EAX: :ref:`EAX Mode <eax_mode>`
a__doc__
a__file__
origin
has_location
a__cached__
sys
uCrypto.Cipher
T a_create_cipher
uCrypto.Util.py3compat
T abyte_string
byte_string
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
c_size_t
c_uint8_ptr
load_pycryptodome_raw_lib
T uCrypto.Cipher._raw_arc2

int ARC2_start_operation(const uint8_t key[],
size_t key_len,
size_t effective_key_len,
void **pResult);
int ARC2_encrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int ARC2_decrypt(const void *state,
const uint8_t *in,
uint8_t *out,
size_t data_len);
int ARC2_stop_operation(void *state);
a_create_base_cipher
new
aMODE_ECB
l aMODE_CBC
l aMODE_CFB
l aMODE_OFB
l aMODE_CTR
l aMODE_OPENPGP
l	aMODE_EAX
l ablock_size
;l l  l uCrypto\Cipher\ARC2.py
u<module Crypto.Cipher.ARC2>
T adict_parameters
key
effective_keylen
start_operation
stop_operation
cipher
result
T akey
mode
args
kwargs

a__spec__
.Crypto.Cipher.ARC4
x
9
:l nnadrop
key_size
uIncorrect ARC4 key length (%d bytes)
aVoidPointer
a_state
a_raw_arc4_lib
aARC4_stream_init
c_uint8_ptr
c_size_t
address_of
uError %d while creating the ARC4 cipher
aSmartPointer
get
aARC4_stream_destroy
encrypt
d
block_size
uInitialize an ARC4 cipher object
See also `new()` at the module level.
create_string_buffer
aARC4_stream_encrypt
uError %d while encrypting with RC4
get_raw_buffer
uEncrypt a piece of data.
:param plaintext: The data to encrypt, of any size.
:type plaintext: bytes, bytearray, memoryview
:returns: the encrypted byte string, of equal length as the
plaintext.
replace
T aenc
dec
uDecrypt a piece of data.
:param ciphertext: The data to decrypt, of any size.
:type ciphertext: bytes, bytearray, memoryview
:returns: the decrypted byte string, of equal length as the
ciphertext.
aARC4Cipher
uCreate a new ARC4 cipher.
:param key:
The secret key to use in the symmetric cipher.
Its length must be in the range ``[1..256]``.
The recommended length is 16 bytes.
:type key: bytes, bytearray, memoryview
:Keyword Arguments:
*   *drop* (``integer``) --
The amount of bytes to discard from the initial part of the keystream.
In fact, such part has been found to be distinguishable from random
data (while it shouldn't) and also correlated to key.
The recommended value is 3072_ bytes. The default value is 0.
:Return: an `ARC4Cipher` object
.. _3072: http://eprint.iacr.org/2002/067.pdf
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
create_string_buffer
get_raw_buffer
aSmartPointer
c_size_t
c_uint8_ptr
load_pycryptodome_raw_lib
T uCrypto.Cipher._ARC4

int ARC4_stream_encrypt(void *rc4State, const uint8_t in[],
uint8_t out[], size_t len);
int ARC4_stream_init(uint8_t *key, size_t keylen,
void **pRc4State);
int ARC4_stream_destroy(void *rc4State);
