# Reconstructed from integrated Nuitka blob
# Module: uattr.validators

a__qualname__
a__call__
u_InstanceOfValidator.__call__
a__repr__
u_InstanceOfValidator.__repr__
instance_of
T arepr
frozen
slots
u_MatchesReValidator.__call__
u_MatchesReValidator.__repr__
T l
namatches_re
u_OptionalValidator.__call__
u_OptionalValidator.__repr__
optional
T ahash
u_InValidator.__call__
u_InValidator.__repr__
in_
T Fptu_IsCallableValidator.__call__
u<is_callable validator>
u_IsCallableValidator.__repr__
is_callable
T avalidator
T adefault
validator
u_DeepIterable.__call__
u_DeepIterable.__repr__
T nadeep_iterable
u_DeepMapping.__call__
u_DeepMapping.__repr__
deep_mapping
u_NumberValidator.__call__
u_NumberValidator.__repr__
u_MaxLengthValidator.__call__
u_MaxLengthValidator.__repr__
max_len
u_MinLengthValidator.__call__
u_MinLengthValidator.__repr__
min_len
u_SubclassOfValidator.__call__
u_SubclassOfValidator.__repr__
a_subclass_of
T unot_ validator child '{validator!r}' did not raise a captured error
T aconverter
T EException
T Otuple
T amember_validator
iterable_validator
u_NotValidator.__call__
u_NotValidator.__repr__
D amsg
exc_types
nT EValueError
ETypeError
not_
u_OrValidator.__call__
u_OrValidator.__repr__
or_
uattr\validators.py
T a.0
weu<module attr.validators>
T a__class__
T aself
inst
attr
value
member
T aself
inst
attr
value
key
T aself
inst
attr
value
in_options
msg
T aself
inst
attr
value
msg
T aself
inst
attr
value
message
T aself
inst
attr
value
T aself
inst
attr
value
wvamsg
T aself
iterable_identifier
T aself
T atype
T akey_validator
value_validator
mapping_validator
T aval
T aoptions
repr_options
T aregex
flags
func
valid_funcs
msg
pattern
match_func
T alength
T avalidator
msg
exc_types
T avalidators
vals
wvT adisabled
a__spec__
.base58
\
encode
T aascii
:l
l nc
wiastring

Encode an integer using Base58
scrub_input
lstrip
T d
from_bytes
D abyteorder
big
b58encode_int
T adefault_one
alphabet

Encode a string using Base58
c0Oo
cIl1
invmap
d arstrip
a_get_base58_decode_map
T aautofix
decimal
base
uInvalid character {!r}
args

Decode a Base58 encoded string as an integer
b58decode_int
T aalphabet
autofix
acc
l  aresult
d

Decode a Base58 encoded string
sha256
digest
b58encode
:nl nT aalphabet

Encode a string using Base58 with a 4 character checksum
b58decode
:nq n:q nnuInvalid checksum
uDecode and verify the checksum of a Base58 encoded string
uBase58 encoding
Implementations of Base58 and Base58Check encodings that are compatible
with the bitcoin network.
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_base58
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
lru_cache
hashlib
T asha256
aMapping
aUnion
u2.1.1
a__version__
c123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
aBITCOIN_ALPHABET
crpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz
aRIPPLE_ALPHABET
aXRP_ALPHABET
alphabet
wvT Ostr
Obytes
return
D wiadefault_one
alphabet
return
Oint
Obool
Obytes
paautofix
T Oint
pD aautofix
Fab58encode_check
b58decode_check
ubase58\__init__.py
u<module base58>
T aalphabet
autofix
invmap
groups
group
pivots
alternative
T wvaalphabet
autofix
origlen
newlen
acc
result
mod
T wvaalphabet
autofix
result
check
digest
T wvaalphabet
autofix
map
decimal
base
char
weT wvaalphabet
origlen
newlen
acc
result
T wvaalphabet
digest
T wiadefault_one
alphabet
string
base
idx
T wvu
a__spec__
.bip32.base58
T
encode
T aascii
:l
l nc
wiastring

Encode an integer using Base58
scrub_input
lstrip
T d
from_bytes
D abyteorder
big
b58encode_int
T adefault_one
alphabet

Encode a string using Base58
c0Oo
cIl1
invmap
d arstrip
a_get_base58_decode_map
T aautofix
decimal
base
uInvalid character {!r}
args

Decode a Base58 encoded string as an integer
b58decode_int
T aalphabet
autofix
to_bytes
bit_length
l l abig

Decode a Base58 encoded string
sha256
digest
b58encode
:nl nT aalphabet

Encode a string using Base58 with a 4 character checksum
b58decode
:nq n:q nnuInvalid checksum
uDecode and verify the checksum of a Base58 encoded string
uBase58 encoding
Implementations of Base58 and Base58Check encodings that are compatible
with the bitcoin network.
This file was copied over and added to the bip32 project from David Keijser's https://github.com/keis/base58 (https://pypi.org/project/base58/). This
package is released under an MIT licensed. The code was copied in this file and left untouched. Here is a copy of the MIT license accompanying the
code:
Copyright (c) 2015 David Keijser
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
ll copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
a__doc__
a__file__
origin
has_location
a__cached__
lru_cache
hashlib
T asha256
aMapping
aUnion
c123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
aBITCOIN_ALPHABET
crpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz
aRIPPLE_ALPHABET
aXRP_ALPHABET
alphabet
wvT Ostr
Obytes
return
D wiadefault_one
alphabet
return
Oint
Obool
Obytes
paautofix
T Oint
pD aautofix
Fab58encode_check
b58decode_check
ubip32\base58.py
u<module bip32.base58>
T aalphabet
autofix
invmap
groups
group
pivots
alternative
T wvaalphabet
autofix
origlen
newlen
acc
T wvaalphabet
autofix
result
check
digest
T wvaalphabet
autofix
map
decimal
base
char
weT wvaalphabet
origlen
newlen
acc
result
T wvaalphabet
digest
T wiadefault_one
alphabet
string
base
idx
T wvu
a__spec__
.bip32.bip32
p
message
T amain
test
aInvalidInputError
T u'network' must be one of 'main' or 'test'
T u'chaincode' must be bytes
T uNeed at least a 'pubkey' or a 'privkey'
T u'privkey' must be bytes
a_privkey_is_valid
T uInvalid secp256k1 private key
T u'pubkey' must be bytes
a_pubkey_is_valid
T uInvalid secp256k1 public key
a_privkey_to_pubkey
b
T uFingerprint must be 0 if depth is 0 (master xpub)
T uIndex must be 0 if depth is 0 (master xpub)
T uUnknown network
chaincode
privkey
pubkey
parent_fingerprint
depth
index
network

:param chaincode: The master chaincode, used to derive keys. As bytes.
:param privkey: The master private key for this index (default 0).
Can be None for pubkey-only derivation.
As bytes.
:param pubkey: The master public key for this index (default 0).
Can be None if private key is specified.
Compressed format. As bytes.
:param fingeprint: If we are instanciated from an xpub/xpriv, we need
to remember the parent's pubkey fingerprint to
reserialize !
:param depth: If we are instanciated from an existing extended key, we
need this for serialization.
:param index: If we are instanciated from an existing extended key, we
need this for serialization.
:param network: Either "main" or "test".
aPrivateDerivationError
a_deriv_path_str_to_list
aHARDENED_INDEX
a_derive_hardened_private_child
a_derive_unhardened_private_child
uGet an extended privkey from a derivation path.
:param path: A list of integers (index of each depth) or a string with
m/x/x'/x notation. (e.g. m/0'/1/2'/2 or m/0H/1/2H/2).
:return: chaincode (bytes), privkey (bytes)
get_extended_privkey_from_path
uGet a privkey from a derivation path.
:param path: A list of integers (index of each depth) or a string with
m/x/x'/x notation. (e.g. m/0'/1/2'/2 or m/0H/1/2H/2).
:return: privkey (bytes)
a_hardened_index_in_path
key
a_derive_public_child
uGet an extended pubkey from a derivation path.
:param path: A list of integers (index of each depth) or a string with
m/x/x'/x notation. (e.g. m/0'/1/2'/2 or m/0H/1/2H/2).
:return: chaincode (bytes), pubkey (bytes)
get_extended_pubkey_from_path
uGet a pubkey from a derivation path.
:param path: A list of integers (index of each depth) or a string with
m/x/x'/x notation. (e.g. m/0'/1/2'/2 or m/0H/1/2H/2).
:return: privkey (bytes)
get_xpriv
get_pubkey_from_path
:nq na_serialize_extended_key
b58encode_check
decode
uGet an encoded extended privkey from a derivation path.
:param path: A list of integers (index of each depth) or a string with
m/x/x'/x notation. (e.g. m/0'/1/2'/2 or m/0H/1/2H/2).
:return: The encoded extended pubkey as str.
get_xpub
uGet an encoded extended pubkey from a derivation path.
:param path: A list of integers (index of each depth) or a string with
m/x/x'/x notation. (e.g. m/0'/1/2'/2 or m/0H/1/2H/2).
:return: The encoded extended pubkey as str.
get_xpriv_bytes
uGet the base58 encoded extended private key.
uGet the encoded extended private key.
get_xpub_bytes
uGet the encoded extended public key.
a_pubkey_to_fingerprint
uGet the public key fingerprint.
T u'xpriv' must be a string
b58decode_check
a_unserialize_extended_key
aParsingError
T uInvalid xpriv: private key prefix must be 0
aBIP32
:l nnuInvalid xpriv: '

w'uGet a BIP32 "wallet" out of this xpriv
:param xpriv: (str) The encoded serialized extended private key.
T u'xpub' must be a string
uInvalid xpub: '
uGet a BIP32 "wallet" out of this xpub
:param xpub: (str) The encoded serialized extended public key.
hmac
new
cBitcoin seed
hashlib
sha512
digest
:l nn:nl nT anetwork
uGet a BIP32 "wallet" out of this seed (maybe after BIP39?)
:param seed: The seed as bytes.
a__doc__
a__file__
origin
has_location
a__cached__
base58
T ab58encode_check
b58decode_check
utils
T aHARDENED_INDEX
a_derive_hardened_private_child
a_derive_unhardened_private_child
a_derive_public_child
a_serialize_extended_key
a_unserialize_extended_key
a_hardened_index_in_path
a_privkey_to_pubkey
a_deriv_path_str_to_list
a_pubkey_is_valid
a_privkey_is_valid
a_pubkey_to_fingerprint
T EValueError
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
