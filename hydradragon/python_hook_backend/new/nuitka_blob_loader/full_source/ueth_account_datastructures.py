# Reconstructed from integrated Nuitka blob
# Module: ueth_account.datastructures

a__qualname__
index
return
uSignedTransaction.__getitem__
slice
str
a__orig_bases__
aSignedMessage
message_hash
signature
uSignedMessage.__getitem__
ueth_account\datastructures.py
u<module eth_account.datastructures>
T a__class__
T aself
index
T aself
index
a__class__

a__spec__
.eth_account.hdaccount._utils
;
decode
T autf8
aValidationError
T uString value expected
unicodedata
normalize
aNFKD
hashlib
sha256
digest
hmac
new
sha512

As specified by RFC4231 - https://tools.ietf.org/html/rfc4231 .
pbkdf2_hmac
encode
T uutf-8
aPBKDF2_ROUNDS
keys
aPrivateKey
aHexBytes
public_key
to_compressed_bytes

Compute `point(p)`, where `point` is ecdsa point multiplication.
Note: Result is ecdsa public key serialized to compressed form
a__doc__
a__file__
origin
has_location
a__cached__
aUnion
eth_keys
T akeys
eth_utils
T aValidationError
hexbytes
T aHexBytes
l  g	                                          aSECP256K1_N
txt
T Ostr
Obytes
return
normalize_string
D adata
return
Obytes
pD achain_code
data
return
Obytes
ppahmac_sha512
D apasscode
salt
return
Ostr
pObytes
pbkdf2_hmac_sha512
D apkey
return
Obytes
paec_point
ueth_account\hdaccount\_utils.py
u<module eth_account.hdaccount._utils>
T apkey
T achain_code
data
T atxt
utxt
T apasscode
salt
T adata

a__spec__
.eth_account.hdaccount
6
aMnemonic
generate
detect_language
expand
is_mnemonic_valid
aValidationError
uProvided words: '

u', are not a valid BIP39 mnemonic phrase!
to_seed
aHDPath
derive
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_eth_account
u\not_existing
hdaccount
T aNUITKA_PACKAGE_eth_account_hdaccount
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
aUnion
warnings
eth_utils
T aValidationError
ueth_account.types
T aLanguage
aLanguage
deterministic
T aHDPath
mnemonic
T aMnemonic
um/44'/60'/0'/0/0
aETHEREUM_DEFAULT_PATH
num_words
lang
return
generate_mnemonic
D awords
passphrase
return
Ostr
pObytes
seed_from_mnemonic
D aseed
account_path
return
Obytes
Ostr
Obytes
key_from_seed
ueth_account\hdaccount\__init__.py
u<module eth_account.hdaccount>
T anum_words
lang
T aseed
account_path
T awords
passphrase
lang
expanded_words
a__spec__
.eth_account.hdaccount.deterministic
g
aValidationError

u cannot be initialized with value
a__new__
aOFFSET
index
a__name__
w(w)ato_bytes
T l abig
T abyteorder
aTAG
T uCannot use empty string
aHARD_NODE_SUFFIXES
aHardNode
:nq naSoftNode
w'u' is not a valid node index.
hmac_sha512
d
serialize
ec_point
uCannot process:
to_int
:nl naSECP256K1_N
derive_child_key
parent_key
node
T l abig
:l nnu
Compute a derivative key from the parent key.
From BIP32:
The function CKDpriv((k_par, c_par), i)     (k_i, c_i) computes a child extended
private key from the parent extended private key:
1. Check whether the child is a hardened key (i     2**31).
If the child is a hardened key,
let I = HMAC-SHA512(Key = c_par, Data = 0x00 || ser_256(k_par) || ser_32(i)).
(Note: The 0x00 pads the private key to make it 33 bytes long.)
If it is not a hardened key, then
let I = HMAC-SHA512(Key = c_par, Data = ser_P(point(k_par)) || ser_32(i)).
2. Split I into two 32-byte sequences, I_L and I_R.
3. The returned child key k_i is parse_256(I_L) + k_par (mod n).
4. The returned chain code c_i is I_R.
5. In case parse_256(I_L)     n or k_i = 0, the resulting key is invalid,
nd one should proceed with the next value for i.
(Note: this has probability lower than 1 in 2**127.)
T uCannot parse path from empty string.
split
T w/aBASE_NODE_IDENTIFIERS
uPath is not valid: "
u". Must start with "m"
:l nnadecoded_path
aNode
decode
uPath "
u" is not valid. Issue with node "
u":
a_path

Create a new Hierarchical Deterministic path by decoding the given path.
Initializes an hd account generator using the
given path string (from BIP-0032). The path is decoded into nodes of the
derivation key tree, which define a pathway from a given main seed to
the child key that is used for a given purpose. Please also reference BIP-
0043 (which definites the first level as the "purpose" field of an HD path)
nd BIP-0044 (which defines a commonly-used, 5-level scheme for BIP32 paths)
for examples of how this object may be used. Please note however that this
object makes no such assumptions of the use of BIP43 or BIP44, or later BIPs.
:param path             : BIP32-compatible derivation path
:type path              : str as "m/idx_0/.../idx_n" or "m/idx_0/.../idx_n"
where idx_* is either an integer value (soft node)
or an integer value followed by either the "'" char
or the "H" char (hardened node)
u(path="
encode
u")
T wmw/u
Encodes this class to a string (reversing the decoding in the constructor).
u<genexpr>
uHDPath.encode.<locals>.<genexpr>
cBitcoin seed
key
chain_code

Perform the BIP32 Hierarchical Derivation recursive loop with the given Path.
Note that the key and chain_code are initialized with the main seed, and that
the key that is returned is the child key at the end of derivation process (and
the chain code is discarded)

Generate Heirarchical Deterministic Wallets (HDWallet).
Partially implements the BIP-0032, BIP-0043, and BIP-0044 specifications:
* BIP-0032: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
* BIP-0043: https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki
* BIP-0044: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
Skips serialization and public key derivation as unnecssary for this library's purposes.
Notes
-----
* Integers are modulo the order of the curve (referred to as n).
* Addition (+) of two coordinate pair is defined as application of
the EC group operation.
* Concatenation (||) is the operation of appending one byte sequence onto another.
Definitions
-----------
* point(p): returns the coordinate pair resulting from EC point multiplication
(repeated application of the EC group operation) of the secp256k1 base point
with the integer p.
* ser_32(i): serialize a 32-bit unsigned integer i as a 4-byte sequence,
most significant byte first.
* ser_256(p): serializes the integer p as a 32-byte sequence, most significant
byte first.
* ser_P(P): serializes the coordinate pair P = (x,y) as a byte sequence using SEC1's
compressed form: (0x02 or 0x03) || ser_256(x), where the header byte depends on the
parity of the omitted y coordinate.
* parse_256(p): interprets a 32-byte sequence as a 256-bit number, most significant
byte first.
a__doc__
a__file__
origin
has_location
a__cached__
aTuple
aType
aUnion
eth_utils
T aValidationError
to_int
a_utils
T aSECP256K1_N
ec_point
hmac_sha512
S wmwMS wHw'T Oint
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
