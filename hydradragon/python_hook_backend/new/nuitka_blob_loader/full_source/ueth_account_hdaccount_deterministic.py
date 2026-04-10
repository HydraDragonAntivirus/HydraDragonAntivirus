# Reconstructed from integrated Nuitka blob
# Module: ueth_account.hdaccount.deterministic


A base node class.
a__qualname__
a__annotations__
int
return
uNode.__new__
str
a__repr__
uNode.__repr__
other
a__add__
uNode.__add__
bytes
uNode.serialize
uNode.encode
staticmethod
T aSoftNode
aHardNode
uNode.decode
a__orig_bases__

Soft node (unhardened), where value = index .

Hard node, where value = index + BIP32_HARDENED_CONSTANT .
wHaparent_chain_code
T Obytes
paHDPath
D apath
Ostr
a__init__
uHDPath.__init__
D areturn
Ostr
uHDPath.__repr__
uHDPath.encode
D aseed
return
Obytes
paderive
uHDPath.derive
ueth_account\hdaccount\deterministic.py
T a.0
node
u<module eth_account.hdaccount.deterministic>
T a__class__
T aself
other
T aself
path
nodes
decoded_path
a_idx
node
err
T acls
index
obj
T aself
T anode
node_class
node_index
node_value
err
T aself
seed
main_node
key
chain_code
node
T aparent_key
parent_chain_code
node
child
child_key
child_key_bytes
child_chain_code
T aself
encoded_path
a__spec__
.eth_account.hdaccount.mnemonic
a_cached_wordlists
keys
aWORDLIST_DIR

u.txt
uutf-8
a__enter__
a__exit__
readlines
strip
T nnnawordlist
aWORDLIST_LEN
aValidationError
uWordlist should contain
u words, but it contains
u words.
warnings
warn
uThe language parameter should be a Language enum, not a string. This will be enforced in a future version.
aDeprecationWarning
D astacklevel
l alower
replace
T w w_aMnemonic
list_languages
uInvalid language choice '
u', must be one of
value
language
get_wordlist
sorted
rglob
T u*.txt

Returns a list of languages available for the seed phrase
aPath
stem
u<genexpr>
uMnemonic.list_languages.<locals>.<genexpr>

Returns a list of Language objects available for the seed phrase
aLanguage
uMnemonic.list_languages_enum.<locals>.<genexpr>
normalize_string
split
T w awords
intersection
cls
uLanguage not detected for word(s):
aCHINESE_SIMPLIFIED
uWord(s) are valid in multiple languages:
chinese
uMnemonic.detect_language.<locals>.<genexpr>
aVALID_WORD_COUNTS
uInvalid choice for number of words:
u, should be one of
to_mnemonic
urandom
l l u
Generate a new mnemonic with the specified number of words.
aVALID_ENTROPY_SIZES
uInvalid data length
bitarray
frombytes
sha256
extend
l ajapanese

w aba2int
bits
uMnemonic.to_mnemonic.<locals>.<genexpr>
self
encoded_seed
int2ba
D alength
l l atobytes
secrets
compare_digest

Checks if mnemonic is valid
:param str mnemonic: Mnemonic string
index
uMnemonic.is_mnemonic_valid.<locals>.<genexpr>
startswith
prefix
expand_word
mnemonic
pbkdf2_hmac_sha512
:nl@nu
:param str checked_mnemonic: Must be a correct, fully-expanded BIP39 seed phrase
:param str passphrase: Encryption passphrase used to secure the mnemonic
:returns bytes: 64 bytes of raw seed material from PRNG
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
os
pathlib
T aPath
aDict
aList
aUnion
T abitarray
ubitarray.util
T aba2int
int2ba
eth_utils
T aValidationError
ueth_account.types
T aLanguage
a_utils
T anormalize_string
pbkdf2_hmac_sha512
sha256
L l l l l l L l l l l l aparent
l  areturn
