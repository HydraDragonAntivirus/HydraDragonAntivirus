# Reconstructed from integrated Nuitka blob
# Module: uCrypto.Hash.SHA384

uA SHA-384 hash object.
Do not instantiate directly. Use the :func:`new` function.
:ivar oid: ASN.1 Object ID
:vartype oid: string
:ivar block_size: the size in bytes of the internal message block,
input to the compression function
:vartype block_size: integer
:ivar digest_size: the size in bytes of the resulting hash
:vartype digest_size: integer
a__qualname__
l0l  ablock_size
u2.16.840.1.101.3.4.2.2
oid
T na__init__
uSHA384Hash.__init__
uSHA384Hash.update
uSHA384Hash.digest
hexdigest
uSHA384Hash.hexdigest
copy
uSHA384Hash.copy
uSHA384Hash.new
a__orig_bases__
a_pbkdf2_hmac_assist
uCrypto\Hash\SHA384.py
u<module Crypto.Hash.SHA384>
T a__class__
T aself
data
state
result
T ainner
outer
first_digest
iterations
bfr
result
T aself
clone
result
T aself
bfr
result
T aself
T aself
data
T adata
T aself
data
result
a__spec__
.Crypto.Hash.SHA3_224
_
a_update_after_digest
a_digest_done
l a_padding
aVoidPointer
a_raw_keccak_lib
keccak_init
address_of
c_size_t
digest_size
l ac_ubyte
T l uError %d while instantiating SHA-3/224
aSmartPointer
get
keccak_destroy
a_state
update
uYou can only call 'digest' or 'hexdigest' on this object
keccak_absorb
c_uint8_ptr
uError %d while updating SHA-3/224
uContinue hashing of a message by consuming the next chunk of data.
Args:
data (byte string/byte array/memoryview): The next chunk of the message being hashed.
create_string_buffer
keccak_digest
get_raw_buffer
a_digest_value
uReturn the **binary** (non-printable) digest of the message that has been hashed so far.
:return: The hash digest, computed over the data processed so far.
Binary form.
:rtype: byte string

digest
u%02x
bord
uReturn the **printable** digest of the message that has been hashed so far.
:return: The hash digest, computed over the data processed so far.
Hexadecimal encoded.
:rtype: string
new
keccak_copy
uError %d while copying SHA3-224
uReturn a copy ("clone") of the hash object.
The copy will have the same internal state as the original hash
object.
This can be used to efficiently compute the digests of strings that
share a common initial substring.
:return: A hash object of the same type
uCreate a fresh SHA3-224 hash object.
data
pop
T aupdate_after_digest
FuInitial data for hash specified twice
uUnknown parameters:
aSHA3_224_Hash
uCreate a new hash object.
Args:
data (byte string/byte array/memoryview):
The very first chunk of the message to hash.
It is equivalent to an early call to :meth:`update`.
update_after_digest (boolean):
Whether :meth:`digest` can be followed by another :meth:`update`
(default: ``False``).
:Return: A :class:`SHA3_224_Hash` hash object
a__doc__
a__file__
origin
has_location
a__cached__
uCrypto.Util.py3compat
T abord
uCrypto.Util._raw_api
T aload_pycryptodome_raw_lib
aVoidPointer
aSmartPointer
create_string_buffer
get_raw_buffer
c_size_t
c_uint8_ptr
c_ubyte
load_pycryptodome_raw_lib
uCrypto.Hash.keccak
T a_raw_keccak_lib
T Oobject
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
