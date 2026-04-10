# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.monero.monero_keys

uMonero public key class.
a__qualname__
a__annotations__
D apub_key
return
uUnion[bytes, IPublicKey]
aMoneroPublicKey
aFromBytesOrKeyObject
uMoneroPublicKey.FromBytesOrKeyObject
D akey_bytes
return
bytes
aMoneroPublicKey
uMoneroPublicKey.FromBytes
D akey_point
return
aIPoint
aMoneroPublicKey
uMoneroPublicKey.FromPoint
D apub_key
return
aIPublicKey
aNone
a__init__
uMoneroPublicKey.__init__
D areturn
aIPublicKey
aKeyObject
uMoneroPublicKey.KeyObject
D areturn
aDataBytes
uMoneroPublicKey.RawCompressed
uMoneroPublicKey.RawUncompressed
D akey_bytes
return
bytes
aIPublicKey
a__KeyFromBytes
uMoneroPublicKey.__KeyFromBytes
D akey_point
return
aIPoint
aIPublicKey
a__KeyFromPoint
uMoneroPublicKey.__KeyFromPoint
uMonero private key class.
aMoneroPrivateKey
D apriv_key
return
uUnion[bytes, IPrivateKey]
aMoneroPrivateKey
uMoneroPrivateKey.FromBytesOrKeyObject
D akey_bytes
return
bytes
aMoneroPrivateKey
uMoneroPrivateKey.FromBytes
D apriv_key
return
aIPrivateKey
aNone
uMoneroPrivateKey.__init__
D areturn
aIPrivateKey
uMoneroPrivateKey.KeyObject
uMoneroPrivateKey.Raw
D areturn
aMoneroPublicKey
uMoneroPrivateKey.PublicKey
D akey_bytes
return
bytes
aIPrivateKey
uMoneroPrivateKey.__KeyFromBytes
ubip_utils\monero\monero_keys.py
u<module bip_utils.monero.monero_keys>
T acls
key_bytes
T acls
priv_key
T acls
pub_key
T acls
key_point
T aself
T a__class__
T akey_bytes
ex
T akey_point
ex
T aself
priv_key
T aself
pub_key

a__spec__
.bip_utils.monero.monero_subaddr
V
m_priv_vkey
m_pub_skey
aPublicKey
m_pub_vkey

Construct class.
Args:
priv_vkey (MoneroPrivateKey)        : Private view key
pub_skey (MoneroPublicKey)          : Public spend key
pub_vkey (MoneroPublicKey, optional): Public view key (if None, it'll be computed from the private one)
aMoneroSubaddressConst
aSUBADDR_MAX_IDX
uInvalid minor index (

w)uInvalid major index (
aIntegerUtils
aToBytes
aSUBADDR_IDX_BYTE_LEN
little
T abytes_num
endianness
aKekkak256
aQuickDigest
aSUBADDR_PREFIX
aRaw
aEd25519Utils
aIntDecode
aScalarReduce
aKeyObject
aPoint
aEd25519Monero
aGenerator
aToInt
T alittle
aMoneroPublicKey
aFromPoint

Compute the public keys of the specified subaddress.
Args:
minor_idx (int): Minor index (i.e. subaddress index)
major_idx (int): Major index (i.e. account index)
Returns:
tuple[MoneroPublicKey, MoneroPublicKey]: Computed public spend key (index 0) and public view key (index 1)
Raises:
ValueError: If one of the indexes is not valid
aComputeKeys
aXmrAddrEncoder
aEncodeKey
T apub_vkey
net_ver

Compute the public keys of the specified subaddress and encode them.
Args:
minor_idx (int): Minor index (i.e. subaddress index)
major_idx (int): Major index (i.e. account index)
net_ver (bytes): Net version
Returns:
str: Encoded subaddress string
Raises:
ValueError: If one of the indexes is not valid
uModule for Monero subaddress computation.
a__doc__
a__file__
origin
has_location
a__cached__
aOptional
aTuple
ubip_utils.addr
T aXmrAddrEncoder
ubip_utils.ecc
T aEd25519Monero
aEd25519Utils
ubip_utils.monero.monero_keys
T aMoneroPrivateKey
aMoneroPublicKey
aMoneroPrivateKey
ubip_utils.utils.crypto
T aKekkak256
ubip_utils.utils.misc
T aIntegerUtils
