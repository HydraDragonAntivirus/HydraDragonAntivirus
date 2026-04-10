# Reconstructed from integrated Nuitka blob
# Module: ubip_utils.base58.base58_ex

uException in case of checksum error.
a__qualname__
a__orig_bases__
ubip_utils\base58\base58_ex.py
u<module bip_utils.base58.base58_ex>

a__spec__
.bip_utils.base58.base58_xmr
[
B

aBase58XmrConst
aBLOCK_DEC_MAX_BYTE_LEN
aBase58Encoder
aEncode
block_dec_len
enc
aBase58XmrEncoder
a_Base58XmrEncoder__Pad
aBLOCK_ENC_MAX_BYTE_LEN
aBLOCK_ENC_BYTE_LENS

Encode bytes into a Base58 string with Monero variation.
Args:
data_bytes (bytes): Data bytes
Returns:
str: Encoded string
rjust
aALPHABET

Pad the encoded string to the specified length.
Args:
enc_str (str): Encoded string
pad_len (int): Pad length
Returns:
str: Padded string
c
index
aBase58Decoder
aDecode
block_enc_len
dec
aBase58XmrDecoder
a_Base58XmrDecoder__UnPad

Decode bytes from a Base58 string with Monero variation.
Args:
data_str (str): Data string
Returns:
bytes: Decoded bytes

Unpad the decoded string to the specified length.
Args:
dec_bytes (bytes): Decoded bytes
unpad_len (int): Unpad length
Returns:
bytes: Unpadded string
uModule for base58-monero decoding/encoding.
a__doc__
a__file__
origin
has_location
a__cached__
aList
ubip_utils.base58.base58
T aBase58Alphabets
aBase58Const
aBase58Decoder
aBase58Encoder
aBase58Alphabets
aBase58Const
