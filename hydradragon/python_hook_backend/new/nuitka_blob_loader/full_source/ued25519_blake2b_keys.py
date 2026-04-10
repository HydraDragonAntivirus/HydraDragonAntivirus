# Reconstructed from integrated Nuitka blob
# Module: ued25519_blake2b.keys

a__qualname__
a__orig_bases__
T u
base64
T Oobject
T u
na__init__
uSigningKey.__init__
T u
to_bytes
uSigningKey.to_bytes
uSigningKey.to_ascii
uSigningKey.to_seed
a__eq__
uSigningKey.__eq__
uSigningKey.get_verifying_key
uSigningKey.sign
uVerifyingKey.__init__
uVerifyingKey.to_bytes
uVerifyingKey.to_ascii
uVerifyingKey.__eq__
uVerifyingKey.verify
selftest
ued25519_blake2b\keys.py
u<module ed25519_blake2b.keys>
T a__class__
T aself
them
T aself
sk_s
prefix
encoding
vk_s
T aself
vk_s
prefix
encoding
T aentropy
aSEEDLEN
seed
sk
vk
T as_ascii
prefix
encoding
s_bytes
T aself
T as_bytes
prefix
T amessage
sk
vk
sig
T	aself
msg
prefix
encoding
sig_and_msg
sig_R
sig_S
msg_out
sig_out
T aself
prefix
encoding
T as_bytes
prefix
encoding
s_ascii
T aself
prefix
T	aself
sig
msg
prefix
encoding
sig_R
sig_S
sig_and_msg
msg2
a__spec__
.ens._normalization

Takes a `[key, [value]]` mapping from the original ENS spec json files and turns it
into a `{key: value}` mapping.
a_original_codepoints

a_original_text
u<genexpr>
uToken.__init__.<locals>.<genexpr>
a_normalized_codepoints
a_codepoints_to_text
codepoints
type
tokens
text
uLabel.text.<locals>.<genexpr>
labels
w.uENSNormalizedName.as_text.<locals>.<genexpr>
aVALID_BY_GROUPS
items
all_valid
update
ord
aNFD
chr
aNORMALIZATION_SPEC
wholes
valid
confused
groups
add
confusable_extents
append
whole_map
confusable_cp_extent_groups
difference

Create a mapping, per confusable, that contains all the groups in the cp's whole
confusable excluding the confusable extent of the cp itself - as per the spec at
https://docs.ens.domains/ens-improvement-proposals/ensip-15-normalization-standard
entry
u_construct_whole_confusable_map.<locals>.<genexpr>
fenced
u_codepoints_to_text.<locals>.<genexpr>
emoji
aTokenType
aTEXT
ascii
w_aInvalidName
uUnderscores '_' may only occur at the start of a label: '
w':l l nu--
uA label's third and fourth characters cannot be hyphens '-': '
l_acount
T l_a_is_fenced
uLabel cannot start or end with a fenced codepoint: '
uLabel cannot contain two fenced codepoints in a row: '
uAt least one text token in label starts with a combining mark: '
text_token_cps_set
issubset
uLabel contains codepoints from multiple groups: '
name
cm
next_index
nsm
nfd_cps
next_cp
contiguous_nsm_cps
aNSM_MAX
uContiguous NSM sequence for label greater than NSM max of
u: '
uContiguous NSM sequence for label contains duplicate codepoints: '
keys
aWHOLE_CONFUSABLE_MAP
get
retained_groups
intersection
confused_chars
aGROUP_COMBINED_VALID_CPS
buffer
uAll characters in label are confusable: '
u' (
u /
w)uLabel is confusable: '

Validate tokens and return the label type.
:param List[Token] tokens: the tokens to validate
:raises InvalidName: if any of the tokens are invalid
aEMOJI
u_validate_tokens_and_get_label_type.<locals>.<genexpr>
retained_group_name
aNFC
a_validate_tokens_and_get_label_type
aLabel
u_buffer_codepoints_to_chars.<locals>.<genexpr>
u_buffer_codepoints_to_chars.<locals>.<genexpr>.<locals>.<genexpr>
aENSNormalizedName
T Obytes
Obytearray
decode
T uutf-8
split
T w.T uLabels cannot be empty
a_input
end_index
aMAX_LEN_EMOJI_PATTERN
l   aremove
T l   T uEmpty name after removing 65039 (0xFE0F)
emoji_codepoint
aTextToken
aEmojiToken
pop
T l
ignored
mapped
aVALID_CODEPOINTS
uInvalid character: '
u' | codepoint
u (
a_build_and_validate_label_from_tokens
normalized_labels

Normalize an ENS name according to ENSIP-15
https://docs.ens.domains/ens-improvement-proposals/ensip-15-normalization-standard
:param str name: the dot-separated ENS name
:raises InvalidName: if ``name`` has invalid syntax
unormalize_name_ensip15.<locals>.<genexpr>
a__doc__
a__file__
origin
has_location
a__cached__
enum
T aEnum
aEnum
json
os
aAny
aDict
aList
aLiteral
aOptional
aSet
aTuple
aUnion
pyunormalize
T aNFC
aNFD
exceptions
T aInvalidName
wfalist_mapped_key
return
a_json_list_mapping_to_dict
join
specs
specs_dir_path
unormalization_spec.json
a__enter__
a__exit__
spec
load
weT nnnunf.json
nf
decomp
aNF
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
