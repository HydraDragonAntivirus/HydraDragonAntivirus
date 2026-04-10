# Reconstructed from integrated Nuitka blob
# Module: ucharset_normalizer.models

a__qualname__
T nnD apayload
guessed_encoding
mean_mess_ratio
has_sig_or_bom
languages
decoded_payload
preemptive_declaration
bytes
str
float
bool
aCoherenceMatches
ustr | None
ustr | None
a__init__
uCharsetMatch.__init__
D aother
return
object
bool
a__eq__
uCharsetMatch.__eq__
a__lt__
uCharsetMatch.__lt__
D areturn
float
uCharsetMatch.multi_byte_usage
D areturn
str
a__str__
uCharsetMatch.__str__
a__repr__
uCharsetMatch.__repr__
D aother
return
aCharsetMatch
aNone
uCharsetMatch.add_submatch
uCharsetMatch.encoding
D areturn
ulist[str]
uCharsetMatch.encoding_aliases
D areturn
bool
bom
uCharsetMatch.bom
byte_order_mark
uCharsetMatch.byte_order_mark
languages
uCharsetMatch.languages
uCharsetMatch.language
uCharsetMatch.chaos
uCharsetMatch.coherence
percent_chaos
uCharsetMatch.percent_chaos
percent_coherence
uCharsetMatch.percent_coherence
D areturn
bytes
uCharsetMatch.raw
D areturn
ulist[CharsetMatch]
submatch
uCharsetMatch.submatch
has_submatch
uCharsetMatch.has_submatch
uCharsetMatch.alphabets
uCharsetMatch.could_be_from_charset
T autf_8
D aencoding
return
str
bytes
uCharsetMatch.output
uCharsetMatch.fingerprint

Container with every CharsetMatch items ordered by default from most probable to the less one.
Act like a list(iterable) but does not implements all related methods.
aCharsetMatches
T nD aresults
ulist[CharsetMatch] | None
uCharsetMatches.__init__
D areturn
uIterator[CharsetMatch]
D aitem
return
uint | str
aCharsetMatch
a__getitem__
uCharsetMatches.__getitem__
D areturn
int
a__len__
uCharsetMatches.__len__
a__bool__
uCharsetMatches.__bool__
D aitem
return
aCharsetMatch
aNone
uCharsetMatches.append
D areturn
uCharsetMatch | None
uCharsetMatches.best
first
uCharsetMatches.first
T Ostr
Ofloat
aCoherenceMatch
aCoherenceMatches
aCliDetectionResult
D apath
encoding
encoding_aliases
alternative_encodings
language
alphabets
has_sig_or_bom
chaos
coherence
unicode_path
is_preferred
str
ustr | None
ulist[str]
ulist[str]
str
ulist[str]
bool
float
pustr | None
bool
uCliDetectionResult.__init__
D areturn
udict[str, Any]
a__dict__
uCliDetectionResult.__dict__
to_json
uCliDetectionResult.to_json
ucharset_normalizer\models.py
T wmaself
T aself
u<module charset_normalizer.models>
T a__class__
T aself
other
T aself
item
result
T aself
payload
guessed_encoding
mean_mess_ratio
has_sig_or_bom
languages
decoded_payload
preemptive_declaration
T aself
results
T aself
path
encoding
encoding_aliases
alternative_encodings
language
alphabets
has_sig_or_bom
chaos
coherence
unicode_path
is_preferred
T aself
other
chaos_difference
coherence_difference
T aself
detected_ranges
T aself
item
match
T aself
also_known_as
wuwpT aself
encoding_languages
mb_encoding_languages
languages
T aself
encoding
decoded_string
patched_header
a__spec__
.charset_normalizer.utils
6
unicodedata
name
uWITH GRAVE
uWITH ACUTE
uWITH CEDILLA
uWITH DIAERESIS
uWITH CIRCUMFLEX
uWITH TILDE
uWITH MACRON
uWITH RING ABOVE
decomposition
split
T w l aUNICODE_RANGES_COMBINED
items

Retrieve the Unicode range official name from a single character.
aLATIN
category
wPaunicode_range
aPunctuation
wSwNaForms
aLo
aEmoticons
aPictographs
isspace
P u
w+w>w<wZP aPd
aPo
aPc
islower
isupper
aCJK
aHIRAGANA
aKATAKANA
aHANGUL
aTHAI
aARABIC
uISOLATED FORM
aUNICODE_SECONDARY_RANGE_KEYWORD
range_name
u<genexpr>
uis_unicode_range_secondary.<locals>.<genexpr>
isprintable
w u
findall
aRE_POSSIBLE_ENCODING_INDICATION
min
decode
T aascii
ignore
T aerrors
lower
replace
T w-w_aaliases

Extract using ASCII-only decoder any specified encoding in the first n-bytes.
P	autf_16_le
utf_8_sig
utf_8
utf_7
utf_16
utf_16_be
utf_32_be
utf_32_le
utf_32
uencodings.

import_module
aIncrementalDecoder
aMultibyteIncrementalDecoder

Verify is a specific encoding is a multi byte one based on it IANA name
aENCODING_MARKS
sequence
startswith
T nc

Identify and extract SIG/BOM in given sequence.
P autf_16
utf_32
uUnable to retrieve IANA for '
w'uReturns the Python normalized encoding name (Not the IANA official name).
is_multi_byte_encoding
Z
T aignore
;l
l  l aid_a
id_b
character_match_count
l  aIANA_SUPPORTED_SIMILAR

Determine if two code page are at least 80% similar. IANA_SUPPORTED_SIMILAR dict was generated using
the function cp_similarity.
logging
getLogger
setLevel
aStreamHandler
setFormatter
aFormatter
addHandler
decoded_payload
is_multi_byte_decoder
offsets
chunk_size
sequences
bom_or_sig_available
strip_sig_or_bom
sig_payload
encoding_iana
ignore
strict
l D aerrors
ignore
chunk
cut_sequence_chunks
a__doc__
a__file__
origin
has_location
a__cached__
annotations
importlib
codecs
T aIncrementalDecoder
uencodings.aliases
T aaliases
lru_cache
re
T afindall
aGenerator
a_multibytecodec
T aMultibyteIncrementalDecoder
constant
T aENCODING_MARKS
aIANA_SUPPORTED_SIMILAR
aRE_POSSIBLE_ENCODING_INDICATION
aUNICODE_RANGES_COMBINED
aUNICODE_SECONDARY_RANGE_KEYWORD
aUTF8_MAXIMAL_ALLOCATION
aUTF8_MAXIMAL_ALLOCATION
T amaxsize
D acharacter
return
str
bool
is_accentuated
D acharacter
return
str
paremove_accent
D acharacter
return
str
ustr | None
is_latin
is_punctuation
is_symbol
is_emoticon
is_separator
is_case_variable
is_cjk
is_hiragana
is_katakana
is_hangul
is_thai
is_arabic
is_arabic_isolated_form
D arange_name
return
str
bool
is_unicode_range_secondary
is_unprintable
T l @D asequence
search_zone
return
bytes
int
ustr | None
any_specified_encoding
T l  D aname
return
str
bool
D asequence
return
bytes
utuple[str | None, bytes]
identify_sig_or_bom
D aiana_encoding
return
str
bool
should_strip_sig_or_bom
T tD acp_name
strict
return
str
bool
str
iana_name
D aiana_name_a
iana_name_b
return
str
pafloat
cp_similarity
D aiana_name_a
iana_name_b
return
str
pabool
is_cp_similar
charset_normalizer
aINFO
u%(asctime)s | %(levelname)s | %(message)s
D aname
level
format_string
return
str
int
str
aNone
set_logging_handler
T nD
sequences
encoding_iana
offsets
chunk_size
bom_or_sig_available
strip_sig_or_bom
sig_payload
is_multi_byte_decoder
decoded_payload
return
bytes
str
range
int
bool
pabytes
bool
ustr | None
uGenerator[str, None, None]
ucharset_normalizer\utils.py
T a.0
keyword
range_name
u<module charset_normalizer.utils>
T asequence
search_zone
seq_len
results
encoding_alias
encoding_iana
specified_encoding
T	aiana_name_a
iana_name_b
id_a
id_b
character_match_count
to_be_decoded
decoder_a
decoder_b
wiT asequences
encoding_iana
offsets
chunk_size
bom_or_sig_available
strip_sig_or_bom
sig_payload
is_multi_byte_decoder
decoded_payload
chunk_partial_size_chk
wiachunk
chunk_end
cut_sequence
wjT acp_name
strict
encoding_alias
encoding_iana
T asequence
marks
iana_encoding
mark
T acharacter
description
T acharacter
character_name
T acharacter
T aiana_name_a
iana_name_b
T acharacter
character_range
T aname
T acharacter
character_category
character_range
T acharacter
character_category
T arange_name
T acharacter
decomposed
codes
T aname
level
format_string
logger
handler
T aiana_encoding
T acharacter
character_ord
range_name
ord_range
a__spec__
.charset_normalizer.version

Expose version
a__doc__
a__file__
origin
has_location
a__cached__
annotations
u3.4.1
a__version__
w.aVERSION
ucharset_normalizer\version.py
u<module charset_normalizer.version>

a__spec__
.coincurve.__about__
a__doc__
a__file__
origin
has_location
a__cached__
u20.0.0
a__version__
ucoincurve\__about__.py
u<module coincurve.__about__>

a__spec__
.coincurve
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_coincurve
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
ucoincurve.context
T aGLOBAL_CONTEXT
aContext
aGLOBAL_CONTEXT
aContext
ucoincurve.keys
T aPrivateKey
aPublicKey
aPublicKeyXOnly
aPrivateKey
aPublicKey
aPublicKeyXOnly
ucoincurve.utils
T averify_signature
verify_signature
L aGLOBAL_CONTEXT
aContext
aPrivateKey
aPublicKey
aPublicKeyXOnly
verify_signature
a__all__
ucoincurve\__init__.py
u<module coincurve>

a__spec__
.coincurve.context
;
9
aCONTEXT_FLAGS

u is an invalid context flag.
aLock
a_lock
ffi
gc
lib
secp256k1_context_create
secp256k1_context_destroy
ctx
reseed
name
a__enter__
a__exit__
urandom
T l asecp256k1_context_randomize
new
uunsigned char [32]
T nnnu
Protects against certain possible future side-channel timing attacks.
a__class__
a__repr__
a__doc__
a__file__
origin
has_location
a__cached__
threading
T aLock
aOptional
ucoincurve.flags
T aCONTEXT_FLAGS
aCONTEXT_NONE
aCONTEXT_NONE
a_libsecp256k1
T affi
lib
