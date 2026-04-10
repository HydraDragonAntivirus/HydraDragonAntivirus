# Reconstructed from integrated Nuitka blob
# Module: ucffi.verifier

a__qualname__
T nnnu
Fu.c
nna__init__
uVerifier.__init__
T nawrite_source
uVerifier.write_source
compile_module
uVerifier.compile_module
uVerifier.load_library
uVerifier.get_module_name
uVerifier.get_extension
generates_python_module
uVerifier.generates_python_module
uVerifier.make_relative_to
uVerifier._locate_module
uVerifier._write_source_to
uVerifier._write_source
uVerifier._compile_module
uVerifier._load_library
a__orig_bases__
set_tmpdir
T nFacleanup_tmpdir
ucffi\verifier.py
u<module cffi.verifier>
T a__class__
T aself
ffi
preamble
tmpdir
modulename
ext_package
tag
force_generic_engine
source_extension
flags
relative_to
kwds
flattened_kwds
vengine_class
key
k1
k2
suffix
T aresult
filename
T aself
tmpdir
outputfilename
same
T afilename
dirname
T asuffixes
T aself
T affi
force_generic_engine
a_cffi_backend
vengine_gen
vengine_cpy
T aself
pkg
path
filename
T aself
file
wfasource_data
fp
needs_written
T aself
file
T atmpdir
keep_so
filelist
suffix
fn
clean_dir
dir
T aself
sourcename
modname
T aself
basename
T aself
kwds
relative_to
dirname
key
lst
T adirname
a__spec__
.charset_normalizer.api
T Obytearray
Obytes
uExpected object of type bytes or bytearray, got: {}
logger
level
addHandler
explain_handler
setLevel
aTRACE
debug
T uEncoding detection on empty bytes, assuming utf_8 intention.
removeHandler
previous_logger_level
logging
aWARNING
aCharsetMatches
aCharsetMatch
utf_8
Z

log
ucp_isolation is set. use this flag for debugging purpose. limited list of encoding allowed : %s.
u,
iana_name
ucp_exclusion is set. use this flag for debugging purpose. limited list of encoding excluded : %s.
uoverride steps (%i) and chunk_size (%i) as content does not fit (%i byte(s) given) parameters.
steps
chunk_size
aTOO_SMALL_SEQUENCE
aTOO_BIG_SEQUENCE
uTrying to detect encoding from a tiny portion of ({}) byte(s).
uUsing lazy str decoding because the payload is quite large, ({}) byte(s).
any_specified_encoding
uDetected declarative mark in sequence. Priority +1 given for %s.
identify_sig_or_bom
uDetected a SIG or BOM mark on first %i byte(s). Priority +1 given for %s.
ascii
aIANA_SUPPORTED
cp_isolation
tested
add
should_strip_sig_or_bom
P autf_16
utf_32
uEncoding %s won't be tested as-is because it require a BOM. Will try some sub-encoder LE/BE.
P autf_7
uEncoding %s won't be tested as-is because detection is unreliable without BOM/SIG.
is_multi_byte_encoding
T EModuleNotFoundError
EImportError
uEncoding %s does not provide an IncrementalDecoder
sequences
:nl   nasig_payload
l   T EUnicodeDecodeError
ELookupError
uCode page %s does not fit given bytes sequence at ALL. %s
tested_but_hard_failure
tested_but_soft_failure
is_cp_similar
encoding_iana
u%s is deemed too similar to code page %s and was consider unsuited already. Continuing!
encoding_soft_failed
length
uCode page %s is a multi byte encoding table and it appear that at least one character was encoded using n-bytes.
l amax
l acut_sequence_chunks
md_chunks
md_ratios
mess_ratio
threshold
early_stop_count
uLazyStr Loading: After MD chunk decode, code page %s does not fit given bytes sequence at ALL. %s
:l   nnadecode
D aerrors
strict
uLazyStr Loading: After final lookup, code page %s does not fit given bytes sequence at ALL. %s
append
u%s was excluded because of initial chaos probing. Gave up %i time(s). Computed mean chaos is %f %%.
round
ldD andigits
l aspecified_encoding
T apreemptive_declaration
u%s passed initial chaos probing. Mean measured chaos is %f %%
encoding_languages
mb_encoding_languages
u{} should target any language(s) of {}
coherence_ratio
language_threshold
w,acd_ratios
merge_coherence_ratios
uWe detected language {} using {}
results
f       ?uEncoding detection: %s is most likely the one.
encoding
early_stop_results
best
uEncoding detection: %s is most likely the one as we detected a BOM or SIG within the beginning of the sequence.
fallback_u8
fallback_ascii
fallback_specified
uNothing got out of the detection process. Using ASCII/UTF-8/Specified fallback.
uEncoding detection: %s will be used as a fallback match
fingerprint
T uEncoding detection: utf_8 will be used as a fallback match
T uEncoding detection: ascii will be used as a fallback match
uEncoding detection: Found %s as plausible (best-candidate) for content. With %i alternatives.
T uEncoding detection: Unable to determine any suitable charset.

Given a raw bytes sequence, return the best possibles charset usable to render str objects.
If there is no results, it is a strong indicator that the source is binary/not text.
By default, the process will extract 5 blocks of 512o each to assess the mess and coherence of a given sequence.
And will give up a particular code page after 20% of measured mess. Those criteria are customizable at will.
The preemptive behavior DOES NOT replace the traditional detection workflow, it prioritize a particular code page
but never take it for granted. Can improve the performance.
You may want to focus your attention to some code page or/and not others, use cp_isolation and cp_exclusion for that
purpose.
This function will strip the SIG in the payload/sequence every time except on UTF-16, UTF-32.
By default the library does not setup any handler other than the NullHandler, if you choose to set the 'explain'
toggle to True it will alter the logger configuration to add a StreamHandler that is suitable for debugging.
Custom logging format and handler can be set manually.
from_bytes
read

Same thing than the function from_bytes but using a file pointer that is already ready.
Will not close the file pointer.
rb
a__enter__
a__exit__
from_fp
T nnnu
Same thing than the function from_bytes but with one extra step. Opening and reading given file path in binary mode.
Can raise IOError.
aPathLike
from_path
T	asteps
chunk_size
threshold
cp_isolation
cp_exclusion
preemptive_behaviour
explain
language_threshold
enable_fallback
T Obytes
Obytearray

Detect if the given input (file, bytes, or path) points to a binary file. aka. not a string.
Based on the same main heuristic algorithms and default kwargs at the sole exception that fallbacks match
re disabled to be stricter around ASCII-compatible but unlikely to be a string.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aBinaryIO
cd
T acoherence_ratio
encoding_languages
mb_encoding_languages
merge_coherence_ratios
constant
T aIANA_SUPPORTED
aTOO_BIG_SEQUENCE
aTOO_SMALL_SEQUENCE
aTRACE
md
T amess_ratio
models
T aCharsetMatch
aCharsetMatches
utils
T aany_specified_encoding
cut_sequence_chunks
iana_name
identify_sig_or_bom
is_cp_similar
is_multi_byte_encoding
should_strip_sig_or_bom
getLogger
T acharset_normalizer
aStreamHandler
setFormatter
aFormatter
T u%(asctime)s | %(levelname)s | %(message)s
T	l l  f       ?nntFf       ?tD asequences
steps
chunk_size
threshold
cp_isolation
cp_exclusion
preemptive_behaviour
explain
language_threshold
enable_fallback
return
ubytes | bytearray
int
pafloat
ulist[str] | None
ulist[str] | None
bool
pafloat
bool
aCharsetMatches
D afp
steps
chunk_size
threshold
cp_isolation
cp_exclusion
preemptive_behaviour
explain
language_threshold
enable_fallback
return
aBinaryIO
int
pafloat
ulist[str] | None
ulist[str] | None
bool
pafloat
bool
aCharsetMatches
D apath
steps
chunk_size
threshold
cp_isolation
cp_exclusion
preemptive_behaviour
explain
language_threshold
enable_fallback
return
ustr | bytes | PathLike
int
pafloat
ulist[str] | None
ulist[str] | None
bool
pafloat
bool
aCharsetMatches
T	l l  f       ?nntFf       ?FD afp_or_path_or_payload
steps
chunk_size
threshold
cp_isolation
cp_exclusion
preemptive_behaviour
explain
language_threshold
enable_fallback
return
uPathLike | str | BinaryIO | bytes
int
pafloat
ulist[str] | None
ulist[str] | None
bool
pafloat
bool
pais_binary
ucharset_normalizer\api.py
u<module charset_normalizer.api>
T2asequences
steps
chunk_size
threshold
cp_isolation
cp_exclusion
preemptive_behaviour
explain
language_threshold
enable_fallback
previous_logger_level
length
is_too_small_sequence
is_too_large_sequence
prioritized_encodings
specified_encoding
tested
tested_but_hard_failure
tested_but_soft_failure
fallback_ascii
fallback_u8
fallback_specified
results
early_stop_results
decoded_payload
bom_or_sig_available
strip_sig_or_bom
is_multi_byte_decoder
similar_soft_failure_test
multi_byte_bonus
max_chunk_gave_up
early_stop_count
md_chunks
mean_mess_ratio
target_languages
probable_result
sig_encoding
sig_payload
encoding_iana
weaencoding_soft_failed
r_
lazy_str_hard_failure
md_ratios
chunk
fallback_entry
cd_ratios
chunk_languages
cd_ratios_merged
current_match
T
fp
steps
chunk_size
threshold
cp_isolation
cp_exclusion
preemptive_behaviour
explain
language_threshold
enable_fallback
T apath
steps
chunk_size
threshold
cp_isolation
cp_exclusion
preemptive_behaviour
explain
language_threshold
enable_fallback
fp
T afp_or_path_or_payload
steps
chunk_size
threshold
cp_isolation
cp_exclusion
preemptive_behaviour
explain
language_threshold
enable_fallback
guesses
a__spec__
.charset_normalizer.cd
is_multi_byte_encoding
uFunction not supported on multi-byte code page
uencodings.

import_module
aIncrementalDecoder
T aignore
T aerrors
;l@l  l wpadecode
unicode_range
is_unicode_range_secondary
seen_ranges
character_count
sorted
f333333 ?u
Return associated unicode ranges in a single byte code page.
aFREQUENCIES
items
languages

Return inferred languages used with a unicode range.
encoding_unicode_range
aLatin
uLatin Based
unicode_range_languages

Single-byte encoding language association. Some code page are heavily linked to particular language(s).
This function does the correspondence.
startswith
T ashift_
T aiso2022_jp
T aeuc_j
cp932
aJapanese
T agb
aZH_NAMES
aChinese
T aiso2022_kr
aKO_NAMES
aKorean

Multi-byte encoding language association. Some code page are heavily linked to particular language(s).
This function does the correspondence.
target_have_accents
is_accentuated
target_pure_latin
is_latin

Determine main aspects from a supported language if it contains accents and if is pure Latin.
get_target_features
u<lambda>
ualphabet_languages.<locals>.<lambda>
T akey
reverse

Return associated languages associated to given characters.
u<genexpr>
ualphabet_languages.<locals>.<genexpr>
u not available
index
l l acharacter_approved_count

Determine if a ordered characters list (by occurrence from most appearance to rarest) match a particular language.
The result is a ratio between 0. (absolutely no correspondence) and 1. (near perfect fit).
Beware that is function is not strict on the match in order to ease the detection. (Meaning close match is 1.)
isalpha
layers
is_suspiciously_successive_range
character_range
lower

Given a decoded text sequence, return a list of str. Unicode range / alphabet separation.
Ex. a text containing English/Latin with a bit a Hebrew will return two items in the resulting list;
One containing the latin letters and the other hebrew.
per_language_ratios
append
round
umerge_coherence_ratios.<locals>.<lambda>

This function merge results previously given by the function coherence_ratio.
The return type is the same as coherence_ratio.
replace
T u

index_results
filtered_results
max

We shall NOT return "English   " in CoherenceMatches because it is an alternative
of "English". This function only keeps the best match and remove the em-dash in it.
ufilter_alt_coherence_matches.<locals>.<genexpr>
split
T w,aremove
T uLatin Based
alpha_unicode_split
aCounter
most_common
aTOO_SMALL_SEQUENCE
alphabet_languages
ignore_non_latin
characters_popularity_compare
popular_character_ordered
f       ?asufficient_match_count
results
filter_alt_coherence_matches
ucoherence_ratio.<locals>.<lambda>

Detect ANY language that can be identified in given sequence. The sequence will be analysed by layers.
A layer = Character extraction by alphabets/ranges.
ucoherence_ratio.<locals>.<genexpr>
a__doc__
a__file__
origin
has_location
a__cached__
annotations
importlib
codecs
T aIncrementalDecoder
collections
T aCounter
lru_cache
aTypeCounter
constant
T aFREQUENCIES
aKO_NAMES
aLANGUAGE_SUPPORTED_COUNT
aTOO_SMALL_SEQUENCE
aZH_NAMES
aLANGUAGE_SUPPORTED_COUNT
md
T ais_suspiciously_successive_range
models
T aCoherenceMatches
aCoherenceMatches
utils
T ais_accentuated
is_latin
is_multi_byte_encoding
is_unicode_range_secondary
unicode_range
D aiana_name
return
str
ulist[str]
D aprimary_range
return
str
ulist[str]
encoding_languages
mb_encoding_languages
T amaxsize
D alanguage
return
str
utuple[bool, bool]
T FD acharacters
ignore_non_latin
return
ulist[str]
bool
ulist[str]
D alanguage
ordered_characters
return
str
ulist[str]
float
D adecoded_sequence
return
str
ulist[str]
D aresults
return
ulist[CoherenceMatches]
aCoherenceMatches
merge_coherence_ratios
D aresults
return
aCoherenceMatches
pT l  T f       ?nD adecoded_sequence
threshold
lg_inclusion
return
str
float
ustr | None
aCoherenceMatches
coherence_ratio
ucharset_normalizer\cd.py
T a.0
character
T a.0
wcwoT a.0
weaindex_results
T wxu<module charset_normalizer.cd>
T adecoded_sequence
layers
character_range
layer_target_range
character
discovered_range
T acharacters
ignore_non_latin
languages
character_count
character_match_count
ratio
source_have_accents
language
language_characters
target_have_accents
target_pure_latin
T alanguage
ordered_characters
character_approved_count
ordered_characters_count
target_language_characters_count
large_alphabet
character_rank_in_language
expected_projection_ratio
character_rank_projection
characters_before_source
characters_after_source
characters_before
characters_after
before_match_count
after_match_count
aFREQUENCIES_language_set
character
character_rank
T adecoded_sequence
threshold
lg_inclusion
results
ignore_non_latin
sufficient_match_count
sequence_frequencies
character_count
popular_character_ordered
ratio
lg_inclusion_list
layer
most_common
language
T aiana_name
unicode_ranges
primary_range
specified_range
T aiana_name
wpaseen_ranges
character_count
chunk
character_range
decoder
wiT aresults
index_results
no_em_name
filtered_results
result
language
ratio
T alanguage
target_have_accents
target_pure_latin
character
T aiana_name
T aresults
per_language_ratios
result
sub_result
language
ratio
merge
T aprimary_range
languages
language
characters
character
a__spec__
.charset_normalizer
z
-

Charset-Normalizer
~~~~~~~~~~~~~~
The Real First Universal Charset Detector.
A library that helps you read text from an unknown charset encoding.
Motivated by chardet, This package is trying to resolve the issue by taking a new approach.
All IANA character set names for which the Python core library provides codecs are supported.
Basic usage:
>>> from charset_normalizer import from_bytes
>>> results = from_bytes('B                                                                 . O                        !'.encode('utf_8'))
>>> best_guess = results.best()
>>> str(best_guess)
'B                                                                 . O                        !'
Others methods and usages are available - see the full documentation
t <https://github.com/Ousret/charset_normalizer>.
:copyright: (c) 2021 by Ahmed TAHRI
:license: MIT, see LICENSE for more details.
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_charset_normalizer
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
annotations
logging
api
T afrom_bytes
from_fp
from_path
is_binary
from_bytes
from_fp
from_path
is_binary
legacy
T adetect
detect
models
T aCharsetMatch
aCharsetMatches
aCharsetMatch
aCharsetMatches
utils
T aset_logging_handler
set_logging_handler
version
T aVERSION
a__version__
aVERSION
a__version__
T
from_fp
from_path
from_bytes
is_binary
detect
aCharsetMatch
aCharsetMatches
a__version__
aVERSION
set_logging_handler
a__all__
getLogger
T acharset_normalizer
addHandler
aNullHandler
ucharset_normalizer\__init__.py
u<module charset_normalizer>

a__spec__
.charset_normalizer.constant
G
P
endswith
T a_codec
P atactis
mbcs
rot_13
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
codecs
T aBOM_UTF8
aBOM_UTF16_BE
aBOM_UTF16_LE
aBOM_UTF32_BE
aBOM_UTF32_LE
aBOM_UTF8
aBOM_UTF16_BE
aBOM_UTF16_LE
aBOM_UTF32_BE
aBOM_UTF32_LE
uencodings.aliases
T aaliases
aliases
re
T aIGNORECASE
aIGNORECASE
T acompile
compile
re_compile
utf_8
utf_7
L c+/v8
c+/v9
c+/v+
c+/v/
c+/v8-
gb18030
c 1 3
utf_32
utf_16
aENCODING_MARKS
udict[str, bytes | list[bytes]]
l aTOO_SMALL_SEQUENCE
int
l    aTOO_BIG_SEQUENCE
l  CaUTF8_MAXIMAL_ALLOCATION
D  uControl character
uBasic Latin
uLatin-1 Supplement
uLatin Extended-A
uLatin Extended-B
uIPA Extensions
uSpacing Modifier Letters
uCombining Diacritical Marks
uGreek and Coptic
aCyrillic
uCyrillic Supplement
aArmenian
aHebrew
aArabic
aSyriac
uArabic Supplement
aThaana
aNKo
aSamaritan
aMandaic
uSyriac Supplement
uArabic Extended-B
uArabic Extended-A
aDevanagari
aBengali
aGurmukhi
aGujarati
aOriya
aTamil
aTelugu
aKannada
aMalayalam
aSinhala
aThai
aLao
aTibetan
aMyanmar
aGeorgian
uHangul Jamo
aEthiopic
uEthiopic Supplement
aCherokee
uUnified Canadian Aboriginal Syllabics
aOgham
aRunic
aTagalog
aHanunoo
aBuhid
aTagbanwa
aKhmer
aMongolian
uUnified Canadian Aboriginal Syllabics Extended
aLimbu
uTai Le
uNew Tai Lue
uKhmer Symbols
aBuginese
uTai Tham
uCombining Diacritical Marks Extended
aBalinese
aSundanese
aBatak
aLepcha
uOl Chiki
uCyrillic Extended-C
uGeorgian Extended
uSundanese Supplement
uVedic Extensions
uPhonetic Extensions
uPhonetic Extensions Supplement
uCombining Diacritical Marks Supplement
uLatin Extended Additional
uGreek Extended
uGeneral Punctuation
uSuperscripts and Subscripts
uCurrency Symbols
uCombining Diacritical Marks for Symbols
uLetterlike Symbols
uNumber Forms
aArrows
uMathematical Operators
uMiscellaneous Technical
uControl Pictures
uOptical Character Recognition
uEnclosed Alphanumerics
uBox Drawing
uBlock Elements
uGeometric Shapes
uMiscellaneous Symbols
aDingbats
uMiscellaneous Mathematical Symbols-A
uSupplemental Arrows-A
uBraille Patterns
uSupplemental Arrows-B
uMiscellaneous Mathematical Symbols-B
uSupplemental Mathematical Operators
uMiscellaneous Symbols and Arrows
aGlagolitic
uLatin Extended-C
aCoptic
uGeorgian Supplement
aTifinagh
uEthiopic Extended
uCyrillic Extended-A
uSupplemental Punctuation
uCJK Radicals Supplement
uKangxi Radicals
uIdeographic Description Characters
uCJK Symbols and Punctuation
aHiragana
aKatakana
aBopomofo
uHangul Compatibility Jamo
aKanbun
uBopomofo Extended
uCJK Strokes
uKatakana Phonetic Extensions
uEnclosed CJK Letters and Months
uCJK Compatibility
uCJK Unified Ideographs Extension A
uYijing Hexagram Symbols
uCJK Unified Ideographs
uYi Syllables
uYi Radicals
aLisu
aVai
uCyrillic Extended-B
aBamum
uModifier Tone Letters
uLatin Extended-D
uSyloti Nagri
uCommon Indic Number Forms
uPhags-pa
aSaurashtra
uDevanagari Extended
uKayah Li
aRejang
uHangul Jamo Extended-A
aJavanese
uMyanmar Extended-B
aCham
uMyanmar Extended-A
uTai Viet
uMeetei Mayek Extensions
uEthiopic Extended-A
uLatin Extended-E
uCherokee Supplement
uMeetei Mayek
uHangul Syllables
uHangul Jamo Extended-B
uHigh Surrogates
uHigh Private Use Surrogates
uLow Surrogates
uPrivate Use Area
uCJK Compatibility Ideographs
uAlphabetic Presentation Forms
uArabic Presentation Forms-A
uVariation Selectors
uVertical Forms
uCombining Half Marks
uCJK Compatibility Forms
uSmall Form Variants
uArabic Presentation Forms-B
uHalfwidth and Fullwidth Forms
aSpecials
uLinear B Syllabary
uLinear B Ideograms
uAegean Numbers
uAncient Greek Numbers
uAncient Symbols
uPhaistos Disc
aLycian
aCarian
uCoptic Epact Numbers
uOld Italic
aGothic
uOld Permic
aUgaritic
uOld Persian
aDeseret
aShavian
aOsmanya
aOsage
aElbasan
uCaucasian Albanian
aVithkuqi
uLinear A
uLatin Extended-F
uCypriot Syllabary
uImperial Aramaic
aPalmyrene
aNabataean
aHatran
aPhoenician
aLydian
uMeroitic Hieroglyphs
uMeroitic Cursive
aKharoshthi
uOld South Arabian
uOld North Arabian
aManichaean
aAvestan
uInscriptional Parthian
uInscriptional Pahlavi
uPsalter Pahlavi
uOld Turkic
uOld Hungarian
uHanifi Rohingya
uRumi Numeral Symbols
aYezidi
uArabic Extended-C
uOld Sogdian
aSogdian
uOld Uyghur
aChorasmian
aElymaic
aBrahmi
aKaithi
uSora Sompeng
aChakma
aMahajani
aSharada
uSinhala Archaic Numbers
aKhojki
aMultani
aKhudawadi
aGrantha
aNewa
aTirhuta
aSiddham
aModi
uMongolian Supplement
aTakri
aAhom
aDogra
uWarang Citi
uDives Akuru
aNandinagari
uZanabazar Square
aSoyombo
uUnified Canadian Aboriginal Syllabics Extended-A
uPau Cin Hau
uDevanagari Extended-A
aBhaiksuki
aMarchen
uMasaram Gondi
uGunjala Gondi
aMakasar
aKawi
uLisu Supplement
uTamil Supplement
aCuneiform
uCuneiform Numbers and Punctuation
uEarly Dynastic Cuneiform
uCypro-Minoan
uEgyptian Hieroglyphs
uEgyptian Hieroglyph Format Controls
uAnatolian Hieroglyphs
uBamum Supplement
aMro
aTangsa
uBassa Vah
uPahawh Hmong
aMedefaidrin
aMiao
uIdeographic Symbols and Punctuation
aTangut
uTangut Components
uKhitan Small Script
uTangut Supplement
uKana Extended-B
uKana Supplement
uKana Extended-A
uSmall Kana Extension
aNushu
aDuployan
uShorthand Format Controls
uZnamenny Musical Notation
uByzantine Musical Symbols
uMusical Symbols
uAncient Greek Musical Notation
uKaktovik Numerals
uMayan Numerals
uTai Xuan Jing Symbols
uCounting Rod Numerals
uMathematical Alphanumeric Symbols
uSutton SignWriting
uLatin Extended-G
uGlagolitic Supplement
uCyrillic Extended-D
uNyiakeng Puachue Hmong
aToto
aWancho
uNag Mundari
uEthiopic Extended-B
uMende Kikakui
aAdlam
uIndic Siyaq Numbers
uOttoman Siyaq Numbers
uArabic Mathematical Alphabetic Symbols
uMahjong Tiles
uDomino Tiles
uPlaying Cards
uEnclosed Alphanumeric Supplement
uEnclosed Ideographic Supplement
uMiscellaneous Symbols and Pictographs
uEmoticons range(Emoji)
uOrnamental Dingbats
uTransport and Map Symbols
uAlchemical Symbols
uGeometric Shapes Extended
uSupplemental Arrows-C
uSupplemental Symbols and Pictographs
uChess Symbols
uSymbols and Pictographs Extended-A
uSymbols for Legacy Computing
uCJK Unified Ideographs Extension B
uCJK Unified Ideographs Extension C
uCJK Unified Ideographs Extension D
uCJK Unified Ideographs Extension E
uCJK Unified Ideographs Extension F
uCJK Compatibility Ideographs Supplement
uCJK Unified Ideographs Extension G
uCJK Unified Ideographs Extension H
aTags
uVariation Selectors Supplement
uSupplementary Private Use Area-A
uSupplementary Private Use Area-B
;l
l l ;l l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l
l ;l
l
l ;l
l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l  l ;l  l !l ;l !l "l ;l "l $l ;l $l 'l ;l 'l 'l ;l 'l (l ;l (l -l ;l -l -l ;l -l .l ;l .l .l ;l .l .l ;l .l .l ;l .l /l ;l /l 0l ;l 0l 1l ;l 1l 2l ;l 2l 2l ;l 2l 3l ;l 3l 3l ;l 3l 4l ;l 4l 4l ;l 4l 5l ;l 5l 6l ;l 6l 7l ;l 7l 7l ;l 7l 8l ;l 8l 8l ;l 8l 9l ;l 9l 9l ;l 9l 9l ;l 9l 9l ;l 9l :l ;l :l ;l ;l ;l ;l ;l ;l <l ;l <l >l ;l >l @l ;l @l @l ;l @l Al ;l Al Al ;l Al Bl ;l Bl Bl ;l Bl Cl ;l Cl Dl ;l Dl Fl ;l Fl Hl ;l Hl Hl ;l Hl Hl ;l Hl Jl ;l Jl Kl ;l Kl Kl ;l Kl Ll ;l Ll Nl ;l Nl Ol ;l Ol Ol ;l Ol Pl ;l Pl Rl ;l Rl Sl ;l Sl Tl ;l Tl Vl ;l Vl Xl ;l Xl Xl ;l Xl Yl ;l Yl Zl ;l Zl Zl ;l Zl [l ;l [l [l ;l [l \l ;l \l ]l ;l ]l ^l ;l ^l _l ;l _l `l ;l `l `l ;l `l al ;l al bl ;l bl bl ;l bl cl ;l cl cl ;l cl cl ;l cl cl ;l cl dl ;l dl fl ;l fl hl ;l hl   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l   l
l ;l
l
l ;l
l
l ;l
l   l ;l   l   l ;l   l   l ;l   l   l ;l   l   l ;l  8l  8l ;l  8l  8l ;l  <l  @l ;l  @l  Dl aUNICODE_RANGES_COMBINED
udict[str, range]
L aSupplement
aExtended
aExtensions
aModifier
aMarks
aPunctuation
aSymbols
aForms
aOperators
aMiscellaneous
aDrawing
aBlock
aShapes
aSupplemental
aTags
aUNICODE_SECONDARY_RANGE_KEYWORD
ulist[str]
u(?:(?:encoding)|(?:charset)|(?:coding))(?:[\:= ]{1,10})(?:[\"\']?)([a-zA-Z0-9\-_]+)(?:[\"\']?)
aRE_POSSIBLE_ENCODING_INDICATION
L	acp720
cp737
cp856
cp874
cp875
cp1006
koi8_r
koi8_t
koi8_u
aIANA_NO_ALIASES
sorted
u<lambda>
values
aIANA_SUPPORTED
aIANA_SUPPORTED_COUNT
D(acp037
cp1026
cp1125
cp1140
cp1250
cp1251
cp1252
cp1253
cp1254
cp1257
cp273
cp437
cp500
cp850
cp857
cp858
cp860
cp861
cp862
cp863
cp865
cp866
iso8859_10
iso8859_11
iso8859_13
iso8859_14
iso8859_15
iso8859_16
iso8859_2
iso8859_3
iso8859_4
iso8859_7
iso8859_9
kz1048
latin_1
mac_iceland
mac_roman
mac_turkish
ptcp154
tis_620
L acp1026
cp1140
cp273
cp500
L acp037
cp1140
cp273
cp500
L acp866
L acp037
cp1026
cp273
cp500
L aiso8859_2
L akz1048
ptcp154
L aiso8859_15
iso8859_9
latin_1
L aiso8859_7
L aiso8859_15
iso8859_9
latin_1
L aiso8859_13
L acp037
cp1026
cp1140
cp500
L acp850
cp858
cp860
cp861
cp862
cp863
cp865
L acp037
cp1026
cp1140
cp273
L acp437
cp857
cp858
cp865
L acp850
cp858
cp865
L acp437
cp850
cp857
cp865
L acp437
cp861
cp862
cp863
cp865
L acp437
cp860
cp862
cp863
cp865
L acp437
cp860
cp861
cp863
cp865
L acp437
cp860
cp861
cp862
cp865
L acp437
cp850
cp857
cp858
cp860
cp861
cp862
cp863
L acp1125
L aiso8859_14
iso8859_15
iso8859_4
iso8859_9
latin_1
L atis_620
L acp1257
L aiso8859_10
iso8859_15
iso8859_16
iso8859_3
iso8859_9
latin_1
L acp1252
cp1254
iso8859_10
iso8859_14
iso8859_16
iso8859_3
iso8859_9
latin_1
L aiso8859_14
iso8859_15
iso8859_2
iso8859_3
iso8859_9
latin_1
L acp1250
iso8859_16
iso8859_4
L aiso8859_14
iso8859_15
iso8859_16
iso8859_9
latin_1
L aiso8859_10
iso8859_2
iso8859_9
latin_1
L acp1253
L
cp1252
cp1254
cp1258
iso8859_10
iso8859_14
iso8859_15
iso8859_16
iso8859_3
iso8859_4
latin_1
L acp1251
ptcp154
L
cp1252
cp1254
cp1258
iso8859_10
iso8859_14
iso8859_15
iso8859_16
iso8859_3
iso8859_4
iso8859_9
L amac_roman
mac_turkish
L amac_iceland
mac_turkish
L amac_iceland
mac_roman
L acp1251
kz1048
L aiso8859_11
aIANA_SUPPORTED_SIMILAR
udict[str, list[str]]
D aiso2022_kr
iso2022_jp
euc_kr
tis_620
utf_32
euc_jp
koi8_r
iso8859_1
iso8859_2
iso8859_5
iso8859_6
iso8859_7
iso8859_8
utf_16
cp855
mac_cyrillic
gb2312
gb18030
cp932
cp866
utf_8
utf_8_sig
shift_jis
big5
cp1250
cp1251
cp1252
cp1253
cp1255
cp1256
cp1254
cp949
uISO-2022-KR
uISO-2022-JP
uEUC-KR
uTIS-620
uUTF-32
uEUC-JP
uKOI8-R
uISO-8859-1
uISO-8859-2
uISO-8859-5
uISO-8859-6
uISO-8859-7
uISO-8859-8
uUTF-16
aIBM855
aMacCyrillic
aGB2312
aGB18030
aCP932
aIBM866
uutf-8
uUTF-8-SIG
aSHIFT_JIS
aBig5
uwindows-1250
uwindows-1251
uWindows-1252
uwindows-1253
uwindows-1255
uwindows-1256
uWindows-1254
aCP949
aCHARDET_CORRESPONDENCE
udict[str, str]
S w[w=w-w{w/w"w(w]w;w&w}w<w|w)w,w>w:aCOMMON_SAFE_ASCII_CHARACTERS
uset[str]
S ajohab
euc_kr
cp949
aKO_NAMES
S acp950
hz
big5
big5hkscs
aZH_NAMES
l aTRACE
D)aEnglish
uEnglish
aGerman
aFrench
aDutch
aItalian
aPolish
aSpanish
aRussian
aJapanese
uJapanese
uJapanese
aPortuguese
aSwedish
aChinese
aUkrainian
aNorwegian
aFinnish
aVietnamese
aCzech
aHungarian
aKorean
aIndonesian
aTurkish
aRomanian
aFarsi
aArabic
aDanish
aSerbian
aLithuanian
aSlovene
aSlovak
aHebrew
aBulgarian
aCroatian
aHindi
aEstonian
aThai
aGreek
aTamil
aKazakh
L wewawtwiwownwswrwhwlwdwcwuwmwfwpwgwwwywbwvwkwxwjwzwqL wewawtwiwownwswrwhwlwdwcwmwuwfwpwgwwwbwywvwkwjwxwzwqL wewnwiwrwswtwawdwhwuwlwgwowcwmwbwfwkwwwzwpwvu


wjL wewawswnwiwtwrwlwuwowdwcwpwmu
wvwgwfwbwhwqu
wxu
wywjL wewnwawiwrwtwowdwswlwgwhwvwmwuwkwcwpwbwwwjwzwfwywxu
L wewiwawownwlwtwrwswcwdwuwpwmwgwvwfwbwzwhwqu

wkwyu
L wawiwowewnwrwzwwwswcwtwkwywdwpwmwuwlwju
wgwbwhu


L wewawownwswrwiwlwdwtwcwuwmwpwbwgwvwfwyu
whwqu
wjwzu
L u

























Ldu



































































































L`u































































































L]u




























































































L wawewowswiwrwdwnwtwmwuwcwlwpwgwvwbwfwhu
wqu


wzu
L wewawnwrwtwswiwlwdwowmwkwgwvwhwfwuwpu
wcwbu

wywjwxLdu



































































































L u

























L wewrwnwtwawswiwowlwdwgwkwmwvwfwpwuwbwhu
wywju
wcu
wwL wawiwnwtwewswlwowuwku
wmwrwvwjwhwpwywdu
wgwcwbwfwwwzL wnwhwtwiwcwgwawowuwmwlwru

wswewvwpwbwyu
wdu
wku

L wowewawnwtwswiwlwvwrwkwdwuwmwpu
wcwhwzu
wywjwbu


L wewawtwlwswnwkwrwiwowzu

wgwmwbwywvwdwhwuwpwju
wfwcL u

























L wawnwewiwrwtwuwswdwkwmwlwgwpwbwowhwywjwcwwwfwvwzwxwqL wawewiwnwrwlu
wkwdwtwswmwywuwowbu

wvwgwzwhwcwpu

L wewiwawrwnwtwuwlwowcwswdwpwmu
wfwvu
wgwbu

wzwhu
wjL u

























L u

























L wewrwnwtwawiwswdwlwowgwmwkwfwvwuwbwhwpu
wyu

wcwjwwL u


















wawiwewownu

L wiwawswowrwewtwnwuwkwmwlwpwvwdwjwgu
wbwyu


wcu

L wewawiwownwrwswlwtwjwvwkwdwpwmwuwzwbwgwhu
wcu

wfwyL wowawewnwiwrwvwtwswlwkwdwmwpwuwcwhwjwbwzu
wyu



L u
























L u

























L wawiwowewnwrwjwswtwuwkwlwvwdwmwpwgwzwbwcu
whu


wfL u

























L wawiwewswtwlwuwnwowkwrwdwmwvwgwpwjwhu
wbu

wfwcu
wyL u

























L u

























L u























L u

























aFREQUENCIES
aLANGUAGE_SUPPORTED_COUNT
ucharset_normalizer\constant.py
T wxu<module charset_normalizer.constant>

a__spec__
.charset_normalizer.legacy
)
warn
ucharset-normalizer disregard arguments '
w,u' in legacy function detect()

T Obytearray
Obytes
uExpected object of type bytes or bytearray, got: {}
from_bytes
best
encoding
language
aUnknown
f
?achaos
utf_8
bom
a_sig
aCHARDET_CORRESPONDENCE
confidence

chardet legacy method
Detect the encoding of the given byte string. It should be mostly backward-compatible.
Encoding name will match Chardet own writing whenever possible. (Not on encoding name unsupported by it)
This function is deprecated and should be used to migrate your project easily, consult the documentation for
further information. Not planned for removal.
:param byte_str:     The byte sequence to examine.
:param should_rename_legacy:  Should we rename legacy encodings
to their more modern equivalents?
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aTYPE_CHECKING
aAny
warnings
T awarn
api
T afrom_bytes
constant
T aCHARDET_CORRESPONDENCE
T FD abyte_str
should_rename_legacy
kwargs
return
bytes
bool
aAny
aResultDict
detect
ucharset_normalizer\legacy.py
u<module charset_normalizer.legacy>
T abyte_str
should_rename_legacy
kwargs
wraencoding
language
confidence
a__spec__
.charset_normalizer.models
`
a_payload
a_encoding
a_mean_mess_ratio
a_languages
a_has_sig_or_bom
a_unicode_ranges
a_leaves
Z
a_mean_coherence_ratio
a_output_payload
a_output_encoding
a_string
a_preemptive_declaration
aCharsetMatch
iana_name
encoding
fingerprint
chaos
coherence
f{  G z ?f{  G z ?aTOO_BIG_SEQUENCE
multi_byte_usage

Implemented to make sorted available upon CharsetMatches items.
raw
strict
u<CharsetMatch '

u' bytes(
u)>
uUnable to add instance <{}> as a submatch of a CharsetMatch
append
aliases
items
self
also_known_as

Encoding name are known by many name, using this could help when searching for IBM855 when it's listed as CP855.

Return the complete list of possible languages found in decoded sequence.
Usually not really useful. Returned list may be empty even if 'language' property return something != 'Unknown'.
ascii
could_be_from_charset
aEnglish
ucharset_normalizer.cd
T aencoding_languages
mb_encoding_languages
encoding_languages
mb_encoding_languages
is_multi_byte_encoding
uLatin Based
aUnknown

Most probable language found in decoded sequence. If none were detected or inferred, the property will return
"Unknown".
round
ldD andigits
l u
Original untouched bytes.
unicode_range
sorted

The complete list of encoding that output the exact SAME str result and therefore could be the originating
encoding.
This list does include the encoding available in property 'encoding'.
lower
T uutf-8
utf8
utf_8
sub
aRE_POSSIBLE_ENCODING_INDICATION
u<lambda>
uCharsetMatch.output.<locals>.<lambda>
:nl @nD acount
l :l @nnaencode
replace

Method to get re-encoded bytes payload using given target encoding. Default to UTF-8.
Any errors will be simply ignored by the encoder NOT replaced.
string
span
groups
T w_w-asha256
output
hexdigest

Retrieve the unique SHA256 computed using the transformed (re-encoded) payload. Not the original one.
a_results
a__iter__
uCharsetMatches.__iter__

Retrieve a single item either by its position or encoding name (alias may be used here).
Raise KeyError upon invalid index or encoding not present in results.
uCannot append instance '{}' to CharsetMatches
item
add_submatch

Insert a single match. Will be inserted accordingly to preserve sort.
Can be inserted as a submatch.

Simply return the first match. Strict equivalent to matches[0].
best

Redundant method, call the method best(). Kept for BC reasons.
path
unicode_path
encoding_aliases
alternative_encodings
language
alphabets
has_sig_or_bom
is_preferred
dumps
D aensure_ascii
indent
tl a__doc__
a__file__
origin
has_location
a__cached__
annotations
uencodings.aliases
T aaliases
hashlib
T asha256
json
T adumps
re
T asub
aAny
aIterator
aList
aTuple
constant
T aRE_POSSIBLE_ENCODING_INDICATION
aTOO_BIG_SEQUENCE
utils
T aiana_name
is_multi_byte_encoding
unicode_range
