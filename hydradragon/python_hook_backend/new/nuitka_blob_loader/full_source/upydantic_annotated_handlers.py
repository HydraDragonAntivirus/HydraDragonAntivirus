# Reconstructed from integrated Nuitka blob
# Module: upydantic.annotated_handlers

uHandler to call into the next JSON schema generation function.
Attributes:
mode: Json schema mode, can be `validation` or `serialization`.
aGetJsonSchemaHandler
a__qualname__
a__annotations__
aJsonSchemaMode
mode
D acore_schema
return
aCoreSchemaOrField
aJsonSchemaValue
a__call__
uGetJsonSchemaHandler.__call__
D amaybe_ref_json_schema
return
aJsonSchemaValue
paresolve_ref_schema
uGetJsonSchemaHandler.resolve_ref_schema
uHandler to call into the next CoreSchema schema generation function.
aGetCoreSchemaHandler
D asource_type
return
aAny
ucore_schema.CoreSchema
uGetCoreSchemaHandler.__call__
generate_schema
uGetCoreSchemaHandler.generate_schema
D amaybe_ref_schema
return
ucore_schema.CoreSchema
ucore_schema.CoreSchema
uGetCoreSchemaHandler.resolve_ref_schema
D areturn
ustr | None
field_name
uGetCoreSchemaHandler.field_name
D areturn
aNamespacesTuple
a_get_types_namespace
uGetCoreSchemaHandler._get_types_namespace
upydantic\annotated_handlers.py
u<module pydantic.annotated_handlers>
T a__class__
T aself
source_type
T aself
core_schema
T aself
T aself
maybe_ref_schema
T aself
maybe_ref_json_schema

a__spec__
.pydantic.class_validators
u`class_validators` module is a backport module from V1.
a__doc__
a__file__
origin
has_location
a__cached__
a_migration
T agetattr_migration
getattr_migration
T upydantic.class_validators
a__getattr__
upydantic\class_validators.py
u<module pydantic.class_validators>

a__spec__
.pydantic.color
1
wrwgwbaalpha
a_tuple
T Otuple
Olist
parse_tuple
a_rgba
parse_str
aColor
a_original
aPydanticCustomError
T acolor_error
uvalue is not a valid color: value must be a tuple, list or string
value
self
type
string
format
color
uOriginal value passed to `Color`.
cast
aTuple
T Oint
ppaas_rgb_tuple
aCOLORS_BY_VALUE
as_hex
uno named color found, use fallback=True, as_hex() or as_rgb()
uReturns the name of the color if it can be found in `COLORS_BY_VALUE` dictionary,
otherwise returns the hexadecimal representation of the color or raises `ValueError`.
Args:
fallback: If True, falls back to returning the hexadecimal representation of
the color instead of raising a ValueError when no named color is found.
Returns:
The name of the color, or the hexadecimal representation of the color.
Raises:
ValueError: When no named color is found and fallback is `False`.
:nl nafloat_to_255
append

l w#uReturns the hexadecimal representation of the color.
Hex string representing the color can be 3, 4, 6, or 8 characters depending on whether the string
a "short" representation of the color is possible and whether there's an alpha channel.
Returns:
The hexadecimal representation of the color.
u02x
u<genexpr>
uColor.as_hex.<locals>.<genexpr>
repeat_colors
urgb(
u,
w)urgba(
round
a_alpha_float
uColor as an `rgb(<r>, <g>, <b>)` or `rgba(<r>, <g>, <b>, <a>)` string.
uReturns the color as an RGB or RGBA tuple.
Args:
lpha: Whether to include the alpha channel. There are three options for this input:
- `None` (default): Include alpha only if it's set. (e.g. not `None`)
- `True`: Always include alpha.
- `False`: Always omit alpha.
Returns:
A tuple that contains the values of the red, green, and blue channels in the range 0 to 255.
If alpha is included, it is in the range 0 to 1.
uColor.as_rgb_tuple.<locals>.<genexpr>
as_hsl_tuple
T FT aalpha
uhsl(
l  u0.0f
u0.0%
T tuColor as an `hsl(<h>, <s>, <l>)` or `hsl(<h>, <s>, <l>, <a>)` string.
rgb_to_hls
uReturns the color as an HSL or HSLA tuple.
Args:
lpha: Whether to include the alpha channel.
- `None` (default): Include the alpha channel only if it's set (e.g. not `None`).
- `True`: Always include alpha.
- `False`: Always omit alpha.
Returns:
The color as a tuple of hue, saturation, lightness, and alpha (if included).
All elements are in the range 0 to 1.
Note:
This is HSL as used in HTML and most other places, not HLS as used in Python's `colorsys`.
upydantic_core.core_schema
with_info_plain_validator_function
a_validate
to_string_ser_schema
T aserialization
as_named
T afallback
rgb
aRGBA
parse_float_alpha
l T acolor_error
uvalue is not a valid color: tuples must have length 3 or 4
uParse a tuple or list to get RGBA values.
Args:
value: A tuple or list.
Returns:
An `RGBA` tuple parsed from the input tuple.
Raises:
PydanticCustomError: If tuple is not valid.
parse_color_value
uparse_tuple.<locals>.<genexpr>
lower
aCOLORS_BY_NAME
ints_to_rgba
re
fullmatch
r_hex_short
groups
unot enough values to unpack (expected at least 1, got %d)
l l  ar_hex_long
r_rgb
r_rgb_v4_style
r_hsl
r_hsl_v4_style
parse_hsl
T acolor_error
uvalue is not a valid color: string not recognised as a valid color
uParse a string representing a color to an RGBA tuple.
Possible formats for the input string include:
* named color, see `COLORS_BY_NAME`
* hex short eg. `<prefix>fff` (prefix can be `#`, `0x` or nothing)
* hex long eg. `<prefix>ffffff` (prefix can be `#`, `0x` or nothing)
* `rgb(<r>, <g>, <b>)`
* `rgba(<r>, <g>, <b>, <a>)`
Args:
value: A string representing a color.
Returns:
An `RGBA` tuple parsed from the input string.
Raises:
ValueError: If the input string cannot be parsed to an RGBA tuple.
uparse_str.<locals>.<genexpr>
uConverts integer or string values for RGB color and an optional alpha value to an `RGBA` object.
Args:
r: An integer or string representing the red color value.
g: An integer or string representing the green color value.
b: An integer or string representing the blue color value.
lpha: A float representing the alpha value. Defaults to None.
Returns:
An instance of the `RGBA` class with the corresponding color and alpha values.
T acolor_error
uvalue is not a valid color: color values must be a valid number
color_error
uvalue is not a valid color: color values must be in the range 0 to {max_val}
max_val
uParse the color value provided and return a number between 0 and 1.
Args:
value: An integer or string color value.
max_val: Maximum range value. Defaults to 255.
Raises:
PydanticCustomError: If the value is not a valid color.
Returns:
A number between 0 and 1.
endswith
T w%:nq nldT acolor_error
uvalue is not a valid color: alpha values must be a valid float
math
isclose
T acolor_error
uvalue is not a valid color: alpha values must be in the range 0 to 1
uParse an alpha value checking it's a valid float in the range 0 to 1.
Args:
value: The input value to parse.
Returns:
The parsed value as a float, or `None` if the value was None or equal 1.
Raises:
PydanticCustomError: If the input value cannot be successfully parsed as a float in the expected range.
P adeg
narad
rads
hls_to_rgb
uParse raw hue, saturation, lightness, and alpha values and convert to RGBA.
Args:
h: The hue value.
h_units: The unit for hue value.
sat: The saturation value.
light: The lightness value.
lpha: Alpha value.
Returns:
An instance of `RGBA`.
uConverts a float value between 0 and 1 (inclusive) to an integer between 0 and 255 (inclusive).
Args:
c: The float value to be converted. Must be between 0 and 1 (inclusive).
Returns:
The integer equivalent of the given float value rounded to the nearest whole number.
Raises:
ValueError: If the given float value is outside the acceptable range of 0 to 1 (inclusive).
uColor definitions are used as per the CSS3
[CSS Color Module Level 3](http://www.w3.org/TR/css3-color/#svg-color) specification.
A few colors have multiple names referring to the sames colors, eg. `grey` and `gray` or `aqua` and `cyan`.
In these cases the _last_ color when sorted alphabetically takes preferences,
eg. `Color((0, 255, 255)).as_named() == 'cyan'` because "cyan" comes after "aqua".
Warning: Deprecated
The `Color` class is deprecated, use `pydantic_extra_types` instead.
See [`pydantic-extra-types.Color`](../usage/types/extra_types/color_types.md)
for more information.
a__doc__
a__file__
origin
has_location
a__cached__
colorsys
T ahls_to_rgb
rgb_to_hls
aAny
aCallable
aOptional
aType
aUnion
pydantic_core
aCoreSchema
core_schema
typing_extensions
T adeprecated
deprecated
a_internal
T a_repr
a_repr
u_internal._schema_generation_shared
T aGetJsonSchemaHandler
aGetJsonSchemaHandler
a_GetJsonSchemaHandler
upydantic.json_schema
aJsonSchemaValue
upydantic.warnings
aPydanticDeprecatedSince20
T Oint
ppOfloat
aColorTuple
aColorType
T Ofloat
ppT Ofloat
pppaHslColorTuple
