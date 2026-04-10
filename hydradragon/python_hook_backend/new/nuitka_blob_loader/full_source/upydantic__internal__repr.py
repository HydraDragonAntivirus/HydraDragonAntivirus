# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._repr

uString class where repr doesn't include quotes. Useful with Representation when you want to return a string
representation of something that is valid (or pseudo-valid) python.
D areturn
str
a__repr__
uPlainRepr.__repr__
a__orig_bases__
D areturn
aReprArgs
uRepresentation.__repr_args__
uRepresentation.__repr_name__
D aobject
return
aAny
str
uRepresentation.__repr_recursion__
D ajoin_str
return
str
puRepresentation.__repr_str__
D afmt
kwargs
return
utyping.Callable[[Any], Any]
aAny
utyping.Generator[Any, None, None]
D areturn
aRichReprResult
a__str__
uRepresentation.__str__
uRepresentation.__repr__
D aobj
return
aAny
str
upydantic\_internal\_repr.py
T a.0
wsaself
T a.0
wawvu<module pydantic._internal._repr>
T a__class__
T aself
fmt
kwargs
name
value
T aself
T aself
attrs_names
attrs
T aself
object
T aself
join_str
T aself
name
field_repr
T aobj
args
a__spec__
.pydantic._internal._schema_generation_shared
^
generate_json_schema
generate_inner
handler
mode
u$ref
get_schema_from_definitions
uCould not find a ref for

u. Maybe you tried to call resolve_ref_schema from within a recursive model?
uResolves `$ref` in the json schema.
This returns the input json schema if there is no `$ref` in json schema.
Args:
maybe_ref_json_schema: The input json schema that may contains `$ref`.
Returns:
Resolved json schema.
Raises:
LookupError: If it can't find the definition for `$ref`.
a_handler
a_generate_schema
a_ref_mode
get
T aref
uto-def
defs
definitions
upydantic_core.core_schema
definition_reference_schema
resolve_ref_schema
a_types_namespace
generate_schema
field_name_stack
type
udefinition-ref
schema_ref
schema
uResolves reference in the core schema.
Args:
maybe_ref_schema: The input core schema that may contains reference.
Returns:
Resolved core schema.
Raises:
LookupError: If it can't find the definition for reference.
uTypes and utility functions used by various other internal tools.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aTYPE_CHECKING
aAny
aCallable
core_schema
typing_extensions
T aLiteral
aLiteral
upydantic.annotated_handlers
aGetCoreSchemaHandler
aGetJsonSchemaHandler
a__prepare__
aGenerateJsonSchemaHandler
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
