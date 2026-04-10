# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._discriminated_union

uRaised when applying a discriminated union discriminator to a schema
requires a definition that is not yet defined
a__qualname__
D aref
return
str
aNone
uMissingDefinitionForUnionRef.__init__
a__orig_bases__
D aschema
discriminator
return
aCoreSchema
aAny
aNone
set_discriminator_in_metadata
D aschema
return
ucore_schema.CoreSchema
ucore_schema.CoreSchema
apply_discriminators
T nD aschema
discriminator
definitions
return
ucore_schema.CoreSchema
ustr | Discriminator
udict[str, core_schema.CoreSchema] | None
ucore_schema.CoreSchema
uThis class is used to convert an input schema containing a union schema into one where that union is
replaced with a tagged-union, with all the associated debugging and performance benefits.
This is done by:
* Validating that the input schema is compatible with the provided discriminator
* Introspecting the schema to determine which discriminator values should map to which union choices
* Handling various edge cases such as 'definitions', 'default', 'nullable' schemas, and more
I have chosen to implement the conversion algorithm in this class, rather than a function,
to make it easier to maintain state while recursively walking the provided CoreSchema.
D adiscriminator
definitions
str
udict[str, core_schema.CoreSchema]
u_ApplyInferredDiscriminator.__init__
u_ApplyInferredDiscriminator.apply
u_ApplyInferredDiscriminator._apply_to_root
D achoice
return
ucore_schema.CoreSchema
aNone
u_ApplyInferredDiscriminator._handle_choice
D achoice
return
ucore_schema.TaggedUnionSchema
bool
u_ApplyInferredDiscriminator._is_discriminator_shared
D achoice
source_name
return
ucore_schema.CoreSchema
ustr | None
ulist[str | int]
u_ApplyInferredDiscriminator._infer_discriminator_values_for_choice
D achoice
source_name
return
ucore_schema.TypedDictSchema
ustr | None
ulist[str | int]
u_ApplyInferredDiscriminator._infer_discriminator_values_for_typed_dict_choice
D achoice
source_name
return
ucore_schema.ModelFieldsSchema
ustr | None
ulist[str | int]
u_ApplyInferredDiscriminator._infer_discriminator_values_for_model_choice
D achoice
source_name
return
ucore_schema.DataclassArgsSchema
ustr | None
ulist[str | int]
u_ApplyInferredDiscriminator._infer_discriminator_values_for_dataclass_choice
D afield
source
return
aCoreSchemaField
str
ulist[str | int]
u_ApplyInferredDiscriminator._infer_discriminator_values_for_field
D aschema
source
return
ucore_schema.CoreSchema
str
ulist[str | int]
u_ApplyInferredDiscriminator._infer_discriminator_values_for_inner_schema
D achoice
values
return
ucore_schema.CoreSchema
uSequence[str | int]
aNone
u_ApplyInferredDiscriminator._set_unique_choice_for_values
upydantic\_internal\_discriminated_union.py
u<module pydantic._internal._discriminated_union>
T a__class__
T aself
ref
a__class__
T aself
discriminator
definitions
T aself
schema
discriminator
wrapped
nullable_wrapper
definitions_wrapper
choices_schemas
choice
T aself
choice
choices_schemas
subchoices
inferred_discriminator_values
T	aself
choice
source_name
values
subchoices
subchoice
subchoice_values
subchoice_schema
schema_ref
T aself
choice
source_name
source
field
T aself
field
source
alias
T aself
schema
source
values
choice
choice_schema
choice_values
validator_type
T aself
choice
inner_discriminator
T aself
choice
values
discriminator_value
existing_choice
T aself
schema
T aschema
discriminator
definitions
aDiscriminator
T aschema
global_definitions
inner
T wsarecurse
global_definitions
metadata
discriminator
inner
T aglobal_definitions
inner
T aschema
discriminator
metadata
a__spec__
.pydantic._internal._docs_extraction
o
W
a__class__
a__init__
target
attrs
previous_node_type
visit
ast
aName
id
value
aConstant
aAnnAssign
inspect
cleandoc
textwrap
dedent

startswith
T T w w	udef dedent_workaround():
dedent_source
currentframe
frame
getmodule
cls
f_lineno
findsource
getblock
lines
a_dedent_source_lines
parse
block_tree
body
aFunctionDef
name
dedent_workaround
stmt
aClassDef
a__name__
f_back
getsourcelines
a_extract_source_from_frame
aDocstringVisitor
uMap model attributes and their corresponding docstring.
Args:
cls: The class of the Pydantic model to inspect.
use_inspect: Whether to skip usage of frames to find the object and use
the `inspect` module instead.
Returns:
A mapping containing attribute names and their corresponding docstring.
uUtilities related to attribute docstring extraction.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
aAny
aNodeVisitor
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
