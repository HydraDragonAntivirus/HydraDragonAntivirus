# Reconstructed from integrated Nuitka blob
# Module: args

u<No __module__>
is_type_alias_type

w.a__name__
w:a__qualname__
u<No __qualname__:
w>u<No __qualname__>
u:str-
a_repr
display_as_type
arg_refs
w[w,w]uProduces the ref to be used for this type by pydantic_core's core schemas.
This `args_override` argument was added for the purpose of creating valid recursive references
when creating generic models without needing to create a concrete class.
get
T aref
nuGet the ref from the schema if it has one.
This exists just for type checking to work correctly.
D wsarecurse
return
ucore_schema.CoreSchema
aRecurse
ucore_schema.CoreSchema
a_record_valid_refs
ucollect_definitions.<locals>._record_valid_refs
walk_core_schema
D acopy
Faget_ref
defs
collect_definitions
keys
difference
upydantic_core.core_schema
invalid_schema
T aref
definitions_schema
a_is_schema_valid
ucollect_invalid_schemas.<locals>._is_schema_valid
invalid
a_build_schema_type_to_method
a_schema_type_to_method
a_copy
copy
aCoreSchemaType
handle_
replace
T w-w_a_schema
self
a_handle_other_schemas
mapping
a_walk
a_copy_schema
T aserialization
a_handle_ser_schemas
serialization
T aschema
nawalk
schema
T areturn_schema
nareturn_schema
ser_schema
definitions
schema_ref
ref
new_definitions
wfT aitems_schema
items_schema
T akeys_schema
keys_schema
T avalues_schema
values_schema
json_schema_input_schema
choices
new_choices
items
T Ostr
Oint
steps
lax_schema
strict_schema
json_schema
python_schema
T aextras_schema
extras_schema
T acomputed_fields
T
replaced_computed_fields
computed_fields
fields
replaced_fields
arguments_schema
replaced_arguments_schema
var_args_schema
var_kwargs_schema
a_dispatch
a_dispatch_no_copy
uRecursively traverse a CoreSchema.
Args:
schema (core_schema.CoreSchema): The CoreSchema to process, it will not be modified.
f (Walk): A function to apply. This function takes two arguments:
1. The current CoreSchema that is being processed
(not the same one you passed into this function, one level down).
2. The "next" `f` to call. This lets you for example use `f=functools.partial(some_method, some_context)`
to pass data down the recursive calls without using globals or other mutable state.
copy: Whether schema should be recursively copied.
Returns:
core_schema.CoreSchema: A processed CoreSchema.
defaultdict
T Oint
collect_refs
usimplify_schema_references.<locals>.collect_refs
count_refs
usimplify_schema_references.<locals>.count_refs
values
T uthis is a bug! please report it
D wsaref
return
ucore_schema.DefinitionReferenceSchema
str
bool
can_be_inlined
usimplify_schema_references.<locals>.can_be_inlined
inline_refs
usimplify_schema_references.<locals>.inline_refs
ref_counts
T aschema
definitions
recurse
definition_reference_schema
T aschema_ref
udefinition-ref
l acurrent_recursion_ref_count
involved_in_recursion
next_s
visited
aPydanticUserError
u contains a circular reference to itself.
D acode
ucircular-reference-schema
add
u<genexpr>
usimplify_schema_references.<locals>.<genexpr>
metadata
aCoreMetadata
a__annotations__
T upydantic.internal.union_discriminator
T upydantic.internal.tagged_union_tag
wsapop
D wsarecurse
return
aCoreSchema
aRecurse
aCoreSchema
strip_metadata
u_strip_metadata.<locals>.strip_metadata
T ametadata
numodel-fields
T acomputed_fields
namodel
T acustom_init
tT acustom_init
T aroot_model
tT aroot_model
S atitle
issuperset
config
T aconfig
narich
T aprint
print
a_strip_metadata
uPretty print a CoreSchema using rich.
This is intended for debugging purposes.
Args:
schema: The CoreSchema to print.
include_metadata: Whether to include metadata in the output. Defaults to `False`.
aPYDANTIC_SKIP_VALIDATING_CORE_SCHEMAS
environ
a_validate_core_schema
a__doc__
a__file__
has_location
a__cached__
annotations
os
collections
T adefaultdict
aAny
aCallable
aHashable
aTypeVar
aUnion
pydantic_core
aCoreSchema
core_schema
validate_core_schema
typing_extensions
T aTypeGuard
get_args
get_origin
aTypeGuard
upydantic.errors
T a_repr
a_core_metadata
T aCoreMetadata
a_typing_extra
T ais_generic_alias
is_type_alias_type
aAfterValidatorFunctionSchema
aBeforeValidatorFunctionSchema
aWrapValidatorFunctionSchema
aPlainValidatorFunctionSchema
aAnyFunctionSchema
aFunctionSchemaWithInnerSchema
aModelField
aDataclassField
aTypedDictField
aComputedField
aCoreSchemaField
aCoreSchemaOrField
S udataclass-field
ucomputed-field
umodel-field
utyped-dict-field
S ufunction-before
ufunction-after
ufunction-wrap
S aset
list
frozenset
upydantic.internal.tagged_union_tag
aTAGGED_UNION_TAG_KEY
D aschema
return
aCoreSchemaOrField
uTypeGuard[CoreSchema]
is_core_schema
D aschema
return
aCoreSchemaOrField
uTypeGuard[CoreSchemaField]
is_core_schema_field
D aschema
return
aCoreSchemaOrField
uTypeGuard[FunctionSchemaWithInnerSchema]
is_function_with_inner_schema
D aschema
return
aCoreSchema
uTypeGuard[core_schema.ListSchema | core_schema.SetSchema | core_schema.FrozenSetSchema]
is_list_like_schema_with_items_schema
T nD atype_
args_override
return
utype[Any]
utuple[type[Any], ...] | None
str
get_type_ref
D wsareturn
ucore_schema.CoreSchema
uNone | str
D aschema
return
ucore_schema.CoreSchema
udict[str, core_schema.CoreSchema]
D aschema
allowed_missing_refs
return
ucore_schema.CoreSchema
uset[str]
ucore_schema.CoreSchema | None
define_expected_missing_refs
D aschema
return
ucore_schema.CoreSchema
bool
collect_invalid_schemas
T wTwTaWalk
aRecurse
T aCoreSchemaT
aCoreSchemaT
upydantic._internal._core_utils
a_WalkCoreSchema
D acopy
tD acopy
bool
a__init__
u_WalkCoreSchema.__init__
D aschema
return
aCoreSchemaT
pu_WalkCoreSchema._copy_schema
D areturn
udict[core_schema.CoreSchemaType, Recurse]
u_WalkCoreSchema._build_schema_type_to_method
D aschema
wfareturn
ucore_schema.CoreSchema
aWalk
ucore_schema.CoreSchema
u_WalkCoreSchema.walk
u_WalkCoreSchema._walk
u_WalkCoreSchema._handle_other_schemas
D aser_schema
wfareturn
ucore_schema.SerSchema
aWalk
ucore_schema.SerSchema
u_WalkCoreSchema._handle_ser_schemas
D aschema
wfareturn
ucore_schema.DefinitionsSchema
aWalk
ucore_schema.CoreSchema
handle_definitions_schema
u_WalkCoreSchema.handle_definitions_schema
D aschema
wfareturn
ucore_schema.ListSchema
aWalk
ucore_schema.CoreSchema
handle_list_schema
u_WalkCoreSchema.handle_list_schema
D aschema
wfareturn
ucore_schema.SetSchema
aWalk
ucore_schema.CoreSchema
handle_set_schema
u_WalkCoreSchema.handle_set_schema
D aschema
wfareturn
ucore_schema.FrozenSetSchema
aWalk
ucore_schema.CoreSchema
handle_frozenset_schema
u_WalkCoreSchema.handle_frozenset_schema
D aschema
wfareturn
ucore_schema.GeneratorSchema
aWalk
ucore_schema.CoreSchema
handle_generator_schema
u_WalkCoreSchema.handle_generator_schema
D aschema
wfareturn
ucore_schema.TupleSchema
aWalk
ucore_schema.CoreSchema
handle_tuple_schema
u_WalkCoreSchema.handle_tuple_schema
D aschema
wfareturn
ucore_schema.DictSchema
aWalk
ucore_schema.CoreSchema
handle_dict_schema
u_WalkCoreSchema.handle_dict_schema
D aschema
wfareturn
ucore_schema.AfterValidatorFunctionSchema
aWalk
ucore_schema.CoreSchema
handle_function_after_schema
u_WalkCoreSchema.handle_function_after_schema
D aschema
wfareturn
ucore_schema.BeforeValidatorFunctionSchema
aWalk
ucore_schema.CoreSchema
handle_function_before_schema
u_WalkCoreSchema.handle_function_before_schema
D aschema
wfareturn
ucore_schema.PlainValidatorFunctionSchema | core_schema.PlainSerializerFunctionSerSchema
aWalk
ucore_schema.CoreSchema
handle_function_plain_schema
u_WalkCoreSchema.handle_function_plain_schema
D aschema
wfareturn
ucore_schema.WrapValidatorFunctionSchema | core_schema.WrapSerializerFunctionSerSchema
aWalk
ucore_schema.CoreSchema
handle_function_wrap_schema
u_WalkCoreSchema.handle_function_wrap_schema
D aschema
wfareturn
ucore_schema.UnionSchema
aWalk
ucore_schema.CoreSchema
handle_union_schema
u_WalkCoreSchema.handle_union_schema
D aschema
wfareturn
ucore_schema.TaggedUnionSchema
aWalk
ucore_schema.CoreSchema
handle_tagged_union_schema
u_WalkCoreSchema.handle_tagged_union_schema
D aschema
wfareturn
ucore_schema.ChainSchema
aWalk
ucore_schema.CoreSchema
handle_chain_schema
u_WalkCoreSchema.handle_chain_schema
D aschema
wfareturn
ucore_schema.LaxOrStrictSchema
aWalk
ucore_schema.CoreSchema
handle_lax_or_strict_schema
u_WalkCoreSchema.handle_lax_or_strict_schema
D aschema
wfareturn
ucore_schema.JsonOrPythonSchema
aWalk
ucore_schema.CoreSchema
handle_json_or_python_schema
u_WalkCoreSchema.handle_json_or_python_schema
D aschema
wfareturn
ucore_schema.ModelFieldsSchema
aWalk
ucore_schema.CoreSchema
handle_model_fields_schema
u_WalkCoreSchema.handle_model_fields_schema
D aschema
wfareturn
ucore_schema.TypedDictSchema
aWalk
ucore_schema.CoreSchema
handle_typed_dict_schema
u_WalkCoreSchema.handle_typed_dict_schema
D aschema
wfareturn
ucore_schema.DataclassArgsSchema
aWalk
ucore_schema.CoreSchema
handle_dataclass_args_schema
u_WalkCoreSchema.handle_dataclass_args_schema
D aschema
wfareturn
ucore_schema.ArgumentsSchema
aWalk
ucore_schema.CoreSchema
handle_arguments_schema
u_WalkCoreSchema.handle_arguments_schema
D aschema
wfareturn
ucore_schema.CallSchema
aWalk
ucore_schema.CoreSchema
handle_call_schema
u_WalkCoreSchema.handle_call_schema
T FT acopy
D aschema
wfacopy
return
ucore_schema.CoreSchema
aWalk
bool
ucore_schema.CoreSchema
D aschema
return
ucore_schema.CoreSchema
ucore_schema.CoreSchema
simplify_schema_references
D aschema
return
aCoreSchema
pD aschema
include_metadata
return
aCoreSchema
bool
aNone
pretty_print_core_schema
upydantic\_internal\_core_utils.py
T a.0
wcu<module pydantic._internal._core_utils>
T aself
copy
T aself
mapping
key
method_name
T aself
schema
T aself
schema
wfasub_schema
T aself
ser_schema
wfaschema
return_schema
T wsarecurse
invalid
a_is_schema_valid
T a_is_schema_valid
invalid
T wsarecurse
ref
defs
a_record_valid_refs
T a_record_valid_refs
defs
T aschema
strip_metadata
T aself
schema
wfaser_schema
T wsaref
metadata
wkaref_counts
involved_in_recursion
T ainvolved_in_recursion
ref_counts
T aschema
defs
a_record_valid_refs
T aschema
invalid
a_is_schema_valid
T wsarecurse
definition
ref
new
new_ref
definitions
collect_refs
T acollect_refs
definitions
T
wsarecurse
visited
ref
next_s
count_refs
ref_counts
current_recursion_ref_count
involved_in_recursion
definitions
T acount_refs
current_recursion_ref_count
definitions
involved_in_recursion
ref_counts
T aschema
allowed_missing_refs
definitions
refs
expected_missing_refs
T wsT atype_
args_override
arg_refs
origin
args
generic_metadata
module_name
type_ref
qualname
arg
arg_ref
T aself
schema
wfareplaced_arguments_schema
param
replaced_param
T aself
schema
wfT aself
schema
wfareplaced_fields
replaced_computed_fields
computed_field
replaced_field
field
T aself
schema
wfanew_definitions
definition
updated_definition
new_inner_schema
new_schema
T aself
schema
wfakeys_schema
values_schema
T aself
schema
wfaitems_schema
T
self
schema
wfareplaced_fields
replaced_computed_fields
extras_schema
computed_field
replaced_field
wkwvT aself
schema
wfanew_choices
wkwvT
self
schema
wfareplaced_computed_fields
replaced_fields
extras_schema
computed_field
replaced_field
wkwvT aself
schema
wfanew_choices
wvT wsarecurse
ref
new
can_be_inlined
definitions
ref_counts
inline_refs
T acan_be_inlined
definitions
inline_refs
ref_counts
T aschema
T aschema
include_metadata
print
T
schema
definitions
ref_counts
involved_in_recursion
current_recursion_ref_count
collect_refs
count_refs
can_be_inlined
inline_refs
def_values
T wsarecurse
field_name
field_schema
computed_fields
cf
strip_metadata
T astrip_metadata
T aschema
wfacopy
a__spec__
.pydantic._internal._dataclasses
)
get_standard_typevars_map
collect_dataclass_fields
T ans_resolver
typevars_map
config_wrapper
a__pydantic_fields__
uCollect and set `cls.__pydantic_fields__`.
Args:
cls: The class.
ns_resolver: Namespace resolver to use when getting dataclass annotations.
config_wrapper: The config wrapper instance, defaults to `None`.
a__init__
D a__dataclass_self__
args
kwargs
return
aPydanticDataclass
aAny
paNone
ucomplete_dataclass.<locals>.__init__
a__qualname__

u.__init__
config_dict
a__pydantic_config__
set_dataclass_fields
T aconfig_wrapper
defer_build
set_dataclass_mocks
a__name__
a__post_init_post_parse__
warnings
warn
uSupport for `__post_init_post_parse__` has been dropped, the method will not be called
aDeprecationWarning
aGenerateSchema
T ans_resolver
typevars_map
aLazyClassAttribute
a__signature__
partial
generate_pydantic_signature
populate_by_name
extra
T ainit
fields
populate_by_name
extra
is_dataclass
a__get_pydantic_core_schema__
aCallbackGetCoreSchemaHandler
generate_schema
D afrom_dunder_get_core_schema
FD aref_mode
unpack
aPydanticUndefinedAnnotation
w`aname
core_config
T atitle
gen_schema
clean_schema
aCollectedInvalid
uall referenced types
cast
utype[PydanticDataclass]
a__pydantic_core_schema__
