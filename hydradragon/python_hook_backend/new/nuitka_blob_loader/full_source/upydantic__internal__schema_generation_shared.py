# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._schema_generation_shared

uJsonSchemaHandler implementation that doesn't do ref unwrapping by default.
This is used for any Annotated metadata so that we don't end up with conflicting
modifications to the definition schema.
Used internally by Pydantic, please do not rely on this implementation.
See `GetJsonSchemaHandler` for the handler API.
a__qualname__
D agenerate_json_schema
handler_override
return
aGenerateJsonSchema
uHandlerOverride | None
aNone
a__init__
uGenerateJsonSchemaHandler.__init__
D acore_schema
return
aCoreSchemaOrField
aJsonSchemaValue
a__call__
uGenerateJsonSchemaHandler.__call__
D amaybe_ref_json_schema
return
aJsonSchemaValue
puGenerateJsonSchemaHandler.resolve_ref_schema
a__orig_bases__
aCallbackGetCoreSchemaHandler
uWrapper to use an arbitrary function as a `GetCoreSchemaHandler`.
Used internally by Pydantic, please do not rely on this implementation.
See `GetCoreSchemaHandler` for the handler API.
T uto-def
D ahandler
generate_schema
ref_mode
return
uCallable[[Any], core_schema.CoreSchema]
aGenerateSchema
uLiteral['to-def', 'unpack']
aNone
uCallbackGetCoreSchemaHandler.__init__
D asource_type
return
aAny
ucore_schema.CoreSchema
uCallbackGetCoreSchemaHandler.__call__
D areturn
aNamespacesTuple
a_get_types_namespace
uCallbackGetCoreSchemaHandler._get_types_namespace
uCallbackGetCoreSchemaHandler.generate_schema
property
D areturn
ustr | None
field_name
uCallbackGetCoreSchemaHandler.field_name
D amaybe_ref_schema
return
ucore_schema.CoreSchema
ucore_schema.CoreSchema
uCallbackGetCoreSchemaHandler.resolve_ref_schema
upydantic\_internal\_schema_generation_shared.py
u<module pydantic._internal._schema_generation_shared>
T a__class__
T aself
source_type
schema
ref
T aself
core_schema
T aself
handler
generate_schema
ref_mode
T aself
generate_json_schema
handler_override
T aself
T aself
source_type
T aself
maybe_ref_schema
ref
T aself
maybe_ref_json_schema
ref
json_schema
a__spec__
.pydantic._internal._serializers
'
aSEQUENCE_ORIGIN_MAP
get
handler
aPydanticOmit
items
wvamode_is_json
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
collections
ucollections.abc
typing
aAny
pydantic_core
upydantic_core.core_schema
core_schema
aDeque
deque
aList
aAbstractSet
aSet
aFrozenSet
aSequence
aMutableSequence
aMutableSet
abc
udict[Any, Any]
D wvahandler
info
return
aAny
ucore_schema.SerializerFunctionWrapHandler
ucore_schema.SerializationInfo
aAny
serialize_sequence_via_list
upydantic\_internal\_serializers.py
u<module pydantic._internal._serializers>
T wvahandler
info
items
mapped_origin
index
item

a__spec__
.pydantic._internal._signature
[
alias
is_valid_identifier
validation_alias
uExtract the correct name to use for the field when generating a signature.
Assuming the field has a valid alias, this will return the alias. Otherwise, it will return the field name.
First priority is given to the alias, then the validation_alias, then the field name.
Args:
field_name: The name of the field
field_info: The corresponding FieldInfo object.
Returns:
The correct name to use when generating a signature.
upydantic.fields
aFieldInfo
default
annotation
aAny
aPydanticUndefined
default_factory
aSignature
empty
dataclasses
a_HAS_DEFAULT_FACTORY
replace
a_field_name_for_signature
name
T aannotation
name
default
uModify the signature for a parameter in a dataclass where the default value is a FieldInfo instance.
Args:
param (Parameter): The parameter
Returns:
Parameter: The custom processed parameter
itertools
T aislice
islice
signature
parameters
values
fields
get
init
T aname
param
T aannotation
kind
aVAR_KEYWORD
merged_params
var_kw
items
is_required
aParameter
param_name
aKEYWORD_ONLY
rebuild_annotation
T aannotation
default
allow
use_var_kw
self
aPOSITIONAL_ONLY
data
extra_data
var_kw_name
w_uGenerate a mapping of parameter names to Parameter objects for a pydantic BaseModel or dataclass.
a_generate_signature_parameters
a_process_param_defaults
T aparameters
return_annotation
uGenerate signature for a pydantic BaseModel or dataclass.
Args:
init: The class init.
fields: The model fields.
populate_by_name: The `populate_by_name` value of the config.
extra: The `extra` value of the config.
is_dataclass: Whether the model is a dataclass.
Returns:
The dataclass/BaseModel subclass signature.
a__doc__
a__file__
origin
has_location
a__cached__
annotations
inspect
T aParameter
aSignature
signature
aTYPE_CHECKING
aCallable
pydantic_core
a_utils
T ais_valid_identifier
