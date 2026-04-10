# Reconstructed from integrated Nuitka blob
# Module: upydantic._internal._core_metadata

uA `TypedDict` for holding the metadata dict of the schema.
Attributes:
pydantic_js_functions: List of JSON schema functions that resolve refs during application.
pydantic_js_annotation_functions: List of JSON schema functions that don't resolve refs during application.
pydantic_js_prefer_positional_arguments: Whether JSON schema generator will
prefer positional over keyword arguments for an 'arguments' schema.
custom validation function. Only applies to before, plain, and wrap validators.
pydantic_js_udpates: key / value pair updates to apply to the JSON schema for a type.
pydantic_js_extra: WIP, either key/value pair updates to apply to the JSON schema, or a custom callable.
TODO: Perhaps we should move this structure to pydantic-core. At the moment, though,
it's easier to iterate on if we leave it in pydantic until we feel there is a semi-stable API.
TODO: It's unfortunate how functionally oriented JSON schema generation is, especially that which occurs during
the core schema generation process. It's inevitable that we need to store some json schema related information
on core schemas, given that we generate JSON schemas directly from core schemas. That being said, debugging related
issues is quite difficult when JSON schema information is disguised via dynamically defined functions.
a__qualname__
a__annotations__
ulist[GetJsonSchemaFunction]
bool
pydantic_js_prefer_positional_arguments
aJsonDict
uJsonDict | JsonSchemaExtraCallable
a__orig_bases__
D apydantic_js_functions
pydantic_js_annotation_functions
pydantic_js_updates
pydantic_js_extra
nnnnD acore_metadata
pydantic_js_functions
pydantic_js_annotation_functions
pydantic_js_updates
pydantic_js_extra
return
aAny
ulist[GetJsonSchemaFunction] | None
ulist[GetJsonSchemaFunction] | None
uJsonDict | None
uJsonDict | JsonSchemaExtraCallable | None
aNone
update_core_metadata
upydantic\_internal\_core_metadata.py
u<module pydantic._internal._core_metadata>
T a__class__
T acore_metadata
pydantic_js_functions
pydantic_js_annotation_functions
pydantic_js_updates
pydantic_js_extra
aPydanticJsonSchemaWarning
existing_updates
existing_pydantic_js_extra

a__spec__
.pydantic._internal._core_utils
/
l atype
a_CORE_SCHEMA_FIELD_TYPES
a_FUNCTION_WITH_INNER_SCHEMA_TYPES
a_LIST_LIKE_SCHEMA_WITH_ITEMS_TYPES
get_origin
is_generic_alias
get_args
a__pydantic_generic_metadata__
origin
