# Reconstructed from integrated Nuitka blob
# Module: uError using plugin `

w:a__name__
u`:
python_event_handlers
json_event_handlers
strings_event_handlers
build_wrapper
validate_python
validate_json
validate_strings
wraps
D aargs
kwargs
return
uP.args
uP.kwargs
wRawrapper
ubuild_wrapper.<locals>.wrapper
filter_handlers
on_enter
u<genexpr>
ubuild_wrapper.<locals>.<genexpr>
on_success
on_error
on_exception
on_enters
args
kwargs
func
aValidationError
on_errors
error
on_exceptions
exception
on_successes
result
upydantic.plugin
uFilter out handler methods which are not implemented by the plugin directly - e.g. are missing
or are inherited from the protocol.
uPluggable schema validator for pydantic.
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
functools
aTYPE_CHECKING
aAny
aCallable
aIterable
aTypeVar
pydantic_core
aCoreConfig
aCoreSchema
typing_extensions
T aLiteral
aParamSpec
aLiteral
aParamSpec
T wPwPT wRwRT aon_validate_python
on_validate_json
on_validate_strings
aEvent
a__args__
events
ulist[Event]
T nnD aschema
schema_type
schema_type_module
schema_type_name
schema_kind
config
plugin_settings
return
aCoreSchema
aAny
str
paSchemaKind
uCoreConfig | None
udict[str, Any] | None
uSchemaValidator | PluggableSchemaValidator
create_schema_validator
upydantic.plugin._schema_validator
uPluggable schema validator.
a__qualname__
T a_schema_validator
validate_json
validate_python
validate_strings
a__slots__
D aschema
schema_type
schema_type_path
schema_kind
config
plugins
plugin_settings
return
aCoreSchema
aAny
aSchemaTypePath
aSchemaKind
uCoreConfig | None
uIterable[PydanticPluginProtocol]
udict[str, Any]
aNone
a__init__
uPluggableSchemaValidator.__init__
D aname
return
str
aAny
a__getattr__
uPluggableSchemaValidator.__getattr__
D afunc
event_handlers
return
uCallable[P, R]
ulist[BaseValidateHandlerProtocol]
uCallable[P, R]
D ahandler_cls
method_name
return
aBaseValidateHandlerProtocol
str
bool
upydantic\plugin\_schema_validator.py
T a.0
whu<module pydantic.plugin._schema_validator>
T aself
name
T aself
schema
schema_type
schema_type_path
schema_kind
config
plugins
plugin_settings
python_event_handlers
json_event_handlers
strings_event_handlers
plugin
wpwjwsweT afunc
event_handlers
on_enters
on_successes
on_errors
on_exceptions
wrapper
T
schema
schema_type
schema_type_module
schema_type_name
schema_kind
config
plugin_settings
aSchemaTypePath
get_plugins
plugins
T ahandler_cls
method_name
handler
T aargs
kwargs
on_enter_handler
result
error
on_error_handler
exception
on_exception_handler
on_success_handler
on_enters
func
on_errors
on_exceptions
on_successes
T afunc
on_enters
on_errors
on_exceptions
on_successes
a__spec__
.pydantic.plugin
J
i
uPydantic plugins should implement `new_schema_validator`.
uThis method is called for each plugin every time a new [`SchemaValidator`][pydantic_core.SchemaValidator]
is created.
It should return an event handler for each of the three validation methods, or `None` if the plugin does not
implement that method.
Args:
schema: The schema to validate against.
schema_type: The original type which the schema was created from, e.g. the model class.
schema_type_path: Path defining where `schema_type` was defined, or where `TypeAdapter` was called.
schema_kind: The kind of schema to validate against.
config: The config to use for validation.
plugin_settings: Any plugin settings.
Returns:
A tuple of optional event handlers for each of the three validation methods -
`validate_python`, `validate_json`, `validate_strings`.
uUsage docs: https://docs.pydantic.dev/2.10/concepts/plugins#build-a-plugin
Plugin interface for Pydantic plugins, and related types.
a__doc__
a__file__
path
dirname
join
environ
get
T aNUITKA_PACKAGE_pydantic
u\not_existing
plugin
T aNUITKA_PACKAGE_pydantic_plugin
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
a__annotations__
annotations
aAny
aCallable
aNamedTuple
pydantic_core
aCoreConfig
aCoreSchema
aValidationError
typing_extensions
T aLiteral
aProtocol
aTypeAlias
aLiteral
aProtocol
aTypeAlias
T aPydanticPluginProtocol
aBaseValidateHandlerProtocol
aValidatePythonHandlerProtocol
aValidateJsonHandlerProtocol
aValidateStringsHandlerProtocol
aNewSchemaReturns
aSchemaTypePath
aSchemaKind
a__all__
utuple[ValidatePythonHandlerProtocol | None, ValidateJsonHandlerProtocol | None, ValidateStringsHandlerProtocol | None]
aNewSchemaReturns
a__prepare__
aSchemaTypePath
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
