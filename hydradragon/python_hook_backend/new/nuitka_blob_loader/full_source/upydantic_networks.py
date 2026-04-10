# Reconstructed from integrated Nuitka blob
# Module: upydantic.networks

uUrl constraints.
Attributes:
max_length: The maximum length of the url. Defaults to `None`.
llowed_schemes: The allowed schemes. Defaults to `None`.
host_required: Whether the host is required. Defaults to `None`.
default_host: The default host. Defaults to `None`.
default_port: The default port. Defaults to `None`.
default_path: The default path. Defaults to `None`.
aUrlConstraints
a__qualname__
uint | None
ulist[str] | None
ubool | None
ustr | None
D areturn
int
a__hash__
uUrlConstraints.__hash__
D areturn
udict[str, Any]
uUrlConstraints.defined_constraints
D asource
handler
return
aAny
aGetCoreSchemaHandler
ucore_schema.CoreSchema
a__get_pydantic_core_schema__
uUrlConstraints.__get_pydantic_core_schema__
uClassVar[UrlConstraints]
D aurl
return
ustr | _CoreUrl | _BaseUrl
aNone
a__init__
u_BaseUrl.__init__
D areturn
str
u_BaseUrl.scheme
D areturn
ustr | None
u_BaseUrl.username
u_BaseUrl.password
u_BaseUrl.host
u_BaseUrl.unicode_host
D areturn
uint | None
u_BaseUrl.port
u_BaseUrl.path
u_BaseUrl.query
D areturn
ulist[tuple[str, str]]
u_BaseUrl.query_params
u_BaseUrl.fragment
u_BaseUrl.unicode_string
a__str__
u_BaseUrl.__str__
a__repr__
u_BaseUrl.__repr__
D amemo
return
dict
aSelf
a__deepcopy__
u_BaseUrl.__deepcopy__
D aother
return
aAny
bool
a__eq__
u_BaseUrl.__eq__
a__lt__
u_BaseUrl.__lt__
a__gt__
u_BaseUrl.__gt__
a__le__
u_BaseUrl.__le__
a__ge__
u_BaseUrl.__ge__
u_BaseUrl.__hash__
a__len__
u_BaseUrl.__len__
D ausername
password
port
path
query
fragment
nnnnnnD	ascheme
username
password
host
port
path
query
fragment
return
str
ustr | None
ustr | None
str
uint | None
ustr | None
ustr | None
ustr | None
aSelf
u_BaseUrl.build
D aurl
info
return
aAny
ucore_schema.SerializationInfo
ustr | Self
u_BaseUrl.serialize_url
D asource
handler
return
utype[_BaseUrl]
aGetCoreSchemaHandler
ucore_schema.CoreSchema
u_BaseUrl.__get_pydantic_core_schema__
D acore_schema
handler
return
ucore_schema.CoreSchema
u_schema_generation_shared.GetJsonSchemaHandler
aJsonSchemaValue
a__get_pydantic_json_schema__
u_BaseUrl.__get_pydantic_json_schema__
any_schema
a__pydantic_serializer__
D aurl
return
ustr | _CoreMultiHostUrl | _BaseMultiHostUrl
aNone
u_BaseMultiHostUrl.__init__
u_BaseMultiHostUrl.scheme
u_BaseMultiHostUrl.path
u_BaseMultiHostUrl.query
u_BaseMultiHostUrl.query_params
u_BaseMultiHostUrl.fragment
D areturn
ulist[MultiHostHost]
u_BaseMultiHostUrl.hosts
u_BaseMultiHostUrl.unicode_string
u_BaseMultiHostUrl.__str__
u_BaseMultiHostUrl.__repr__
u_BaseMultiHostUrl.__deepcopy__
u_BaseMultiHostUrl.__eq__
u_BaseMultiHostUrl.__hash__
u_BaseMultiHostUrl.__len__
D ahosts
username
password
host
port
path
query
fragment
nnnnnnnnD
scheme
hosts
username
password
host
port
path
query
fragment
return
str
ulist[MultiHostHost] | None
ustr | None
ustr | None
ustr | None
uint | None
ustr | None
ustr | None
ustr | None
aSelf
u_BaseMultiHostUrl.build
u_BaseMultiHostUrl.serialize_url
D asource
handler
return
utype[_BaseMultiHostUrl]
aGetCoreSchemaHandler
ucore_schema.CoreSchema
u_BaseMultiHostUrl.__get_pydantic_core_schema__
u_BaseMultiHostUrl.__get_pydantic_json_schema__
D acls
return
utype[_BaseUrl | _BaseMultiHostUrl]
aTypeAdapter
a__prepare__
aAnyUrl
a__getitem__
u%s.__prepare__() must return a mapping, not %s
u<metaclass>
uBase type for all URLs.
* Any scheme allowed
* Top-level domain (TLD) not required
* Host not required
Assuming an input URL of `http://samuel:pass@example.com:8000/the/path/?query=here#fragment=is;this=bit`,
the types export the following properties:
- `scheme`: the URL scheme (`http`), always set.
- `host`: the URL host (`example.com`).
- `username`: optional username if included (`samuel`).
- `password`: optional password if included (`pass`).
- `port`: optional port (`8000`).
- `path`: optional path (`/the/path/`).
- `query`: optional URL query (for example, `GET` arguments or "search string", such as `query=here`).
- `fragment`: optional fragment (`fragment=is;this=bit`).
a__orig_bases__
aAnyHttpUrl
uA type that will accept any http or https URL.
* TLD not required
* Host not required
T L ahttp
https
T aallowed_schemes
aHttpUrl
uA type that will accept any http or https URL.
* TLD not required
* Host not required
* Max length 2083
```python
from pydantic import BaseModel, HttpUrl, ValidationError
class MyModel(BaseModel):
url: HttpUrl
m = MyModel(url='http://www.example.com')  # (1)!
print(m.url)
#> http://www.example.com/
try:
MyModel(url='ftp://invalid.url')
except ValidationError as e:
print(e)
'''
1 validation error for MyModel
url
URL scheme should be 'http' or 'https' [type=url_scheme, input_value='ftp://invalid.url', input_type=str]
'''
try:
MyModel(url='not a url')
except ValidationError as e:
print(e)
'''
1 validation error for MyModel
url
Input should be a valid URL, relative URL without a base [type=url_parsing, input_value='not a url', input_type=str]
'''
```
1. Note: mypy would prefer `m = MyModel(url=HttpUrl('http://www.example.com'))`, but Pydantic will convert the string to an HttpUrl instance anyway.
"International domains" (e.g. a URL where the host or TLD includes non-ascii characters) will be encoded via
[punycode](https://en.wikipedia.org/wiki/Punycode) (see
[this article](https://www.xudongz.com/blog/2017/idn-phishing/) for a good description of why this is important):
```python
from pydantic import BaseModel, HttpUrl
class MyModel(BaseModel):
url: HttpUrl
m1 = MyModel(url='http://puny  code.com')
print(m1.url)
#> http://xn--punycode-eja.com/
m2 = MyModel(url='https://www.          .com/')
print(m2.url)
#> https://www.xn--80ak6aa92e.com/
m3 = MyModel(url='https://www.example.      /')
print(m3.url)
#> https://www.example.xn--pbt977c/
```
!!! warning "Underscores in Hostnames"
In Pydantic, underscores are allowed in all parts of a domain except the TLD.
Technically this might be wrong - in theory the hostname cannot have underscores, but subdomains can.
To explain this; consider the following two cases:
- `exam_ple.co.uk`: the hostname is `exam_ple`, which should not be allowed since it contains an underscore.
- `foo_bar.example.com` the hostname is `example`, which should be allowed since the underscore is in the subdomain.
Without having an exhaustive list of TLDs, it would be impossible to differentiate between these two. Therefore
underscores are allowed, but you can always do further validation in a validator if desired.
Also, Chrome, Firefox, and Safari all currently accept `http://exam_ple.com` as a URL, so we're in good
(or at least big) company.
T l  L ahttp
https
T amax_length
allowed_schemes
aAnyWebsocketUrl
uA type that will accept any ws or wss URL.
* TLD not required
* Host not required
T L aws
wss
aWebsocketUrl
uA type that will accept any ws or wss URL.
* TLD not required
* Host not required
* Max length 2083
T l  L aws
wss
aFileUrl
uA type that will accept any file URL.
* Host not required
T L afile
aFtpUrl
uA type that will accept ftp URL.
* TLD not required
* Host not required
T L aftp
aPostgresDsn
uA type that will accept any Postgres DSN.
* User info required
* TLD not required
* Host required
* Supports multiple hosts
If further validation is required, these properties can be used by validators to enforce specific behaviour:
```python
from pydantic import (
BaseModel,
HttpUrl,
PostgresDsn,
ValidationError,
field_validator,
)
class MyModel(BaseModel):
url: HttpUrl
m = MyModel(url='http://www.example.com')
# the repr() method for a url will display all properties of the url
print(repr(m.url))
#> HttpUrl('http://www.example.com/')
print(m.url.scheme)
#> http
print(m.url.host)
#> www.example.com
print(m.url.port)
#> 80
class MyDatabaseModel(BaseModel):
db: PostgresDsn
@field_validator('db')
def check_db_name(cls, v):
ssert v.path and len(v.path) > 1, 'database must be provided'
return v
m = MyDatabaseModel(db='postgres://user:pass@localhost:5432/foobar')
print(m.db)
#> postgres://user:pass@localhost:5432/foobar
try:
MyDatabaseModel(db='postgres://user:pass@localhost:5432')
except ValidationError as e:
print(e)
'''
1 validation error for MyDatabaseModel
db
Assertion failed, database must be provided
ssert (None)
+  where None = PostgresDsn('postgres://user:pass@localhost:5432').path [type=assertion_error, input_value='postgres://user:pass@localhost:5432', input_type=str]
'''
```
T tL	apostgres
postgresql
upostgresql+asyncpg
upostgresql+pg8000
upostgresql+psycopg
upostgresql+psycopg2
upostgresql+psycopg2cffi
upostgresql+py-postgresql
upostgresql+pygresql
T ahost_required
allowed_schemes
property
uPostgresDsn.host
aCockroachDsn
uA type that will accept any Cockroach DSN.
* User info required
* TLD not required
* Host required
T tL acockroachdb
ucockroachdb+psycopg2
ucockroachdb+asyncpg
uCockroachDsn.host
aAmqpDsn
uA type that will accept any AMQP DSN.
* User info required
* TLD not required
* Host not required
T L aamqp
amqps
aRedisDsn
uA type that will accept any Redis DSN.
* User info required
* TLD not required
* Host required (e.g., `rediss://:pass@localhost`)
T L aredis
rediss
localhost
l 1u/0
tT aallowed_schemes
default_host
default_port
default_path
host_required
uRedisDsn.host
aMongoDsn
uA type that will accept any MongoDB DSN.
* User info not required
* Database name not required
* Port not required
* User info may be passed without user part (e.g., `mongodb://mongodb0.example.com:27017`).
T L amongodb
umongodb+srv
l   T aallowed_schemes
default_port
aKafkaDsn
uA type that will accept any Kafka DSN.
* User info required
* TLD not required
* Host not required
T L akafka
localhost
l GT aallowed_schemes
default_host
default_port
aNatsDsn
uA type that will accept any NATS DSN.
NATS is a connective technology built for the ever increasingly hyper-connected world.
It is a single technology that enables applications to securely communicate across
ny combination of cloud vendors, on-premise, edge, web and mobile, and devices.
More: https://nats.io
T L anats
tls
ws
wss
localhost
l  aMySQLDsn
uA type that will accept any MySQL DSN.
* User info required
* TLD not required
* Host not required
T L amysql
umysql+mysqlconnector
umysql+aiomysql
umysql+asyncmy
umysql+mysqldb
umysql+pymysql
umysql+cymysql
umysql+pyodbc
l  tT aallowed_schemes
default_port
host_required
aMariaDBDsn
uA type that will accept any MariaDB DSN.
* User info required
* TLD not required
* Host not required
T L amariadb
umariadb+mariadbconnector
umariadb+pymysql
l  aClickHouseDsn
uA type that will accept any ClickHouse DSN.
* User info required
* TLD not required
* Host not required
T L uclickhouse+native
uclickhouse+asynch
localhost
l FaSnowflakeDsn
uA type that will accept any Snowflake DSN.
* User info required
* TLD not required
* Host required
T L asnowflake
tT aallowed_schemes
host_required
uSnowflakeDsn.host
D areturn
aNone

Info:
To use this type, you need to install the optional
[`email-validator`](https://github.com/JoshData/python-email-validator) package:
```bash
pip install email-validator
```
Validate email addresses.
```python
from pydantic import BaseModel, EmailStr
class Model(BaseModel):
email: EmailStr
print(Model(email='contact@mail.com'))
#> email='contact@mail.com'
```
aEmailStr
D a_source
a_handler
return
utype[Any]
aGetCoreSchemaHandler
ucore_schema.CoreSchema
uEmailStr.__get_pydantic_core_schema__
uEmailStr.__get_pydantic_json_schema__
D ainput_value
return
str
puEmailStr._validate
aRepresentation

Info:
To use this type, you need to install the optional
[`email-validator`](https://github.com/JoshData/python-email-validator) package:
```bash
pip install email-validator
```
Validate a name and email address combination, as specified by
[RFC 5322](https://datatracker.ietf.org/doc/html/rfc5322#section-3.4).
The `NameEmail` has two properties: `name` and `email`.
In case the `name` is not provided, it's inferred from the email address.
```python
from pydantic import BaseModel, NameEmail
class User(BaseModel):
email: NameEmail
user = User(email='Fred Bloggs <fred.bloggs@example.com>')
print(user.email)
#> Fred Bloggs <fred.bloggs@example.com>
print(user.email.name)
#> Fred Bloggs
user = User(email='fred.bloggs@example.com')
print(user.email)
#> fred.bloggs <fred.bloggs@example.com>
print(user.email.name)
#> fred.bloggs
```
T aname
email
a__slots__
D aname
email
str
puNameEmail.__init__
uNameEmail.__eq__
classmethod
uNameEmail.__get_pydantic_json_schema__
uNameEmail.__get_pydantic_core_schema__
D ainput_value
return
uSelf | str
aSelf
uNameEmail._validate
uNameEmail.__str__
uIPv4Address | IPv6Address
aIPvAnyAddressType
uIPv4Interface | IPv6Interface
aIPvAnyInterfaceType
uIPv4Network | IPv6Network
aIPvAnyNetworkType
uValidate an IPv4 or IPv6 address.
```python
from pydantic import BaseModel
from pydantic.networks import IPvAnyAddress
class IpModel(BaseModel):
ip: IPvAnyAddress
print(IpModel(ip='127.0.0.1'))
#> ip=IPv4Address('127.0.0.1')
try:
IpModel(ip='http://www.example.com')
except ValueError as e:
print(e.errors())
'''
[
{
'type': 'ip_any_address',
'loc': ('ip',),
'msg': 'value is not a valid IPv4 or IPv6 address',
'input': 'http://www.example.com',
}
]
'''
```
aIPvAnyAddress
D avalue
return
aAny
aIPvAnyAddressType
uIPvAnyAddress.__new__
uIPvAnyAddress.__get_pydantic_json_schema__
uIPvAnyAddress.__get_pydantic_core_schema__
D ainput_value
return
aAny
aIPvAnyAddressType
uIPvAnyAddress._validate
aIPvAnyInterface
D avalue
return
aNetworkType
aIPvAnyInterfaceType
uIPvAnyInterface.__new__
uIPvAnyInterface.__get_pydantic_json_schema__
uIPvAnyInterface.__get_pydantic_core_schema__
D ainput_value
return
aNetworkType
aIPvAnyInterfaceType
uIPvAnyInterface._validate
aIPvAnyNetwork
D avalue
return
aNetworkType
aIPvAnyNetworkType
uIPvAnyNetwork.__new__
uIPvAnyNetwork.__get_pydantic_json_schema__
uIPvAnyNetwork.__get_pydantic_core_schema__
D ainput_value
return
aNetworkType
aIPvAnyNetworkType
uIPvAnyNetwork._validate
D areturn
ure.Pattern[str]
a_build_pretty_email_regex
l  D avalue
return
str
utuple[str, str]
T upydantic.networks
a__getattr__
upydantic\networks.py
u<module pydantic.networks>
T a__class__
T aself
memo
T aself
other
T acls
a_source
a_handler
T aself
source
handler
schema
schema_to_mutate
annotated_type
constraint_key
constraint_value
T acls
source
handler
wrap_val
T acls
core_schema
handler
field_schema
T acls
core_schema
handler
inner_schema
T aself
T aself
name
email
T aself
url
T acls
value
T aname_chars
unquoted_name_group
quoted_name_group
email_group
T acls
T acls
input_value
T acls
input_value
name
email
T
cls
scheme
hosts
username
password
host
port
path
query
fragment
T	acls
scheme
username
password
host
port
path
query
fragment
T aself
value
T weT acls
url
info
T avalue
name
wmaunquoted_name
quoted_name
email
parts
weT wvwhacore_url
instance
source
T asource
a__spec__
.pydantic.parse
uThe `parse` module is a backport module from V1.
a__doc__
a__file__
origin
has_location
a__cached__
a_migration
T agetattr_migration
getattr_migration
T upydantic.parse
a__getattr__
upydantic\parse.py
u<module pydantic.parse>

a__spec__
.pydantic.plugin._loader
W
.
getenv
T aPYDANTIC_DISABLE_PLUGINS
a_loading_plugins
T a__all__
w1atrue
a_plugins
distributions
entry_points
group
aPYDANTIC_ENTRY_POINT_GROUP
value
disabled_plugins
name
split
T w,aload
T EImportError
EAttributeError
warnings
warn
a__name__

u while loading the `
u` Pydantic plugin, this plugin will not be installed.
values
uLoad plugins for Pydantic.
Inspired by: https://github.com/pytest-dev/pluggy/blob/1.3.0/src/pluggy/_manager.py#L376-L402
a__doc__
a__file__
origin
has_location
a__cached__
a__annotations__
annotations
importlib_metadata
os
aTYPE_CHECKING
aFinal
aIterable
pydantic
uFinal[str]
udict[str, PydanticPluginProtocol] | None
bool
D areturn
uIterable[PydanticPluginProtocol]
get_plugins
upydantic\plugin\_loader.py
u<module pydantic.plugin._loader>
T adisabled_plugins
dist
entry_point
wea__spec__
.pydantic.plugin._schema_validator
n

T aSchemaTypePath
aSchemaTypePath
a_loader
T aget_plugins
get_plugins
aPluggableSchemaValidator
aSchemaValidator
uCreate a `SchemaValidator` or `PluggableSchemaValidator` if plugins are installed.
Returns:
If plugins are installed then return `PluggableSchemaValidator`, otherwise return `SchemaValidator`.
a_schema_validator
new_schema_validator
schema
schema_type
schema_type_path
schema_kind
config
plugin_settings
