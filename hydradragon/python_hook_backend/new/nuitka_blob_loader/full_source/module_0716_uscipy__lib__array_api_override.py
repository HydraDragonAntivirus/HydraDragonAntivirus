# Reconstructed from integrated Nuitka blob
# Module: uscipy._lib._array_api_override

a__qualname__
l l l a__orig_bases__
T lduscipy\_lib\_array_api_override.py
u<module scipy._lib._array_api_override>
T a__class__
T acls
msg
T aarrays
numpy_arrays
api_arrays
array
arr_info
.scipy._lib._bunch
k
utypename and all field names must be strings
isidentifier
utypename and all field names must be valid identifiers:

a_iskeyword
utypename and all field names cannot be a keyword:
startswith
T w_uField names cannot start with an underscore:
seen
uDuplicate field name:
add
ufield_names must contain at least one name
a_validate_names
intern
u,
w(w)a__new__
T Odict
Otuple
Ozip
utoo many values to unpack (expected 3)
udef __new__(_cls,
u, **extra_fields):
return _tuple_new(_cls, (
u,))
def __init__(self,
u, **extra_fields):
for key in self._extra_fields:
if key not in extra_fields:
raise TypeError("missing keyword argument '%s'" % (key,))
for key, val in extra_fields.items():
if key not in self._extra_fields:
raise TypeError("unexpected keyword argument '%s'" % (key,))
self.__dict__[key] = val
def __setattr__(self, key, val):
if key in
u:
raise AttributeError("can't set attribute %r of class %r"
% (key, self.__class__.__name__))
else:
self.__dict__[key] = val
a_tuple_new
a__builtins__
D aTypeError
aAttributeError
ETypeError
EAttributeError
a__name__
namedtuple_
typename
field_names
extra_field_names
module
all_names
arg_list
full_list
repr_fmt
tuple_new
a_dict
a_tuple
a_zip
wsanamespace
u<string>
exec
uCreate new instance of
a__doc__
a__init__
uInstantiate instance of
a__setattr__
a__repr__
u_make_tuple_bunch.<locals>.__repr__
a_asdict
u_make_tuple_bunch.<locals>._asdict
a__getnewargs_ex__
u_make_tuple_bunch.<locals>.__getnewargs_ex__
w.a__qualname__
a_fields
a_extra_fields
a_field_defaults
a_replace
utoo many values to unpack (expected 2)
a_get
u_make_tuple_bunch.<locals>._get
class_namespace
T Otuple
uscipy._lib._bunch
a_getframe
T l af_globals
get
T a__name__
a__main__
T EAttributeError
