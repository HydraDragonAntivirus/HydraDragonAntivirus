# Reconstructed from integrated Nuitka blob
# Module: uasn1crypto.util


Utc class where dst does not return None; required for astimezone
a__qualname__
aUTC
tzname
u_UtcWithDst.tzname
u_UtcWithDst.utcoffset
dst
u_UtcWithDst.dst
a__orig_bases__
utc_with_dst
create_timezone
T Oobject

A datetime.datetime-like object that represents the year 0. This is just
to handle 0000-01-01 found in some certificates. Python's datetime does
not support year 0.
The proleptic gregorian calendar repeats itself every 400 years. Therefore,
the simplest way to format is to substitute year 2000.
a__init__
uextended_date.__init__
property

:return:
The integer 0
uextended_date.year
uextended_date.month
uextended_date.day
uextended_date.strftime
uextended_date.isoformat
T nnnuextended_date.replace
a__str__
uextended_date.__str__
uextended_date.__eq__
a__ne__
uextended_date.__ne__
uextended_date._comparison_error
uextended_date.__cmp__
a__lt__
uextended_date.__lt__
a__le__
uextended_date.__le__
a__gt__
uextended_date.__gt__
a__ge__
uextended_date.__ge__
l   aDAYS_IN_400_YEARS
l uextended_datetime.__init__
uextended_datetime.year
uextended_datetime.month
uextended_datetime.day
uextended_datetime.hour
uextended_datetime.minute
uextended_datetime.second
uextended_datetime.microsecond
uextended_datetime.tzinfo
uextended_datetime.utcoffset
uextended_datetime.time
uextended_datetime.date
uextended_datetime.strftime
T wTuextended_datetime.isoformat
T nuextended_datetime.replace
uextended_datetime.astimezone
uextended_datetime.timestamp
uextended_datetime.__str__
uextended_datetime.__eq__
uextended_datetime.__ne__
uextended_datetime._comparison_error
uextended_datetime.__cmp__
uextended_datetime.__lt__
uextended_datetime.__le__
uextended_datetime.__gt__
uextended_datetime.__ge__
a__add__
uextended_datetime.__add__
a__sub__
uextended_datetime.__sub__
a__rsub__
uextended_datetime.__rsub__
classmethod
uextended_datetime.from_y2k
uasn1crypto\util.py
T a.0
c2
c4
u<module asn1crypto.util>
T a__class__
T aself
other
T aself
other
diff
zero
T aself
year
month
day
T aself
year
args
kwargs
T aself
T aoff
mins
sign
T aself
tz
T aoffset
tz
T aself
dt
T acls
value
year
new_cls
T avalue
signed
T avalue
signed
width
bits_required
T aself
sep
wsT aself
year
month
day
cls
T aself
format
y2k
y4k
a__spec__
.asn1crypto.version
a__doc__
a__file__
origin
has_location
a__cached__
unicode_literals
division
absolute_import
print_function
u1.5.1
a__version__
T l l l a__version_info__
uasn1crypto\version.py
u<module asn1crypto.version>

a__spec__
.async_timeout
x
asyncio
get_running_loop
time
aTimeout
utimeout context manager.
Useful in cases when you want to apply timeout logic around block
of code or in cases when asyncio.wait_for is not suitable. For example:
>>> async with timeout(0.001):
...     async with aiohttp.get('https://github.com') as r:
...         await r.text()
delay - value in seconds or None to disable timeout logic
uSchedule the timeout at absolute time.
deadline argument points on the time in the same clock system
s loop.time().
Please note: it is not POSIX time but a time with
undefined starting base, e.g. the time of the system power on.
>>> async with timeout_at(loop.time() + 10):
...     async with aiohttp.get('https://github.com') as r:
...         await r.text()
a_loop
a_State
aINIT
a_state
a_task
a_timeout_handler
a_deadline
update
self
a_do_enter
a__aenter__
uTimeout.__aenter__
a_do_exit
exc_type
a__aexit__
uTimeout.__aexit__
aTIMEOUT
uIs timeout expired during execution?
aENTER
uinvalid state
value

a_reject
uReject scheduled timeout if any.
cancel
ucannot shift timeout if deadline is not scheduled
uAdvance timeout on delay seconds.
The delay can be negative.
Raise RuntimeError if shift is called when deadline is not scheduled
aEXIT
ucannot reschedule after exit from context manager
ucannot reschedule expired timeout
a_reschedule
uSet deadline to absolute value.
deadline argument points on the time in the same clock system
s loop.time().
If new deadline is in the past the timeout is raised immediately.
Please note: it is not POSIX time but a time with
undefined starting base, e.g. the time of the system power on.
current_task
call_soon
a_on_timeout
call_at
aCancelledError
aTimeoutError
a__doc__
a__file__
path
dirname
environ
get
T aNUITKA_PACKAGE_async_timeout
u\not_existing
a__path__
origin
has_location
submodule_search_locations
a__cached__
enum
sys
aTracebackType
aOptional
aType
final
u5.0.1
a__version__
T atimeout
timeout_at
aTimeout
a__all__
delay
return
timeout
deadline
timeout_at
aEnum
a__prepare__
a__getitem__
u%s.__prepare__() must return a mapping, not %s
a__name__
u<metaclass>
