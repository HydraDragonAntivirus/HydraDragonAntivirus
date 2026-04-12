#ifndef LOG4CPLUS_CONFIG_DEFINES_HXX
#define LOG4CPLUS_CONFIG_DEFINES_HXX

/* */
#cmakedefine LOG4CPLUS_HAVE_SYSLOG_H @LOG4CPLUS_HAVE_SYSLOG_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_ARPA_INET_H @LOG4CPLUS_HAVE_ARPA_INET_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_NETINET_IN_H @LOG4CPLUS_HAVE_NETINET_IN_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_NETINET_TCP_H @LOG4CPLUS_HAVE_NETINET_TCP_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_SYS_TIMEB_H @LOG4CPLUS_HAVE_SYS_TIMEB_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_SYS_TIME_H @LOG4CPLUS_HAVE_SYS_TIME_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_SYS_TYPES_H @LOG4CPLUS_HAVE_SYS_TYPES_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_SYS_STAT_H @LOG4CPLUS_HAVE_SYS_STAT_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_SYS_SYSCALL_H @LOG4CPLUS_HAVE_SYS_SYSCALL_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_SYS_FILE_H @LOG4CPLUS_HAVE_SYS_FILE_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_TIME_H @LOG4CPLUS_HAVE_TIME_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_SYS_SOCKET_H @LOG4CPLUS_HAVE_SYS_SOCKET_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_NETDB_H @LOG4CPLUS_HAVE_NETDB_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_UNISTD_H @LOG4CPLUS_HAVE_UNISTD_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_FCNTL_H @LOG4CPLUS_HAVE_FCNTL_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_STDARG_H @LOG4CPLUS_HAVE_STDARG_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_STDIO_H @LOG4CPLUS_HAVE_STDIO_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_STDLIB_H @LOG4CPLUS_HAVE_STDLIB_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_ERRNO_H @LOG4CPLUS_HAVE_ERRNO_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_WCHAR_H @LOG4CPLUS_HAVE_WCHAR_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_ICONV_H @LOG4CPLUS_HAVE_ICONV_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_LIMITS_H @LOG4CPLUS_HAVE_LIMITS_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_FTIME @LOG4CPLUS_HAVE_FTIME@

/* */
#cmakedefine LOG4CPLUS_HAVE_GETADDRINFO @LOG4CPLUS_HAVE_GETADDRINFO@

/* */
#cmakedefine LOG4CPLUS_HAVE_GETHOSTBYNAME_R @LOG4CPLUS_HAVE_GETHOSTBYNAME_R@

/* */
#cmakedefine LOG4CPLUS_HAVE_GETPID @LOG4CPLUS_HAVE_GETPID@

/* */
#cmakedefine LOG4CPLUS_HAVE_GMTIME_R @LOG4CPLUS_HAVE_GMTIME_R@

/* */
#cmakedefine LOG4CPLUS_HAVE_HTONL @LOG4CPLUS_HAVE_HTONL@

/* */
#cmakedefine LOG4CPLUS_HAVE_HTONS @LOG4CPLUS_HAVE_HTONS@

/* */
#cmakedefine LOG4CPLUS_HAVE_LOCALTIME_R @LOG4CPLUS_HAVE_LOCALTIME_R@

/* */
#cmakedefine LOG4CPLUS_HAVE_LSTAT @LOG4CPLUS_HAVE_LSTAT@

/* */
#cmakedefine LOG4CPLUS_HAVE_FCNTL @LOG4CPLUS_HAVE_FCNTL@

/* */
#cmakedefine LOG4CPLUS_HAVE_LOCKF @LOG4CPLUS_HAVE_LOCKF@

/* */
#cmakedefine LOG4CPLUS_HAVE_FLOCK @LOG4CPLUS_HAVE_FLOCK@

/* */
#cmakedefine LOG4CPLUS_HAVE_NTOHL @LOG4CPLUS_HAVE_NTOHL@

/* */
#cmakedefine LOG4CPLUS_HAVE_NTOHS @LOG4CPLUS_HAVE_NTOHS@

/* Define to 1 if you have the `shutdown' function. */
#cmakedefine LOG4CPLUS_HAVE_SHUTDOWN @LOG4CPLUS_HAVE_SHUTDOWN@

/* */
#cmakedefine LOG4CPLUS_HAVE_PIPE @LOG4CPLUS_HAVE_PIPE@

/* */
#cmakedefine LOG4CPLUS_HAVE_PIPE2 @LOG4CPLUS_HAVE_PIPE2@

/* */
#cmakedefine LOG4CPLUS_HAVE_POLL @LOG4CPLUS_HAVE_POLL@

/* */
#cmakedefine LOG4CPLUS_HAVE_POLL_H @LOG4CPLUS_HAVE_POLL_H@

/* */
#cmakedefine LOG4CPLUS_HAVE_STAT @LOG4CPLUS_HAVE_STAT@

/* Define if this is a single-threaded library. */
#cmakedefine LOG4CPLUS_SINGLE_THREADED @LOG4CPLUS_SINGLE_THREADED@

/* */
#cmakedefine LOG4CPLUS_USE_PTHREADS @LOG4CPLUS_USE_PTHREADS@

/* Define for compilers/standard libraries that support more than just the "C"
   locale. */
#cmakedefine LOG4CPLUS_WORKING_LOCALE @LOG4CPLUS_WORKING_LOCALE@

/* Define for C99 compilers/standard libraries that support more than just the
   "C" locale. */
#cmakedefine LOG4CPLUS_WORKING_C_LOCALE @LOG4CPLUS_WORKING_C_LOCALE@

/* Define to int if undefined. */
#cmakedefine socklen_t @socklen_t@

/* Defined for --enable-debugging builds. */
#cmakedefine LOG4CPLUS_DEBUGGING @LOG4CPLUS_DEBUGGING@

/* Defined if the compiler understands __declspec(dllexport) or
   __attribute__((visibility("default"))) construct. */
#cmakedefine LOG4CPLUS_DECLSPEC_EXPORT @LOG4CPLUS_DECLSPEC_EXPORT@

/* Defined if the compiler understands __declspec(dllimport) or
   __attribute__((visibility("default"))) construct. */
#cmakedefine LOG4CPLUS_DECLSPEC_IMPORT @LOG4CPLUS_DECLSPEC_IMPORT@

/* Defined if the compiler understands
   __attribute__((visibility("hidden"))) construct. */
#cmakedefine LOG4CPLUS_DECLSPEC_PRIVATE @LOG4CPLUS_DECLSPEC_PRIVATE@

/* */
#cmakedefine LOG4CPLUS_HAVE_TLS_SUPPORT @LOG4CPLUS_HAVE_TLS_SUPPORT@

/* */
#cmakedefine LOG4CPLUS_THREAD_LOCAL_VAR @LOG4CPLUS_THREAD_LOCAL_VAR@

/* Defined if the host OS provides ENAMETOOLONG errno value. */
#cmakedefine LOG4CPLUS_HAVE_ENAMETOOLONG @LOG4CPLUS_HAVE_ENAMETOOLONG@

/* */
#cmakedefine LOG4CPLUS_HAVE_VSNPRINTF @LOG4CPLUS_HAVE_VSNPRINTF@

/* Define to 1 if you have the `vsnwprintf' function. */
#cmakedefine LOG4CPLUS_HAVE_VSNWPRINTF @LOG4CPLUS_HAVE_VSNWPRINTF@

/* Define to 1 if you have the `_vsnwprintf' function. */
#cmakedefine LOG4CPLUS_HAVE__VSNWPRINTF @LOG4CPLUS_HAVE__VSNWPRINTF@

/* */
#cmakedefine LOG4CPLUS_HAVE__VSNPRINTF @LOG4CPLUS_HAVE__VSNPRINTF@

/* Define to 1 if you have the `vfprintf_s' function. */
#cmakedefine LOG4CPLUS_HAVE_VFPRINTF_S @LOG4CPLUS_HAVE_VFPRINTF_S@

/* Define to 1 if you have the `vfwprintf_s' function. */
#cmakedefine LOG4CPLUS_HAVE_VFWPRINTF_S @LOG4CPLUS_HAVE_VFWPRINTF_S@

/* Define to 1 if you have the `vsprintf_s' function. */
#cmakedefine LOG4CPLUS_HAVE_VSPRINTF_S @LOG4CPLUS_HAVE_VSPRINTF_S@

/* Define to 1 if you have the `vswprintf_s' function. */
#cmakedefine LOG4CPLUS_HAVE_VSWPRINTF_S @LOG4CPLUS_HAVE_VSWPRINTF_S@

/* Define to 1 if you have the `_vsnprintf_s' function. */
#cmakedefine LOG4CPLUS_HAVE__VSNPRINTF_S @LOG4CPLUS_HAVE__VSNPRINTF_S@

/* Define to 1 if you have the `_vsnwprintf_s' function. */
#cmakedefine LOG4CPLUS_HAVE__VSNWPRINTF_S @LOG4CPLUS_HAVE__VSNWPRINTF_S@

/* Defined if the compiler supports __FUNCTION__ macro. */
#cmakedefine LOG4CPLUS_HAVE_FUNCTION_MACRO @LOG4CPLUS_HAVE_FUNCTION_MACRO@

/* Defined if the compiler supports __PRETTY_FUNCTION__ macro. */
#cmakedefine LOG4CPLUS_HAVE_PRETTY_FUNCTION_MACRO @LOG4CPLUS_HAVE_PRETTY_FUNCTION_MACRO@

/* Defined if the compiler supports __func__ symbol. */
#cmakedefine LOG4CPLUS_HAVE_FUNC_SYMBOL @LOG4CPLUS_HAVE_FUNC_SYMBOL@

/* Define to 1 if you have the `mbstowcs' function. */
#cmakedefine LOG4CPLUS_HAVE_MBSTOWCS @LOG4CPLUS_HAVE_MBSTOWCS@

/* Define to 1 if you have the `wcstombs' function. */
#cmakedefine LOG4CPLUS_HAVE_WCSTOMBS @LOG4CPLUS_HAVE_WCSTOMBS@

/* Define to 1 if you have Linux style syscall(SYS_gettid). */
#cmakedefine LOG4CPLUS_HAVE_GETTID @LOG4CPLUS_HAVE_GETTID@

/* Define when iconv() is available. */
#cmakedefine LOG4CPLUS_WITH_ICONV @LOG4CPLUS_WITH_ICONV@

/* Define to 1 if you have the `iconv' function. */
#cmakedefine LOG4CPLUS_HAVE_ICONV @LOG4CPLUS_HAVE_ICONV@

/* Define to 1 if you have the `iconv_close' function. */
#cmakedefine LOG4CPLUS_HAVE_ICONV_CLOSE @LOG4CPLUS_HAVE_ICONV_CLOSE@

/* Define to 1 if you have the `iconv_open' function. */
#cmakedefine LOG4CPLUS_HAVE_ICONV_OPEN @LOG4CPLUS_HAVE_ICONV_OPEN@

/* Define to 1 if you have the `OutputDebugString' function. */
#cmakedefine LOG4CPLUS_HAVE_OUTPUTDEBUGSTRING @LOG4CPLUS_HAVE_OUTPUTDEBUGSTRING@

/* Define to 1 if the system has the `constructor' function attribute
   with priority */
#cmakedefine LOG4CPLUS_HAVE_FUNC_ATTRIBUTE_CONSTRUCTOR_PRIORITY @LOG4CPLUS_HAVE_FUNC_ATTRIBUTE_CONSTRUCTOR_PRIORITY@

/* Define to 1 if the system has the `constructor' function attribute */
#cmakedefine LOG4CPLUS_HAVE_FUNC_ATTRIBUTE_CONSTRUCTOR @LOG4CPLUS_HAVE_FUNC_ATTRIBUTE_CONSTRUCTOR@

/* Define to 1 if the system has the `init_priority' variable attribute */
#cmakedefine LOG4CPLUS_HAVE_VAR_ATTRIBUTE_INIT_PRIORITY @LOG4CPLUS_HAVE_VAR_ATTRIBUTE_INIT_PRIORITY@

/* Defined to enable unit tests. */
#cmakedefine LOG4CPLUS_WITH_UNIT_TESTS @LOG4CPLUS_WITH_UNIT_TESTS@

#endif // LOG4CPLUS_CONFIG_DEFINES_HXX
