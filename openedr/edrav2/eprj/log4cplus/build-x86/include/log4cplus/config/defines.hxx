#ifndef LOG4CPLUS_CONFIG_DEFINES_HXX
#define LOG4CPLUS_CONFIG_DEFINES_HXX

/* */
/* #undef LOG4CPLUS_HAVE_SYSLOG_H */

/* */
/* #undef LOG4CPLUS_HAVE_ARPA_INET_H */

/* */
/* #undef LOG4CPLUS_HAVE_NETINET_IN_H */

/* */
/* #undef LOG4CPLUS_HAVE_NETINET_TCP_H */

/* */
#define LOG4CPLUS_HAVE_SYS_TIMEB_H 1

/* */
/* #undef LOG4CPLUS_HAVE_SYS_TIME_H */

/* */
#define LOG4CPLUS_HAVE_SYS_TYPES_H 1

/* */
#define LOG4CPLUS_HAVE_SYS_STAT_H 1

/* */
/* #undef LOG4CPLUS_HAVE_SYS_SYSCALL_H */

/* */
/* #undef LOG4CPLUS_HAVE_SYS_FILE_H */

/* */
#define LOG4CPLUS_HAVE_TIME_H 1

/* */
/* #undef LOG4CPLUS_HAVE_SYS_SOCKET_H */

/* */
/* #undef LOG4CPLUS_HAVE_NETDB_H */

/* */
/* #undef LOG4CPLUS_HAVE_UNISTD_H */

/* */
#define LOG4CPLUS_HAVE_FCNTL_H 1

/* */
#define LOG4CPLUS_HAVE_STDARG_H 1

/* */
#define LOG4CPLUS_HAVE_STDIO_H 1

/* */
#define LOG4CPLUS_HAVE_STDLIB_H 1

/* */
#define LOG4CPLUS_HAVE_ERRNO_H 1

/* */
#define LOG4CPLUS_HAVE_WCHAR_H 1

/* */
/* #undef LOG4CPLUS_HAVE_ICONV_H */

/* */
#define LOG4CPLUS_HAVE_LIMITS_H 1

/* */
#define LOG4CPLUS_HAVE_FTIME 1

/* */
/* #undef LOG4CPLUS_HAVE_GETADDRINFO */

/* */
/* #undef LOG4CPLUS_HAVE_GETHOSTBYNAME_R */

/* */
#define LOG4CPLUS_HAVE_GETPID 1

/* */
/* #undef LOG4CPLUS_HAVE_GMTIME_R */

/* */
/* #undef LOG4CPLUS_HAVE_HTONL */

/* */
/* #undef LOG4CPLUS_HAVE_HTONS */

/* */
/* #undef LOG4CPLUS_HAVE_LOCALTIME_R */

/* */
/* #undef LOG4CPLUS_HAVE_LSTAT */

/* */
/* #undef LOG4CPLUS_HAVE_FCNTL */

/* */
/* #undef LOG4CPLUS_HAVE_LOCKF */

/* */
/* #undef LOG4CPLUS_HAVE_FLOCK */

/* */
/* #undef LOG4CPLUS_HAVE_NTOHL */

/* */
/* #undef LOG4CPLUS_HAVE_NTOHS */

/* Define to 1 if you have the `shutdown' function. */
/* #undef LOG4CPLUS_HAVE_SHUTDOWN */

/* */
/* #undef LOG4CPLUS_HAVE_PIPE */

/* */
/* #undef LOG4CPLUS_HAVE_PIPE2 */

/* */
/* #undef LOG4CPLUS_HAVE_POLL */

/* */
/* #undef LOG4CPLUS_HAVE_POLL_H */

/* */
#define LOG4CPLUS_HAVE_STAT 1

/* Define if this is a single-threaded library. */
/* #undef LOG4CPLUS_SINGLE_THREADED */

/* */
/* #undef LOG4CPLUS_USE_PTHREADS */

/* Define for compilers/standard libraries that support more than just the "C"
   locale. */
#define LOG4CPLUS_WORKING_LOCALE ON

/* Define for C99 compilers/standard libraries that support more than just the
   "C" locale. */
/* #undef LOG4CPLUS_WORKING_C_LOCALE */

/* Define to int if undefined. */
#define socklen_t TRUE

/* Defined for --enable-debugging builds. */
/* #undef LOG4CPLUS_DEBUGGING */

/* Defined if the compiler understands __declspec(dllexport) or
   __attribute__((visibility("default"))) construct. */
#define LOG4CPLUS_DECLSPEC_EXPORT __declspec(dllexport)

/* Defined if the compiler understands __declspec(dllimport) or
   __attribute__((visibility("default"))) construct. */
#define LOG4CPLUS_DECLSPEC_IMPORT __declspec(dllimport)

/* Defined if the compiler understands
   __attribute__((visibility("hidden"))) construct. */
/* #undef LOG4CPLUS_DECLSPEC_PRIVATE */

/* */
#define LOG4CPLUS_HAVE_TLS_SUPPORT 1

/* */
#define LOG4CPLUS_THREAD_LOCAL_VAR thread_local

/* Defined if the host OS provides ENAMETOOLONG errno value. */
#define LOG4CPLUS_HAVE_ENAMETOOLONG 1

/* */
/* #undef LOG4CPLUS_HAVE_VSNPRINTF */

/* Define to 1 if you have the `vsnwprintf' function. */
/* #undef LOG4CPLUS_HAVE_VSNWPRINTF */

/* Define to 1 if you have the `_vsnwprintf' function. */
/* #undef LOG4CPLUS_HAVE__VSNWPRINTF */

/* */
/* #undef LOG4CPLUS_HAVE__VSNPRINTF */

/* Define to 1 if you have the `vfprintf_s' function. */
/* #undef LOG4CPLUS_HAVE_VFPRINTF_S */

/* Define to 1 if you have the `vfwprintf_s' function. */
/* #undef LOG4CPLUS_HAVE_VFWPRINTF_S */

/* Define to 1 if you have the `vsprintf_s' function. */
/* #undef LOG4CPLUS_HAVE_VSPRINTF_S */

/* Define to 1 if you have the `vswprintf_s' function. */
/* #undef LOG4CPLUS_HAVE_VSWPRINTF_S */

/* Define to 1 if you have the `_vsnprintf_s' function. */
/* #undef LOG4CPLUS_HAVE__VSNPRINTF_S */

/* Define to 1 if you have the `_vsnwprintf_s' function. */
/* #undef LOG4CPLUS_HAVE__VSNWPRINTF_S */

/* Defined if the compiler supports __FUNCTION__ macro. */
#define LOG4CPLUS_HAVE_FUNCTION_MACRO 1

/* Defined if the compiler supports __PRETTY_FUNCTION__ macro. */
/* #undef LOG4CPLUS_HAVE_PRETTY_FUNCTION_MACRO */

/* Defined if the compiler supports __func__ symbol. */
#define LOG4CPLUS_HAVE_FUNC_SYMBOL 1

/* Define to 1 if you have the `mbstowcs' function. */
#define LOG4CPLUS_HAVE_MBSTOWCS 1

/* Define to 1 if you have the `wcstombs' function. */
#define LOG4CPLUS_HAVE_WCSTOMBS 1

/* Define to 1 if you have Linux style syscall(SYS_gettid). */
/* #undef LOG4CPLUS_HAVE_GETTID */

/* Define when iconv() is available. */
/* #undef LOG4CPLUS_WITH_ICONV */

/* Define to 1 if you have the `iconv' function. */
/* #undef LOG4CPLUS_HAVE_ICONV */

/* Define to 1 if you have the `iconv_close' function. */
/* #undef LOG4CPLUS_HAVE_ICONV_CLOSE */

/* Define to 1 if you have the `iconv_open' function. */
/* #undef LOG4CPLUS_HAVE_ICONV_OPEN */

/* Define to 1 if you have the `OutputDebugString' function. */
/* #undef LOG4CPLUS_HAVE_OUTPUTDEBUGSTRING */

/* Define to 1 if the system has the `constructor' function attribute
   with priority */
/* #undef LOG4CPLUS_HAVE_FUNC_ATTRIBUTE_CONSTRUCTOR_PRIORITY */

/* Define to 1 if the system has the `constructor' function attribute */
/* #undef LOG4CPLUS_HAVE_FUNC_ATTRIBUTE_CONSTRUCTOR */

/* Define to 1 if the system has the `init_priority' variable attribute */
/* #undef LOG4CPLUS_HAVE_VAR_ATTRIBUTE_INIT_PRIORITY */

/* Defined to enable unit tests. */
#define LOG4CPLUS_WITH_UNIT_TESTS 1

#endif // LOG4CPLUS_CONFIG_DEFINES_HXX
