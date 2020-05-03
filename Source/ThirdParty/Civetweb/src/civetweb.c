/* Copyright (c) 2013-2018 the Civetweb developers
 * Copyright (c) 2004-2013 Sergey Lyubka
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


// Modified by cosmy1, Yao Wei Tjong & Lasse Oorni for Urho3D


#if defined(__GNUC__) || defined(__MINGW32__)
#define GCC_VERSION                                                            \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if GCC_VERSION >= 40500
/* gcc diagnostic pragmas available */
#define GCC_DIAGNOSTIC
#endif
#endif

#if defined(GCC_DIAGNOSTIC)
/* Disable unused macros warnings - not all defines are required
 * for all systems and all compilers. */
#pragma GCC diagnostic ignored "-Wunused-macros"
/* A padding warning is just plain useless */
#pragma GCC diagnostic ignored "-Wpadded"
#endif

#if defined(__clang__) /* GCC does not (yet) support this pragma */
/* We must set some flags for the headers we include. These flags
 * are reserved ids according to C99, so we need to disable a
 * warning for that. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreserved-id-macro"
#endif

#if defined(_WIN32)
#if !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS /* Disable deprecation warning in VS2005 */
#endif
#if !defined(_WIN32_WINNT) /* defined for tdm-gcc so we can use getnameinfo */
#define _WIN32_WINNT 0x0501
#endif
#else
#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE /* for setgroups(), pthread_setname_np() */
#endif
#if defined(__linux__) && !defined(_XOPEN_SOURCE)
#define _XOPEN_SOURCE 600 /* For flockfile() on Linux */
#endif
#if !defined(_LARGEFILE_SOURCE)
#define _LARGEFILE_SOURCE /* For fseeko(), ftello() */
#endif
#if !defined(_FILE_OFFSET_BITS)
#define _FILE_OFFSET_BITS 64 /* Use 64-bit file offsets by default */
#endif
#if !defined(__STDC_FORMAT_MACROS)
#define __STDC_FORMAT_MACROS /* <inttypes.h> wants this for C++ */
#endif
#if !defined(__STDC_LIMIT_MACROS)
#define __STDC_LIMIT_MACROS /* C++ wants that for INT64_MAX */
#endif
#if !defined(_DARWIN_UNLIMITED_SELECT)
#define _DARWIN_UNLIMITED_SELECT
#endif
#if defined(__sun)
#define __EXTENSIONS__  /* to expose flockfile and friends in stdio.h */
#define __inline inline /* not recognized on older compiler versions */
#endif
#endif

#if defined(__clang__)
/* Enable reserved-id-macro warning again. */
#pragma GCC diagnostic pop
#endif


#if defined(USE_LUA)
#define USE_TIMERS
#endif

#if defined(_MSC_VER)
/* 'type cast' : conversion from 'int' to 'HANDLE' of greater size */
#pragma warning(disable : 4306)
/* conditional expression is constant: introduced by FD_SET(..) */
#pragma warning(disable : 4127)
/* non-constant aggregate initializer: issued due to missing C99 support */
#pragma warning(disable : 4204)
/* padding added after data member */
#pragma warning(disable : 4820)
/* not defined as a preprocessor macro, replacing with '0' for '#if/#elif' */
#pragma warning(disable : 4668)
/* no function prototype given: converting '()' to '(void)' */
#pragma warning(disable : 4255)
/* function has been selected for automatic inline expansion */
#pragma warning(disable : 4711)
#endif


/* This code uses static_assert to check some conditions.
 * Unfortunately some compilers still do not support it, so we have a
 * replacement function here. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ > 201100L
#define mg_static_assert _Static_assert
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define mg_static_assert static_assert
#else
char static_assert_replacement[1];
#define mg_static_assert(cond, txt)                                            \
    extern char static_assert_replacement[(cond) ? 1 : -1]
#endif

mg_static_assert(sizeof(int) == 4 || sizeof(int) == 8,
                 "int data type size check");
mg_static_assert(sizeof(void *) == 4 || sizeof(void *) == 8,
                 "pointer data type size check");
mg_static_assert(sizeof(void *) >= sizeof(int), "data type size check");


/* Alternative queue is well tested and should be the new default */
#if defined(NO_ALTERNATIVE_QUEUE)
#if defined(ALTERNATIVE_QUEUE)
#error "Define ALTERNATIVE_QUEUE or NO_ALTERNATIVE_QUEUE or none, but not both"
#endif
#else
#define ALTERNATIVE_QUEUE
#endif


/* DTL -- including winsock2.h works better if lean and mean */
#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#endif

#if defined(__SYMBIAN32__)
/* According to https://en.wikipedia.org/wiki/Symbian#History,
 * Symbian is no longer maintained since 2014-01-01.
 * Recent versions of CivetWeb are no longer tested for Symbian.
 * It makes no sense, to support an abandoned operating system.
 */
#error "Symbian is no longer maintained. CivetWeb no longer supports Symbian."
#define NO_SSL /* SSL is not supported */
#define NO_CGI /* CGI is not supported */
#define PATH_MAX FILENAME_MAX
#endif /* __SYMBIAN32__ */


#if !defined(CIVETWEB_HEADER_INCLUDED)
/* Include the header file here, so the CivetWeb interface is defined for the
 * entire implementation, including the following forward definitions. */
#include "civetweb.h"
#endif

#if !defined(DEBUG_TRACE)
#if defined(DEBUG)
mg_static_assert(MAX_WORKER_THREADS >= 1,

mg_static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8,
                 "size_t data type size check");

#if defined(_WIN32) /* WINDOWS include block */
#include <windows.h>
#include <winsock2.h> /* DTL add for SO_EXCLUSIVE */
#include <ws2tcpip.h>

typedef const char *SOCK_OPT_TYPE;

#if !defined(PATH_MAX)
#define W_PATH_MAX (MAX_PATH)
/* at most three UTF-8 chars per wchar_t */
#define PATH_MAX (W_PATH_MAX * 3)
#else
#define W_PATH_MAX ((PATH_MAX + 2) / 3)
#endif

mg_static_assert(PATH_MAX >= 1, "path length must be a positive number");

#if !defined(_IN_PORT_T)
#if !defined(in_port_t)
#define in_port_t u_short
#endif
#endif

#if !defined(_WIN32_WCE)
#include <direct.h>
#include <io.h>
#include <process.h>
#else            /* _WIN32_WCE */
#define NO_CGI   /* WinCE has no pipes */
#define NO_POPEN /* WinCE has no popen */

typedef long off_t;

#define errno ((int)(GetLastError()))
#define strerror(x) (_ultoa(x, (char *)_alloca(sizeof(x) * 3), 10))
#endif /* _WIN32_WCE */

#define MAKEUQUAD(lo, hi)                                                      \
    ((uint64_t)(((uint32_t)(lo)) | ((uint64_t)((uint32_t)(hi))) << 32))
#define RATE_DIFF (10000000) /* 100 nsecs */
#define EPOCH_DIFF (MAKEUQUAD(0xd53e8000, 0x019db1de))
#define SYS2UNIX_TIME(lo, hi)                                                  \
    ((time_t)((MAKEUQUAD((lo), (hi)) - EPOCH_DIFF) / RATE_DIFF))

/* Visual Studio 6 does not know __func__ or __FUNCTION__
 * The rest of MS compilers use __FUNCTION__, not C99 __func__
 * Also use _strtoui64 on modern M$ compilers */
#if defined(_MSC_VER)
#if (_MSC_VER < 1300)
#define STRX(x) #x
#define STR(x) STRX(x)
#define __func__ __FILE__ ":" STR(__LINE__)
#define strtoull(x, y, z) ((unsigned __int64)_atoi64(x))
#define strtoll(x, y, z) (_atoi64(x))
#else
#define __func__ __FUNCTION__
#define strtoull(x, y, z) (_strtoui64(x, y, z))
#define strtoll(x, y, z) (_strtoi64(x, y, z))
#endif
#endif /* _MSC_VER */

#define ERRNO ((int)(GetLastError()))
#define NO_SOCKLEN_T

#if defined(_WIN64) || defined(__MINGW64__)
#if !defined(SSL_LIB)
#define SSL_LIB "ssleay64.dll"
#endif
#if !defined(CRYPTO_LIB)
#define CRYPTO_LIB "libeay64.dll"
#endif
#else
#if !defined(SSL_LIB)
#define SSL_LIB "ssleay32.dll"
#endif
#if !defined(CRYPTO_LIB)
#define CRYPTO_LIB "libeay32.dll"
#endif
#endif

#define O_NONBLOCK (0)
#if !defined(W_OK)
#define W_OK (2) /* http://msdn.microsoft.com/en-us/library/1w06ktdy.aspx */
#endif
#if !defined(EWOULDBLOCK)
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif /* !EWOULDBLOCK */
#define _POSIX_
#define INT64_FMT "I64d"
#define UINT64_FMT "I64u"

#define WINCDECL __cdecl
#define vsnprintf_impl _vsnprintf
#define access _access
#define mg_sleep(x) (Sleep(x))

#define pipe(x) _pipe(x, MG_BUF_LEN, _O_BINARY)
#if !defined(popen)
#define popen(x, y) (_popen(x, y))
#endif
#if !defined(pclose)
#define pclose(x) (_pclose(x))
#endif
#define close(x) (_close(x))
#define dlsym(x, y) (GetProcAddress((HINSTANCE)(x), (y)))
#define RTLD_LAZY (0)
#define fseeko(x, y, z) ((_lseeki64(_fileno(x), (y), (z)) == -1) ? -1 : 0)
#define fdopen(x, y) (_fdopen((x), (y)))
#define write(x, y, z) (_write((x), (y), (unsigned)z))
#define read(x, y, z) (_read((x), (y), (unsigned)z))
#define flockfile(x) (EnterCriticalSection(&global_log_file_lock))
#define funlockfile(x) (LeaveCriticalSection(&global_log_file_lock))
#define sleep(x) (Sleep((x)*1000))
#define rmdir(x) (_rmdir(x))
#if defined(_WIN64) || !defined(__MINGW32__)
/* Only MinGW 32 bit is missing this function */
#define timegm(x) (_mkgmtime(x))
#else
time_t timegm(struct tm *tm);
#define NEED_TIMEGM
#endif


#if !defined(fileno)
#define fileno(x) (_fileno(x))
#endif /* !fileno MINGW #defines fileno */

typedef HANDLE pthread_mutex_t;
typedef DWORD pthread_key_t;
typedef HANDLE pthread_t;
typedef struct {
CRITICAL_SECTION threadIdSec;
struct mg_workerTLS *waiting_thread; /* The chain of threads */
} pthread_cond_t;

#if !defined(__clockid_t_defined)
typedef DWORD clockid_t;
#endif
#if !defined(CLOCK_MONOTONIC)
#define CLOCK_MONOTONIC (1)
#endif
#if !defined(CLOCK_REALTIME)
#define CLOCK_REALTIME (2)
#endif
#if !defined(CLOCK_THREAD)
#define CLOCK_THREAD (3)
#endif
#if !defined(CLOCK_PROCESS)
#define CLOCK_PROCESS (4)
#endif


#if defined(_MSC_VER) && (_MSC_VER >= 1900)
#define _TIMESPEC_DEFINED
#endif
#if !defined(_TIMESPEC_DEFINED)
struct timespec {
time_t tv_sec; /* seconds */
long tv_nsec;  /* nanoseconds */
};
#endif

#if defined(_MSC_VER) && (_MSC_VER >= 1900)
#define _TIMESPEC_DEFINED
#endif
#if !defined(_TIMESPEC_DEFINED)
struct timespec {
time_t tv_sec; /* seconds */
long tv_nsec;  /* nanoseconds */
};
#endif

#if !defined(WIN_PTHREADS_TIME_H)
#define MUST_IMPLEMENT_CLOCK_GETTIME
#endif

#if defined(MUST_IMPLEMENT_CLOCK_GETTIME)
#define clock_gettime mg_clock_gettime
static int
clock_gettime(clockid_t clk_id, struct timespec *tp)
{
FILETIME ft;
ULARGE_INTEGER li, li2;
BOOL ok = FALSE;
double d;
static double perfcnt_per_sec = 0.0;
static BOOL initialized = FALSE;

if (!initialized) {
QueryPerformanceFrequency((LARGE_INTEGER *)&li);
perfcnt_per_sec = 1.0 / li.QuadPart;
initialized = TRUE;
}

if (tp) {
memset(tp, 0, sizeof(*tp));

if (clk_id == CLOCK_REALTIME) {

/* BEGIN: CLOCK_REALTIME = wall clock (date and time) */
GetSystemTimeAsFileTime(&ft);
li.LowPart = ft.dwLowDateTime;
li.HighPart = ft.dwHighDateTime;
li.QuadPart -= 116444736000000000; /* 1.1.1970 in filedate */
tp->tv_sec = (time_t)(li.QuadPart / 10000000);
tp->tv_nsec = (long)(li.QuadPart % 10000000) * 100;
ok = TRUE;
/* END: CLOCK_REALTIME */

} else if (clk_id == CLOCK_MONOTONIC) {

/* BEGIN: CLOCK_MONOTONIC = stopwatch (time differences) */
QueryPerformanceCounter((LARGE_INTEGER *)&li);
d = li.QuadPart * perfcnt_per_sec;
tp->tv_sec = (time_t)d;
d -= (double)tp->tv_sec;
tp->tv_nsec = (long)(d * 1.0E9);
ok = TRUE;
/* END: CLOCK_MONOTONIC */

} else if (clk_id == CLOCK_THREAD) {

/* BEGIN: CLOCK_THREAD = CPU usage of thread */
FILETIME t_create, t_exit, t_kernel, t_user;
if (GetThreadTimes(GetCurrentThread(),
&t_create,
&t_exit,
&t_kernel,
&t_user)) {
li.LowPart = t_user.dwLowDateTime;
li.HighPart = t_user.dwHighDateTime;
li2.LowPart = t_kernel.dwLowDateTime;
li2.HighPart = t_kernel.dwHighDateTime;
li.QuadPart += li2.QuadPart;
tp->tv_sec = (time_t)(li.QuadPart / 10000000);
tp->tv_nsec = (long)(li.QuadPart % 10000000) * 100;
ok = TRUE;
}
/* END: CLOCK_THREAD */

} else if (clk_id == CLOCK_PROCESS) {

/* BEGIN: CLOCK_PROCESS = CPU usage of process */
FILETIME t_create, t_exit, t_kernel, t_user;
if (GetProcessTimes(GetCurrentProcess(),
&t_create,
&t_exit,
&t_kernel,
&t_user)) {
li.LowPart = t_user.dwLowDateTime;
li.HighPart = t_user.dwHighDateTime;
li2.LowPart = t_kernel.dwLowDateTime;
li2.HighPart = t_kernel.dwHighDateTime;
li.QuadPart += li2.QuadPart;
tp->tv_sec = (time_t)(li.QuadPart / 10000000);
tp->tv_nsec = (long)(li.QuadPart % 10000000) * 100;
ok = TRUE;
}
/* END: CLOCK_PROCESS */

} else {

/* BEGIN: unknown clock */
/* ok = FALSE; already set by init */
/* END: unknown clock */
}
}

return ok ? 0 : -1;
}
#endif


#define pid_t HANDLE /* MINGW typedefs pid_t to int. Using #define here. */

static int pthread_mutex_lock(pthread_mutex_t *);
static int pthread_mutex_unlock(pthread_mutex_t *);
static void path_to_unicode(const struct mg_connection *conn,
const char *path,
wchar_t *wbuf,
size_t wbuf_len);

/* All file operations need to be rewritten to solve #246. */

struct mg_file;

static const char *
mg_fgets(char *buf, size_t size, struct mg_file *filep, char **p);


/* POSIX dirent interface */
struct dirent {
char d_name[PATH_MAX];
};

typedef struct DIR {
HANDLE handle;
WIN32_FIND_DATAW info;
struct dirent result;
} DIR;

#if defined(_WIN32)
#if !defined(HAVE_POLL)
struct pollfd {
SOCKET fd;
short events;
short revents;
};
#endif
#endif

/* Mark required libraries */
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif

#else /* defined(_WIN32) - WINDOWS vs UNIX include block */

#include <arpa/inet.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
typedef const void *SOCK_OPT_TYPE;

#if defined(ANDROID)
typedef unsigned short int in_port_t;
#endif

#if defined(ANDROID)
typedef unsigned short int in_port_t;
#define vsnprintf_impl vsnprintf
#if !defined(NO_SSL_DL) && !defined(NO_SSL)


#endif

#include <pthread.h>

#if defined(__MACH__)
#define SSL_LIB "libssl.dylib"
#define CRYPTO_LIB "libcrypto.dylib"
#else
#if !defined(SSL_LIB)
#define SSL_LIB "libssl.so"
#endif
#if !defined(CRYPTO_LIB)
#define CRYPTO_LIB "libcrypto.so"
#endif
#endif
#if !defined(O_BINARY)
#define O_BINARY (0)
#endif /* O_BINARY */
#define closesocket(a) (close(a))
#define mg_mkdir(conn, path, mode) (mkdir(path, mode))
#define mg_remove(conn, x) (remove(x))
#define mg_sleep(x) (usleep((x)*1000))
#define mg_opendir(conn, x) (opendir(x))
#define mg_closedir(x) (closedir(x))
#define mg_readdir(x) (readdir(x))
#define ERRNO (errno)
#define INVALID_SOCKET (-1)
#define INT64_FMT PRId64
#define UINT64_FMT PRIu64
typedef int SOCKET;
#define WINCDECL

#if defined(__hpux)
/* HPUX 11 does not have monotonic, fall back to realtime */
#if !defined(CLOCK_MONOTONIC)
#define CLOCK_MONOTONIC CLOCK_REALTIME
#endif

/* HPUX defines socklen_t incorrectly as size_t which is 64bit on
 * Itanium.  Without defining _XOPEN_SOURCE or _XOPEN_SOURCE_EXTENDED
 * the prototypes use int* rather than socklen_t* which matches the
 * actual library expectation.  When called with the wrong size arg
 * accept() returns a zero client inet addr and check_acl() always
 * fails.  Since socklen_t is widely used below, just force replace
 * their typedef with int. - DTL
 */
#define socklen_t int
#endif /* hpux */

#endif /* defined(_WIN32) - WINDOWS vs UNIX include block */

/* Maximum queue length for pending connections. This value is passed as
 * parameter to the "listen" socket call. */
#if !defined(SOMAXCONN)
/* This symbol may be defined in winsock2.h so this must after that include */
#define SOMAXCONN (100) /* in pending connections (count) */
#endif

/* In case our C library is missing "timegm", provide an implementation */
#if defined(NEED_TIMEGM)
static inline int
is_leap(int y)
{
return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static inline int
count_leap(int y)
{
    return (y - 1969) / 4 - (y - 1901) / 100 + (y - 1601) / 400;
}

time_t
timegm(struct tm *tm)
{
    static const unsigned short ydays[] = {
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365};
    int year = tm->tm_year + 1900;
    int mon = tm->tm_mon;
    int mday = tm->tm_mday - 1;
    int hour = tm->tm_hour;
    int min = tm->tm_min;
    int sec = tm->tm_sec;

    if (year < 1970 || mon < 0 || mon > 11 || mday < 0
    || (mday >= ydays[mon + 1] - ydays[mon]
    + (mon == 1 && is_leap(year) ? 1 : 0))
    || hour < 0 || hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 60)
    return -1;

    time_t res = year - 1970;
    res *= 365;
    res += mday;
    res += ydays[mon] + (mon > 1 && is_leap(year) ? 1 : 0);
    res += count_leap(year);

    res *= 24;
    res += hour;
    res *= 60;
    res += min;
    res *= 60;
    res += sec;
    return res;
}
#endif /* NEED_TIMEGM */


/* va_copy should always be a macro, C99 and C++11 - DTL */
#if !defined(va_copy)
#define va_copy(x, y) ((x) = (y))
#endif


#if defined(_WIN32)
/* Create substitutes for POSIX functions in Win32. */

#if defined(GCC_DIAGNOSTIC)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif


static CRITICAL_SECTION global_log_file_lock;

FUNCTION_MAY_BE_UNUSED
static DWORD
pthread_self(void)
{
return GetCurrentThreadId();
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_key_create(
pthread_key_t *key,
void (*_ignored)(void *) /* destructor not supported for Windows */
)
{
(void)_ignored;

if ((key != 0)) {
*key = TlsAlloc();
return (*key != TLS_OUT_OF_INDEXES) ? 0 : -1;
}
return -2;
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_key_delete(pthread_key_t key)
{
return TlsFree(key) ? 0 : 1;
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_setspecific(pthread_key_t key, void *value)
{
return TlsSetValue(key, value) ? 0 : 1;
}


FUNCTION_MAY_BE_UNUSED
static void *
pthread_getspecific(pthread_key_t key)
{
return TlsGetValue(key);
}

#if defined(GCC_DIAGNOSTIC)
/* Enable unused function warning again */
#pragma GCC diagnostic pop
#endif

static struct pthread_mutex_undefined_struct *pthread_mutex_attr = NULL;
#else
static pthread_mutexattr_t pthread_mutex_attr;
#endif /* _WIN32 */


#if defined(_WIN32_WCE)
/* Create substitutes for POSIX functions in Win32. */

#if defined(GCC_DIAGNOSTIC)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif


FUNCTION_MAY_BE_UNUSED
static time_t
time(time_t *ptime)
{
time_t t;
SYSTEMTIME st;
FILETIME ft;

GetSystemTime(&st);
SystemTimeToFileTime(&st, &ft);
t = SYS2UNIX_TIME(ft.dwLowDateTime, ft.dwHighDateTime);

if (ptime != NULL) {
*ptime = t;
}

return t;
}


FUNCTION_MAY_BE_UNUSED
static struct tm *
localtime_s(const time_t *ptime, struct tm *ptm)
{
int64_t t = ((int64_t)*ptime) * RATE_DIFF + EPOCH_DIFF;
FILETIME ft, lft;
SYSTEMTIME st;
TIME_ZONE_INFORMATION tzinfo;

if (ptm == NULL) {
return NULL;
}

*(int64_t *)&ft = t;
FileTimeToLocalFileTime(&ft, &lft);
FileTimeToSystemTime(&lft, &st);
ptm->tm_year = st.wYear - 1900;
ptm->tm_mon = st.wMonth - 1;
ptm->tm_wday = st.wDayOfWeek;
ptm->tm_mday = st.wDay;
ptm->tm_hour = st.wHour;
ptm->tm_min = st.wMinute;
ptm->tm_sec = st.wSecond;
ptm->tm_yday = 0; /* hope nobody uses this */
ptm->tm_isdst =
(GetTimeZoneInformation(&tzinfo) == TIME_ZONE_ID_DAYLIGHT) ? 1 : 0;

return ptm;
}


FUNCTION_MAY_BE_UNUSED
static struct tm *
gmtime_s(const time_t *ptime, struct tm *ptm)
{
/* FIXME(lsm): fix this. */
return localtime_s(ptime, ptm);
}


static int mg_atomic_inc(volatile int *addr);
static struct tm tm_array[MAX_WORKER_THREADS];
static int tm_index = 0;


FUNCTION_MAY_BE_UNUSED
static struct tm *
localtime(const time_t *ptime)
{
int i = mg_atomic_inc(&tm_index) % (sizeof(tm_array) / sizeof(tm_array[0]));
return localtime_s(ptime, tm_array + i);
}


FUNCTION_MAY_BE_UNUSED
static struct tm *
gmtime(const time_t *ptime)
{
int i = mg_atomic_inc(&tm_index) % ARRAY_SIZE(tm_array);
return gmtime_s(ptime, tm_array + i);
}


FUNCTION_MAY_BE_UNUSED
static size_t
strftime(char *dst, size_t dst_size, const char *fmt, const struct tm *tm)
{
/* TODO: (void)mg_snprintf(NULL, dst, dst_size, "implement strftime()
     * for WinCE"); */
return 0;
}

#define _beginthreadex(psec, stack, func, prm, flags, ptid)                    \
    (uintptr_t) CreateThread(psec, stack, func, prm, flags, ptid)

#define remove(f) mg_remove(NULL, f)


FUNCTION_MAY_BE_UNUSED
static int
rename(const char *a, const char *b)
{
wchar_t wa[W_PATH_MAX];
wchar_t wb[W_PATH_MAX];
path_to_unicode(NULL, a, wa, ARRAY_SIZE(wa));
path_to_unicode(NULL, b, wb, ARRAY_SIZE(wb));

return MoveFileW(wa, wb) ? 0 : -1;
}


struct stat {
int64_t st_size;
time_t st_mtime;
};

enum { REQUEST_HANDLER, WEBSOCKET_HANDLER, AUTH_HANDLER };


struct mg_handler_info {
	/* Name/Pattern of the URI. */
	char *uri;
	size_t uri_len;

    if (sizeof(pthread_t) > sizeof(unsigned long)) {
/* This is the problematic case for CRYPTO_set_id_callback:
		 * The OS pthread_t can not be cast to unsigned long. */
        struct mg_workerTLS *tls =
                (struct mg_workerTLS *) pthread_getspecific(sTlsKey);
        if (tls == NULL) {
/* SSL called from an unknown thread: Create some thread index.
			 */
            tls = (struct mg_workerTLS *) mg_malloc(sizeof(struct mg_workerTLS));
            tls->is_master = -2; /* -2 means "3rd party thread" */
            tls->thread_idx = (unsigned) mg_atomic_inc(&thread_idx_max);
            pthread_setspecific(sTlsKey, tls);
        }
        return tls->thread_idx;
    } else {
/* pthread_t may be any data type, so a simple cast to unsigned long
		 * can rise a warning/error, depending on the platform.
		 * Here memcpy is used as an anything-to-anything cast. */
        unsigned long ret = 0;
        pthread_t t = pthread_self();
        memcpy(&ret, &t, sizeof(pthread_t));
        return ret;
    }

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

#endif
}


FUNCTION_MAY_BE_UNUSED
static uint64_t
mg_get_current_time_ns(void) {
    struct timespec tsnow;
    clock_gettime(CLOCK_REALTIME, &tsnow);
    return (((uint64_t) tsnow.tv_sec) * 1000000000) + (uint64_t) tsnow.tv_nsec;
}


#if defined(GCC_DIAGNOSTIC)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic pop
#endif /* defined(GCC_DIAGNOSTIC) */
#if defined(__clang__)
/* Show no warning in case system functions are not used. */
#pragma clang diagnostic pop
#endif


#if defined(NEED_DEBUG_TRACE_FUNC)

static void
DEBUG_TRACE_FUNC(const char *func, unsigned line, const char *fmt, ...) {
    va_list args;
    uint64_t nsnow;
    static uint64_t nslast;
    struct timespec tsnow;

/* Get some operating system independent thread id */
    unsigned long thread_id = mg_current_thread_id();

    clock_gettime(CLOCK_REALTIME, &tsnow);
    nsnow = ((uint64_t) tsnow.tv_sec) * ((uint64_t) 1000000000)
            + ((uint64_t) tsnow.tv_nsec);

    if (!nslast) {
        nslast = nsnow;
    }

    flockfile(stdout);
    printf("*** %lu.%09lu %12" INT64_FMT " %lu %s:%u: ",
           (unsigned long) tsnow.tv_sec,
           (unsigned long) tsnow.tv_nsec,
           nsnow - nslast,
           thread_id,
           func,
           line);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    putchar('\n');
    fflush(stdout);
    funlockfile(stdout);
    nslast = nsnow;
}

#endif /* NEED_DEBUG_TRACE_FUNC */


#define MD5_STATIC static

#include "md5.inl"

/* Darwin prior to 7.0 and Win32 do not have socklen_t */
#if defined(NO_SOCKLEN_T)
typedef int socklen_t;
#endif /* NO_SOCKLEN_T */

#define IP_ADDR_STR_LEN (50) /* IPv6 hex string is 46 chars */

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL (0)
#endif


#if defined(NO_SSL)
typedef struct SSL SSL; /* dummy for SSL argument to push/pull */
typedef struct SSL_CTX SSL_CTX;
#else
#if defined(NO_SSL_DL)
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#if defined(WOLFSSL_VERSION)
/* Additional defines for WolfSSL, see
 * https://github.com/civetweb/civetweb/issues/583 */
#include "wolfssl_extras.inl"
#endif

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
/* If OpenSSL headers are included, automatically select the API version */
#if !defined(OPENSSL_API_1_1)
#define OPENSSL_API_1_1
#endif
#endif


#else

/* SSL loaded dynamically from DLL.
 * I put the prototypes here to be independent from OpenSSL source
 * installation. */

typedef struct ssl_st SSL;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct x509_name X509_NAME;
typedef struct asn1_integer ASN1_INTEGER;
typedef struct bignum BIGNUM;
typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;
typedef struct evp_md EVP_MD;
typedef struct x509 X509;


#define SSL_CTRL_OPTIONS (32)
#define SSL_CTRL_CLEAR_OPTIONS (77)
#define SSL_CTRL_SET_ECDH_AUTO (94)

#define OPENSSL_INIT_NO_LOAD_SSL_STRINGS 0x00100000L
#define OPENSSL_INIT_LOAD_SSL_STRINGS 0x00200000L
#define OPENSSL_INIT_LOAD_CRYPTO_STRINGS 0x00000002L

#define SSL_VERIFY_NONE (0)
#define SSL_VERIFY_PEER (1)
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT (2)
#define SSL_VERIFY_CLIENT_ONCE (4)
#define SSL_OP_ALL ((long)(0x80000BFFUL))
#define SSL_OP_NO_SSLv2 (0x01000000L)
#define SSL_OP_NO_SSLv3 (0x02000000L)
#define SSL_OP_NO_TLSv1 (0x04000000L)
#define SSL_OP_NO_TLSv1_2 (0x08000000L)
#define SSL_OP_NO_TLSv1_1 (0x10000000L)
#define SSL_OP_SINGLE_DH_USE (0x00100000L)
#define SSL_OP_CIPHER_SERVER_PREFERENCE (0x00400000L)
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION (0x00010000L)
#define SSL_OP_NO_COMPRESSION (0x00020000L)

#define SSL_CB_HANDSHAKE_START (0x10)
#define SSL_CB_HANDSHAKE_DONE (0x20)

#define SSL_ERROR_NONE (0)
#define SSL_ERROR_SSL (1)
#define SSL_ERROR_WANT_READ (2)
#define SSL_ERROR_WANT_WRITE (3)
#define SSL_ERROR_WANT_X509_LOOKUP (4)
#define SSL_ERROR_SYSCALL (5) /* see errno */
#define SSL_ERROR_ZERO_RETURN (6)
#define SSL_ERROR_WANT_CONNECT (7)
#define SSL_ERROR_WANT_ACCEPT (8)

#define TLSEXT_TYPE_server_name (0)
#define TLSEXT_NAMETYPE_host_name (0)
#define SSL_TLSEXT_ERR_OK (0)
#define SSL_TLSEXT_ERR_ALERT_WARNING (1)
#define SSL_TLSEXT_ERR_ALERT_FATAL (2)
#define SSL_TLSEXT_ERR_NOACK (3)

struct ssl_func {
    const char *name;  /* SSL function name */
    void (*ptr)(void); /* Function pointer */
};


#if defined(OPENSSL_API_1_1)

#define SSL_free (*(void (*)(SSL *))ssl_sw[0].ptr)
#define SSL_accept (*(int (*)(SSL *))ssl_sw[1].ptr)
#define SSL_connect (*(int (*)(SSL *))ssl_sw[2].ptr)
#define SSL_read (*(int (*)(SSL *, void *, int))ssl_sw[3].ptr)
#define SSL_write (*(int (*)(SSL *, const void *, int))ssl_sw[4].ptr)
#define SSL_get_error (*(int (*)(SSL *, int))ssl_sw[5].ptr)
#define SSL_set_fd (*(int (*)(SSL *, SOCKET))ssl_sw[6].ptr)
#define SSL_new (*(SSL * (*)(SSL_CTX *)) ssl_sw[7].ptr)
#define SSL_CTX_new (*(SSL_CTX * (*)(SSL_METHOD *)) ssl_sw[8].ptr)
#define TLS_server_method (*(SSL_METHOD * (*)(void)) ssl_sw[9].ptr)
#define OPENSSL_init_ssl                                                       \
    (*(int (*)(uint64_t opts,                                                  \
               const OPENSSL_INIT_SETTINGS *settings))ssl_sw[10]               \
          .ptr)
#define SSL_CTX_use_PrivateKey_file                                            \
    (*(int (*)(SSL_CTX *, const char *, int))ssl_sw[11].ptr)
#define SSL_CTX_use_certificate_file                                           \
    (*(int (*)(SSL_CTX *, const char *, int))ssl_sw[12].ptr)
#define SSL_CTX_set_default_passwd_cb                                          \
    (*(void (*)(SSL_CTX *, mg_callback_t))ssl_sw[13].ptr)
#define SSL_CTX_free (*(void (*)(SSL_CTX *))ssl_sw[14].ptr)
#define SSL_CTX_use_certificate_chain_file                                     \
    (*(int (*)(SSL_CTX *, const char *))ssl_sw[15].ptr)
#define TLS_client_method (*(SSL_METHOD * (*)(void)) ssl_sw[16].ptr)
#define SSL_pending (*(int (*)(SSL *))ssl_sw[17].ptr)
#define SSL_CTX_set_verify                                                     \
    (*(void (*)(SSL_CTX *,                                                     \
                int,                                                           \
                int (*verify_callback)(int, X509_STORE_CTX *)))ssl_sw[18]      \
          .ptr)
#define SSL_shutdown (*(int (*)(SSL *))ssl_sw[19].ptr)
#define SSL_CTX_load_verify_locations                                          \
    (*(int (*)(SSL_CTX *, const char *, const char *))ssl_sw[20].ptr)
#define SSL_CTX_set_default_verify_paths (*(int (*)(SSL_CTX *))ssl_sw[21].ptr)
#define SSL_CTX_set_verify_depth (*(void (*)(SSL_CTX *, int))ssl_sw[22].ptr)
#define SSL_get_peer_certificate (*(X509 * (*)(SSL *)) ssl_sw[23].ptr)
#define SSL_get_version (*(const char *(*)(SSL *))ssl_sw[24].ptr)
#define SSL_get_current_cipher (*(SSL_CIPHER * (*)(SSL *)) ssl_sw[25].ptr)
#define SSL_CIPHER_get_name                                                    \
    (*(const char *(*)(const SSL_CIPHER *))ssl_sw[26].ptr)
#define SSL_CTX_check_private_key (*(int (*)(SSL_CTX *))ssl_sw[27].ptr)
#define SSL_CTX_set_session_id_context                                         \
    (*(int (*)(SSL_CTX *, const unsigned char *, unsigned int))ssl_sw[28].ptr)
#define SSL_CTX_ctrl (*(long (*)(SSL_CTX *, int, long, void *))ssl_sw[29].ptr)
#define SSL_CTX_set_cipher_list                                                \
    (*(int (*)(SSL_CTX *, const char *))ssl_sw[30].ptr)
#define SSL_CTX_set_options                                                    \
    (*(unsigned long (*)(SSL_CTX *, unsigned long))ssl_sw[31].ptr)
#define SSL_CTX_set_info_callback                                              \
    (*(void (*)(SSL_CTX * ctx, void (*callback)(SSL * s, int, int)))           \
          ssl_sw[32]                                                           \
              .ptr)
#define SSL_get_ex_data (*(char *(*)(SSL *, int))ssl_sw[33].ptr)
#define SSL_set_ex_data (*(void (*)(SSL *, int, char *))ssl_sw[34].ptr)
#define SSL_CTX_callback_ctrl                                                  \
    (*(long (*)(SSL_CTX *, int, void (*)(void)))ssl_sw[35].ptr)
#define SSL_get_servername                                                     \
    (*(const char *(*)(const SSL *, int type))ssl_sw[36].ptr)
#define SSL_set_SSL_CTX (*(SSL_CTX * (*)(SSL *, SSL_CTX *)) ssl_sw[37].ptr)

#define SSL_CTX_clear_options(ctx, op)                                         \
    SSL_CTX_ctrl((ctx), SSL_CTRL_CLEAR_OPTIONS, (op), NULL)
#define SSL_CTX_set_ecdh_auto(ctx, onoff)                                      \
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, onoff, NULL)

#define SSL_CTRL_SET_TLSEXT_SERVERNAME_CB 53
#define SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG 54
#define SSL_CTX_set_tlsext_servername_callback(ctx, cb)                        \
    SSL_CTX_callback_ctrl(ctx,                                                 \
                          SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,                   \
                          (void (*)(void))cb)
#define SSL_CTX_set_tlsext_servername_arg(ctx, arg)                            \
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, (void *)arg)

#define X509_get_notBefore(x) ((x)->cert_info->validity->notBefore)
#define X509_get_notAfter(x) ((x)->cert_info->validity->notAfter)

#define SSL_set_app_data(s, arg) (SSL_set_ex_data(s, 0, (char *)arg))
#define SSL_get_app_data(s) (SSL_get_ex_data(s, 0))

#define ERR_get_error (*(unsigned long (*)(void))crypto_sw[0].ptr)
#define ERR_error_string (*(char *(*)(unsigned long, char *))crypto_sw[1].ptr)
#define ERR_remove_state (*(void (*)(unsigned long))crypto_sw[2].ptr)
#define CONF_modules_unload (*(void (*)(int))crypto_sw[3].ptr)
#define X509_free (*(void (*)(X509 *))crypto_sw[4].ptr)
#define X509_get_subject_name (*(X509_NAME * (*)(X509 *)) crypto_sw[5].ptr)
#define X509_get_issuer_name (*(X509_NAME * (*)(X509 *)) crypto_sw[6].ptr)
#define X509_NAME_oneline                                                      \
    (*(char *(*)(X509_NAME *, char *, int))crypto_sw[7].ptr)
#define X509_get_serialNumber (*(ASN1_INTEGER * (*)(X509 *)) crypto_sw[8].ptr)
#define EVP_get_digestbyname                                                   \
    (*(const EVP_MD *(*)(const char *))crypto_sw[9].ptr)
#define EVP_Digest                                                             \
    (*(int (*)(                                                                \
        const void *, size_t, void *, unsigned int *, const EVP_MD *, void *)) \
          crypto_sw[10]                                                        \
              .ptr)
#define i2d_X509 (*(int (*)(X509 *, unsigned char **))crypto_sw[11].ptr)
#define BN_bn2hex (*(char *(*)(const BIGNUM *a))crypto_sw[12].ptr)
#define ASN1_INTEGER_to_BN                                                     \
    (*(BIGNUM * (*)(const ASN1_INTEGER *ai, BIGNUM *bn)) crypto_sw[13].ptr)
#define BN_free (*(void (*)(const BIGNUM *a))crypto_sw[14].ptr)
#define CRYPTO_free (*(void (*)(void *addr))crypto_sw[15].ptr)

#define OPENSSL_free(a) CRYPTO_free(a)


/* init_ssl_ctx() function updates this array.
 * It loads SSL library dynamically and changes NULLs to the actual addresses
 * of respective functions. The macros above (like SSL_connect()) are really
 * just calling these functions indirectly via the pointer. */
static struct ssl_func ssl_sw[] = {{"SSL_free", NULL},
{"SSL_accept", NULL},
{"SSL_connect", NULL},
{"SSL_read", NULL},
{"SSL_write", NULL},
{"SSL_get_error", NULL},
{"SSL_set_fd", NULL},
{"SSL_new", NULL},
{"SSL_CTX_new", NULL},
{"TLS_server_method", NULL},
{"OPENSSL_init_ssl", NULL},
{"SSL_CTX_use_PrivateKey_file", NULL},
{"SSL_CTX_use_certificate_file", NULL},
{"SSL_CTX_set_default_passwd_cb", NULL},
{"SSL_CTX_free", NULL},
{"SSL_CTX_use_certificate_chain_file", NULL},
{"TLS_client_method", NULL},
{"SSL_pending", NULL},
{"SSL_CTX_set_verify", NULL},
{"SSL_shutdown", NULL},
{"SSL_CTX_load_verify_locations", NULL},
{"SSL_CTX_set_default_verify_paths", NULL},
{"SSL_CTX_set_verify_depth", NULL},
{"SSL_get_peer_certificate", NULL},
{"SSL_get_version", NULL},
{"SSL_get_current_cipher", NULL},
{"SSL_CIPHER_get_name", NULL},
{"SSL_CTX_check_private_key", NULL},
{"SSL_CTX_set_session_id_context", NULL},
{"SSL_CTX_ctrl", NULL},
{"SSL_CTX_set_cipher_list", NULL},
{"SSL_CTX_set_options", NULL},
{"SSL_CTX_set_info_callback", NULL},
{"SSL_get_ex_data", NULL},
{"SSL_set_ex_data", NULL},
{"SSL_CTX_callback_ctrl", NULL},
{"SSL_get_servername", NULL},
{"SSL_set_SSL_CTX", NULL},
{NULL, NULL}};


/* Similar array as ssl_sw. These functions could be located in different
 * lib. */
static struct ssl_func crypto_sw[] = {{"ERR_get_error", NULL},
{"ERR_error_string", NULL},
{"ERR_remove_state", NULL},
{"CONF_modules_unload", NULL},
{"X509_free", NULL},
{"X509_get_subject_name", NULL},
{"X509_get_issuer_name", NULL},
{"X509_NAME_oneline", NULL},
{"X509_get_serialNumber", NULL},
{"EVP_get_digestbyname", NULL},
{"EVP_Digest", NULL},
{"i2d_X509", NULL},
{"BN_bn2hex", NULL},
{"ASN1_INTEGER_to_BN", NULL},
{"BN_free", NULL},
{"CRYPTO_free", NULL},
{NULL, NULL}};
#else

#define SSL_free (*(void (*)(SSL *))ssl_sw[0].ptr)
#define SSL_accept (*(int (*)(SSL *))ssl_sw[1].ptr)
#define SSL_connect (*(int (*)(SSL *))ssl_sw[2].ptr)
#define SSL_read (*(int (*)(SSL *, void *, int))ssl_sw[3].ptr)
#define SSL_write (*(int (*)(SSL *, const void *, int))ssl_sw[4].ptr)
#define SSL_get_error (*(int (*)(SSL *, int))ssl_sw[5].ptr)
#define SSL_set_fd (*(int (*)(SSL *, SOCKET))ssl_sw[6].ptr)
#define SSL_new (*(SSL * (*)(SSL_CTX *)) ssl_sw[7].ptr)
#define SSL_CTX_new (*(SSL_CTX * (*)(SSL_METHOD *)) ssl_sw[8].ptr)
#define SSLv23_server_method (*(SSL_METHOD * (*)(void)) ssl_sw[9].ptr)
#define SSL_library_init (*(int (*)(void))ssl_sw[10].ptr)
#define SSL_CTX_use_PrivateKey_file                                            \
    (*(int (*)(SSL_CTX *, const char *, int))ssl_sw[11].ptr)
#define SSL_CTX_use_certificate_file                                           \
    (*(int (*)(SSL_CTX *, const char *, int))ssl_sw[12].ptr)
#define SSL_CTX_set_default_passwd_cb                                          \
    (*(void (*)(SSL_CTX *, mg_callback_t))ssl_sw[13].ptr)
#define SSL_CTX_free (*(void (*)(SSL_CTX *))ssl_sw[14].ptr)
#define SSL_load_error_strings (*(void (*)(void))ssl_sw[15].ptr)
#define SSL_CTX_use_certificate_chain_file                                     \
    (*(int (*)(SSL_CTX *, const char *))ssl_sw[16].ptr)
#define SSLv23_client_method (*(SSL_METHOD * (*)(void)) ssl_sw[17].ptr)
#define SSL_pending (*(int (*)(SSL *))ssl_sw[18].ptr)
#define SSL_CTX_set_verify                                                     \
    (*(void (*)(SSL_CTX *,                                                     \
                int,                                                           \
                int (*verify_callback)(int, X509_STORE_CTX *)))ssl_sw[19]      \
          .ptr)
#define SSL_shutdown (*(int (*)(SSL *))ssl_sw[20].ptr)
#define SSL_CTX_load_verify_locations                                          \
    (*(int (*)(SSL_CTX *, const char *, const char *))ssl_sw[21].ptr)
#define SSL_CTX_set_default_verify_paths (*(int (*)(SSL_CTX *))ssl_sw[22].ptr)
#define SSL_CTX_set_verify_depth (*(void (*)(SSL_CTX *, int))ssl_sw[23].ptr)
#define SSL_get_peer_certificate (*(X509 * (*)(SSL *)) ssl_sw[24].ptr)
#define SSL_get_version (*(const char *(*)(SSL *))ssl_sw[25].ptr)
#define SSL_get_current_cipher (*(SSL_CIPHER * (*)(SSL *)) ssl_sw[26].ptr)
#define SSL_CIPHER_get_name                                                    \
    (*(const char *(*)(const SSL_CIPHER *))ssl_sw[27].ptr)
#define SSL_CTX_check_private_key (*(int (*)(SSL_CTX *))ssl_sw[28].ptr)
#define SSL_CTX_set_session_id_context                                         \
    (*(int (*)(SSL_CTX *, const unsigned char *, unsigned int))ssl_sw[29].ptr)
#define SSL_CTX_ctrl (*(long (*)(SSL_CTX *, int, long, void *))ssl_sw[30].ptr)
#define SSL_CTX_set_cipher_list                                                \
    (*(int (*)(SSL_CTX *, const char *))ssl_sw[31].ptr)
#define SSL_CTX_set_info_callback                                              \
    (*(void (*)(SSL_CTX *, void (*callback)(SSL * s, int, int))) ssl_sw[32].ptr)
#define SSL_get_ex_data (*(char *(*)(SSL *, int))ssl_sw[33].ptr)
#define SSL_set_ex_data (*(void (*)(SSL *, int, char *))ssl_sw[34].ptr)
#define SSL_CTX_callback_ctrl                                                  \
    (*(long (*)(SSL_CTX *, int, void (*)(void)))ssl_sw[35].ptr)
#define SSL_get_servername                                                     \
    (*(const char *(*)(const SSL *, int type))ssl_sw[36].ptr)
#define SSL_set_SSL_CTX (*(SSL_CTX * (*)(SSL *, SSL_CTX *)) ssl_sw[37].ptr)

#define SSL_CTX_set_options(ctx, op)                                           \
    SSL_CTX_ctrl((ctx), SSL_CTRL_OPTIONS, (op), NULL)
#define SSL_CTX_clear_options(ctx, op)                                         \
    SSL_CTX_ctrl((ctx), SSL_CTRL_CLEAR_OPTIONS, (op), NULL)
#define SSL_CTX_set_ecdh_auto(ctx, onoff)                                      \
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_ECDH_AUTO, onoff, NULL)

#define SSL_CTRL_SET_TLSEXT_SERVERNAME_CB 53
#define SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG 54
#define SSL_CTX_set_tlsext_servername_callback(ctx, cb)                        \
    SSL_CTX_callback_ctrl(ctx,                                                 \
                          SSL_CTRL_SET_TLSEXT_SERVERNAME_CB,                   \
                          (void (*)(void))cb)
#define SSL_CTX_set_tlsext_servername_arg(ctx, arg)                            \
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, (void *)arg)

#define X509_get_notBefore(x) ((x)->cert_info->validity->notBefore)
#define X509_get_notAfter(x) ((x)->cert_info->validity->notAfter)

#define SSL_set_app_data(s, arg) (SSL_set_ex_data(s, 0, (char *)arg))
#define SSL_get_app_data(s) (SSL_get_ex_data(s, 0))

#define CRYPTO_num_locks (*(int (*)(void))crypto_sw[0].ptr)
#define CRYPTO_set_locking_callback                                            \
    (*(void (*)(void (*)(int, int, const char *, int)))crypto_sw[1].ptr)
#define CRYPTO_set_id_callback                                                 \
    (*(void (*)(unsigned long (*)(void)))crypto_sw[2].ptr)
#define ERR_get_error (*(unsigned long (*)(void))crypto_sw[3].ptr)
#define ERR_error_string (*(char *(*)(unsigned long, char *))crypto_sw[4].ptr)
#define ERR_remove_state (*(void (*)(unsigned long))crypto_sw[5].ptr)
#define ERR_free_strings (*(void (*)(void))crypto_sw[6].ptr)
#define ENGINE_cleanup (*(void (*)(void))crypto_sw[7].ptr)
#define CONF_modules_unload (*(void (*)(int))crypto_sw[8].ptr)
#define CRYPTO_cleanup_all_ex_data (*(void (*)(void))crypto_sw[9].ptr)
#define EVP_cleanup (*(void (*)(void))crypto_sw[10].ptr)
#define X509_free (*(void (*)(X509 *))crypto_sw[11].ptr)
#define X509_get_subject_name (*(X509_NAME * (*)(X509 *)) crypto_sw[12].ptr)
#define X509_get_issuer_name (*(X509_NAME * (*)(X509 *)) crypto_sw[13].ptr)
#define X509_NAME_oneline                                                      \
    (*(char *(*)(X509_NAME *, char *, int))crypto_sw[14].ptr)
#define X509_get_serialNumber (*(ASN1_INTEGER * (*)(X509 *)) crypto_sw[15].ptr)
#define i2c_ASN1_INTEGER                                                       \
    (*(int (*)(ASN1_INTEGER *, unsigned char **))crypto_sw[16].ptr)
#define EVP_get_digestbyname                                                   \
    (*(const EVP_MD *(*)(const char *))crypto_sw[17].ptr)
#define EVP_Digest                                                             \
    (*(int (*)(                                                                \
        const void *, size_t, void *, unsigned int *, const EVP_MD *, void *)) \
          crypto_sw[18]                                                        \
              .ptr)
#define i2d_X509 (*(int (*)(X509 *, unsigned char **))crypto_sw[19].ptr)
#define BN_bn2hex (*(char *(*)(const BIGNUM *a))crypto_sw[20].ptr)
#define ASN1_INTEGER_to_BN                                                     \
    (*(BIGNUM * (*)(const ASN1_INTEGER *ai, BIGNUM *bn)) crypto_sw[21].ptr)
#define BN_free (*(void (*)(const BIGNUM *a))crypto_sw[22].ptr)
#define CRYPTO_free (*(void (*)(void *addr))crypto_sw[23].ptr)

#define OPENSSL_free(a) CRYPTO_free(a)

/* init_ssl_ctx() function updates this array.
 * It loads SSL library dynamically and changes NULLs to the actual addresses
 * of respective functions. The macros above (like SSL_connect()) are really
 * just calling these functions indirectly via the pointer. */
static struct ssl_func ssl_sw[] = {{"SSL_free",                           NULL},
                                   {"SSL_accept",                         NULL},
                                   {"SSL_connect",                        NULL},
                                   {"SSL_read",                           NULL},
                                   {"SSL_write",                          NULL},
                                   {"SSL_get_error",                      NULL},
                                   {"SSL_set_fd",                         NULL},
                                   {"SSL_new",                            NULL},
                                   {"SSL_CTX_new",                        NULL},
                                   {"SSLv23_server_method",               NULL},
                                   {"SSL_library_init",                   NULL},
                                   {"SSL_CTX_use_PrivateKey_file",        NULL},
                                   {"SSL_CTX_use_certificate_file",       NULL},
                                   {"SSL_CTX_set_default_passwd_cb",      NULL},
                                   {"SSL_CTX_free",                       NULL},
                                   {"SSL_load_error_strings",             NULL},
                                   {"SSL_CTX_use_certificate_chain_file", NULL},
                                   {"SSLv23_client_method",               NULL},
                                   {"SSL_pending",                        NULL},
                                   {"SSL_CTX_set_verify",                 NULL},
                                   {"SSL_shutdown",                       NULL},
                                   {"SSL_CTX_load_verify_locations",      NULL},
                                   {"SSL_CTX_set_default_verify_paths",   NULL},
                                   {"SSL_CTX_set_verify_depth",           NULL},
                                   {"SSL_get_peer_certificate",           NULL},
                                   {"SSL_get_version",                    NULL},
                                   {"SSL_get_current_cipher",             NULL},
                                   {"SSL_CIPHER_get_name",                NULL},
                                   {"SSL_CTX_check_private_key",          NULL},
                                   {"SSL_CTX_set_session_id_context",     NULL},
                                   {"SSL_CTX_ctrl",                       NULL},
                                   {"SSL_CTX_set_cipher_list",            NULL},
                                   {"SSL_CTX_set_info_callback",          NULL},
                                   {"SSL_get_ex_data",                    NULL},
                                   {"SSL_set_ex_data",                    NULL},
                                   {"SSL_CTX_callback_ctrl",              NULL},
                                   {"SSL_get_servername",                 NULL},
                                   {"SSL_set_SSL_CTX",                    NULL},
                                   {NULL,                                 NULL}};


/* Similar array as ssl_sw. These functions could be located in different
 * lib. */
static struct ssl_func crypto_sw[] = {{"CRYPTO_num_locks",            NULL},
                                      {"CRYPTO_set_locking_callback", NULL},
                                      {"CRYPTO_set_id_callback",      NULL},
                                      {"ERR_get_error",               NULL},
                                      {"ERR_error_string",            NULL},
                                      {"ERR_remove_state",            NULL},
                                      {"ERR_free_strings",            NULL},
                                      {"ENGINE_cleanup",              NULL},
                                      {"CONF_modules_unload",         NULL},
                                      {"CRYPTO_cleanup_all_ex_data",  NULL},
                                      {"EVP_cleanup",                 NULL},
                                      {"X509_free",                   NULL},
                                      {"X509_get_subject_name",       NULL},
                                      {"X509_get_issuer_name",        NULL},
                                      {"X509_NAME_oneline",           NULL},
                                      {"X509_get_serialNumber",       NULL},
                                      {"i2c_ASN1_INTEGER",            NULL},
                                      {"EVP_get_digestbyname",        NULL},
                                      {"EVP_Digest",                  NULL},
                                      {"i2d_X509",                    NULL},
                                      {"BN_bn2hex",                   NULL},
                                      {"ASN1_INTEGER_to_BN",          NULL},
                                      {"BN_free",                     NULL},
                                      {"CRYPTO_free",                 NULL},
                                      {NULL,                          NULL}};
#endif /* OPENSSL_API_1_1 */
#endif /* NO_SSL_DL */
#endif /* NO_SSL */


#if !defined(NO_CACHING)
static const char *month_names[] = {"Jan",
"Feb",
"Mar",
"Apr",
"May",
"Jun",
"Jul",
"Aug",
"Sep",
"Oct",
"Nov",
"Dec"};
#endif /* !NO_CACHING */

/* Unified socket address. For IPv6 support, add IPv6 address structure in
 * the
 * union u. */
union usa {
    struct sockaddr sa;
    struct sockaddr_in sin;
#if defined(USE_IPV6)
    struct sockaddr_in6 sin6;
#endif
};

/* Describes a string (chunk of memory). */
struct vec {
    const char *ptr;
    size_t len;
};

struct mg_file_stat {
/* File properties filled by mg_stat: */
    uint64_t size;
    time_t last_modified;
    int is_directory; /* Set to 1 if mg_stat is called for a directory */
    int is_gzipped;   /* Set to 1 if the content is gzipped, in which
	                   * case we need a "Content-Eencoding: gzip" header */
    int location;     /* 0 = nowhere, 1 = on disk, 2 = in memory */
};

struct mg_file_in_memory {
    char *p;
    uint32_t pos;
    char mode;
};

struct mg_file_access {
/* File properties filled by mg_fopen: */
    FILE *fp;
#if defined(MG_USE_OPEN_FILE)
    /* TODO (low): Remove obsolete "file in memory" implementation.
     * In an "early 2017" discussion at Google groups
     * https://groups.google.com/forum/#!topic/civetweb/h9HT4CmeYqI
     * we decided to get rid of this feature (after some fade-out
     * phase). */
const char *membuf;
#endif
};

struct mg_file {
    struct mg_file_stat stat;
    struct mg_file_access access;
};

#if defined(MG_USE_OPEN_FILE)

#define STRUCT_FILE_INITIALIZER                                                \
    {                                                                          \
        {(uint64_t)0, (time_t)0, 0, 0, 0},                                     \
        {                                                                      \
            (FILE *)NULL, (const char *)NULL                                   \
        }                                                                      \
    }

#else

#define STRUCT_FILE_INITIALIZER                                                \
    {                                                                          \
        {(uint64_t)0, (time_t)0, 0, 0, 0},                                     \
        {                                                                      \
            (FILE *)NULL                                                       \
        }                                                                      \
    }

#endif


/* Describes listening socket, or socket which was accept()-ed by the master
 * thread and queued for future handling by the worker thread. */
struct socket {
    SOCKET sock;             /* Listening socket */
    union usa lsa;           /* Local socket address */
    union usa rsa;           /* Remote socket address */
    unsigned char is_ssl;    /* Is port SSL-ed */
    unsigned char ssl_redir; /* Is port supposed to redirect everything to SSL
	                          * port */
    unsigned char in_use;    /* Is valid */
};


/* Enum const for all options must be in sync with
 * static struct mg_option config_options[]
 * This is tested in the unit test (test/private.c)
 * "Private Config Options"
 */
enum {
/* Once for each server */
            LISTENING_PORTS,
    NUM_THREADS,
    RUN_AS_USER,
    CONFIG_TCP_NODELAY, /* Prepended CONFIG_ to avoid conflict with the
	                     * socket option typedef TCP_NODELAY. */
    MAX_REQUEST_SIZE,
    LINGER_TIMEOUT,
#if defined(__linux__)
    ALLOW_SENDFILE_CALL,
#endif
#if defined(_WIN32)
    CASE_SENSITIVE_FILES,
#endif
    THROTTLE,
    ACCESS_LOG_FILE,
    ERROR_LOG_FILE,
    ENABLE_KEEP_ALIVE,
    REQUEST_TIMEOUT,
    KEEP_ALIVE_TIMEOUT,
#if defined(USE_WEBSOCKET)
    WEBSOCKET_TIMEOUT,
ENABLE_WEBSOCKET_PING_PONG,
#endif
    DECODE_URL,
#if defined(USE_LUA)
    LUA_BACKGROUND_SCRIPT,
LUA_BACKGROUND_SCRIPT_PARAMS,
#endif
#if defined(USE_TIMERS)
    CGI_TIMEOUT,
#endif

/* Once for each domain */
            DOCUMENT_ROOT,
    CGI_EXTENSIONS,
    CGI_ENVIRONMENT,
    PUT_DELETE_PASSWORDS_FILE,
    CGI_INTERPRETER,
    PROTECT_URI,
    AUTHENTICATION_DOMAIN,
    ENABLE_AUTH_DOMAIN_CHECK,
    SSI_EXTENSIONS,
    ENABLE_DIRECTORY_LISTING,
    GLOBAL_PASSWORDS_FILE,
    INDEX_FILES,
    ACCESS_CONTROL_LIST,
    EXTRA_MIME_TYPES,
    SSL_CERTIFICATE,
    SSL_CERTIFICATE_CHAIN,
    URL_REWRITE_PATTERN,
    HIDE_FILES,
    SSL_DO_VERIFY_PEER,
    SSL_CA_PATH,
    SSL_CA_FILE,
    SSL_VERIFY_DEPTH,
    SSL_DEFAULT_VERIFY_PATHS,
    SSL_CIPHER_LIST,
    SSL_PROTOCOL_VERSION,
    SSL_SHORT_TRUST,

#if defined(USE_LUA)
    LUA_PRELOAD_FILE,
LUA_SCRIPT_EXTENSIONS,
LUA_SERVER_PAGE_EXTENSIONS,
#if defined(MG_EXPERIMENTAL_INTERFACES)
LUA_DEBUG_PARAMS,
#endif
#endif
#if defined(USE_DUKTAPE)
    DUKTAPE_SCRIPT_EXTENSIONS,
#endif

#if defined(USE_WEBSOCKET)
    WEBSOCKET_ROOT,
#endif
#if defined(USE_LUA) && defined(USE_WEBSOCKET)
    LUA_WEBSOCKET_EXTENSIONS,
#endif

    ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_HEADERS,
    ERROR_PAGES,
#if !defined(NO_CACHING)
    STATIC_FILE_MAX_AGE,
#endif
#if !defined(NO_SSL)
    STRICT_HTTPS_MAX_AGE,
#endif
    ADDITIONAL_HEADER,
    ALLOW_INDEX_SCRIPT_SUB_RES,

    NUM_OPTIONS
};


/* Config option name, config types, default value.
 * Must be in the same order as the enum const above.
 */
static const struct mg_option config_options[] = {

/* Once for each server */
        {"listening_ports", MG_CONFIG_TYPE_STRING_LIST, "8080"},
        {"num_threads", MG_CONFIG_TYPE_NUMBER, "50"},
        {"run_as_user", MG_CONFIG_TYPE_STRING, NULL},
        {"tcp_nodelay", MG_CONFIG_TYPE_NUMBER, "0"},
        {"max_request_size", MG_CONFIG_TYPE_NUMBER, "16384"},
        {"linger_timeout_ms", MG_CONFIG_TYPE_NUMBER, NULL},
#if defined(__linux__)
        {"allow_sendfile_call", MG_CONFIG_TYPE_BOOLEAN, "yes"},
#endif
#if defined(_WIN32)
        {"case_sensitive", MG_CONFIG_TYPE_BOOLEAN, "no"},
#endif
        {"throttle", MG_CONFIG_TYPE_STRING_LIST, NULL},
        {"access_log_file", MG_CONFIG_TYPE_FILE, NULL},
        {"error_log_file", MG_CONFIG_TYPE_FILE, NULL},
        {"enable_keep_alive", MG_CONFIG_TYPE_BOOLEAN, "no"},
        {"request_timeout_ms", MG_CONFIG_TYPE_NUMBER, "30000"},
        {"keep_alive_timeout_ms", MG_CONFIG_TYPE_NUMBER, "500"},
#if defined(USE_WEBSOCKET)
{"websocket_timeout_ms", MG_CONFIG_TYPE_NUMBER, NULL},
{"enable_websocket_ping_pong", MG_CONFIG_TYPE_BOOLEAN, "no"},
#endif
        {"decode_url", MG_CONFIG_TYPE_BOOLEAN, "yes"},
#if defined(USE_LUA)
{"lua_background_script", MG_CONFIG_TYPE_FILE, NULL},
{"lua_background_script_params", MG_CONFIG_TYPE_STRING_LIST, NULL},
#endif
#if defined(USE_TIMERS)
        {"cgi_timeout_ms", MG_CONFIG_TYPE_NUMBER, NULL},
#endif

/* Once for each domain */
        {"document_root", MG_CONFIG_TYPE_DIRECTORY, NULL},
        {"cgi_pattern", MG_CONFIG_TYPE_EXT_PATTERN, "**.cgi$|**.pl$|**.php$"},
        {"cgi_environment", MG_CONFIG_TYPE_STRING_LIST, NULL},
        {"put_delete_auth_file", MG_CONFIG_TYPE_FILE, NULL},
        {"cgi_interpreter", MG_CONFIG_TYPE_FILE, NULL},
        {"protect_uri", MG_CONFIG_TYPE_STRING_LIST, NULL},
        {"authentication_domain", MG_CONFIG_TYPE_STRING, "mydomain.com"},
        {"enable_auth_domain_check", MG_CONFIG_TYPE_BOOLEAN, "yes"},
        {"ssi_pattern", MG_CONFIG_TYPE_EXT_PATTERN, "**.shtml$|**.shtm$"},
        {"enable_directory_listing", MG_CONFIG_TYPE_BOOLEAN, "yes"},
        {"global_auth_file", MG_CONFIG_TYPE_FILE, NULL},
        {"index_files",
         MG_CONFIG_TYPE_STRING_LIST,
#if defined(USE_LUA)
        "index.xhtml,index.html,index.htm,"
"index.lp,index.lsp,index.lua,index.cgi,"
"index.shtml,index.php"},
#else
         "index.xhtml,index.html,index.htm,index.cgi,index.shtml,index.php"},
#endif
        {"access_control_list", MG_CONFIG_TYPE_STRING_LIST, NULL},
        {"extra_mime_types", MG_CONFIG_TYPE_STRING_LIST, NULL},
        {"ssl_certificate", MG_CONFIG_TYPE_FILE, NULL},
        {"ssl_certificate_chain", MG_CONFIG_TYPE_FILE, NULL},
        {"url_rewrite_patterns", MG_CONFIG_TYPE_STRING_LIST, NULL},
        {"hide_files_patterns", MG_CONFIG_TYPE_EXT_PATTERN, NULL},

        {"ssl_verify_peer", MG_CONFIG_TYPE_YES_NO_OPTIONAL, "no"},

        {"ssl_ca_path", MG_CONFIG_TYPE_DIRECTORY, NULL},
        {"ssl_ca_file", MG_CONFIG_TYPE_FILE, NULL},
        {"ssl_verify_depth", MG_CONFIG_TYPE_NUMBER, "9"},
        {"ssl_default_verify_paths", MG_CONFIG_TYPE_BOOLEAN, "yes"},
        {"ssl_cipher_list", MG_CONFIG_TYPE_STRING, NULL},
        {"ssl_protocol_version", MG_CONFIG_TYPE_NUMBER, "0"},
        {"ssl_short_trust", MG_CONFIG_TYPE_BOOLEAN, "no"},

#if defined(USE_LUA)
{"lua_preload_file", MG_CONFIG_TYPE_FILE, NULL},
{"lua_script_pattern", MG_CONFIG_TYPE_EXT_PATTERN, "**.lua$"},
{"lua_server_page_pattern", MG_CONFIG_TYPE_EXT_PATTERN, "**.lp$|**.lsp$"},
#if defined(MG_EXPERIMENTAL_INTERFACES)
{"lua_debug", MG_CONFIG_TYPE_STRING, NULL},
#endif
#endif
#if defined(USE_DUKTAPE)
/* The support for duktape is still in alpha version state.
     * The name of this config option might change. */
{"duktape_script_pattern", MG_CONFIG_TYPE_EXT_PATTERN, "**.ssjs$"},
#endif

#if defined(USE_WEBSOCKET)
        {"websocket_root", MG_CONFIG_TYPE_DIRECTORY, NULL},
#endif
#if defined(USE_LUA) && defined(USE_WEBSOCKET)
        {"lua_websocket_pattern", MG_CONFIG_TYPE_EXT_PATTERN, "**.lua$"},
#endif
        {"access_control_allow_origin", MG_CONFIG_TYPE_STRING, "*"},
        {"access_control_allow_methods", MG_CONFIG_TYPE_STRING, "*"},
        {"access_control_allow_headers", MG_CONFIG_TYPE_STRING, "*"},
        {"error_pages", MG_CONFIG_TYPE_DIRECTORY, NULL},
#if !defined(NO_CACHING)
        {"static_file_max_age", MG_CONFIG_TYPE_NUMBER, "3600"},
#endif
#if !defined(NO_SSL)
        {"strict_transport_security_max_age", MG_CONFIG_TYPE_NUMBER, NULL},
#endif
        {"additional_header", MG_CONFIG_TYPE_STRING_MULTILINE, NULL},
        {"allow_index_script_resource", MG_CONFIG_TYPE_BOOLEAN, "no"},

        {NULL, MG_CONFIG_TYPE_UNKNOWN, NULL}};


/* Check if the config_options and the corresponding enum have compatible
 * sizes. */
mg_static_assert((sizeof(config_options) / sizeof(config_options[0]))
                 == (NUM_OPTIONS + 1),
                 "config_options and enum not sync");


enum {
    REQUEST_HANDLER, WEBSOCKET_HANDLER, AUTH_HANDLER
};


struct mg_handler_info {
/* Name/Pattern of the URI. */
    char *uri;
    size_t uri_len;

/* handler type */
    int handler_type;

/* Handler for http/https or authorization requests. */
    mg_request_handler handler;
    unsigned int refcount;
    pthread_mutex_t refcount_mutex; /* Protects refcount */
    pthread_cond_t
            refcount_cond; /* Signaled when handler refcount is decremented */

/* Handler for ws/wss (websocket) requests. */
    mg_websocket_connect_handler connect_handler;
    mg_websocket_ready_handler ready_handler;
    mg_websocket_data_handler data_handler;
    mg_websocket_close_handler close_handler;

/* accepted subprotocols for ws/wss requests. */
    struct mg_websocket_subprotocols *subprotocols;

/* Handler for authorization requests */
    mg_authorization_handler auth_handler;

/* User supplied argument for the handler function. */
    void *cbdata;

/* next handler in a linked list */
    struct mg_handler_info *next;
};


enum {
    CONTEXT_INVALID,
    CONTEXT_SERVER,
    CONTEXT_HTTP_CLIENT,
    CONTEXT_WS_CLIENT
};


struct mg_domain_context {
    SSL_CTX *ssl_ctx;                 /* SSL context */
    char *config[NUM_OPTIONS];        /* Civetweb configuration parameters */
    struct mg_handler_info *handlers; /* linked list of uri handlers */

/* Server nonce */
    uint64_t auth_nonce_mask;  /* Mask for all nonce values */
    unsigned long nonce_count; /* Used nonces, used for authentication */

#if defined(USE_LUA) && defined(USE_WEBSOCKET)
    /* linked list of shared lua websockets */
struct mg_shared_lua_websocket_list *shared_lua_websockets;
#endif

/* Linked list of domains */
    struct mg_domain_context *next;
};


struct mg_context {

/* Part 1 - Physical context:
	 * This holds threads, ports, timeouts, ...
	 * set for the entire server, independent from the
	 * addressed hostname.
	 */

/* Connection related */
    int context_type; /* See CONTEXT_* above */

    struct socket *listening_sockets;
    struct pollfd *listening_socket_fds;
    unsigned int num_listening_sockets;

    struct mg_connection *worker_connections; /* The connection struct, pre-
	                                           * allocated for each worker */

#if defined(USE_SERVER_STATS)
    int active_connections;
int max_connections;
int64_t total_connections;
int64_t total_requests;
int64_t total_data_read;
int64_t total_data_written;
#endif

/* Thread related */
    volatile int stop_flag;       /* Should we stop event loop */
    pthread_mutex_t thread_mutex; /* Protects (max|num)_threads */

    pthread_t masterthreadid; /* The master thread ID */
    unsigned int
            cfg_worker_threads;      /* The number of configured worker threads. */
    pthread_t *worker_threadids; /* The worker thread IDs */

/* Connection to thread dispatching */
#if defined(ALTERNATIVE_QUEUE)
    struct socket *client_socks;
    void **client_wait_events;
#else
    struct socket queue[MGSQLEN]; /* Accepted sockets */
volatile int sq_head;         /* Head of the socket queue */
volatile int sq_tail;         /* Tail of the socket queue */
pthread_cond_t sq_full;       /* Signaled when socket is produced */
pthread_cond_t sq_empty;      /* Signaled when socket is consumed */
#endif

/* Memory related */
    unsigned int max_request_size; /* The max request size */

#if defined(USE_SERVER_STATS)
    struct mg_memory_stat ctx_memory;
#endif

/* Operating system related */
    char *systemName;  /* What operating system is running */
    time_t start_time; /* Server start time, used for authentication
	                    * and for diagnstics. */

#if defined(USE_TIMERS)
    struct ttimers *timers;
#endif

/* Lua specific: Background operations and shared websockets */
#if defined(USE_LUA)
    void *lua_background_state;
#endif

/* Server nonce */
    pthread_mutex_t nonce_mutex; /* Protects nonce_count */

/* Server callbacks */
    struct mg_callbacks callbacks; /* User-defined callback function */
    void *user_data;               /* User-defined data */

/* Part 2 - Logical domain:
	 * This holds hostname, TLS certificate, document root, ...
	 * set for a domain hosted at the server.
	 * There may be multiple domains hosted at one physical server.
	 * The default domain "dd" is the first element of a list of
	 * domains.
	 */
    struct mg_domain_context dd; /* default domain */
};


#if defined(USE_SERVER_STATS)
static struct mg_memory_stat mg_common_memory = {0, 0, 0};

static struct mg_memory_stat *
get_memory_stat(struct mg_context *ctx)
{
if (ctx) {
return &(ctx->ctx_memory);
}
return &mg_common_memory;
}
#endif

enum {
    CONNECTION_TYPE_INVALID,
    CONNECTION_TYPE_REQUEST,
    CONNECTION_TYPE_RESPONSE
};

struct mg_connection {
    int connection_type; /* see CONNECTION_TYPE_* above */

    struct mg_request_info request_info;
    struct mg_response_info response_info;

    struct mg_context *phys_ctx;
    struct mg_domain_context *dom_ctx;

#if defined(USE_SERVER_STATS)
    int conn_state; /* 0 = undef, numerical value may change in different
	                 * versions. For the current definition, see
	                 * mg_get_connection_info_impl */
#endif

    const char *host;         /* Host (HTTP/1.1 header or SNI) */
    SSL *ssl;                 /* SSL descriptor */
    SSL_CTX *client_ssl_ctx;  /* SSL context for client connections */
    struct socket client;     /* Connected client */
    time_t conn_birth_time;   /* Time (wall clock) when connection was
	                           * established */
    struct timespec req_time; /* Time (since system start) when the request
	                           * was received */
    int64_t num_bytes_sent;   /* Total bytes sent to client */
    int64_t content_len;      /* Content-Length header value */
    int64_t consumed_content; /* How many bytes of content have been read */
    int is_chunked;           /* Transfer-Encoding is chunked:
	                           * 0 = not chunked,
	                           * 1 = chunked, do data read yet,
	                           * 2 = chunked, some data read,
	                           * 3 = chunked, all data read
	                           */
    size_t chunk_remainder;   /* Unread data from the last chunk */
    char *buf;                /* Buffer for received data */
    char *path_info;          /* PATH_INFO part of the URL */

    int must_close;       /* 1 if connection must be closed */
    int accept_gzip;      /* 1 if gzip encoding is accepted */
    int in_error_handler; /* 1 if in handler for user defined error
	                       * pages */
#if defined(USE_WEBSOCKET)
    int in_websocket_handling; /* 1 if in read_websocket */
#endif
    int handled_requests; /* Number of requests handled by this connection
	                       */
    int buf_size;         /* Buffer size */
    int request_len;      /* Size of the request + headers in a buffer */
    int data_len;         /* Total size of data in a buffer */
    int status_code;      /* HTTP reply status code, e.g. 200 */
    int throttle;         /* Throttling, bytes/sec. <= 0 means no
	                       * throttle */

    time_t last_throttle_time;   /* Last time throttled data was sent */
    int64_t last_throttle_bytes; /* Bytes sent this second */
    pthread_mutex_t mutex;       /* Used by mg_(un)lock_connection to ensure
	                              * atomic transmissions for websockets */
#if defined(USE_LUA) && defined(USE_WEBSOCKET)
    void *lua_websocket_state; /* Lua_State for a websocket connection */
#endif

    int thread_index; /* Thread index within ctx */
};


/* Directory entry */
struct de {
    struct mg_connection *conn;
    char *file_name;
    struct mg_file_stat file;
};


#if defined(USE_WEBSOCKET)
static int is_websocket_protocol(const struct mg_connection *conn);
#else
#define is_websocket_protocol(conn) (0)
#endif


#define mg_cry_internal(conn, fmt, ...)                                        \
    mg_cry_internal_wrap(conn, __func__, __LINE__, fmt, __VA_ARGS__)

static void mg_cry_internal_wrap(const struct mg_connection *conn,
                                 const char *func,
                                 unsigned line,
                                 const char *fmt,
                                 ...) PRINTF_ARGS(4, 5);


#if !defined(NO_THREAD_NAME)
#if defined(_WIN32) && defined(_MSC_VER)
/* Set the thread name for debugging purposes in Visual Studio
 * http://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx
 */
#pragma pack(push, 8)
typedef struct tagTHREADNAME_INFO {
DWORD dwType;     /* Must be 0x1000. */
LPCSTR szName;    /* Pointer to name (in user addr space). */
DWORD dwThreadID; /* Thread ID (-1=caller thread). */
DWORD dwFlags;    /* Reserved for future use, must be zero. */
} THREADNAME_INFO;
#pragma pack(pop)

#elif defined(__linux__)

#include <sys/prctl.h>
#include <sys/sendfile.h>

#if defined(ALTERNATIVE_QUEUE)

#include <sys/eventfd.h>

#endif /* ALTERNATIVE_QUEUE */


#if defined(ALTERNATIVE_QUEUE)

static void *
event_create(void) {
    int evhdl = eventfd(0, EFD_CLOEXEC);
    int *ret;

    if (evhdl == -1) {
/* Linux uses -1 on error, Windows NULL. */
/* However, Linux does not return 0 on success either. */
        return 0;
    }

    ret = (int *) mg_malloc(sizeof(int));
    if (ret) {
        *ret = evhdl;
    } else {
        (void) close(evhdl);
    }

    return (void *) ret;
}


static int
event_wait(void *eventhdl) {
    uint64_t u;
    int evhdl, s;

    if (!eventhdl) {
/* error */
        return 0;
    }
    evhdl = *(int *) eventhdl;

    s = (int) read(evhdl, &u, sizeof(u));
    if (s != sizeof(u)) {
/* error */
        return 0;
    }
    (void) u; /* the value is not required */
    return 1;
}


static int
event_signal(void *eventhdl) {
    uint64_t u = 1;
    int evhdl, s;

    if (!eventhdl) {
/* error */
        return 0;
    }
    evhdl = *(int *) eventhdl;

    s = (int) write(evhdl, &u, sizeof(u));
    if (s != sizeof(u)) {
/* error */
        return 0;
    }
    return 1;
}


static void
event_destroy(void *eventhdl) {
    int evhdl;

    if (!eventhdl) {
/* error */
        return;
    }
    evhdl = *(int *) eventhdl;

    close(evhdl);
    mg_free(eventhdl);
}


#endif

#endif


#if !defined(__linux__) && !defined(_WIN32) && defined(ALTERNATIVE_QUEUE)

struct posix_event {
pthread_mutex_t mutex;
pthread_cond_t cond;
};


static void *
event_create(void)
{
struct posix_event *ret = mg_malloc(sizeof(struct posix_event));
if (ret == 0) {
/* out of memory */
return 0;
}
if (0 != pthread_mutex_init(&(ret->mutex), NULL)) {
/* pthread mutex not available */
mg_free(ret);
return 0;
}
if (0 != pthread_cond_init(&(ret->cond), NULL)) {
/* pthread cond not available */
pthread_mutex_destroy(&(ret->mutex));
mg_free(ret);
return 0;
}
return (void *)ret;
}


static int
event_wait(void *eventhdl)
{
struct posix_event *ev = (struct posix_event *)eventhdl;
pthread_mutex_lock(&(ev->mutex));
pthread_cond_wait(&(ev->cond), &(ev->mutex));
pthread_mutex_unlock(&(ev->mutex));
return 1;
}


static int
event_signal(void *eventhdl)
{
struct posix_event *ev = (struct posix_event *)eventhdl;
pthread_mutex_lock(&(ev->mutex));
pthread_cond_signal(&(ev->cond));
pthread_mutex_unlock(&(ev->mutex));
return 1;
}


static void
event_destroy(void *eventhdl)
{
struct posix_event *ev = (struct posix_event *)eventhdl;
pthread_cond_destroy(&(ev->cond));
pthread_mutex_destroy(&(ev->mutex));
mg_free(ev);
}
#endif


static void
mg_set_thread_name(const char *name) {
    char threadName[16 + 1]; /* 16 = Max. thread length in Linux/OSX/.. */

    mg_snprintf(
            NULL, NULL, threadName, sizeof(threadName), "civetweb-%s", name);

#if defined(_WIN32)
#if defined(_MSC_VER)
    /* Windows and Visual Studio Compiler */
    __try {
    THREADNAME_INFO info;
    info.dwType = 0x1000;
    info.szName = threadName;
    info.dwThreadID = ~0U;
    info.dwFlags = 0;

    RaiseException(0x406D1388,
    0,
    sizeof(info) / sizeof(ULONG_PTR),
    (ULONG_PTR *)&info);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
#elif defined(__MINGW32__)
    /* No option known to set thread name for MinGW */
#endif
#elif defined(_GNU_SOURCE) && defined(__GLIBC__)                               \
 && ((__GLIBC__ > 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ >= 12)))
/* pthread_setname_np first appeared in glibc in version 2.12*/
#if defined(__MACH__)
    /* OS X only current thread name can be changed */
(void)pthread_setname_np(threadName);
#else
    (void) pthread_setname_np(pthread_self(), threadName);
#endif
#elif defined(__linux__)
    /* on linux we can use the old prctl function */
(void)prctl(PR_SET_NAME, threadName, 0, 0, 0);
#endif
}

#else /* !defined(NO_THREAD_NAME) */
void
mg_set_thread_name(const char *threadName)
{
}
#endif


#if defined(MG_LEGACY_INTERFACE)
const char **
mg_get_valid_option_names(void)
{
/* This function is deprecated. Use mg_get_valid_options instead. */
static const char
*data[2 * sizeof(config_options) / sizeof(config_options[0])] = {0};
int i;

for (i = 0; config_options[i].name != NULL; i++) {
data[i * 2] = config_options[i].name;
data[i * 2 + 1] = config_options[i].default_value;
}

return data;
}
#endif


const struct mg_option *
mg_get_valid_options(void) {
    return config_options;
}


/* Do not open file (used in is_file_in_memory) */
#define MG_FOPEN_MODE_NONE (0)

/* Open file for read only access */
#define MG_FOPEN_MODE_READ (1)

/* Open file for writing, create and overwrite */
#define MG_FOPEN_MODE_WRITE (2)

/* Open file for writing, create and append */
#define MG_FOPEN_MODE_APPEND (4)


/* If a file is in memory, set all "stat" members and the membuf pointer of
 * output filep and return 1, otherwise return 0 and don't modify anything.
 */
static int
open_file_in_memory(const struct mg_connection *conn,
                    const char *path,
                    struct mg_file *filep,
                    int mode) {
#if defined(MG_USE_OPEN_FILE)

    size_t size = 0;
const char *buf = NULL;
if (!conn) {
return 0;
}

if ((mode != MG_FOPEN_MODE_NONE) && (mode != MG_FOPEN_MODE_READ)) {
return 0;
}

if (conn->phys_ctx->callbacks.open_file) {
buf = conn->phys_ctx->callbacks.open_file(conn, path, &size);
if (buf != NULL) {
if (filep == NULL) {
/* This is a file in memory, but we cannot store the
                 * properties
                 * now.
                 * Called from "is_file_in_memory" function. */
return 1;
}

/* NOTE: override filep->size only on success. Otherwise, it
             * might
             * break constructs like if (!mg_stat() || !mg_fopen()) ... */
filep->access.membuf = buf;
filep->access.fp = NULL;

/* Size was set by the callback */
filep->stat.size = size;

/* Assume the data may change during runtime by setting
             * last_modified = now */
filep->stat.last_modified = time(NULL);

filep->stat.is_directory = 0;
filep->stat.is_gzipped = 0;
}
}

return (buf != NULL);

#else
    (void) conn;
    (void) path;
    (void) filep;
    (void) mode;

    return 0;

#endif
}


static int
is_file_in_memory(const struct mg_connection *conn, const char *path) {
    return open_file_in_memory(conn, path, NULL, MG_FOPEN_MODE_NONE);
}


static int
is_file_opened(const struct mg_file_access *fileacc) {
    if (!fileacc) {
        return 0;
    }

#if defined(MG_USE_OPEN_FILE)
    return (fileacc->membuf != NULL) || (fileacc->fp != NULL);
#else
    return (fileacc->fp != NULL);
#endif
}


static int mg_stat(const struct mg_connection *conn,
                   const char *path,
                   struct mg_file_stat *filep);


/* mg_fopen will open a file either in memory or on the disk.
 * The input parameter path is a string in UTF-8 encoding.
 * The input parameter mode is MG_FOPEN_MODE_*
 * On success, either fp or membuf will be set in the output
 * struct file. All status members will also be set.
 * The function returns 1 on success, 0 on error. */
static int
mg_fopen(const struct mg_connection *conn,
         const char *path,
         int mode,
         struct mg_file *filep) {
    int found;

    if (!filep) {
        return 0;
    }
    filep->access.fp = NULL;
#if defined(MG_USE_OPEN_FILE)
    filep->access.membuf = NULL;
#endif

    if (!is_file_in_memory(conn, path)) {

/* filep is initialized in mg_stat: all fields with memset to,
		 * some fields like size and modification date with values */
        found = mg_stat(conn, path, &(filep->stat));

        if ((mode == MG_FOPEN_MODE_READ) && (!found)) {
/* file does not exist and will not be created */
            return 0;
        }

#if defined(_WIN32)
        {
wchar_t wbuf[W_PATH_MAX];
path_to_unicode(conn, path, wbuf, ARRAY_SIZE(wbuf));
switch (mode) {
case MG_FOPEN_MODE_READ:
filep->access.fp = _wfopen(wbuf, L"rb");
break;
case MG_FOPEN_MODE_WRITE:
filep->access.fp = _wfopen(wbuf, L"wb");
break;
case MG_FOPEN_MODE_APPEND:
filep->access.fp = _wfopen(wbuf, L"ab");
break;
}
}
#else
/* Linux et al already use unicode. No need to convert. */
        switch (mode) {
            case MG_FOPEN_MODE_READ:
                filep->access.fp = fopen(path, "r");
                break;
            case MG_FOPEN_MODE_WRITE:
                filep->access.fp = fopen(path, "w");
                break;
            case MG_FOPEN_MODE_APPEND:
                filep->access.fp = fopen(path, "a");
                break;
        }

#endif
        if (!found) {
/* File did not exist before fopen was called.
			 * Maybe it has been created now. Get stat info
			 * like creation time now. */
            found = mg_stat(conn, path, &(filep->stat));
            (void) found;
        }

/* file is on disk */
        return (filep->access.fp != NULL);

    } else {
#if defined(MG_USE_OPEN_FILE)
        /* is_file_in_memory returned true */
if (open_file_in_memory(conn, path, filep, mode)) {
/* file is in memory */
return (filep->access.membuf != NULL);
}
#endif
    }

/* Open failed */
    return 0;
}


/* return 0 on success, just like fclose */
static int
mg_fclose(struct mg_file_access *fileacc) {
    int ret = -1;
    if (fileacc != NULL) {
        if (fileacc->fp != NULL) {
            ret = fclose(fileacc->fp);
#if defined(MG_USE_OPEN_FILE)
            } else if (fileacc->membuf != NULL) {
ret = 0;
#endif
        }
/* reset all members of fileacc */
        memset(fileacc, 0, sizeof(*fileacc));
    }
    return ret;
}


static void
mg_strlcpy(register char *dst, register const char *src, size_t n) {
    for (; *src != '\0' && n > 1; n--) {
        *dst++ = *src++;
    }
    *dst = '\0';
}


static int
lowercase(const char *s) {
    return tolower(*(const unsigned char *) s);
}


int
mg_strncasecmp(const char *s1, const char *s2, size_t len) {
    int diff = 0;

    if (len > 0) {
        do {
            diff = lowercase(s1++) - lowercase(s2++);
        } while (diff == 0 && s1[-1] != '\0' && --len > 0);
    }

    return diff;
}


int
mg_strcasecmp(const char *s1, const char *s2) {
    int diff;

    do {
        diff = lowercase(s1++) - lowercase(s2++);
    } while (diff == 0 && s1[-1] != '\0');

    return diff;
}


static char *
mg_strndup_ctx(const char *ptr, size_t len, struct mg_context *ctx) {
    char *p;
    (void) ctx; /* Avoid Visual Studio warning if USE_SERVER_STATS is not
	            * defined */

    if ((p = (char *) mg_malloc_ctx(len + 1, ctx)) != NULL) {
        mg_strlcpy(p, ptr, len + 1);
    }

    return p;
}


static char *
mg_strdup_ctx(const char *str, struct mg_context *ctx) {
    return mg_strndup_ctx(str, strlen(str), ctx);
}

static char *
mg_strdup(const char *str) {
    return mg_strndup_ctx(str, strlen(str), NULL);
}


static const char *
mg_strcasestr(const char *big_str, const char *small_str) {
    size_t i, big_len = strlen(big_str), small_len = strlen(small_str);

    if (big_len >= small_len) {
        for (i = 0; i <= (big_len - small_len); i++) {
            if (mg_strncasecmp(big_str + i, small_str, small_len) == 0) {
                return big_str + i;
            }
        }
    }

    return NULL;
}


/* Return null terminated string of given maximum length.
 * Report errors if length is exceeded. */
static void
mg_vsnprintf(const struct mg_connection *conn,
             int *truncated,
             char *buf,
             size_t buflen,
             const char *fmt,
             va_list ap) {
    int n, ok;

    if (buflen == 0) {
        if (truncated) {
            *truncated = 1;
        }
        return;
    }

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
    /* Using fmt as a non-literal is intended here, since it is mostly called
     * indirectly by mg_snprintf */
#endif

    n = (int) vsnprintf_impl(buf, buflen, fmt, ap);
    ok = (n >= 0) && ((size_t) n < buflen);

#if defined(__clang__)
#pragma clang diagnostic pop
#endif

    if (ok) {
        if (truncated) {
            *truncated = 0;
        }
    } else {
        if (truncated) {
            *truncated = 1;
        }
        mg_cry_internal(conn,
                        "truncating vsnprintf buffer: [%.*s]",
                        (int) ((buflen > 200) ? 200 : (buflen - 1)),
                        buf);
        n = (int) buflen - 1;
    }
    buf[n] = '\0';
}


static void
mg_snprintf(const struct mg_connection *conn,
            int *truncated,
            char *buf,
            size_t buflen,
            const char *fmt,
            ...) {
    va_list ap;

    va_start(ap, fmt);
    mg_vsnprintf(conn, truncated, buf, buflen, fmt, ap);
    va_end(ap);
}


static int
get_option_index(const char *name) {
    int i;

    for (i = 0; config_options[i].name != NULL; i++) {
        if (strcmp(config_options[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}


const char *
mg_get_option(const struct mg_context *ctx, const char *name) {
    int i;
    if ((i = get_option_index(name)) == -1) {
        return NULL;
    } else if (!ctx || ctx->dd.config[i] == NULL) {
        return "";
    } else {
        return ctx->dd.config[i];
    }
}

#define mg_get_option DO_NOT_USE_THIS_FUNCTION_INTERNALLY__access_directly

struct mg_context *
mg_get_context(const struct mg_connection *conn) {
    return (conn == NULL) ? (struct mg_context *) NULL : (conn->phys_ctx);
}


void *
mg_get_user_data(const struct mg_context *ctx) {
    return (ctx == NULL) ? NULL : ctx->user_data;
}


void
mg_set_user_connection_data(struct mg_connection *conn, void *data) {
    if (conn != NULL) {
        conn->request_info.conn_data = data;
    }
}


void *
mg_get_user_connection_data(const struct mg_connection *conn) {
    if (conn != NULL) {
        return conn->request_info.conn_data;
    }
    return NULL;
}


#if defined(MG_LEGACY_INTERFACE)
/* Deprecated: Use mg_get_server_ports instead. */
size_t
mg_get_ports(const struct mg_context *ctx, size_t size, int *ports, int *ssl)
{
size_t i;
if (!ctx) {
return 0;
}
for (i = 0; i < size && i < ctx->num_listening_sockets; i++) {
ssl[i] = ctx->listening_sockets[i].is_ssl;
ports[i] =
#if defined(USE_IPV6)
(ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET6)
? ntohs(ctx->listening_sockets[i].lsa.sin6.sin6_port)
:
#endif
ntohs(ctx->listening_sockets[i].lsa.sin.sin_port);
}
return i;
}
#endif


int
mg_get_server_ports(const struct mg_context *ctx,
                    int size,
                    struct mg_server_ports *ports) {
    int i, cnt = 0;

    if (size <= 0) {
        return -1;
    }
    memset(ports, 0, sizeof(*ports) * (size_t) size);
    if (!ctx) {
        return -1;
    }
    if (!ctx->listening_sockets) {
        return -1;
    }

    for (i = 0; (i < size) && (i < (int) ctx->num_listening_sockets); i++) {

        ports[cnt].port =
#if defined(USE_IPV6)
        (ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET6)
? ntohs(ctx->listening_sockets[i].lsa.sin6.sin6_port)
:
#endif
                ntohs(ctx->listening_sockets[i].lsa.sin.sin_port);
        ports[cnt].is_ssl = ctx->listening_sockets[i].is_ssl;
        ports[cnt].is_redirect = ctx->listening_sockets[i].ssl_redir;

        if (ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET) {
/* IPv4 */
            ports[cnt].protocol = 1;
            cnt++;
        } else if (ctx->listening_sockets[i].lsa.sa.sa_family == AF_INET6) {
/* IPv6 */
            ports[cnt].protocol = 3;
            cnt++;
        }
    }

    return cnt;
}


static void
sockaddr_to_string(char *buf, size_t len, const union usa *usa) {
    buf[0] = '\0';

    if (!usa) {
        return;
    }

    if (usa->sa.sa_family == AF_INET) {
        getnameinfo(&usa->sa,
                    sizeof(usa->sin),
                    buf,
                    (unsigned) len,
                    NULL,
                    0,
                    NI_NUMERICHOST);
    }
#if defined(USE_IPV6)
    else if (usa->sa.sa_family == AF_INET6) {
getnameinfo(&usa->sa,
sizeof(usa->sin6),
buf,
(unsigned)len,
NULL,
0,
NI_NUMERICHOST);
}
#endif
}


/* Convert time_t to a string. According to RFC2616, Sec 14.18, this must be
 * included in all responses other than 100, 101, 5xx. */
static void
gmt_time_string(char *buf, size_t buf_len, time_t *t) {
#if !defined(REENTRANT_TIME)
    struct tm *tm;

    tm = ((t != NULL) ? gmtime(t) : NULL);
    if (tm != NULL) {
#else
        struct tm _tm;
struct tm *tm = &_tm;

if (t != NULL) {
gmtime_r(t, tm);
#endif
        strftime(buf, buf_len, "%a, %d %b %Y %H:%M:%S GMT", tm);
    } else {
        mg_strlcpy(buf, "Thu, 01 Jan 1970 00:00:00 GMT", buf_len);
        buf[buf_len - 1] = '\0';
    }
}


/* difftime for struct timespec. Return value is in seconds. */
static double
mg_difftimespec(const struct timespec *ts_now, const struct timespec *ts_before) {
    return (double) (ts_now->tv_nsec - ts_before->tv_nsec) * 1.0E-9
           + (double) (ts_now->tv_sec - ts_before->tv_sec);
}


#if defined(MG_EXTERNAL_FUNCTION_mg_cry_internal_impl)
static void mg_cry_internal_impl(const struct mg_connection *conn,
const char *func,
unsigned line,
const char *fmt,
va_list ap);
#include "external_mg_cry_internal_impl.inl"
#else

/* Print error message to the opened error log stream. */
static void
mg_cry_internal_impl(const struct mg_connection *conn,
                     const char *func,
                     unsigned line,
                     const char *fmt,
                     va_list ap) {
    char buf[MG_BUF_LEN], src_addr[IP_ADDR_STR_LEN];
    struct mg_file fi;
    time_t timestamp;

/* Unused, in the RELEASE build */
    (void) func;
    (void) line;

#if defined(GCC_DIAGNOSTIC)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif

    IGNORE_UNUSED_RESULT(vsnprintf_impl(buf, sizeof(buf), fmt, ap));

#if defined(GCC_DIAGNOSTIC)
#pragma GCC diagnostic pop
#endif

    buf[sizeof(buf) - 1] = 0;

    DEBUG_TRACE("mg_cry called from %s:%u: %s", func, line, buf);

    if (!conn) {
        puts(buf);
        return;
    }

/* Do not lock when getting the callback value, here and below.
	 * I suppose this is fine, since function cannot disappear in the
	 * same way string option can. */
    if ((conn->phys_ctx->callbacks.log_message == NULL)
        || (conn->phys_ctx->callbacks.log_message(conn, buf) == 0)) {

        if (conn->dom_ctx->config[ERROR_LOG_FILE] != NULL) {
            if (mg_fopen(conn,
                         conn->dom_ctx->config[ERROR_LOG_FILE],
                         MG_FOPEN_MODE_APPEND,
                         &fi)
                == 0) {
                fi.access.fp = NULL;
            }
        } else {
            fi.access.fp = NULL;
        }

        if (fi.access.fp != NULL) {
            flockfile(fi.access.fp);
            timestamp = time(NULL);

            sockaddr_to_string(src_addr, sizeof(src_addr), &conn->client.rsa);
            fprintf(fi.access.fp,
                    "[%010lu] [error] [client %s] ",
                    (unsigned long) timestamp,
                    src_addr);

            if (conn->request_info.request_method != NULL) {
                fprintf(fi.access.fp,
                        "%s %s: ",
                        conn->request_info.request_method,
                        conn->request_info.request_uri
                        ? conn->request_info.request_uri
                        : "");
            }

            fprintf(fi.access.fp, "%s", buf);
            fputc('\n', fi.access.fp);
            fflush(fi.access.fp);
            funlockfile(fi.access.fp);
            (void) mg_fclose(&fi.access); /* Ignore errors. We can't call
			                              * mg_cry here anyway ;-) */
        }
    }
}

#endif /* Externally provided function */


static void
mg_cry_internal_wrap(const struct mg_connection *conn,
                     const char *func,
                     unsigned line,
                     const char *fmt,
                     ...) {
    va_list ap;
    va_start(ap, fmt);
    mg_cry_internal_impl(conn, func, line, fmt, ap);
    va_end(ap);
}


void
mg_cry(const struct mg_connection *conn, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    mg_cry_internal_impl(conn, "user", 0, fmt, ap);
    va_end(ap);
}


#define mg_cry DO_NOT_USE_THIS_FUNCTION__USE_mg_cry_internal


/* Return fake connection structure. Used for logging, if connection
 * is not applicable at the moment of logging. */
static struct mg_connection *
fc(struct mg_context *ctx) {
    static struct mg_connection fake_connection;
    fake_connection.phys_ctx = ctx;
    fake_connection.dom_ctx = &(ctx->dd);
    return &fake_connection;
}


const char *
mg_version(void) {
    return CIVETWEB_VERSION;
}


const struct mg_request_info *
mg_get_request_info(const struct mg_connection *conn) {
    if (!conn) {
        return NULL;
    }
#if defined(MG_ALLOW_USING_GET_REQUEST_INFO_FOR_RESPONSE)
    if (conn->connection_type == CONNECTION_TYPE_RESPONSE) {
char txt[16];
struct mg_workerTLS *tls =
(struct mg_workerTLS *)pthread_getspecific(sTlsKey);

sprintf(txt, "%03i", conn->response_info.status_code);
if (strlen(txt) == 3) {
memcpy(tls->txtbuf, txt, 4);
} else {
strcpy(tls->txtbuf, "ERR");
}

((struct mg_connection *)conn)->request_info.local_uri =
((struct mg_connection *)conn)->request_info.request_uri =
tls->txtbuf; /* use thread safe buffer */

((struct mg_connection *)conn)->request_info.num_headers =
conn->response_info.num_headers;
memcpy(((struct mg_connection *)conn)->request_info.http_headers,
conn->response_info.http_headers,
sizeof(conn->response_info.http_headers));
} else
#endif
    if (conn->connection_type != CONNECTION_TYPE_REQUEST) {
        return NULL;
    }
    return &conn->request_info;
}


const struct mg_response_info *
mg_get_response_info(const struct mg_connection *conn) {
    if (!conn) {
        return NULL;
    }
    if (conn->connection_type != CONNECTION_TYPE_RESPONSE) {
        return NULL;
    }
    return &conn->response_info;
}


static const char *
get_proto_name(const struct mg_connection *conn) {
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunreachable-code"
    /* Depending on USE_WEBSOCKET and NO_SSL, some oft the protocols might be
     * not supported. Clang raises an "unreachable code" warning for parts of ?:
     * unreachable, but splitting into four different #ifdef clauses here is more
     * complicated.
     */
#endif

    const struct mg_request_info *ri = &conn->request_info;

    const char *proto =
            (is_websocket_protocol(conn) ? (ri->is_ssl ? "wss" : "ws")
                                         : (ri->is_ssl ? "https" : "http"));

    return proto;

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
}


int
mg_get_request_link(const struct mg_connection *conn, char *buf, size_t buflen) {
    if ((buflen < 1) || (buf == 0) || (conn == 0)) {
        return -1;
    } else {

        int truncated = 0;
        const struct mg_request_info *ri = &conn->request_info;

        const char *proto = get_proto_name(conn);

        if (ri->local_uri == NULL) {
            return -1;
        }

        if ((ri->request_uri != NULL)
            && (0 != strcmp(ri->local_uri, ri->request_uri))) {
/* The request uri is different from the local uri.
			 * This is usually if an absolute URI, including server
			 * name has been provided. */
            mg_snprintf(conn,
                        &truncated,
                        buf,
                        buflen,
                        "%s://%s",
                        proto,
                        ri->request_uri);
            if (truncated) {
                return -1;
            }
            return 0;

        } else {

/* The common case is a relative URI, so we have to
			 * construct an absolute URI from server name and port */

#if defined(USE_IPV6)
            int is_ipv6 = (conn->client.lsa.sa.sa_family == AF_INET6);
int port = is_ipv6 ? htons(conn->client.lsa.sin6.sin6_port)
: htons(conn->client.lsa.sin.sin_port);
#else
            int port = htons(conn->client.lsa.sin.sin_port);
#endif
            int def_port = ri->is_ssl ? 443 : 80;
            int auth_domain_check_enabled =
                    conn->dom_ctx->config[ENABLE_AUTH_DOMAIN_CHECK]
                    && (!mg_strcasecmp(
                            conn->dom_ctx->config[ENABLE_AUTH_DOMAIN_CHECK], "yes"));
            const char *server_domain =
                    conn->dom_ctx->config[AUTHENTICATION_DOMAIN];

            char portstr[16];
            char server_ip[48];

            if (port != def_port) {
                sprintf(portstr, ":%u", (unsigned) port);
            } else {
                portstr[0] = 0;
            }

            if (!auth_domain_check_enabled || !server_domain) {

                sockaddr_to_string(server_ip,
                                   sizeof(server_ip),
                                   &conn->client.lsa);

                server_domain = server_ip;
            }

            mg_snprintf(conn,
                        &truncated,
                        buf,
                        buflen,
                        "%s://%s%s%s",
                        proto,
                        server_domain,
                        portstr,
                        ri->local_uri);
            if (truncated) {
                return -1;
            }
            return 0;
        }
    }
}

/* Skip the characters until one of the delimiters characters found.
 * 0-terminate resulting word. Skip the delimiter and following whitespaces.
 * Advance pointer to buffer to the next word. Return found 0-terminated
 * word.
 * Delimiters can be quoted with quotechar. */
static char *
skip_quoted(char **buf,
            const char *delimiters,
            const char *whitespace,
            char quotechar) {
    char *p, *begin_word, *end_word, *end_whitespace;

    begin_word = *buf;
    end_word = begin_word + strcspn(begin_word, delimiters);

/* Check for quotechar */
    if (end_word > begin_word) {
        p = end_word - 1;
        while (*p == quotechar) {
/* While the delimiter is quoted, look for the next delimiter.
			 */
/* This happens, e.g., in calls from parse_auth_header,
			 * if the user name contains a " character. */

/* If there is anything beyond end_word, copy it. */
            if (*end_word != '\0') {
                size_t end_off = strcspn(end_word + 1, delimiters);
                memmove(p, end_word, end_off + 1);
                p += end_off; /* p must correspond to end_word - 1 */
                end_word += end_off + 1;
            } else {
                *p = '\0';
                break;
            }
        }
        for (p++; p < end_word; p++) {
            *p = '\0';
        }
    }

    if (*end_word == '\0') {
        *buf = end_word;
    } else {

#if defined(GCC_DIAGNOSTIC)
/* Disable spurious conversion warning for GCC */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif /* defined(GCC_DIAGNOSTIC) */

        end_whitespace = end_word + strspn(&end_word[1], whitespace) + 1;

#if defined(GCC_DIAGNOSTIC)
#pragma GCC diagnostic pop
#endif /* defined(GCC_DIAGNOSTIC) */

        for (p = end_word; p < end_whitespace; p++) {
            *p = '\0';
        }

        *buf = end_whitespace;
    }

    return begin_word;
}


/* Return HTTP header value, or NULL if not found. */
static const char *
get_header(const struct mg_header *hdr, int num_hdr, const char *name) {
    int i;
    for (i = 0; i < num_hdr; i++) {
        if (!mg_strcasecmp(name, hdr[i].name)) {
            return hdr[i].value;
        }
    }

    return NULL;
}


#if defined(USE_WEBSOCKET)
/* Retrieve requested HTTP header multiple values, and return the number of
 * found occurrences */
static int
get_req_headers(const struct mg_request_info *ri,
const char *name,
const char **output,
int output_max_size)
{
int i;
int cnt = 0;
if (ri) {
for (i = 0; i < ri->num_headers && cnt < output_max_size; i++) {
if (!mg_strcasecmp(name, ri->http_headers[i].name)) {
output[cnt++] = ri->http_headers[i].value;
}
}
}
return cnt;
}
#endif


const char *
mg_get_header(const struct mg_connection *conn, const char *name) {
    if (!conn) {
        return NULL;
    }

    if (conn->connection_type == CONNECTION_TYPE_REQUEST) {
        return get_header(conn->request_info.http_headers,
                          conn->request_info.num_headers,
                          name);
    }
    if (conn->connection_type == CONNECTION_TYPE_RESPONSE) {
        return get_header(conn->response_info.http_headers,
                          conn->response_info.num_headers,
                          name);
    }
    return NULL;
}


static const char *
get_http_version(const struct mg_connection *conn) {
    if (!conn) {
        return NULL;
    }

    if (conn->connection_type == CONNECTION_TYPE_REQUEST) {
        return conn->request_info.http_version;
    }
    if (conn->connection_type == CONNECTION_TYPE_RESPONSE) {
        return conn->response_info.http_version;
    }
    return NULL;
}


/* A helper function for traversing a comma separated list of values.
 * It returns a list pointer shifted to the next value, or NULL if the end
 * of the list found.
 * Value is stored in val vector. If value has form "x=y", then eq_val
 * vector is initialized to point to the "y" part, and val vector length
 * is adjusted to point only to "x". */
static const char *
next_option(const char *list, struct vec *val, struct vec *eq_val) {
    int end;

    reparse:
    if (val == NULL || list == NULL || *list == '\0') {
/* End of the list */
        return NULL;
    }

/* Skip over leading LWS */
    while (*list == ' ' || *list == '\t')
        list++;

    val->ptr = list;
    if ((list = strchr(val->ptr, ',')) != NULL) {
/* Comma found. Store length and shift the list ptr */
        val->len = ((size_t) (list - val->ptr));
        list++;
    } else {
/* This value is the last one */
        list = val->ptr + strlen(val->ptr);
        val->len = ((size_t) (list - val->ptr));
    }

/* Adjust length for trailing LWS */
    end = (int) val->len - 1;
    while (end >= 0 && ((val->ptr[end] == ' ') || (val->ptr[end] == '\t')))
        end--;
    val->len = (size_t) (end + 1);

    if (val->len == 0) {
/* Ignore any empty entries. */
        goto reparse;
    }

    if (eq_val != NULL) {
/* Value has form "x=y", adjust pointers and lengths
		 * so that val points to "x", and eq_val points to "y". */
        eq_val->len = 0;
        eq_val->ptr = (const char *) memchr(val->ptr, '=', val->len);
        if (eq_val->ptr != NULL) {
            eq_val->ptr++; /* Skip over '=' character */
            eq_val->len = ((size_t) (val->ptr - eq_val->ptr)) + val->len;
            val->len = ((size_t) (eq_val->ptr - val->ptr)) - 1;
        }
    }

    return list;
}


/* A helper function for checking if a comma separated list of values
 * contains
 * the given option (case insensitvely).
 * 'header' can be NULL, in which case false is returned. */
static int
header_has_option(const char *header, const char *option) {
    struct vec opt_vec;
    struct vec eq_vec;

    DEBUG_ASSERT(option != NULL);
    DEBUG_ASSERT(option[0] != '\0');

    while ((header = next_option(header, &opt_vec, &eq_vec)) != NULL) {
        if (mg_strncasecmp(option, opt_vec.ptr, opt_vec.len) == 0)
            return 1;
    }

    return 0;
}


/* Perform case-insensitive match of string against pattern */
static ptrdiff_t
match_prefix(const char *pattern, size_t pattern_len, const char *str) {
    const char *or_str;
    ptrdiff_t i, j, len, res;

    if ((or_str = (const char *) memchr(pattern, '|', pattern_len)) != NULL) {
        res = match_prefix(pattern, (size_t) (or_str - pattern), str);
        return (res > 0) ? res
                         : match_prefix(or_str + 1,
                                        (size_t) ((pattern + pattern_len)
                                                  - (or_str + 1)),
                                        str);
    }

    for (i = 0, j = 0; (i < (ptrdiff_t) pattern_len); i++, j++) {
        if ((pattern[i] == '?') && (str[j] != '\0')) {
            continue;
        } else if (pattern[i] == '$') {
            return (str[j] == '\0') ? j : -1;
        } else if (pattern[i] == '*') {
            i++;
            if (pattern[i] == '*') {
                i++;
                len = strlen(str + j);
            } else {
                len = strcspn(str + j, "/");
            }
            if (i == (ptrdiff_t) pattern_len) {
                return j + len;
            }
            do {
                res = match_prefix(pattern + i, pattern_len - i, str + j + len);
            } while (res == -1 && len-- > 0);
            return (res == -1) ? -1 : j + res + len;
        } else if (lowercase(&pattern[i]) != lowercase(&str[j])) {
            return -1;
        }
    }
    return (ptrdiff_t) j;
}


/* HTTP 1.1 assumes keep alive if "Connection:" header is not set
 * This function must tolerate situations when connection info is not
 * set up, for example if request parsing failed. */
static int
should_keep_alive(const struct mg_connection *conn) {
    const char *http_version;
    const char *header;

/* First satisfy needs of the server */
    if ((conn == NULL) || conn->must_close) {
/* Close, if civetweb framework needs to close */
        return 0;
    }

    if (mg_strcasecmp(conn->dom_ctx->config[ENABLE_KEEP_ALIVE], "yes") != 0) {
/* Close, if keep alive is not enabled */
        return 0;
    }

/* Check explicit wish of the client */
    header = mg_get_header(conn, "Connection");
    if (header) {
/* If there is a connection header from the client, obey */
        if (header_has_option(header, "keep-alive")) {
            return 1;
        }
        return 0;
    }

/* Use default of the standard */
    http_version = get_http_version(conn);
    if (http_version && (0 == strcmp(http_version, "1.1"))) {
/* HTTP 1.1 default is keep alive */
        return 1;
    }

/* HTTP 1.0 (and earlier) default is to close the connection */
    return 0;
}


static int
should_decode_url(const struct mg_connection *conn) {
    if (!conn || !conn->dom_ctx) {
        return 0;
    }

    return (mg_strcasecmp(conn->dom_ctx->config[DECODE_URL], "yes") == 0);
}


static const char *
suggest_connection_header(const struct mg_connection *conn) {
    return should_keep_alive(conn) ? "keep-alive" : "close";
}


static int
send_no_cache_header(struct mg_connection *conn) {
/* Send all current and obsolete cache opt-out directives. */
    return mg_printf(conn,
                     "Cache-Control: no-cache, no-store, "
                     "must-revalidate, private, max-age=0\r\n"
                     "Pragma: no-cache\r\n"
                     "Expires: 0\r\n");
}


static int
send_static_cache_header(struct mg_connection *conn) {
#if !defined(NO_CACHING)
    /* Read the server config to check how long a file may be cached.
     * The configuration is in seconds. */
int max_age = atoi(conn->dom_ctx->config[STATIC_FILE_MAX_AGE]);
if (max_age <= 0) {
/* 0 means "do not cache". All values <0 are reserved
         * and may be used differently in the future. */
/* If a file should not be cached, do not only send
         * max-age=0, but also pragmas and Expires headers. */
return send_no_cache_header(conn);
}

/* Use "Cache-Control: max-age" instead of "Expires" header.
     * Reason: see https://www.mnot.net/blog/2007/05/15/expires_max-age */
/* See also https://www.mnot.net/cache_docs/ */
/* According to RFC 2616, Section 14.21, caching times should not exceed
     * one year. A year with 365 days corresponds to 31536000 seconds, a
     * leap
     * year to 31622400 seconds. For the moment, we just send whatever has
     * been configured, still the behavior for >1 year should be considered
     * as undefined. */
return mg_printf(conn, "Cache-Control: max-age=%u\r\n", (unsigned)max_age);
#else  /* NO_CACHING */
    return send_no_cache_header(conn);
#endif /* !NO_CACHING */
}


static int
send_additional_header(struct mg_connection *conn) {
    int i = 0;
    const char *header = conn->dom_ctx->config[ADDITIONAL_HEADER];

#if !defined(NO_SSL)
    if (conn->dom_ctx->config[STRICT_HTTPS_MAX_AGE]) {
        int max_age = atoi(conn->dom_ctx->config[STRICT_HTTPS_MAX_AGE]);
        if (max_age >= 0) {
            i += mg_printf(conn,
                           "Strict-Transport-Security: max-age=%u\r\n",
                           (unsigned) max_age);
        }
    }
#endif

    if (header && header[0]) {
        i += mg_printf(conn, "%s\r\n", header);
    }

    return i;
}


static void handle_file_based_request(struct mg_connection *conn,
                                      const char *path,
                                      struct mg_file *filep);


const char *
mg_get_response_code_text(const struct mg_connection *conn, int response_code) {
/* See IANA HTTP status code assignment:
	 * http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
	 */

    switch (response_code) {
/* RFC2616 Section 10.1 - Informational 1xx */
        case 100:
            return "Continue"; /* RFC2616 Section 10.1.1 */
        case 101:
            return "Switching Protocols"; /* RFC2616 Section 10.1.2 */
        case 102:
            return "Processing"; /* RFC2518 Section 10.1 */

/* RFC2616 Section 10.2 - Successful 2xx */
        case 200:
            return "OK"; /* RFC2616 Section 10.2.1 */
        case 201:
            return "Created"; /* RFC2616 Section 10.2.2 */
        case 202:
            return "Accepted"; /* RFC2616 Section 10.2.3 */
        case 203:
            return "Non-Authoritative Information"; /* RFC2616 Section 10.2.4 */
        case 204:
            return "No Content"; /* RFC2616 Section 10.2.5 */
        case 205:
            return "Reset Content"; /* RFC2616 Section 10.2.6 */
        case 206:
            return "Partial Content"; /* RFC2616 Section 10.2.7 */
        case 207:
            return "Multi-Status"; /* RFC2518 Section 10.2, RFC4918 Section 11.1
		                        */
        case 208:
            return "Already Reported"; /* RFC5842 Section 7.1 */

        case 226:
            return "IM used"; /* RFC3229 Section 10.4.1 */

/* RFC2616 Section 10.3 - Redirection 3xx */
        case 300:
            return "Multiple Choices"; /* RFC2616 Section 10.3.1 */
        case 301:
            return "Moved Permanently"; /* RFC2616 Section 10.3.2 */
        case 302:
            return "Found"; /* RFC2616 Section 10.3.3 */
        case 303:
            return "See Other"; /* RFC2616 Section 10.3.4 */
        case 304:
            return "Not Modified"; /* RFC2616 Section 10.3.5 */
        case 305:
            return "Use Proxy"; /* RFC2616 Section 10.3.6 */
        case 307:
            return "Temporary Redirect"; /* RFC2616 Section 10.3.8 */
        case 308:
            return "Permanent Redirect"; /* RFC7238 Section 3 */

/* RFC2616 Section 10.4 - Client Error 4xx */
        case 400:
            return "Bad Request"; /* RFC2616 Section 10.4.1 */
        case 401:
            return "Unauthorized"; /* RFC2616 Section 10.4.2 */
        case 402:
            return "Payment Required"; /* RFC2616 Section 10.4.3 */
        case 403:
            return "Forbidden"; /* RFC2616 Section 10.4.4 */
        case 404:
            return "Not Found"; /* RFC2616 Section 10.4.5 */
        case 405:
            return "Method Not Allowed"; /* RFC2616 Section 10.4.6 */
        case 406:
            return "Not Acceptable"; /* RFC2616 Section 10.4.7 */
        case 407:
            return "Proxy Authentication Required"; /* RFC2616 Section 10.4.8 */
        case 408:
            return "Request Time-out"; /* RFC2616 Section 10.4.9 */
        case 409:
            return "Conflict"; /* RFC2616 Section 10.4.10 */
        case 410:
            return "Gone"; /* RFC2616 Section 10.4.11 */
        case 411:
            return "Length Required"; /* RFC2616 Section 10.4.12 */
        case 412:
            return "Precondition Failed"; /* RFC2616 Section 10.4.13 */
        case 413:
            return "Request Entity Too Large"; /* RFC2616 Section 10.4.14 */
        case 414:
            return "Request-URI Too Large"; /* RFC2616 Section 10.4.15 */
        case 415:
            return "Unsupported Media Type"; /* RFC2616 Section 10.4.16 */
        case 416:
            return "Requested range not satisfiable"; /* RFC2616 Section 10.4.17
		                                           */
        case 417:
            return "Expectation Failed"; /* RFC2616 Section 10.4.18 */

        case 421:
            return "Misdirected Request"; /* RFC7540 Section 9.1.2 */
        case 422:
            return "Unproccessable entity"; /* RFC2518 Section 10.3, RFC4918
		                                 * Section 11.2 */
        case 423:
            return "Locked"; /* RFC2518 Section 10.4, RFC4918 Section 11.3 */
        case 424:
            return "Failed Dependency"; /* RFC2518 Section 10.5, RFC4918
		                             * Section 11.4 */

        case 426:
            return "Upgrade Required"; /* RFC 2817 Section 4 */

        case 428:
            return "Precondition Required"; /* RFC 6585, Section 3 */
        case 429:
            return "Too Many Requests"; /* RFC 6585, Section 4 */

        case 431:
            return "Request Header Fields Too Large"; /* RFC 6585, Section 5 */

        case 451:
            return "Unavailable For Legal Reasons"; /* draft-tbray-http-legally-restricted-status-05,
		                                         * Section 3 */

/* RFC2616 Section 10.5 - Server Error 5xx */
        case 500:
            return "Internal Server Error"; /* RFC2616 Section 10.5.1 */
        case 501:
            return "Not Implemented"; /* RFC2616 Section 10.5.2 */
        case 502:
            return "Bad Gateway"; /* RFC2616 Section 10.5.3 */
        case 503:
            return "Service Unavailable"; /* RFC2616 Section 10.5.4 */
        case 504:
            return "Gateway Time-out"; /* RFC2616 Section 10.5.5 */
        case 505:
            return "HTTP Version not supported"; /* RFC2616 Section 10.5.6 */
        case 506:
            return "Variant Also Negotiates"; /* RFC 2295, Section 8.1 */
        case 507:
            return "Insufficient Storage"; /* RFC2518 Section 10.6, RFC4918
		                                * Section 11.5 */
        case 508:
            return "Loop Detected"; /* RFC5842 Section 7.1 */

        case 510:
            return "Not Extended"; /* RFC 2774, Section 7 */
        case 511:
            return "Network Authentication Required"; /* RFC 6585, Section 6 */

/* Other status codes, not shown in the IANA HTTP status code
	 * assignment.
	 * E.g., "de facto" standards due to common use, ... */
        case 418:
            return "I am a teapot"; /* RFC2324 Section 2.3.2 */
        case 419:
            return "Authentication Timeout"; /* common use */
        case 420:
            return "Enhance Your Calm"; /* common use */
        case 440:
            return "Login Timeout"; /* common use */
        case 509:
            return "Bandwidth Limit Exceeded"; /* common use */

        default:
/* This error code is unknown. This should not happen. */
            if (conn) {
                mg_cry_internal(conn,
                                "Unknown HTTP response code: %u",
                                response_code);
            }

/* Return at least a category according to RFC 2616 Section 10. */
            if (response_code >= 100 && response_code < 200) {
/* Unknown informational status code */
                return "Information";
            }
            if (response_code >= 200 && response_code < 300) {
/* Unknown success code */
                return "Success";
            }
            if (response_code >= 300 && response_code < 400) {
/* Unknown redirection code */
                return "Redirection";
            }
            if (response_code >= 400 && response_code < 500) {
/* Unknown request error code */
                return "Client Error";
            }
            if (response_code >= 500 && response_code < 600) {
/* Unknown server error code */
                return "Server Error";
            }

/* Response code not even within reasonable range */
            return "";
    }
}


static int
mg_send_http_error_impl(struct mg_connection *conn,
                        int status,
                        const char *fmt,
                        va_list args) {
    char errmsg_buf[MG_BUF_LEN];
    char path_buf[PATH_MAX];
    va_list ap;
    int len, i, page_handler_found, scope, truncated, has_body;
    char date[64];
    time_t curtime = time(NULL);
    const char *error_handler = NULL;
    struct mg_file error_page_file = STRUCT_FILE_INITIALIZER;
    const char *error_page_file_ext, *tstr;
    int handled_by_callback = 0;

    const char *status_text = mg_get_response_code_text(conn, status);

    if ((conn == NULL) || (fmt == NULL)) {
        return -2;
    }

/* Set status (for log) */
    conn->status_code = status;

/* Errors 1xx, 204 and 304 MUST NOT send a body */
    has_body = ((status > 199) && (status != 204) && (status != 304));

/* Prepare message in buf, if required */
    if (has_body
        || (!conn->in_error_handler
            && (conn->phys_ctx->callbacks.http_error != NULL))) {
/* Store error message in errmsg_buf */
        va_copy(ap, args);
        mg_vsnprintf(conn, NULL, errmsg_buf, sizeof(errmsg_buf), fmt, ap);
        va_end(ap);
/* In a debug build, print all html errors */
        DEBUG_TRACE("Error %i - [%s]", status, errmsg_buf);
    }

/* If there is a http_error callback, call it.
	 * But don't do it recursively, if callback calls mg_send_http_error again.
	 */
    if (!conn->in_error_handler
        && (conn->phys_ctx->callbacks.http_error != NULL)) {
/* Mark in_error_handler to avoid recursion and call user callback. */
        conn->in_error_handler = 1;
        handled_by_callback =
                (conn->phys_ctx->callbacks.http_error(conn, status, errmsg_buf)
                 == 0);
        conn->in_error_handler = 0;
    }

    if (!handled_by_callback) {
/* Check for recursion */
        if (conn->in_error_handler) {
            DEBUG_TRACE(
                    "Recursion when handling error %u - fall back to default",
                    status);
        } else {
/* Send user defined error pages, if defined */
            error_handler = conn->dom_ctx->config[ERROR_PAGES];
            error_page_file_ext = conn->dom_ctx->config[INDEX_FILES];
            page_handler_found = 0;

            if (error_handler != NULL) {
                for (scope = 1; (scope <= 3) && !page_handler_found; scope++) {
                    switch (scope) {
                        case 1: /* Handler for specific error, e.g. 404 error */
                            mg_snprintf(conn,
                                        &truncated,
                                        path_buf,
                                        sizeof(path_buf) - 32,
                                        "%serror%03u.",
                                        error_handler,
                                        status);
                            break;
                        case 2: /* Handler for error group, e.g., 5xx error
					         * handler
					         * for all server errors (500-599) */
                            mg_snprintf(conn,
                                        &truncated,
                                        path_buf,
                                        sizeof(path_buf) - 32,
                                        "%serror%01uxx.",
                                        error_handler,
                                        status / 100);
                            break;
                        default: /* Handler for all errors */
                            mg_snprintf(conn,
                                        &truncated,
                                        path_buf,
                                        sizeof(path_buf) - 32,
                                        "%serror.",
                                        error_handler);
                            break;
                    }

/* String truncation in buf may only occur if
					 * error_handler is too long. This string is
					 * from the config, not from a client. */
                    (void) truncated;

                    len = (int) strlen(path_buf);

                    tstr = strchr(error_page_file_ext, '.');

                    while (tstr) {
                        for (i = 1;
                             (i < 32) && (tstr[i] != 0) && (tstr[i] != ',');
                             i++) {
/* buffer overrun is not possible here, since
							 * (i < 32) && (len < sizeof(path_buf) - 32)
							 * ==> (i + len) < sizeof(path_buf) */
                            path_buf[len + i - 1] = tstr[i];
                        }
/* buffer overrun is not possible here, since
						 * (i <= 32) && (len < sizeof(path_buf) - 32)
						 * ==> (i + len) <= sizeof(path_buf) */
                        path_buf[len + i - 1] = 0;

                        if (mg_stat(conn, path_buf, &error_page_file.stat)) {
                            DEBUG_TRACE("Check error page %s - found",
                                        path_buf);
                            page_handler_found = 1;
                            break;
                        }
                        DEBUG_TRACE("Check error page %s - not found",
                                    path_buf);

                        tstr = strchr(tstr + i, '.');
                    }
                }
            }

            if (page_handler_found) {
                conn->in_error_handler = 1;
                handle_file_based_request(conn, path_buf, &error_page_file);
                conn->in_error_handler = 0;
                return 0;
            }
        }

/* No custom error page. Send default error page. */
        gmt_time_string(date, sizeof(date), &curtime);

        conn->must_close = 1;
        mg_printf(conn, "HTTP/1.1 %d %s\r\n", status, status_text);
        send_no_cache_header(conn);
        send_additional_header(conn);
        if (has_body) {
            mg_printf(conn,
                      "%s",
                      "Content-Type: text/plain; charset=utf-8\r\n");
        }
        mg_printf(conn,
                  "Date: %s\r\n"
                  "Connection: close\r\n\r\n",
                  date);

/* HTTP responses 1xx, 204 and 304 MUST NOT send a body */
        if (has_body) {
/* For other errors, send a generic error message. */
            mg_printf(conn, "Error %d: %s\n", status, status_text);
            mg_write(conn, errmsg_buf, strlen(errmsg_buf));

        } else {
/* No body allowed. Close the connection. */
            DEBUG_TRACE("Error %i", status);
        }
    }
    return 0;
}


int
mg_send_http_error(struct mg_connection *conn, int status, const char *fmt, ...) {
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = mg_send_http_error_impl(conn, status, fmt, ap);
    va_end(ap);

    return ret;
}


int
mg_send_http_ok(struct mg_connection *conn,
                const char *mime_type,
                long long content_length) {
    char date[64];
    time_t curtime = time(NULL);

    if ((mime_type == NULL) || (*mime_type == 0)) {
/* Parameter error */
        return -2;
    }

    gmt_time_string(date, sizeof(date), &curtime);

    mg_printf(conn,
              "HTTP/1.1 200 OK\r\n"
              "Content-Type: %s\r\n"
              "Date: %s\r\n"
              "Connection: %s\r\n",
              mime_type,
              date,
              suggest_connection_header(conn));

    send_no_cache_header(conn);
    send_additional_header(conn);
    if (content_length < 0) {
        mg_printf(conn, "Transfer-Encoding: chunked\r\n\r\n");
    } else {
        mg_printf(conn,
                  "Content-Length: %" UINT64_FMT "\r\n\r\n",
                  (uint64_t) content_length);
    }

    return 0;
}


int
mg_send_http_redirect(struct mg_connection *conn,
                      const char *target_url,
                      int redirect_code) {
/* Send a 30x redirect response.
	 *
	 * Redirect types (status codes):
	 *
	 * Status | Perm/Temp | Method              | Version
	 *   301  | permanent | POST->GET undefined | HTTP/1.0
	 *   302  | temporary | POST->GET undefined | HTTP/1.0
	 *   303  | temporary | always use GET      | HTTP/1.1
	 *   307  | temporary | always keep method  | HTTP/1.1
	 *   308  | permanent | always keep method  | HTTP/1.1
	 */
    const char *redirect_text;
    int ret;
    size_t content_len = 0;
    char reply[MG_BUF_LEN];

/* In case redirect_code=0, use 307. */
    if (redirect_code == 0) {
        redirect_code = 307;
    }

/* In case redirect_code is none of the above, return error. */
    if ((redirect_code != 301) && (redirect_code != 302)
        && (redirect_code != 303) && (redirect_code != 307)
        && (redirect_code != 308)) {
/* Parameter error */
        return -2;
    }

/* Get proper text for response code */
    redirect_text = mg_get_response_code_text(conn, redirect_code);

/* If target_url is not defined, redirect to "/". */
    if ((target_url == NULL) || (*target_url == 0)) {
        target_url = "/";
    }

#if defined(MG_SEND_REDIRECT_BODY)
    /* TODO: condition name? */

/* Prepare a response body with a hyperlink.
     *
     * According to RFC2616 (and RFC1945 before):
     * Unless the request method was HEAD, the entity of the
     * response SHOULD contain a short hypertext note with a hyperlink to
     * the new URI(s).
     *
     * However, this response body is not useful in M2M communication.
     * Probably the original reason in the RFC was, clients not supporting
     * a 30x HTTP redirect could still show the HTML page and let the user
     * press the link. Since current browsers support 30x HTTP, the additional
     * HTML body does not seem to make sense anymore.
     *
     * The new RFC7231 (Section 6.4) does no longer recommend it ("SHOULD"),
     * but it only notes:
     * The server's response payload usually contains a short
     * hypertext note with a hyperlink to the new URI(s).
     *
     * Deactivated by default. If you need the 30x body, set the define.
     */
mg_snprintf(
conn,
NULL /* ignore truncation */,
reply,
sizeof(reply),
"<html><head>%s</head><body><a href=\"%s\">%s</a></body></html>",
redirect_text,
target_url,
target_url);
content_len = strlen(reply);
#else
    reply[0] = 0;
#endif

/* Do not send any additional header. For all other options,
	 * including caching, there are suitable defaults. */
    ret = mg_printf(conn,
                    "HTTP/1.1 %i %s\r\n"
                    "Location: %s\r\n"
                    "Content-Length: %u\r\n"
                    "Connection: %s\r\n\r\n",
                    redirect_code,
                    redirect_text,
                    target_url,
                    (unsigned int) content_len,
                    suggest_connection_header(conn));

/* Send response body */
    if (ret > 0) {
/* ... unless it is a HEAD request */
        if (0 != strcmp(conn->request_info.request_method, "HEAD")) {
            ret = mg_write(conn, reply, content_len);
        }
    }

    return (ret > 0) ? ret : -1;
}


// Urho3D: Prefer own implementation of clock_gettime() to prevent dependency on pthread library which is not needed otherwise
#ifdef __MINGW32__
int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	FILETIME ft;
	ULARGE_INTEGER li;
	BOOL ok = FALSE;
	double d;
	static double perfcnt_per_sec = 0.0;

	if (tp) {
		if (clk_id == CLOCK_REALTIME) {
			GetSystemTimeAsFileTime(&ft);
			li.LowPart = ft.dwLowDateTime;
			li.HighPart = ft.dwHighDateTime;
			li.QuadPart -= 116444736000000000; /* 1.1.1970 in filedate */
			tp->tv_sec = (time_t)(li.QuadPart / 10000000);
			tp->tv_nsec = (long)(li.QuadPart % 10000000) * 100;
			ok = TRUE;
		} else if (clk_id == CLOCK_MONOTONIC) {
			if (perfcnt_per_sec == 0.0) {
				QueryPerformanceFrequency((LARGE_INTEGER *)&li);
				perfcnt_per_sec = 1.0 / li.QuadPart;
			}
			if (perfcnt_per_sec != 0.0) {
				QueryPerformanceCounter((LARGE_INTEGER *)&li);
				d = li.QuadPart * perfcnt_per_sec;
				tp->tv_sec = (time_t)d;
				d -= tp->tv_sec;
				tp->tv_nsec = (long)(d * 1.0E9);
				ok = TRUE;
			}
		}
	}

	return ok ? 0 : -1;
}
#endif

#if defined(_WIN32)
/* Create substitutes for POSIX functions in Win32. */

#if defined(GCC_DIAGNOSTIC)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif


FUNCTION_MAY_BE_UNUSED
static int
pthread_mutex_init(pthread_mutex_t *mutex, void *unused)
{
(void)unused;
*mutex = CreateMutex(NULL, FALSE, NULL);
return (*mutex == NULL) ? -1 : 0;
}

FUNCTION_MAY_BE_UNUSED
static int
pthread_mutex_destroy(pthread_mutex_t *mutex)
{
return (CloseHandle(*mutex) == 0) ? -1 : 0;
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_mutex_lock(pthread_mutex_t *mutex)
{
return (WaitForSingleObject(*mutex, (DWORD)INFINITE) == WAIT_OBJECT_0) ? 0
: -1;
}

#if defined(ENABLE_UNUSED_PTHREAD_FUNCTIONS)
FUNCTION_MAY_BE_UNUSED
static int
pthread_mutex_trylock(pthread_mutex_t *mutex)
{
switch (WaitForSingleObject(*mutex, 0)) {
case WAIT_OBJECT_0:
return 0;
case WAIT_TIMEOUT:
return -2; /* EBUSY */
}
return -1;
}
#endif


FUNCTION_MAY_BE_UNUSED
static int
pthread_mutex_unlock(pthread_mutex_t *mutex)
{
return (ReleaseMutex(*mutex) == 0) ? -1 : 0;
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_cond_init(pthread_cond_t *cv, const void *unused)
{
(void)unused;
InitializeCriticalSection(&cv->threadIdSec);
cv->waiting_thread = NULL;
return 0;
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_cond_timedwait(pthread_cond_t *cv,
pthread_mutex_t *mutex,
FUNCTION_MAY_BE_UNUSED const struct timespec *abstime)
{
struct mg_workerTLS **ptls,
*tls = (struct mg_workerTLS *)pthread_getspecific(sTlsKey);
int ok;
int64_t nsnow, nswaitabs, nswaitrel;
DWORD mswaitrel;

EnterCriticalSection(&cv->threadIdSec);
/* Add this thread to cv's waiting list */
ptls = &cv->waiting_thread;
for (; *ptls != NULL; ptls = &(*ptls)->next_waiting_thread)
;
tls->next_waiting_thread = NULL;
*ptls = tls;
LeaveCriticalSection(&cv->threadIdSec);

if (abstime) {
nsnow = mg_get_current_time_ns();
nswaitabs =
(((int64_t)abstime->tv_sec) * 1000000000) + abstime->tv_nsec;
nswaitrel = nswaitabs - nsnow;
if (nswaitrel < 0) {
nswaitrel = 0;
}
mswaitrel = (DWORD)(nswaitrel / 1000000);
} else {
mswaitrel = (DWORD)INFINITE;
}

pthread_mutex_unlock(mutex);
ok = (WAIT_OBJECT_0
== WaitForSingleObject(tls->pthread_cond_helper_mutex, mswaitrel));
if (!ok) {
ok = 1;
EnterCriticalSection(&cv->threadIdSec);
ptls = &cv->waiting_thread;
for (; *ptls != NULL; ptls = &(*ptls)->next_waiting_thread) {
if (*ptls == tls) {
*ptls = tls->next_waiting_thread;
ok = 0;
break;
}
}
LeaveCriticalSection(&cv->threadIdSec);
if (ok) {
WaitForSingleObject(tls->pthread_cond_helper_mutex,
(DWORD)INFINITE);
}
}
/* This thread has been removed from cv's waiting list */
pthread_mutex_lock(mutex);

return ok ? 0 : -1;
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_cond_wait(pthread_cond_t *cv, pthread_mutex_t *mutex)
{
return pthread_cond_timedwait(cv, mutex, NULL);
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_cond_signal(pthread_cond_t *cv)
{
HANDLE wkup = NULL;
BOOL ok = FALSE;

EnterCriticalSection(&cv->threadIdSec);
if (cv->waiting_thread) {
wkup = cv->waiting_thread->pthread_cond_helper_mutex;
cv->waiting_thread = cv->waiting_thread->next_waiting_thread;

ok = SetEvent(wkup);
DEBUG_ASSERT(ok);
}
LeaveCriticalSection(&cv->threadIdSec);

return ok ? 0 : 1;
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_cond_broadcast(pthread_cond_t *cv)
{
EnterCriticalSection(&cv->threadIdSec);
while (cv->waiting_thread) {
pthread_cond_signal(cv);
}
LeaveCriticalSection(&cv->threadIdSec);

return 0;
}


FUNCTION_MAY_BE_UNUSED
static int
pthread_cond_destroy(pthread_cond_t *cv)
{
EnterCriticalSection(&cv->threadIdSec);
DEBUG_ASSERT(cv->waiting_thread == NULL);
LeaveCriticalSection(&cv->threadIdSec);
DeleteCriticalSection(&cv->threadIdSec);

return 0;
}


#if defined(ALTERNATIVE_QUEUE)
FUNCTION_MAY_BE_UNUSED
static void *
event_create(void)
{
return (void *)CreateEvent(NULL, FALSE, FALSE, NULL);
}


FUNCTION_MAY_BE_UNUSED
static int
event_wait(void *eventhdl)
{
int res = WaitForSingleObject((HANDLE)eventhdl, (DWORD)INFINITE);
return (res == WAIT_OBJECT_0);
}


FUNCTION_MAY_BE_UNUSED
static int
event_signal(void *eventhdl)
{
return (int)SetEvent((HANDLE)eventhdl);
}


FUNCTION_MAY_BE_UNUSED
static void
event_destroy(void *eventhdl)
{
CloseHandle((HANDLE)eventhdl);
}
#endif


#if defined(GCC_DIAGNOSTIC)
/* Enable unused function warning again */
#pragma GCC diagnostic pop
#endif


/* For Windows, change all slashes to backslashes in path names. */
static void
change_slashes_to_backslashes(char *path)
{
int i;

for (i = 0; path[i] != '\0'; i++) {
if (path[i] == '/') {
path[i] = '\\';
}

/* remove double backslash (check i > 0 to preserve UNC paths,
         * like \\server\file.txt) */
if ((path[i] == '\\') && (i > 0)) {
while ((path[i + 1] == '\\') || (path[i + 1] == '/')) {
(void)memmove(path + i + 1, path + i + 2, strlen(path + i + 1));
}
}
}
}


static int
mg_wcscasecmp(const wchar_t *s1, const wchar_t *s2)
{
int diff;

do {
diff = tolower(*s1) - tolower(*s2);
s1++;
s2++;
} while ((diff == 0) && (s1[-1] != '\0'));

return diff;
}


/* Encode 'path' which is assumed UTF-8 string, into UNICODE string.
 * wbuf and wbuf_len is a target buffer and its length. */
static void
path_to_unicode(const struct mg_connection *conn,
const char *path,
wchar_t *wbuf,
size_t wbuf_len)
{
char buf[PATH_MAX], buf2[PATH_MAX];
wchar_t wbuf2[W_PATH_MAX + 1];
DWORD long_len, err;
int (*fcompare)(const wchar_t *, const wchar_t *) = mg_wcscasecmp;

mg_strlcpy(buf, path, sizeof(buf));
change_slashes_to_backslashes(buf);

/* Convert to Unicode and back. If doubly-converted string does not
     * match the original, something is fishy, reject. */
memset(wbuf, 0, wbuf_len * sizeof(wchar_t));
MultiByteToWideChar(CP_UTF8, 0, buf, -1, wbuf, (int)wbuf_len);
WideCharToMultiByte(
CP_UTF8, 0, wbuf, (int)wbuf_len, buf2, sizeof(buf2), NULL, NULL);
if (strcmp(buf, buf2) != 0) {
wbuf[0] = L'\0';
}

/* Windows file systems are not case sensitive, but you can still use
     * uppercase and lowercase letters (on all modern file systems).
     * The server can check if the URI uses the same upper/lowercase
     * letters an the file system, effectively making Windows servers
     * case sensitive (like Linux servers are). It is still not possible
     * to use two files with the same name in different cases on Windows
     * (like /a and /A) - this would be possible in Linux.
     * As a default, Windows is not case sensitive, but the case sensitive
     * file name check can be activated by an additional configuration. */
if (conn) {
if (conn->dom_ctx->config[CASE_SENSITIVE_FILES]
&& !mg_strcasecmp(conn->dom_ctx->config[CASE_SENSITIVE_FILES],
"yes")) {
/* Use case sensitive compare function */
fcompare = wcscmp;
}
}
(void)conn; /* conn is currently unused */

#if !defined(_WIN32_WCE)
/* Only accept a full file path, not a Windows short (8.3) path. */
memset(wbuf2, 0, ARRAY_SIZE(wbuf2) * sizeof(wchar_t));
long_len = GetLongPathNameW(wbuf, wbuf2, ARRAY_SIZE(wbuf2) - 1);
if (long_len == 0) {
err = GetLastError();
if (err == ERROR_FILE_NOT_FOUND) {
/* File does not exist. This is not always a problem here. */
return;
}
}
if ((long_len >= ARRAY_SIZE(wbuf2)) || (fcompare(wbuf, wbuf2) != 0)) {
/* Short name is used. */
wbuf[0] = L'\0';
}
#else
(void)long_len;
(void)wbuf2;
(void)err;

if (strchr(path, '~')) {
wbuf[0] = L'\0';
}
#endif
}


/* Windows happily opens files with some garbage at the end of file name.
 * For example, fopen("a.cgi    ", "r") on Windows successfully opens
 * "a.cgi", despite one would expect an error back.
 * This function returns non-0 if path ends with some garbage. */
static int
path_cannot_disclose_cgi(const char *path)
{
static const char *allowed_last_characters = "_-";
int last = path[strlen(path) - 1];
return isalnum(last) || strchr(allowed_last_characters, last) != NULL;
}


static int
mg_stat(const struct mg_connection *conn,
const char *path,
struct mg_file_stat *filep)
{
wchar_t wbuf[W_PATH_MAX];
WIN32_FILE_ATTRIBUTE_DATA info;
time_t creation_time;

if (!filep) {
return 0;
}
memset(filep, 0, sizeof(*filep));

if (conn && is_file_in_memory(conn, path)) {
/* filep->is_directory = 0; filep->gzipped = 0; .. already done by
         * memset */

/* Quick fix (for 1.9.x): */
/* mg_stat must fill all fields, also for files in memory */
struct mg_file tmp_file = STRUCT_FILE_INITIALIZER;
open_file_in_memory(conn, path, &tmp_file, MG_FOPEN_MODE_NONE);
filep->size = tmp_file.stat.size;
filep->location = 2;
/* TODO: for 1.10: restructure how files in memory are handled */

/* The "file in memory" feature is a candidate for deletion.
         * Please join the discussion at
         * https://groups.google.com/forum/#!topic/civetweb/h9HT4CmeYqI
         */

filep->last_modified = time(NULL); /* TODO */
/* last_modified = now ... assumes the file may change during
         * runtime,
         * so every mg_fopen call may return different data */
/* last_modified = conn->phys_ctx.start_time;
         * May be used it the data does not change during runtime. This
         * allows
         * browser caching. Since we do not know, we have to assume the file
         * in memory may change. */
return 1;
}

path_to_unicode(conn, path, wbuf, ARRAY_SIZE(wbuf));
if (GetFileAttributesExW(wbuf, GetFileExInfoStandard, &info) != 0) {
filep->size = MAKEUQUAD(info.nFileSizeLow, info.nFileSizeHigh);
filep->last_modified =
SYS2UNIX_TIME(info.ftLastWriteTime.dwLowDateTime,
info.ftLastWriteTime.dwHighDateTime);

/* On Windows, the file creation time can be higher than the
         * modification time, e.g. when a file is copied.
         * Since the Last-Modified timestamp is used for caching
         * it should be based on the most recent timestamp. */
creation_time = SYS2UNIX_TIME(info.ftCreationTime.dwLowDateTime,
info.ftCreationTime.dwHighDateTime);
if (creation_time > filep->last_modified) {
filep->last_modified = creation_time;
}

filep->is_directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
/* If file name is fishy, reset the file structure and return
         * error.
         * Note it is important to reset, not just return the error, cause
         * functions like is_file_opened() check the struct. */
if (!filep->is_directory && !path_cannot_disclose_cgi(path)) {
memset(filep, 0, sizeof(*filep));
return 0;
}

return 1;
}

return 0;
}


static int
mg_remove(const struct mg_connection *conn, const char *path)
{
wchar_t wbuf[W_PATH_MAX];
path_to_unicode(conn, path, wbuf, ARRAY_SIZE(wbuf));
return DeleteFileW(wbuf) ? 0 : -1;
}


static int
mg_mkdir(const struct mg_connection *conn, const char *path, int mode)
{
wchar_t wbuf[W_PATH_MAX];
(void)mode;
path_to_unicode(conn, path, wbuf, ARRAY_SIZE(wbuf));
return CreateDirectoryW(wbuf, NULL) ? 0 : -1;
}


/* Create substitutes for POSIX functions in Win32. */

#if defined(GCC_DIAGNOSTIC)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif


/* Implementation of POSIX opendir/closedir/readdir for Windows. */
FUNCTION_MAY_BE_UNUSED
static DIR *
mg_opendir(const struct mg_connection *conn, const char *name)
{
DIR *dir = NULL;
wchar_t wpath[W_PATH_MAX];
DWORD attrs;

if (name == NULL) {
SetLastError(ERROR_BAD_ARGUMENTS);
} else if ((dir = (DIR *)mg_malloc(sizeof(*dir))) == NULL) {
SetLastError(ERROR_NOT_ENOUGH_MEMORY);
} else {
path_to_unicode(conn, name, wpath, ARRAY_SIZE(wpath));
attrs = GetFileAttributesW(wpath);
if ((wcslen(wpath) + 2 < ARRAY_SIZE(wpath)) && (attrs != 0xFFFFFFFF)
&& ((attrs & FILE_ATTRIBUTE_DIRECTORY) != 0)) {
(void)wcscat(wpath, L"\\*");
dir->handle = FindFirstFileW(wpath, &dir->info);
dir->result.d_name[0] = '\0';
} else {
mg_free(dir);
dir = NULL;
}
}

return dir;
}


FUNCTION_MAY_BE_UNUSED
static int
mg_closedir(DIR *dir)
{
int result = 0;

if (dir != NULL) {
if (dir->handle != INVALID_HANDLE_VALUE)
result = FindClose(dir->handle) ? 0 : -1;

mg_free(dir);
} else {
result = -1;
SetLastError(ERROR_BAD_ARGUMENTS);
}

return result;
}


FUNCTION_MAY_BE_UNUSED
static struct dirent *
mg_readdir(DIR *dir)
{
struct dirent *result = 0;

if (dir) {
if (dir->handle != INVALID_HANDLE_VALUE) {
result = &dir->result;
(void)WideCharToMultiByte(CP_UTF8,
0,
dir->info.cFileName,
-1,
result->d_name,
sizeof(result->d_name),
NULL,
NULL);

if (!FindNextFileW(dir->handle, &dir->info)) {
(void)FindClose(dir->handle);
dir->handle = INVALID_HANDLE_VALUE;
}

} else {
SetLastError(ERROR_FILE_NOT_FOUND);
}
} else {
SetLastError(ERROR_BAD_ARGUMENTS);
}

return result;
}


#if !defined(HAVE_POLL)
#define POLLIN (1)  /* Data ready - read will not block. */
#define POLLPRI (2) /* Priority data ready. */
#define POLLOUT (4) /* Send queue not full - write will not block. */

FUNCTION_MAY_BE_UNUSED
static int
poll(struct pollfd *pfd, unsigned int n, int milliseconds)
{
struct timeval tv;
fd_set rset;
fd_set wset;
unsigned int i;
int result;
SOCKET maxfd = 0;

memset(&tv, 0, sizeof(tv));
tv.tv_sec = milliseconds / 1000;
tv.tv_usec = (milliseconds % 1000) * 1000;
FD_ZERO(&rset);
FD_ZERO(&wset);

for (i = 0; i < n; i++) {
if (pfd[i].events & POLLIN) {
FD_SET((SOCKET)pfd[i].fd, &rset);
} else if (pfd[i].events & POLLOUT) {
FD_SET((SOCKET)pfd[i].fd, &wset);
}
pfd[i].revents = 0;

if (pfd[i].fd > maxfd) {
maxfd = pfd[i].fd;
}
}

if ((result = select((int)maxfd + 1, &rset, &wset, NULL, &tv)) > 0) {
for (i = 0; i < n; i++) {
if (FD_ISSET(pfd[i].fd, &rset)) {
pfd[i].revents |= POLLIN;
}
if (FD_ISSET(pfd[i].fd, &wset)) {
pfd[i].revents |= POLLOUT;
}
}
}

/* We should subtract the time used in select from remaining
     * "milliseconds", in particular if called from mg_poll with a
     * timeout quantum.
     * Unfortunately, the remaining time is not stored in "tv" in all
     * implementations, so the result in "tv" must be considered undefined.
     * See http://man7.org/linux/man-pages/man2/select.2.html */

return result;
}
#endif /* HAVE_POLL */


#if defined(GCC_DIAGNOSTIC)
/* Enable unused function warning again */
#pragma GCC diagnostic pop
#endif


static void
set_close_on_exec(SOCKET sock, struct mg_connection *conn /* may be null */)
{
(void)conn; /* Unused. */
#if defined(_WIN32_WCE)
(void)sock;
#else
(void)SetHandleInformation((HANDLE)(intptr_t)sock, HANDLE_FLAG_INHERIT, 0);
#endif
}


int
mg_start_thread(mg_thread_func_t f, void *p)
{
#if defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1)
/* Compile-time option to control stack size, e.g.
     * -DUSE_STACK_SIZE=16384
     */
return ((_beginthread((void(__cdecl *)(void *))f, USE_STACK_SIZE, p)
== ((uintptr_t)(-1L)))
? -1
: 0);
#else
return (
(_beginthread((void(__cdecl *)(void *))f, 0, p) == ((uintptr_t)(-1L)))
? -1
: 0);
#endif /* defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1) */
}


/* Start a thread storing the thread context. */
static int
mg_start_thread_with_id(unsigned(__stdcall *f)(void *),
void *p,
pthread_t *threadidptr)
{
uintptr_t uip;
HANDLE threadhandle;
int result = -1;

uip = _beginthreadex(NULL, 0, (unsigned(__stdcall *)(void *))f, p, 0, NULL);
threadhandle = (HANDLE)uip;
if ((uip != (uintptr_t)(-1L)) && (threadidptr != NULL)) {
*threadidptr = threadhandle;
result = 0;
}

return result;
}


/* Wait for a thread to finish. */
static int
mg_join_thread(pthread_t threadid)
{
int result;
DWORD dwevent;

result = -1;
dwevent = WaitForSingleObject(threadid, (DWORD)INFINITE);
if (dwevent == WAIT_FAILED) {
DEBUG_TRACE("WaitForSingleObject() failed, error %d", ERRNO);
} else {
if (dwevent == WAIT_OBJECT_0) {
CloseHandle(threadid);
result = 0;
}
}

return result;
}

#if !defined(NO_SSL_DL) && !defined(NO_SSL)
/* If SSL is loaded dynamically, dlopen/dlclose is required. */
/* Create substitutes for POSIX functions in Win32. */

#if defined(GCC_DIAGNOSTIC)
/* Show no warning in case system functions are not used. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif


FUNCTION_MAY_BE_UNUSED
static HANDLE
dlopen(const char *dll_name, int flags)
{
wchar_t wbuf[W_PATH_MAX];
(void)flags;
path_to_unicode(NULL, dll_name, wbuf, ARRAY_SIZE(wbuf));
return LoadLibraryW(wbuf);
}


FUNCTION_MAY_BE_UNUSED
static int
dlclose(void *handle)
{
int result;

if (FreeLibrary((HMODULE)handle) != 0) {
result = 0;
} else {
result = -1;
}

return result;
}


#if defined(GCC_DIAGNOSTIC)
/* Enable unused function warning again */
#pragma GCC diagnostic pop
#endif

#endif


#if !defined(NO_CGI)
#define SIGKILL (0)


static int
kill(pid_t pid, int sig_num)
{
(void)TerminateProcess((HANDLE)pid, (UINT)sig_num);
(void)CloseHandle((HANDLE)pid);
return 0;
}


#if !defined(WNOHANG)
#define WNOHANG (1)
#endif


static pid_t
waitpid(pid_t pid, int *status, int flags)
{
DWORD timeout = INFINITE;
DWORD waitres;

(void)status; /* Currently not used by any client here */

if ((flags | WNOHANG) == WNOHANG) {
timeout = 0;
}

waitres = WaitForSingleObject((HANDLE)pid, timeout);
if (waitres == WAIT_OBJECT_0) {
return pid;
}
if (waitres == WAIT_TIMEOUT) {
return 0;
}
return (pid_t)-1;
}


static void
trim_trailing_whitespaces(char *s)
{
char *e = s + strlen(s) - 1;
while ((e > s) && isspace(*(unsigned char *)e)) {
*e-- = '\0';
}
}


static pid_t
spawn_process(struct mg_connection *conn,
const char *prog,
char *envblk,
char *envp[],
int fdin[2],
int fdout[2],
int fderr[2],
const char *dir)
{
HANDLE me;
char *p, *interp, full_interp[PATH_MAX], full_dir[PATH_MAX],
cmdline[PATH_MAX], buf[PATH_MAX];
int truncated;
struct mg_file file = STRUCT_FILE_INITIALIZER;
STARTUPINFOA si;
PROCESS_INFORMATION pi = {0};

(void)envp;

memset(&si, 0, sizeof(si));
si.cb = sizeof(si);

si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
si.wShowWindow = SW_HIDE;

me = GetCurrentProcess();
DuplicateHandle(me,
(HANDLE)_get_osfhandle(fdin[0]),
me,
&si.hStdInput,
0,
TRUE,
DUPLICATE_SAME_ACCESS);
DuplicateHandle(me,
(HANDLE)_get_osfhandle(fdout[1]),
me,
&si.hStdOutput,
0,
TRUE,
DUPLICATE_SAME_ACCESS);
DuplicateHandle(me,
(HANDLE)_get_osfhandle(fderr[1]),
me,
&si.hStdError,
0,
TRUE,
DUPLICATE_SAME_ACCESS);

/* Mark handles that should not be inherited. See
     * https://msdn.microsoft.com/en-us/library/windows/desktop/ms682499%28v=vs.85%29.aspx
     */
SetHandleInformation((HANDLE)_get_osfhandle(fdin[1]),
HANDLE_FLAG_INHERIT,
0);
SetHandleInformation((HANDLE)_get_osfhandle(fdout[0]),
HANDLE_FLAG_INHERIT,
0);
SetHandleInformation((HANDLE)_get_osfhandle(fderr[0]),
HANDLE_FLAG_INHERIT,
0);

/* If CGI file is a script, try to read the interpreter line */
interp = conn->dom_ctx->config[CGI_INTERPRETER];
if (interp == NULL) {
buf[0] = buf[1] = '\0';

/* Read the first line of the script into the buffer */
mg_snprintf(
conn, &truncated, cmdline, sizeof(cmdline), "%s/%s", dir, prog);

if (truncated) {
pi.hProcess = (pid_t)-1;
goto spawn_cleanup;
}

if (mg_fopen(conn, cmdline, MG_FOPEN_MODE_READ, &file)) {
#if defined(MG_USE_OPEN_FILE)
p = (char *)file.access.membuf;
#else
p = (char *)NULL;
#endif
mg_fgets(buf, sizeof(buf), &file, &p);
(void)mg_fclose(&file.access); /* ignore error on read only file */
buf[sizeof(buf) - 1] = '\0';
}

if ((buf[0] == '#') && (buf[1] == '!')) {
trim_trailing_whitespaces(buf + 2);
} else {
buf[2] = '\0';
}
interp = buf + 2;
}

if (interp[0] != '\0') {
GetFullPathNameA(interp, sizeof(full_interp), full_interp, NULL);
interp = full_interp;
}
GetFullPathNameA(dir, sizeof(full_dir), full_dir, NULL);

if (interp[0] != '\0') {
mg_snprintf(conn,
&truncated,
cmdline,
sizeof(cmdline),
"\"%s\" \"%s\\%s\"",
interp,
full_dir,
prog);
} else {
mg_snprintf(conn,
&truncated,
cmdline,
sizeof(cmdline),
"\"%s\\%s\"",
full_dir,
prog);
}

if (truncated) {
pi.hProcess = (pid_t)-1;
goto spawn_cleanup;
}

DEBUG_TRACE("Running [%s]", cmdline);
if (CreateProcessA(NULL,
cmdline,
NULL,
NULL,
TRUE,
CREATE_NEW_PROCESS_GROUP,
envblk,
NULL,
&si,
&pi)
== 0) {
mg_cry_internal(
conn, "%s: CreateProcess(%s): %ld", __func__, cmdline, (long)ERRNO);
pi.hProcess = (pid_t)-1;
/* goto spawn_cleanup; */
}

spawn_cleanup:
(void)CloseHandle(si.hStdOutput);
(void)CloseHandle(si.hStdError);
(void)CloseHandle(si.hStdInput);
if (pi.hThread != NULL) {
(void)CloseHandle(pi.hThread);
}

return (pid_t)pi.hProcess;
}
#endif /* !NO_CGI */


static int
set_blocking_mode(SOCKET sock)
{
unsigned long non_blocking = 0;
return ioctlsocket(sock, (long)FIONBIO, &non_blocking);
}

static int
set_non_blocking_mode(SOCKET sock)
{
unsigned long non_blocking = 1;
return ioctlsocket(sock, (long)FIONBIO, &non_blocking);
}

#else

static int
mg_stat(const struct mg_connection *conn,
        const char *path,
        struct mg_file_stat *filep) {
    struct stat st;
    if (!filep) {
        return 0;
    }
    memset(filep, 0, sizeof(*filep));

    if (conn && is_file_in_memory(conn, path)) {

/* Quick fix (for 1.9.x): */
/* mg_stat must fill all fields, also for files in memory */
        struct mg_file tmp_file = STRUCT_FILE_INITIALIZER;
        open_file_in_memory(conn, path, &tmp_file, MG_FOPEN_MODE_NONE);
        filep->size = tmp_file.stat.size;
        filep->last_modified = time(NULL);
        filep->location = 2;
/* TODO: remove legacy "files in memory" feature */

        return 1;
    }

    if (0 == stat(path, &st)) {
        filep->size = (uint64_t) (st.st_size);
        filep->last_modified = st.st_mtime;
        filep->is_directory = S_ISDIR(st.st_mode);
        return 1;
    }

    return 0;
}


static void
set_close_on_exec(SOCKET fd, struct mg_connection *conn /* may be null */) {
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        if (conn) {
            mg_cry_internal(conn,
                            "%s: fcntl(F_SETFD FD_CLOEXEC) failed: %s",
                            __func__,
                            strerror(ERRNO));
        }
    }
}


int
mg_start_thread(mg_thread_func_t func, void *param) {
    pthread_t thread_id;
    pthread_attr_t attr;
    int result;

    (void) pthread_attr_init(&attr);
    (void) pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

#if defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1)
    /* Compile-time option to control stack size,
     * e.g. -DUSE_STACK_SIZE=16384 */
(void)pthread_attr_setstacksize(&attr, USE_STACK_SIZE);
#endif /* defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1) */

    result = pthread_create(&thread_id, &attr, func, param);
    pthread_attr_destroy(&attr);

    return result;
}


/* Start a thread storing the thread context. */
static int
mg_start_thread_with_id(mg_thread_func_t func,
                        void *param,
                        pthread_t *threadidptr) {
    pthread_t thread_id;
    pthread_attr_t attr;
    int result;

    (void) pthread_attr_init(&attr);

#if defined(USE_STACK_SIZE) && (USE_STACK_SIZE > 1)
    /* Compile-time option to control stack size,
     * e.g. -DUSE_STACK_SIZE=16384 */
(void)pthread_attr_setstacksize(&attr, USE_STACK_SIZE);
#endif /* defined(USE_STACK_SIZE) && USE_STACK_SIZE > 1 */

    result = pthread_create(&thread_id, &attr, func, param);
    pthread_attr_destroy(&attr);
    if ((result == 0) && (threadidptr != NULL)) {
        *threadidptr = thread_id;
    }
    return result;
}


/* Wait for a thread to finish. */
static int
mg_join_thread(pthread_t threadid) {
    int result;

    result = pthread_join(threadid, NULL);
    return result;
}


#if !defined(NO_CGI)
static pid_t
spawn_process(struct mg_connection *conn,
const char *prog,
char *envblk,
char *envp[],
int fdin[2],
int fdout[2],
int fderr[2],
const char *dir)
{
pid_t pid;
const char *interp;

(void)envblk;

if (conn == NULL) {
return 0;
}

if ((pid = fork()) == -1) {
/* Parent */
mg_send_http_error(conn,
500,
"Error: Creating CGI process\nfork(): %s",
strerror(ERRNO));
} else if (pid == 0) {
/* Child */
if (chdir(dir) != 0) {
mg_cry_internal(
conn, "%s: chdir(%s): %s", __func__, dir, strerror(ERRNO));
} else if (dup2(fdin[0], 0) == -1) {
mg_cry_internal(conn,
"%s: dup2(%d, 0): %s",
__func__,
fdin[0],
strerror(ERRNO));
} else if (dup2(fdout[1], 1) == -1) {
mg_cry_internal(conn,
"%s: dup2(%d, 1): %s",
__func__,
fdout[1],
strerror(ERRNO));
} else if (dup2(fderr[1], 2) == -1) {
mg_cry_internal(conn,
"%s: dup2(%d, 2): %s",
__func__,
fderr[1],
strerror(ERRNO));
} else {
/* Keep stderr and stdout in two different pipes.
             * Stdout will be sent back to the client,
             * stderr should go into a server error log. */
(void)close(fdin[0]);
(void)close(fdout[1]);
(void)close(fderr[1]);

/* Close write end fdin and read end fdout and fderr */
(void)close(fdin[1]);
(void)close(fdout[0]);
(void)close(fderr[0]);

/* After exec, all signal handlers are restored to their default
             * values, with one exception of SIGCHLD. According to
             * POSIX.1-2001 and Linux's implementation, SIGCHLD's handler
             * will leave unchanged after exec if it was set to be ignored.
             * Restore it to default action. */
signal(SIGCHLD, SIG_DFL);

interp = conn->dom_ctx->config[CGI_INTERPRETER];
if (interp == NULL) {
(void)execle(prog, prog, NULL, envp);
mg_cry_internal(conn,
"%s: execle(%s): %s",
__func__,
prog,
strerror(ERRNO));
} else {
(void)execle(interp, interp, prog, NULL, envp);
mg_cry_internal(conn,
"%s: execle(%s %s): %s",
__func__,
interp,
prog,
strerror(ERRNO));
}
}
exit(EXIT_FAILURE);
}

return pid;
}
#endif /* !NO_CGI */


static int
set_non_blocking_mode(SOCKET sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }

    if (fcntl(sock, F_SETFL, (flags | O_NONBLOCK)) < 0) {
        return -1;
    }
    return 0;
}

static int
set_blocking_mode(SOCKET sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }

    if (fcntl(sock, F_SETFL, flags & (~(int) (O_NONBLOCK))) < 0) {
        return -1;
    }
    return 0;
}

#endif /* _WIN32 / else */

/* End of initial operating system specific define block. */


/* Get a random number (independent of C rand function) */
static uint64_t
get_random(void) {
    static uint64_t lfsr = 0; /* Linear feedback shift register */
    static uint64_t lcg = 0;  /* Linear congruential generator */
    uint64_t now = mg_get_current_time_ns();

    if (lfsr == 0) {
/* lfsr will be only 0 if has not been initialized,
		 * so this code is called only once. */
        lfsr = mg_get_current_time_ns();
        lcg = mg_get_current_time_ns();
    } else {
/* Get the next step of both random number generators. */
        lfsr = (lfsr >> 1)
               | ((((lfsr >> 0) ^ (lfsr >> 1) ^ (lfsr >> 3) ^ (lfsr >> 4)) & 1)
                << 63);
        lcg = lcg * 6364136223846793005LL + 1442695040888963407LL;
    }

/* Combining two pseudo-random number generators and a high resolution
	 * part
	 * of the current server time will make it hard (impossible?) to guess
	 * the
	 * next number. */
    return (lfsr ^ lcg ^ now);
}


static int
mg_poll(struct pollfd *pfd,
        unsigned int n,
        int milliseconds,
        volatile int *stop_server) {
/* Call poll, but only for a maximum time of a few seconds.
	 * This will allow to stop the server after some seconds, instead
	 * of having to wait for a long socket timeout. */
    int ms_now = SOCKET_TIMEOUT_QUANTUM; /* Sleep quantum in ms */

    do {
        int result;

        if (*stop_server) {
/* Shut down signal */
            return -2;
        }

        if ((milliseconds >= 0) && (milliseconds < ms_now)) {
            ms_now = milliseconds;
        }

        result = poll(pfd, n, ms_now);
        if (result != 0) {
/* Poll returned either success (1) or error (-1).
			 * Forward both to the caller. */
            return result;
        }

/* Poll returned timeout (0). */
        if (milliseconds > 0) {
            milliseconds -= ms_now;
        }

    } while (milliseconds != 0);

/* timeout: return 0 */
    return 0;
}


/* Write data to the IO channel - opened file descriptor, socket or SSL
 * descriptor.
 * Return value:
 *  >=0 .. number of bytes successfully written
 *   -1 .. timeout
 *   -2 .. error
 */
static int
push_inner(struct mg_context *ctx,
           FILE *fp,
           SOCKET sock,
           SSL *ssl,
           const char *buf,
           int len,
           double timeout) {
    uint64_t start = 0, now = 0, timeout_ns = 0;
    int n, err;
    unsigned ms_wait = SOCKET_TIMEOUT_QUANTUM; /* Sleep quantum in ms */

#if defined(_WIN32)
    typedef int len_t;
#else
    typedef size_t len_t;
#endif

    if (timeout > 0) {
        now = mg_get_current_time_ns();
        start = now;
        timeout_ns = (uint64_t) (timeout * 1.0E9);
    }

    if (ctx == NULL) {
        return -2;
    }

#if defined(NO_SSL)
    if (ssl) {
return -2;
}
#endif

/* Try to read until it succeeds, fails, times out, or the server
	 * shuts down. */
    for (;;) {

#if !defined(NO_SSL)
        if (ssl != NULL) {
            n = SSL_write(ssl, buf, len);
            if (n <= 0) {
                err = SSL_get_error(ssl, n);
                if ((err == SSL_ERROR_SYSCALL) && (n == -1)) {
                    err = ERRNO;
                } else if ((err == SSL_ERROR_WANT_READ)
                           || (err == SSL_ERROR_WANT_WRITE)) {
                    n = 0;
                } else {
                    DEBUG_TRACE("SSL_write() failed, error %d", err);
                    return -2;
                }
            } else {
                err = 0;
            }
        } else
#endif
        if (fp != NULL) {
            n = (int) fwrite(buf, 1, (size_t) len, fp);
            if (ferror(fp)) {
                n = -1;
                err = ERRNO;
            } else {
                err = 0;
            }
        } else {
            n = (int) send(sock, buf, (len_t) len, MSG_NOSIGNAL);
            err = (n < 0) ? ERRNO : 0;
#if defined(_WIN32)
            if (err == WSAEWOULDBLOCK) {
err = 0;
n = 0;
}
#else
            if (err == EWOULDBLOCK) {
                err = 0;
                n = 0;
            }
#endif
            if (n < 0) {
/* shutdown of the socket at client side */
                return -2;
            }
        }

        if (ctx->stop_flag) {
            return -2;
        }

        if ((n > 0) || ((n == 0) && (len == 0))) {
/* some data has been read, or no data was requested */
            return n;
        }
        if (n < 0) {
/* socket error - check errno */
            DEBUG_TRACE("send() failed, error %d", err);

/* TODO (mid): error handling depending on the error code.
			 * These codes are different between Windows and Linux.
			 * Currently there is no problem with failing send calls,
			 * if there is a reproducible situation, it should be
			 * investigated in detail.
			 */
            return -2;
        }

/* Only in case n=0 (timeout), repeat calling the write function */

/* If send failed, wait before retry */
        if (fp != NULL) {
/* For files, just wait a fixed time.
			 * Maybe it helps, maybe not. */
            mg_sleep(5);
        } else {
/* For sockets, wait for the socket using poll */
            struct pollfd pfd[1];
            int pollres;

            pfd[0].fd = sock;
            pfd[0].events = POLLOUT;
            pollres = mg_poll(pfd, 1, (int) (ms_wait), &(ctx->stop_flag));
            if (ctx->stop_flag) {
                return -2;
            }
            if (pollres > 0) {
                continue;
            }
        }

        if (timeout > 0) {
            now = mg_get_current_time_ns();
            if ((now - start) > timeout_ns) {
/* Timeout */
                break;
            }
        }
    }

    (void) err; /* Avoid unused warning if NO_SSL is set and DEBUG_TRACE is not
	              used */

    return -1;
}


static int64_t
push_all(struct mg_context *ctx,
         FILE *fp,
         SOCKET sock,
         SSL *ssl,
         const char *buf,
         int64_t len) {
    double timeout = -1.0;
    int64_t n, nwritten = 0;

    if (ctx == NULL) {
        return -1;
    }

    if (ctx->dd.config[REQUEST_TIMEOUT]) {
        timeout = atoi(ctx->dd.config[REQUEST_TIMEOUT]) / 1000.0;
    }

    while ((len > 0) && (ctx->stop_flag == 0)) {
        n = push_inner(ctx, fp, sock, ssl, buf + nwritten, (int) len, timeout);
        if (n < 0) {
            if (nwritten == 0) {
                nwritten = n; /* Propagate the error */
            }
            break;
        } else if (n == 0) {
            break; /* No more data to write */
        } else {
            nwritten += n;
            len -= n;
        }
    }

    return nwritten;
}


/* Read from IO channel - opened file descriptor, socket, or SSL descriptor.
 * Return value:
 *  >=0 .. number of bytes successfully read
 *   -1 .. timeout
 *   -2 .. error
 */
static int
pull_inner(FILE *fp,
           struct mg_connection *conn,
           char *buf,
           int len,
           double timeout) {
    int nread, err = 0;

#if defined(_WIN32)
    typedef int len_t;
#else
    typedef size_t len_t;
#endif
#if !defined(NO_SSL)
    int ssl_pending;
#endif

/* We need an additional wait loop around this, because in some cases
	 * with TLSwe may get data from the socket but not from SSL_read.
	 * In this case we need to repeat at least once.
	 */

    if (fp != NULL) {
#if !defined(_WIN32_WCE)
/* Use read() instead of fread(), because if we're reading from the
		 * CGI pipe, fread() may block until IO buffer is filled up. We
		 * cannot afford to block and must pass all read bytes immediately
		 * to the client. */
        nread = (int) read(fileno(fp), buf, (size_t) len);
#else
        /* WinCE does not support CGI pipes */
nread = (int)fread(buf, 1, (size_t)len, fp);
#endif
        err = (nread < 0) ? ERRNO : 0;
        if ((nread == 0) && (len > 0)) {
/* Should get data, but got EOL */
            return -2;
        }

#if !defined(NO_SSL)
    } else if ((conn->ssl != NULL)
               && ((ssl_pending = SSL_pending(conn->ssl)) > 0)) {
/* We already know there is no more data buffered in conn->buf
		 * but there is more available in the SSL layer. So don't poll
		 * conn->client.sock yet. */
        if (ssl_pending > len) {
            ssl_pending = len;
        }
        nread = SSL_read(conn->ssl, buf, ssl_pending);
        if (nread <= 0) {
            err = SSL_get_error(conn->ssl, nread);
            if ((err == SSL_ERROR_SYSCALL) && (nread == -1)) {
                err = ERRNO;
            } else if ((err == SSL_ERROR_WANT_READ)
                       || (err == SSL_ERROR_WANT_WRITE)) {
                nread = 0;
            } else {
                DEBUG_TRACE("SSL_read() failed, error %d", err);
                return -1;
            }
        } else {
            err = 0;
        }

    } else if (conn->ssl != NULL) {

        struct pollfd pfd[1];
        int pollres;

        pfd[0].fd = conn->client.sock;
        pfd[0].events = POLLIN;
        pollres = mg_poll(pfd,
                          1,
                          (int) (timeout * 1000.0),
                          &(conn->phys_ctx->stop_flag));
        if (conn->phys_ctx->stop_flag) {
            return -2;
        }
        if (pollres > 0) {
            nread = SSL_read(conn->ssl, buf, len);
            if (nread <= 0) {
                err = SSL_get_error(conn->ssl, nread);
                if ((err == SSL_ERROR_SYSCALL) && (nread == -1)) {
                    err = ERRNO;
                } else if ((err == SSL_ERROR_WANT_READ)
                           || (err == SSL_ERROR_WANT_WRITE)) {
                    nread = 0;
                } else {
                    DEBUG_TRACE("SSL_read() failed, error %d", err);
                    return -2;
                }
            } else {
                err = 0;
            }

        } else if (pollres < 0) {
/* Error */
            return -2;
        } else {
/* pollres = 0 means timeout */
            nread = 0;
        }
#endif

    } else {
        struct pollfd pfd[1];
        int pollres;

        pfd[0].fd = conn->client.sock;
        pfd[0].events = POLLIN;
        pollres = mg_poll(pfd,
                          1,
                          (int) (timeout * 1000.0),
                          &(conn->phys_ctx->stop_flag));
        if (conn->phys_ctx->stop_flag) {
            return -2;
        }
        if (pollres > 0) {
            nread = (int) recv(conn->client.sock, buf, (len_t) len, 0);
            err = (nread < 0) ? ERRNO : 0;
            if (nread <= 0) {
/* shutdown of the socket at client side */
                return -2;
            }
        } else if (pollres < 0) {
/* error callint poll */
            return -2;
        } else {
/* pollres = 0 means timeout */
            nread = 0;
        }
    }

    if (conn->phys_ctx->stop_flag) {
        return -2;
    }

    if ((nread > 0) || ((nread == 0) && (len == 0))) {
/* some data has been read, or no data was requested */
        return nread;
    }

    if (nread < 0) {
/* socket error - check errno */
#if defined(_WIN32)
        if (err == WSAEWOULDBLOCK) {
/* TODO (low): check if this is still required */
/* standard case if called from close_socket_gracefully */
return -2;
} else if (err == WSAETIMEDOUT) {
/* TODO (low): check if this is still required */
/* timeout is handled by the while loop  */
return 0;
} else if (err == WSAECONNABORTED) {
/* See https://www.chilkatsoft.com/p/p_299.asp */
return -2;
} else {
DEBUG_TRACE("recv() failed, error %d", err);
return -2;
}
#else
/* TODO: POSIX returns either EAGAIN or EWOULDBLOCK in both cases,
		 * if the timeout is reached and if the socket was set to non-
		 * blocking in close_socket_gracefully, so we can not distinguish
		 * here. We have to wait for the timeout in both cases for now.
		 */
        if ((err == EAGAIN) || (err == EWOULDBLOCK) || (err == EINTR)) {
/* TODO (low): check if this is still required */
/* EAGAIN/EWOULDBLOCK:
			 * standard case if called from close_socket_gracefully
			 * => should return -1 */
/* or timeout occurred
			 * => the code must stay in the while loop */

/* EINTR can be generated on a socket with a timeout set even
			 * when SA_RESTART is effective for all relevant signals
			 * (see signal(7)).
			 * => stay in the while loop */
        } else {
            DEBUG_TRACE("recv() failed, error %d", err);
            return -2;
        }
#endif
    }

/* Timeout occurred, but no data available. */
    return -1;
}


static int
pull_all(FILE *fp, struct mg_connection *conn, char *buf, int len) {
    int n, nread = 0;
    double timeout = -1.0;
    uint64_t start_time = 0, now = 0, timeout_ns = 0;

    if (conn->dom_ctx->config[REQUEST_TIMEOUT]) {
        timeout = atoi(conn->dom_ctx->config[REQUEST_TIMEOUT]) / 1000.0;
    }
    if (timeout >= 0.0) {
        start_time = mg_get_current_time_ns();
        timeout_ns = (uint64_t) (timeout * 1.0E9);
    }

    while ((len > 0) && (conn->phys_ctx->stop_flag == 0)) {
        n = pull_inner(fp, conn, buf + nread, len, timeout);
        if (n == -2) {
            if (nread == 0) {
                nread = -1; /* Propagate the error */
            }
            break;
        } else if (n == -1) {
/* timeout */
            if (timeout >= 0.0) {
                now = mg_get_current_time_ns();
                if ((now - start_time) <= timeout_ns) {
                    continue;
                }
            }
            break;
        } else if (n == 0) {
            break; /* No more data to read */
        } else {
            conn->consumed_content += n;
            nread += n;
            len -= n;
        }
    }

    return nread;
}


static void
discard_unread_request_data(struct mg_connection *conn) {
    char buf[MG_BUF_LEN];
    size_t to_read;
    int nread;

    if (conn == NULL) {
        return;
    }

    to_read = sizeof(buf);

    if (conn->is_chunked) {
/* Chunked encoding: 3=chunk read completely
		 * completely */
        while (conn->is_chunked != 3) {
            nread = mg_read(conn, buf, to_read);
            if (nread <= 0) {
                break;
            }
        }

    } else {
/* Not chunked: content length is known */
        while (conn->consumed_content < conn->content_len) {
            if (to_read
                > (size_t) (conn->content_len - conn->consumed_content)) {
                to_read = (size_t) (conn->content_len - conn->consumed_content);
            }

            nread = mg_read(conn, buf, to_read);
            if (nread <= 0) {
                break;
            }
        }
    }
}


static int
mg_read_inner(struct mg_connection *conn, void *buf, size_t len) {
    int64_t n, buffered_len, nread;
    int64_t len64 =
            (int64_t) ((len > INT_MAX) ? INT_MAX : len); /* since the return value is
	                                                 * int, we may not read more
	                                                 * bytes */
    const char *body;

    if (conn == NULL) {
        return 0;
    }

/* If Content-Length is not set for a request with body data
	 * (e.g., a PUT or POST request), we do not know in advance
	 * how much data should be read. */
    if (conn->consumed_content == 0) {
        if (conn->is_chunked == 1) {
            conn->content_len = len64;
            conn->is_chunked = 2;
        } else if (conn->content_len == -1) {
/* The body data is completed when the connection
			 * is closed. */
            conn->content_len = INT64_MAX;
            conn->must_close = 1;
        }
    }

    nread = 0;
    if (conn->consumed_content < conn->content_len) {
/* Adjust number of bytes to read. */
        int64_t left_to_read = conn->content_len - conn->consumed_content;
        if (left_to_read < len64) {
/* Do not read more than the total content length of the
			 * request.
			 */
            len64 = left_to_read;
        }

/* Return buffered data */
        buffered_len = (int64_t) (conn->data_len) - (int64_t) conn->request_len
                       - conn->consumed_content;
        if (buffered_len > 0) {
            if (len64 < buffered_len) {
                buffered_len = len64;
            }
            body = conn->buf + conn->request_len + conn->consumed_content;
            memcpy(buf, body, (size_t) buffered_len);
            len64 -= buffered_len;
            conn->consumed_content += buffered_len;
            nread += buffered_len;
            buf = (char *) buf + buffered_len;
        }

/* We have returned all buffered data. Read new data from the remote
		 * socket.
		 */
        if ((n = pull_all(NULL, conn, (char *) buf, (int) len64)) >= 0) {
            nread += n;
        } else {
            nread = ((nread > 0) ? nread : n);
        }
    }
    return (int) nread;
}


static char
mg_getc(struct mg_connection *conn) {
    char c;
    if (conn == NULL) {
        return 0;
    }
    if (mg_read_inner(conn, &c, 1) <= 0) {
        return (char) 0;
    }
    return c;
}


int
mg_read(struct mg_connection *conn, void *buf, size_t len) {
    if (len > INT_MAX) {
        len = INT_MAX;
    }

    if (conn == NULL) {
        return 0;
    }

    if (conn->is_chunked) {
        size_t all_read = 0;

        while (len > 0) {
            if (conn->is_chunked == 3) {
/* No more data left to read */
                return 0;
            }

            if (conn->chunk_remainder) {
/* copy from the remainder of the last received chunk */
                long read_ret;
                size_t read_now =
                        ((conn->chunk_remainder > len) ? (len)
                                                       : (conn->chunk_remainder));

                conn->content_len += (int) read_now;
                read_ret =
                        mg_read_inner(conn, (char *) buf + all_read, read_now);

                if (read_ret < 1) {
/* read error */
                    return -1;
                }

                all_read += (size_t) read_ret;
                conn->chunk_remainder -= (size_t) read_ret;
                len -= (size_t) read_ret;

                if (conn->chunk_remainder == 0) {
/* Add data bytes in the current chunk have been read,
					 * so we are expecting \r\n now. */
                    char x1, x2;
                    conn->content_len += 2;
                    x1 = mg_getc(conn);
                    x2 = mg_getc(conn);
                    if ((x1 != '\r') || (x2 != '\n')) {
/* Protocol violation */
                        return -1;
                    }
                }

            } else {
/* fetch a new chunk */
                int i = 0;
                char lenbuf[64];
                char *end = 0;
                unsigned long chunkSize = 0;

                for (i = 0; i < ((int) sizeof(lenbuf) - 1); i++) {
                    conn->content_len++;
                    lenbuf[i] = mg_getc(conn);
                    if ((i > 0) && (lenbuf[i] == '\r')
                        && (lenbuf[i - 1] != '\r')) {
                        continue;
                    }
                    if ((i > 1) && (lenbuf[i] == '\n')
                        && (lenbuf[i - 1] == '\r')) {
                        lenbuf[i + 1] = 0;
                        chunkSize = strtoul(lenbuf, &end, 16);
                        if (chunkSize == 0) {
/* regular end of content */
                            conn->is_chunked = 3;
                        }
                        break;
                    }
                    if (!isxdigit(lenbuf[i])) {
/* illegal character for chunk length */
                        return -1;
                    }
                }
                if ((end == NULL) || (*end != '\r')) {
/* chunksize not set correctly */
                    return -1;
                }
                if (chunkSize == 0) {
                    break;
                }

                conn->chunk_remainder = chunkSize;
            }
        }

        return (int) all_read;
    }
    return mg_read_inner(conn, buf, len);
}


int
mg_write(struct mg_connection *conn, const void *buf, size_t len) {
    time_t now;
    int64_t n, total, allowed;

    if (conn == NULL) {
        return 0;
    }

    if (conn->throttle > 0) {
        if ((now = time(NULL)) != conn->last_throttle_time) {
            conn->last_throttle_time = now;
            conn->last_throttle_bytes = 0;
        }
        allowed = conn->throttle - conn->last_throttle_bytes;
        if (allowed > (int64_t) len) {
            allowed = (int64_t) len;
        }
        if ((total = push_all(conn->phys_ctx,
                              NULL,
                              conn->client.sock,
                              conn->ssl,
                              (const char *) buf,
                              (int64_t) allowed))
            == allowed) {
            buf = (const char *) buf + total;
            conn->last_throttle_bytes += total;
            while ((total < (int64_t) len) && (conn->phys_ctx->stop_flag == 0)) {
                allowed = (conn->throttle > ((int64_t) len - total))
                          ? (int64_t) len - total
                          : conn->throttle;
                if ((n = push_all(conn->phys_ctx,
                                  NULL,
                                  conn->client.sock,
                                  conn->ssl,
                                  (const char *) buf,
                                  (int64_t) allowed))
                    != allowed) {
                    break;
                }
                sleep(1);
                conn->last_throttle_bytes = allowed;
                conn->last_throttle_time = time(NULL);
                buf = (const char *) buf + n;
                total += n;
            }
        }
    } else {
        total = push_all(conn->phys_ctx,
                         NULL,
                         conn->client.sock,
                         conn->ssl,
                         (const char *) buf,
                         (int64_t) len);
    }
    if (total > 0) {
        conn->num_bytes_sent += total;
    }
    return (int) total;
}


/* Send a chunk, if "Transfer-Encoding: chunked" is used */
int
mg_send_chunk(struct mg_connection *conn,
              const char *chunk,
              unsigned int chunk_len) {
    char lenbuf[16];
    size_t lenbuf_len;
    int ret;
    int t;

/* First store the length information in a text buffer. */
    sprintf(lenbuf, "%x\r\n", chunk_len);
    lenbuf_len = strlen(lenbuf);

/* Then send length information, chunk and terminating \r\n. */
    ret = mg_write(conn, lenbuf, lenbuf_len);
    if (ret != (int) lenbuf_len) {
        return -1;
    }
    t = ret;

    ret = mg_write(conn, chunk, chunk_len);
    if (ret != (int) chunk_len) {
        return -1;
    }
    t += ret;

    ret = mg_write(conn, "\r\n", 2);
    if (ret != 2) {
        return -1;
    }
    t += ret;

    return t;
}


#if defined(GCC_DIAGNOSTIC)
/* This block forwards format strings to printf implementations,
 * so we need to disable the format-nonliteral warning. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif


/* Alternative alloc_vprintf() for non-compliant C runtimes */
static int
alloc_vprintf2(char **buf, const char *fmt, va_list ap) {
    va_list ap_copy;
    size_t size = MG_BUF_LEN / 4;
    int len = -1;

    *buf = NULL;
    while (len < 0) {
        if (*buf) {
            mg_free(*buf);
        }

        size *= 4;
        *buf = (char *) mg_malloc(size);
        if (!*buf) {
            break;
        }

        va_copy(ap_copy, ap);
        len = vsnprintf_impl(*buf, size - 1, fmt, ap_copy);
        va_end(ap_copy);
        (*buf)[size - 1] = 0;
    }

    return len;
}


/* Print message to buffer. If buffer is large enough to hold the message,
 * return buffer. If buffer is to small, allocate large enough buffer on
 * heap,
 * and return allocated buffer. */
static int
alloc_vprintf(char **out_buf,
              char *prealloc_buf,
              size_t prealloc_size,
              const char *fmt,
              va_list ap) {
    va_list ap_copy;
    int len;

/* Windows is not standard-compliant, and vsnprintf() returns -1 if
	 * buffer is too small. Also, older versions of msvcrt.dll do not have
	 * _vscprintf().  However, if size is 0, vsnprintf() behaves correctly.
	 * Therefore, we make two passes: on first pass, get required message
	 * length.
	 * On second pass, actually print the message. */
    va_copy(ap_copy, ap);
    len = vsnprintf_impl(NULL, 0, fmt, ap_copy);
    va_end(ap_copy);

    if (len < 0) {
/* C runtime is not standard compliant, vsnprintf() returned -1.
		 * Switch to alternative code path that uses incremental
		 * allocations.
		 */
        va_copy(ap_copy, ap);
        len = alloc_vprintf2(out_buf, fmt, ap_copy);
        va_end(ap_copy);

    } else if ((size_t) (len) >= prealloc_size) {
/* The pre-allocated buffer not large enough. */
/* Allocate a new buffer. */
        *out_buf = (char *) mg_malloc((size_t) (len) + 1);
        if (!*out_buf) {
/* Allocation failed. Return -1 as "out of memory" error. */
            return -1;
        }
/* Buffer allocation successful. Store the string there. */
        va_copy(ap_copy, ap);
        IGNORE_UNUSED_RESULT(
                vsnprintf_impl(*out_buf, (size_t) (len) + 1, fmt, ap_copy));
        va_end(ap_copy);

    } else {
/* The pre-allocated buffer is large enough.
		 * Use it to store the string and return the address. */
        va_copy(ap_copy, ap);
        IGNORE_UNUSED_RESULT(
                vsnprintf_impl(prealloc_buf, prealloc_size, fmt, ap_copy));
        va_end(ap_copy);
        *out_buf = prealloc_buf;
    }

    return len;
}


#if defined(GCC_DIAGNOSTIC)
/* Enable format-nonliteral warning again. */
#pragma GCC diagnostic pop
#endif


static int
mg_vprintf(struct mg_connection *conn, const char *fmt, va_list ap) {
    char mem[MG_BUF_LEN];
    char *buf = NULL;
    int len;

    if ((len = alloc_vprintf(&buf, mem, sizeof(mem), fmt, ap)) > 0) {
        len = mg_write(conn, buf, (size_t) len);
    }
    if ((buf != mem) && (buf != NULL)) {
        mg_free(buf);
    }

    return len;
}


int
mg_printf(struct mg_connection *conn, const char *fmt, ...) {
    va_list ap;
    int result;

    va_start(ap, fmt);
    result = mg_vprintf(conn, fmt, ap);
    va_end(ap);

    return result;
}


int
mg_url_decode(const char *src,
              int src_len,
              char *dst,
              int dst_len,
              int is_form_url_encoded) {
    int i, j, a, b;
#define HEXTOI(x) (isdigit(x) ? (x - '0') : (x - 'W'))

    for (i = j = 0; (i < src_len) && (j < (dst_len - 1)); i++, j++) {
        if ((i < src_len - 2) && (src[i] == '%')
            && isxdigit(*(const unsigned char *) (src + i + 1))
            && isxdigit(*(const unsigned char *) (src + i + 2))) {
            a = tolower(*(const unsigned char *) (src + i + 1));
            b = tolower(*(const unsigned char *) (src + i + 2));
            dst[j] = (char) ((HEXTOI(a) << 4) | HEXTOI(b));
            i += 2;
        } else if (is_form_url_encoded && (src[i] == '+')) {
            dst[j] = ' ';
        } else {
            dst[j] = src[i];
        }
    }

    dst[j] = '\0'; /* Null-terminate the destination */

    return (i >= src_len) ? j : -1;
}


int
mg_get_var(const char *data,
           size_t data_len,
           const char *name,
           char *dst,
           size_t dst_len) {
    return mg_get_var2(data, data_len, name, dst, dst_len, 0);
}


int
mg_get_var2(const char *data,
            size_t data_len,
            const char *name,
            char *dst,
            size_t dst_len,
            size_t occurrence) {
    const char *p, *e, *s;
    size_t name_len;
    int len;

    if ((dst == NULL) || (dst_len == 0)) {
        len = -2;
    } else if ((data == NULL) || (name == NULL) || (data_len == 0)) {
        len = -1;
        dst[0] = '\0';
    } else {
        name_len = strlen(name);
        e = data + data_len;
        len = -1;
        dst[0] = '\0';

/* data is "var1=val1&var2=val2...". Find variable first */
        for (p = data; p + name_len < e; p++) {
            if (((p == data) || (p[-1] == '&')) && (p[name_len] == '=')
                && !mg_strncasecmp(name, p, name_len) && 0 == occurrence--) {
/* Point p to variable value */
                p += name_len + 1;

/* Point s to the end of the value */
                s = (const char *) memchr(p, '&', (size_t) (e - p));
                if (s == NULL) {
                    s = e;
                }
                DEBUG_ASSERT(s >= p);
                if (s < p) {
                    return -3;
                }

/* Decode variable into destination buffer */
                len = mg_url_decode(p, (int) (s - p), dst, (int) dst_len, 1);

/* Redirect error code from -1 to -2 (destination buffer too
				 * small). */
                if (len == -1) {
                    len = -2;
                }
                break;
            }
        }
    }

    return len;
}


/* HCP24: some changes to compare hole var_name */
int
mg_get_cookie(const char *cookie_header,
              const char *var_name,
              char *dst,
              size_t dst_size) {
    const char *s, *p, *end;
    int name_len, len = -1;

    if ((dst == NULL) || (dst_size == 0)) {
        return -2;
    }

    dst[0] = '\0';
    if ((var_name == NULL) || ((s = cookie_header) == NULL)) {
        return -1;
    }

    name_len = (int) strlen(var_name);
    end = s + strlen(s);
    for (; (s = mg_strcasestr(s, var_name)) != NULL; s += name_len) {
        if (s[name_len] == '=') {
/* HCP24: now check is it a substring or a full cookie name */
            if ((s == cookie_header) || (s[-1] == ' ')) {
                s += name_len + 1;
                if ((p = strchr(s, ' ')) == NULL) {
                    p = end;
                }
                if (p[-1] == ';') {
                    p--;
                }
                if ((*s == '"') && (p[-1] == '"') && (p > s + 1)) {
                    s++;
                    p--;
                }
                if ((size_t) (p - s) < dst_size) {
                    len = (int) (p - s);
                    mg_strlcpy(dst, s, (size_t) len + 1);
                } else {
                    len = -3;
                }
                break;
            }
        }
    }
    return len;
}


#if defined(USE_WEBSOCKET) || defined(USE_LUA)
static void
base64_encode(const unsigned char *src, int src_len, char *dst)
{
static const char *b64 =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int i, j, a, b, c;

for (i = j = 0; i < src_len; i += 3) {
a = src[i];
b = ((i + 1) >= src_len) ? 0 : src[i + 1];
c = ((i + 2) >= src_len) ? 0 : src[i + 2];

dst[j++] = b64[a >> 2];
dst[j++] = b64[((a & 3) << 4) | (b >> 4)];
if (i + 1 < src_len) {
dst[j++] = b64[(b & 15) << 2 | (c >> 6)];
}
if (i + 2 < src_len) {
dst[j++] = b64[c & 63];
}
}
while (j % 4 != 0) {
dst[j++] = '=';
}
dst[j++] = '\0';
}
#endif


#if defined(USE_LUA)
static unsigned char
b64reverse(char letter)
{
if ((letter >= 'A') && (letter <= 'Z')) {
return letter - 'A';
}
if ((letter >= 'a') && (letter <= 'z')) {
return letter - 'a' + 26;
}
if ((letter >= '0') && (letter <= '9')) {
return letter - '0' + 52;
}
if (letter == '+') {
return 62;
}
if (letter == '/') {
return 63;
}
if (letter == '=') {
return 255; /* normal end */
}
return 254; /* error */
}


static int
base64_decode(const unsigned char *src, int src_len, char *dst, size_t *dst_len)
{
int i;
unsigned char a, b, c, d;

*dst_len = 0;

for (i = 0; i < src_len; i += 4) {
a = b64reverse(src[i]);
if (a >= 254) {
return i;
}

b = b64reverse(((i + 1) >= src_len) ? 0 : src[i + 1]);
if (b >= 254) {
return i + 1;
}

c = b64reverse(((i + 2) >= src_len) ? 0 : src[i + 2]);
if (c == 254) {
return i + 2;
}

d = b64reverse(((i + 3) >= src_len) ? 0 : src[i + 3]);
if (d == 254) {
return i + 3;
}

dst[(*dst_len)++] = (a << 2) + (b >> 4);
if (c != 255) {
dst[(*dst_len)++] = (b << 4) + (c >> 2);
if (d != 255) {
dst[(*dst_len)++] = (c << 6) + d;
}
}
}
return -1;
}
#endif


static int
is_put_or_delete_method(const struct mg_connection *conn) {
    if (conn) {
        const char *s = conn->request_info.request_method;
        return (s != NULL)
               && (!strcmp(s, "PUT") || !strcmp(s, "DELETE")
                   || !strcmp(s, "MKCOL") || !strcmp(s, "PATCH"));
    }
    return 0;
}


#if !defined(NO_FILES)
static int
extention_matches_script(
struct mg_connection *conn, /* in: request (must be valid) */
const char *filename        /* in: filename  (must be valid) */
)
{
#if !defined(NO_CGI)
if (match_prefix(conn->dom_ctx->config[CGI_EXTENSIONS],
strlen(conn->dom_ctx->config[CGI_EXTENSIONS]),
filename)
> 0) {
return 1;
}
#endif
#if defined(USE_LUA)
if (match_prefix(conn->dom_ctx->config[LUA_SCRIPT_EXTENSIONS],
strlen(conn->dom_ctx->config[LUA_SCRIPT_EXTENSIONS]),
filename)
> 0) {
return 1;
}
#endif
#if defined(USE_DUKTAPE)
if (match_prefix(conn->dom_ctx->config[DUKTAPE_SCRIPT_EXTENSIONS],
strlen(conn->dom_ctx->config[DUKTAPE_SCRIPT_EXTENSIONS]),
filename)
> 0) {
return 1;
#endif
/* filename and conn could be unused, if all preocessor conditions
     * are false (no script language supported). */
(void)filename;
(void)conn;

#if defined(MG_LEGACY_INTERFACE)
const char **
mg_get_valid_option_names(void)
	/* This function is deprecated. Use mg_get_valid_options instead. */
	static const char
	    *data[2 * sizeof(config_options) / sizeof(config_options[0])] = {0};
substitute_index_file(struct mg_connection *conn,
char *path,
size_t path_len,
struct mg_file_stat *filestat)
{
const char *list = conn->dom_ctx->config[INDEX_FILES];
size_t n = strlen(path);
int found = 0;

/* The 'path' given to us points to the directory. Remove all trailing
     * directory separator characters from the end of the path, and
     * then append single directory separator character. */
while ((n > 0) && (path[n - 1] == '/')) {
n--;
}
path[n] = '/';

/* Traverse index files list. For each entry, append it to the given
     * path and see if the file exists. If it exists, break the loop */
while ((list = next_option(list, &filename_vec, NULL)) != NULL) {
/* Ignore too long entries that may overflow path buffer */
if ((filename_vec.len + 1) > (path_len - (n + 1))) {
continue;
}
/* Prepare full path to the index file */
mg_strlcpy(path + n + 1, filename_vec.ptr, filename_vec.len + 1);

/* Does it exist? */
if (mg_stat(conn, path, filestat)) {
/* Yes it does, break the loop */
found = 1;
}
}

/* If no index file exists, restore directory path */
if (!found) {
path[n] = '\0';
}

return found;
}
#endif

static void
interpret_uri(struct mg_connection *conn, /* in/out: request (must be valid) */
              char *filename,             /* out: filename */
              size_t filename_buf_len,    /* in: size of filename buffer */
              struct mg_file_stat *filestat, /* out: file status structure */
              int *is_found,                 /* out: file found (directly) */
              int *is_script_resource,       /* out: handled by a script? */
              int *is_websocket_request,     /* out: websocket connetion? */
              int *is_put_or_delete_request  /* out: put/delete a file? */
) {
    char const *accept_encoding;

#if !defined(NO_FILES)
    const char *uri = conn->request_info.local_uri;
const char *root = conn->dom_ctx->config[DOCUMENT_ROOT];
const char *rewrite;
struct vec a, b;
ptrdiff_t match_len;
char gz_path[PATH_MAX];
int truncated;
#if !defined(NO_CGI) || defined(USE_LUA) || defined(USE_DUKTAPE)
char *tmp_str;
size_t tmp_str_len, sep_pos;
int allow_substitute_script_subresources;
#endif
#else
    (void) filename_buf_len; /* unused if NO_FILES is defined */
#endif

/* Step 1: Set all initially unknown outputs to zero */
    memset(filestat, 0, sizeof(*filestat));
    *filename = 0;
    *is_found = 0;
    *is_script_resource = 0;

/* Step 2: Check if the request attempts to modify the file system */
    *is_put_or_delete_request = is_put_or_delete_method(conn);

/* Step 3: Check if it is a websocket request, and modify the document
 * root if required */
#if defined(USE_WEBSOCKET)
    *is_websocket_request = is_websocket_protocol(conn);
#if !defined(NO_FILES)
if (*is_websocket_request && conn->dom_ctx->config[WEBSOCKET_ROOT]) {
root = conn->dom_ctx->config[WEBSOCKET_ROOT];
}
#endif /* !NO_FILES */
#else  /* USE_WEBSOCKET */
    *is_websocket_request = 0;
#endif /* USE_WEBSOCKET */

/* Step 4: Check if gzip encoded response is allowed */
    conn->accept_gzip = 0;
    if ((accept_encoding = mg_get_header(conn, "Accept-Encoding")) != NULL) {
        if (strstr(accept_encoding, "gzip") != NULL) {
            conn->accept_gzip = 1;
        }
    }

#if !defined(NO_FILES)
    /* Step 5: If there is no root directory, don't look for files. */
/* Note that root == NULL is a regular use case here. This occurs,
     * if all requests are handled by callbacks, so the WEBSOCKET_ROOT
     * config is not required. */
if (root == NULL) {
/* all file related outputs have already been set to 0, just return
         */
return;
}

/* Step 6: Determine the local file path from the root path and the
     * request uri. */
/* Using filename_buf_len - 1 because memmove() for PATH_INFO may shift
     * part of the path one byte on the right. */
mg_snprintf(
conn, &truncated, filename, filename_buf_len - 1, "%s%s", root, uri);

if (truncated) {
goto interpret_cleanup;
}

/* Step 7: URI rewriting */
rewrite = conn->dom_ctx->config[URL_REWRITE_PATTERN];
while ((rewrite = next_option(rewrite, &a, &b)) != NULL) {
if ((match_len = match_prefix(a.ptr, a.len, uri)) > 0) {
mg_snprintf(conn,
&truncated,
filename,
filename_buf_len - 1,
"%.*s%s",
(int)b.len,
b.ptr,
uri + match_len);
break;
}
}

if (truncated) {
goto interpret_cleanup;
}

/* Step 8: Check if the file exists at the server */
/* Local file path and name, corresponding to requested URI
     * is now stored in "filename" variable. */
if (mg_stat(conn, filename, filestat)) {
int uri_len = (int)strlen(uri);
int is_uri_end_slash = (uri_len > 0) && (uri[uri_len - 1] == '/');

/* 8.1: File exists. */
*is_found = 1;

/* 8.2: Check if it is a script type. */
if (extention_matches_script(conn, filename)) {
/* The request addresses a CGI resource, Lua script or
             * server-side javascript.
             * The URI corresponds to the script itself (like
             * /path/script.cgi), and there is no additional resource
             * path (like /path/script.cgi/something).
             * Requests that modify (replace or delete) a resource, like
             * PUT and DELETE requests, should replace/delete the script
             * file.
             * Requests that read or write from/to a resource, like GET and
             * POST requests, should call the script and return the
             * generated response. */
*is_script_resource = (!*is_put_or_delete_request);
}

/* 8.3: If the request target is a directory, there could be
         * a substitute file (index.html, index.cgi, ...). */
if (filestat->is_directory && is_uri_end_slash) {
/* Use a local copy here, since substitute_index_file will
             * change the content of the file status */
struct mg_file_stat tmp_filestat;
memset(&tmp_filestat, 0, sizeof(tmp_filestat));

if (substitute_index_file(
conn, filename, filename_buf_len, &tmp_filestat)) {

/* Substitute file found. Copy stat to the output, then
                 * check if the file is a script file */
*filestat = tmp_filestat;

if (extention_matches_script(conn, filename)) {
/* Substitute file is a script file */
*is_script_resource = 1;
} else {
/* Substitute file is a regular file */
*is_script_resource = 0;
*is_found = (mg_stat(conn, filename, filestat) ? 1 : 0);
}
}
/* If there is no substitute file, the server could return
             * a directory listing in a later step */
}
return;
}

/* Step 9: Check for zipped files: */
/* If we can't find the actual file, look for the file
     * with the same name but a .gz extension. If we find it,
     * use that and set the gzipped flag in the file struct
     * to indicate that the response need to have the content-
     * encoding: gzip header.
     * We can only do this if the browser declares support. */
if (conn->accept_gzip) {
mg_snprintf(
conn, &truncated, gz_path, sizeof(gz_path), "%s.gz", filename);

if (truncated) {
goto interpret_cleanup;
}

if (mg_stat(conn, gz_path, filestat)) {
if (filestat) {
filestat->is_gzipped = 1;
*is_found = 1;
}
/* Currently gz files can not be scripts. */
return;
}
}

#if !defined(NO_CGI) || defined(USE_LUA) || defined(USE_DUKTAPE)
/* Step 10: Script resources may handle sub-resources */
/* Support PATH_INFO for CGI scripts. */
tmp_str_len = strlen(filename);
tmp_str = (char *)mg_malloc_ctx(tmp_str_len + PATH_MAX + 1, conn->phys_ctx);
if (!tmp_str) {
/* Out of memory */
goto interpret_cleanup;
}
memcpy(tmp_str, filename, tmp_str_len + 1);

/* Check config, if index scripts may have sub-resources */
allow_substitute_script_subresources =
!mg_strcasecmp(conn->dom_ctx->config[ALLOW_INDEX_SCRIPT_SUB_RES],
"yes");

sep_pos = tmp_str_len;
while (sep_pos > 0) {
sep_pos--;
if (tmp_str[sep_pos] == '/') {
int is_script = 0, does_exist = 0;

tmp_str[sep_pos] = 0;
if (tmp_str[0]) {
is_script = extention_matches_script(conn, tmp_str);
does_exist = mg_stat(conn, tmp_str, filestat);
}

if (does_exist && is_script) {
filename[sep_pos] = 0;
memmove(filename + sep_pos + 2,
filename + sep_pos + 1,
strlen(filename + sep_pos + 1) + 1);
conn->path_info = filename + sep_pos + 1;
filename[sep_pos + 1] = '/';
*is_script_resource = 1;
*is_found = 1;
break;
}

if (allow_substitute_script_subresources) {
if (substitute_index_file(
conn, tmp_str, tmp_str_len + PATH_MAX, filestat)) {

/* some intermediate directory has an index file */
if (extention_matches_script(conn, tmp_str)) {

char *tmp_str2;

DEBUG_TRACE("Substitute script %s serving path %s",
tmp_str,
filename);

/* this index file is a script */
tmp_str2 = mg_strdup_ctx(filename + sep_pos + 1,
conn->phys_ctx);
mg_snprintf(conn,
&truncated,
filename,
filename_buf_len,
"%s//%s",
tmp_str,
tmp_str2);
mg_free(tmp_str2);

if (truncated) {
mg_free(tmp_str);
goto interpret_cleanup;
}
sep_pos = strlen(tmp_str);
filename[sep_pos] = 0;
conn->path_info = filename + sep_pos + 1;
*is_script_resource = 1;
*is_found = 1;
break;

} else {

DEBUG_TRACE("Substitute file %s serving path %s",
tmp_str,
filename);

/* non-script files will not have sub-resources */
filename[sep_pos] = 0;
conn->path_info = 0;
*is_script_resource = 0;
*is_found = 0;
break;
}
}
}

tmp_str[sep_pos] = '/';
}
}

mg_free(tmp_str);

#endif /* !defined(NO_CGI) || defined(USE_LUA) || defined(USE_DUKTAPE) */
#endif /* !defined(NO_FILES) */
    return;

#if !defined(NO_FILES)
    /* Reset all outputs */
interpret_cleanup:
memset(filestat, 0, sizeof(*filestat));
*filename = 0;
*is_found = 0;
*is_script_resource = 0;
*is_websocket_request = 0;
*is_put_or_delete_request = 0;
#endif /* !defined(NO_FILES) */
}


/* Check whether full request is buffered. Return:
 * -1  if request or response is malformed
 *  0  if request or response is not yet fully buffered
 * >0  actual request length, including last \r\n\r\n */
static int
get_http_header_len(const char *buf, int buflen) {
    int i;
    for (i = 0; i < buflen; i++) {
/* Do an unsigned comparison in some conditions below */
        const unsigned char c = ((const unsigned char *) buf)[i];

        if ((c < 128) && ((char) c != '\r') && ((char) c != '\n')
            && !isprint(c)) {
/* abort scan as soon as one malformed character is found */
            return -1;
        }

        if (i < buflen - 1) {
            if ((buf[i] == '\n') && (buf[i + 1] == '\n')) {
/* Two newline, no carriage return - not standard compliant,
				 * but
				 * it
				 * should be accepted */
                return i + 2;
            }
        }

        if (i < buflen - 3) {
            if ((buf[i] == '\r') && (buf[i + 1] == '\n') && (buf[i + 2] == '\r')
                && (buf[i + 3] == '\n')) {
/* Two \r\n - standard compliant */
                return i + 4;
            }
        }
    }

    return 0;
}


#if !defined(NO_CACHING)
/* Convert month to the month number. Return -1 on error, or month number */
static int
get_month_index(const char *s)
{
size_t i;

for (i = 0; i < ARRAY_SIZE(month_names); i++) {
if (!strcmp(s, month_names[i])) {
return (int)i;
}
}

return -1;
}

static char *
mg_strdup_ctx(const char *str, struct mg_context *ctx)
{
	return mg_strndup_ctx(str, strlen(str), ctx);
}

static char *
mg_strdup(const char *str)
{
	return mg_strndup_ctx(str, strlen(str), NULL);
}

month_str,
&year,
&hour,
&second)
== 6)
|| (sscanf(datetime,
"%d %3s %d %d:%d:%d",
&day,
month_str,
&year,
&hour,
&minute,
&second)
== 6)
|| (sscanf(datetime,
"%*3s, %d %3s %d %d:%d:%d",
&day,
month_str,
&year,
&hour,
&minute,
&second)
== 6)
|| (sscanf(datetime,
"%d-%3s-%d %d:%d:%d",
&day,
month_str,
&year,
&hour,
&minute,
&second)
== 6)) {
month = get_month_index(month_str);
if ((month >= 0) && (year >= 1970)) {
memset(&tm, 0, sizeof(tm));
tm.tm_year = year - 1900;
tm.tm_mon = month;
tm.tm_mday = day;
tm.tm_hour = hour;
tm.tm_min = minute;
tm.tm_sec = second;
result = timegm(&tm);
}
}

return result;
}
#endif /* !NO_CACHING */


/* Protect against directory disclosure attack by removing '..',
 * excessive '/' and '\' characters */
static void
remove_double_dots_and_double_slashes(char *s) {
    char *p = s;

    while ((s[0] == '.') && (s[1] == '.')) {
        s++;
    }

    while (*s != '\0') {
        *p++ = *s++;
        if ((s[-1] == '/') || (s[-1] == '\\')) {
/* Skip all following slashes, backslashes and double-dots */
            while (s[0] != '\0') {
                if ((s[0] == '/') || (s[0] == '\\')) {
                    s++;
                } else if ((s[0] == '.') && (s[1] == '.')) {
                    s += 2;
                } else {
                    break;
                }
            }
        }
    }
    *p = '\0';
}


static const struct {
    const char *extension;
    size_t ext_len;
    const char *mime_type;
} builtin_mime_types[] = {
/* IANA registered MIME types
     * (http://www.iana.org/assignments/media-types)
     * application types */
        {".doc",     4, "application/msword"},
        {".eps",     4, "application/postscript"},
        {".exe",     4, "application/octet-stream"},
        {".js",      3, "application/javascript"},
        {".json",    5, "application/json"},
        {".pdf",     4, "application/pdf"},
        {".ps",      3, "application/postscript"},
        {".rtf",     4, "application/rtf"},
        {".xhtml",   6, "application/xhtml+xml"},
        {".xsl",     4, "application/xml"},
        {".xslt",    5, "application/xml"},

/* fonts */
        {".ttf",     4, "application/font-sfnt"},
        {".cff",     4, "application/font-sfnt"},
        {".otf",     4, "application/font-sfnt"},
        {".aat",     4, "application/font-sfnt"},
        {".sil",     4, "application/font-sfnt"},
        {".pfr",     4, "application/font-tdpfr"},
        {".woff",    5, "application/font-woff"},

/* audio */
        {".mp3",     4, "audio/mpeg"},
        {".oga",     4, "audio/ogg"},
        {".ogg",     4, "audio/ogg"},

/* image */
        {".gif",     4, "image/gif"},
        {".ief",     4, "image/ief"},
        {".jpeg",    5, "image/jpeg"},
        {".jpg",     4, "image/jpeg"},
        {".jpm",     4, "image/jpm"},
        {".jpx",     4, "image/jpx"},
        {".png",     4, "image/png"},
        {".svg",     4, "image/svg+xml"},
        {".tif",     4, "image/tiff"},
        {".tiff",    5, "image/tiff"},

/* model */
        {".wrl",     4, "model/vrml"},

/* text */
        {".css",     4, "text/css"},
        {".csv",     4, "text/csv"},
        {".htm",     4, "text/html"},
        {".html",    5, "text/html"},
        {".sgm",     4, "text/sgml"},
        {".shtm",    5, "text/html"},
        {".shtml",   6, "text/html"},
        {".txt",     4, "text/plain"},
        {".xml",     4, "text/xml"},

/* video */
        {".mov",     4, "video/quicktime"},
        {".mp4",     4, "video/mp4"},
        {".mpeg",    5, "video/mpeg"},
        {".mpg",     4, "video/mpeg"},
        {".ogv",     4, "video/ogg"},
        {".qt",      3, "video/quicktime"},

/* not registered types
     * (http://reference.sitepoint.com/html/mime-types-full,
     * http://www.hansenb.pdx.edu/DMKB/dict/tutorials/mime_typ.php, ..) */
        {".arj",     4, "application/x-arj-compressed"},
        {".gz",      3, "application/x-gunzip"},
        {".rar",     4, "application/x-arj-compressed"},
        {".swf",     4, "application/x-shockwave-flash"},
        {".tar",     4, "application/x-tar"},
        {".tgz",     4, "application/x-tar-gz"},
        {".torrent", 8, "application/x-bittorrent"},
        {".ppt",     4, "application/x-mspowerpoint"},
        {".xls",     4, "application/x-msexcel"},
        {".zip",     4, "application/x-zip-compressed"},
        {".aac",
                     4,
                        "audio/aac"}, /* http://en.wikipedia.org/wiki/Advanced_Audio_Coding */
        {".aif",     4, "audio/x-aif"},
        {".m3u",     4, "audio/x-mpegurl"},
        {".mid",     4, "audio/x-midi"},
        {".ra",      3, "audio/x-pn-realaudio"},
        {".ram",     4, "audio/x-pn-realaudio"},
        {".wav",     4, "audio/x-wav"},
        {".bmp",     4, "image/bmp"},
        {".ico",     4, "image/x-icon"},
        {".pct",     4, "image/x-pct"},
        {".pict",    5, "image/pict"},
        {".rgb",     4, "image/x-rgb"},
        {".webm",    5, "video/webm"}, /* http://en.wikipedia.org/wiki/WebM */
        {".asf",     4, "video/x-ms-asf"},
        {".avi",     4, "video/x-msvideo"},
        {".m4v",     4, "video/x-m4v"},
        {NULL,       0, NULL}};


const char *
mg_get_builtin_mime_type(const char *path) {
    const char *ext;
    size_t i, path_len;

    path_len = strlen(path);

    for (i = 0; builtin_mime_types[i].extension != NULL; i++) {
        ext = path + (path_len - builtin_mime_types[i].ext_len);
        if ((path_len > builtin_mime_types[i].ext_len)
            && (mg_strcasecmp(ext, builtin_mime_types[i].extension) == 0)) {
            return builtin_mime_types[i].mime_type;
        }
    }

    return "text/plain";
}


/* Look at the "path" extension and figure what mime type it has.
 * Store mime type in the vector. */
static void
get_mime_type(struct mg_connection *conn, const char *path, struct vec *vec) {
    struct vec ext_vec, mime_vec;
    const char *list, *ext;
    size_t path_len;

    path_len = strlen(path);

    if ((conn == NULL) || (vec == NULL)) {
        if (vec != NULL) {
            memset(vec, '\0', sizeof(struct vec));
        }
        return;
    }

/* Scan user-defined mime types first, in case user wants to
	 * override default mime types. */
    list = conn->dom_ctx->config[EXTRA_MIME_TYPES];
    while ((list = next_option(list, &ext_vec, &mime_vec)) != NULL) {
/* ext now points to the path suffix */
        ext = path + path_len - ext_vec.len;
        if (mg_strncasecmp(ext, ext_vec.ptr, ext_vec.len) == 0) {
            *vec = mime_vec;
            return;
        }
    }

    vec->ptr = mg_get_builtin_mime_type(path);
    vec->len = strlen(vec->ptr);
}


/* Stringify binary data. Output buffer must be twice as big as input,
 * because each byte takes 2 bytes in string representation */
static void
bin2str(char *to, const unsigned char *p, size_t len) {
    static const char *hex = "0123456789abcdef";

    for (; len--; p++) {
        *to++ = hex[p[0] >> 4];
        *to++ = hex[p[0] & 0x0f];
    }
    *to = '\0';
}


/* Return stringified MD5 hash for list of strings. Buffer must be 33 bytes.
 */
char *
mg_md5(char buf[33], ...) {
    md5_byte_t hash[16];
    const char *p;
    va_list ap;
    md5_state_t ctx;

    md5_init(&ctx);

    va_start(ap, buf);
    while ((p = va_arg(ap, const char *)) != NULL) {
        md5_append(&ctx, (const md5_byte_t *) p, strlen(p));
    }
    va_end(ap);

    md5_finish(&ctx, hash);
    bin2str(buf, hash, sizeof(hash));
    return buf;
}


/* Check the user's password, return 1 if OK */
static int
check_password(const char *method,
               const char *ha1,
               const char *uri,
               const char *nonce,
               const char *nc,
               const char *cnonce,
               const char *qop,
               const char *response) {
    char ha2[32 + 1], expected_response[32 + 1];

/* Some of the parameters may be NULL */
    if ((method == NULL) || (nonce == NULL) || (nc == NULL) || (cnonce == NULL)
        || (qop == NULL) || (response == NULL)) {
        return 0;
    }

/* NOTE(lsm): due to a bug in MSIE, we do not compare the URI */
    if (strlen(response) != 32) {
        return 0;
    }

    mg_md5(ha2, method, ":", uri, NULL);
    mg_md5(expected_response,
           ha1,
           ":",
           nonce,
           ":",
           nc,
           ":",
           cnonce,
           ":",
           qop,
           ":",
           ha2,
           NULL);

    return mg_strcasecmp(response, expected_response) == 0;
}


/* Use the global passwords file, if specified by auth_gpass option,
 * or search for .htpasswd in the requested directory. */
static void
open_auth_file(struct mg_connection *conn,
               const char *path,
               struct mg_file *filep) {
    if ((conn != NULL) && (conn->dom_ctx != NULL)) {
        char name[PATH_MAX];
        const char *p, *e,
                *gpass = conn->dom_ctx->config[GLOBAL_PASSWORDS_FILE];
        int truncated;

        if (gpass != NULL) {
/* Use global passwords file */
            if (!mg_fopen(conn, gpass, MG_FOPEN_MODE_READ, filep)) {
#if defined(DEBUG)
/* Use mg_cry_internal here, since gpass has been configured. */
                mg_cry_internal(conn, "fopen(%s): %s", gpass, strerror(ERRNO));
#endif
            }
/* Important: using local struct mg_file to test path for
			 * is_directory flag. If filep is used, mg_stat() makes it
			 * appear as if auth file was opened.
			 * TODO(mid): Check if this is still required after rewriting
			 * mg_stat */
        } else if (mg_stat(conn, path, &filep->stat)
                   && filep->stat.is_directory) {
            mg_snprintf(conn,
                        &truncated,
                        name,
                        sizeof(name),
                        "%s/%s",
                        path,
                        PASSWORDS_FILE_NAME);

            if (truncated || !mg_fopen(conn, name, MG_FOPEN_MODE_READ, filep)) {
#if defined(DEBUG)
/* Don't use mg_cry_internal here, but only a trace, since this
				 * is
				 * a typical case. It will occur for every directory
				 * without a password file. */
                DEBUG_TRACE("fopen(%s): %s", name, strerror(ERRNO));
#endif
            }
        } else {
/* Try to find .htpasswd in requested directory. */
            for (p = path, e = p + strlen(p) - 1; e > p; e--) {
                if (e[0] == '/') {
                    break;
                }
            }
            mg_snprintf(conn,
                        &truncated,
                        name,
                        sizeof(name),
                        "%.*s/%s",
                        (int) (e - p),
                        p,
                        PASSWORDS_FILE_NAME);

            if (truncated || !mg_fopen(conn, name, MG_FOPEN_MODE_READ, filep)) {
#if defined(DEBUG)
/* Don't use mg_cry_internal here, but only a trace, since this
				 * is
				 * a typical case. It will occur for every directory
				 * without a password file. */
                DEBUG_TRACE("fopen(%s): %s", name, strerror(ERRNO));
#endif
            }
        }
    }
}


/* Parsed Authorization header */
struct ah {
    char *user, *uri, *cnonce, *response, *qop, *nc, *nonce;
};


/* Return 1 on success. Always initializes the ah structure. */
static int
parse_auth_header(struct mg_connection *conn,
                  char *buf,
                  size_t buf_size,
                  struct ah *ah) {
    char *name, *value, *s;
    const char *auth_header;
    uint64_t nonce;

    if (!ah || !conn) {
        return 0;
    }

    (void) memset(ah, 0, sizeof(*ah));
    if (((auth_header = mg_get_header(conn, "Authorization")) == NULL)
        || mg_strncasecmp(auth_header, "Digest ", 7) != 0) {
        return 0;
    }

/* Make modifiable copy of the auth header */
    (void) mg_strlcpy(buf, auth_header + 7, buf_size);
    s = buf;

/* Parse authorization header */
    for (;;) {
/* Gobble initial spaces */
        while (isspace(*(unsigned char *) s)) {
            s++;
        }
        name = skip_quoted(&s, "=", " ", 0);
/* Value is either quote-delimited, or ends at first comma or space.
		 */
        if (s[0] == '\"') {
            s++;
            value = skip_quoted(&s, "\"", " ", '\\');
            if (s[0] == ',') {
                s++;
            }
        } else {
            value = skip_quoted(&s, ", ", " ", 0); /* IE uses commas, FF uses
			                                        * spaces */
        }
        if (*name == '\0') {
            break;
        }

        if (!strcmp(name, "username")) {
            ah->user = value;
        } else if (!strcmp(name, "cnonce")) {
            ah->cnonce = value;
        } else if (!strcmp(name, "response")) {
            ah->response = value;
        } else if (!strcmp(name, "uri")) {
            ah->uri = value;
        } else if (!strcmp(name, "qop")) {
            ah->qop = value;
        } else if (!strcmp(name, "nc")) {
            ah->nc = value;
        } else if (!strcmp(name, "nonce")) {
            ah->nonce = value;
        }
    }

#if !defined(NO_NONCE_CHECK)
/* Read the nonce from the response. */
    if (ah->nonce == NULL) {
        return 0;
    }
    s = NULL;
    nonce = strtoull(ah->nonce, &s, 10);
    if ((s == NULL) || (*s != 0)) {
        return 0;
    }

/* Convert the nonce from the client to a number. */
    nonce ^= conn->dom_ctx->auth_nonce_mask;

/* The converted number corresponds to the time the nounce has been
	 * created. This should not be earlier than the server start. */
/* Server side nonce check is valuable in all situations but one:
	 * if the server restarts frequently, but the client should not see
	 * that, so the server should accept nonces from previous starts. */
/* However, the reasonable default is to not accept a nonce from a
	 * previous start, so if anyone changed the access rights between
	 * two restarts, a new login is required. */
    if (nonce < (uint64_t) conn->phys_ctx->start_time) {
/* nonce is from a previous start of the server and no longer valid
		 * (replay attack?) */
        return 0;
    }
/* Check if the nonce is too high, so it has not (yet) been used by the
	 * server. */
    if (nonce >= ((uint64_t) conn->phys_ctx->start_time
                  + conn->dom_ctx->nonce_count)) {
        return 0;
    }
#else
    (void)nonce;
#endif

/* CGI needs it as REMOTE_USER */
    if (ah->user != NULL) {
        conn->request_info.remote_user =
                mg_strdup_ctx(ah->user, conn->phys_ctx);
    } else {
        return 0;
    }

    return 1;
}


static const char *
mg_fgets(char *buf, size_t size, struct mg_file *filep, char **p) {
#if defined(MG_USE_OPEN_FILE)
    const char *eof;
size_t len;
const char *memend;
#else
    (void) p; /* parameter is unused */
#endif

    if (!filep) {
        return NULL;
    }

#if defined(MG_USE_OPEN_FILE)
    if ((filep->access.membuf != NULL) && (*p != NULL)) {
memend = (const char *)&filep->access.membuf[filep->stat.size];
/* Search for \n from p till the end of stream */
eof = (char *)memchr(*p, '\n', (size_t)(memend - *p));
if (eof != NULL) {
eof += 1; /* Include \n */
} else {
eof = memend; /* Copy remaining data */
}
len =
((size_t)(eof - *p) > (size - 1)) ? (size - 1) : (size_t)(eof - *p);
memcpy(buf, *p, len);
buf[len] = '\0';
*p += len;
return len ? eof : NULL;
} else /* filep->access.fp block below */
#endif
    if (filep->access.fp != NULL) {
        return fgets(buf, (int) size, filep->access.fp);
    } else {
        return NULL;
    }
}

/* Define the initial recursion depth for procesesing htpasswd files that
 * include other htpasswd
 * (or even the same) files.  It is not difficult to provide a file or files
 * s.t. they force civetweb
 * to infinitely recurse and then crash.
 */
#define INITIAL_DEPTH 9
#if INITIAL_DEPTH <= 0
#error Bad INITIAL_DEPTH for recursion, set to at least 1
#endif

struct read_auth_file_struct {
    struct mg_connection *conn;
    struct ah ah;
    const char *domain;
    char buf[256 + 256 + 40];
    const char *f_user;
    const char *f_domain;
    const char *f_ha1;
};


static int
read_auth_file(struct mg_file *filep,
               struct read_auth_file_struct *workdata,
               int depth) {
    char *p = NULL /* init if MG_USE_OPEN_FILE is not set */;
    int is_authorized = 0;
    struct mg_file fp;
    size_t l;

    if (!filep || !workdata || (0 == depth)) {
        return 0;
    }

/* Loop over passwords file */
#if defined(MG_USE_OPEN_FILE)
    p = (char *)filep->access.membuf;
#endif
    while (mg_fgets(workdata->buf, sizeof(workdata->buf), filep, &p) != NULL) {
        l = strlen(workdata->buf);
        while (l > 0) {
            if (isspace(workdata->buf[l - 1])
                || iscntrl(workdata->buf[l - 1])) {
                l--;
                workdata->buf[l] = 0;
            } else
                break;
        }
        if (l < 1) {
            continue;
        }

        workdata->f_user = workdata->buf;

        if (workdata->f_user[0] == ':') {
/* user names may not contain a ':' and may not be empty,
			 * so lines starting with ':' may be used for a special purpose
			 */
            if (workdata->f_user[1] == '#') {
/* :# is a comment */
                continue;
            } else if (!strncmp(workdata->f_user + 1, "include=", 8)) {
                if (mg_fopen(workdata->conn,
                             workdata->f_user + 9,
                             MG_FOPEN_MODE_READ,
                             &fp)) {
                    is_authorized = read_auth_file(&fp, workdata, depth - 1);
                    (void) mg_fclose(
                            &fp.access); /* ignore error on read only file */

/* No need to continue processing files once we have a
					 * match, since nothing will reset it back
					 * to 0.
					 */
                    if (is_authorized) {
                        return is_authorized;
                    }
                } else {
                    mg_cry_internal(workdata->conn,
                                    "%s: cannot open authorization file: %s",
                                    __func__,
                                    workdata->buf);
                }
                continue;
            }
/* everything is invalid for the moment (might change in the
			 * future) */
            mg_cry_internal(workdata->conn,
                            "%s: syntax error in authorization file: %s",
                            __func__,
                            workdata->buf);
            continue;
        }

        workdata->f_domain = strchr(workdata->f_user, ':');
        if (workdata->f_domain == NULL) {
            mg_cry_internal(workdata->conn,
                            "%s: syntax error in authorization file: %s",
                            __func__,
                            workdata->buf);
            continue;
        }
        *(char *) (workdata->f_domain) = 0;
        (workdata->f_domain)++;

        workdata->f_ha1 = strchr(workdata->f_domain, ':');
        if (workdata->f_ha1 == NULL) {
            mg_cry_internal(workdata->conn,
                            "%s: syntax error in authorization file: %s",
                            __func__,
                            workdata->buf);
            continue;
        }
        *(char *) (workdata->f_ha1) = 0;
        (workdata->f_ha1)++;

        if (!strcmp(workdata->ah.user, workdata->f_user)
            && !strcmp(workdata->domain, workdata->f_domain)) {
            return check_password(workdata->conn->request_info.request_method,
                                  workdata->f_ha1,
                                  workdata->ah.uri,
                                  workdata->ah.nonce,
                                  workdata->ah.nc,
                                  workdata->ah.cnonce,
                                  workdata->ah.qop,
                                  workdata->ah.response);
        }
    }

    return is_authorized;
}


/* Authorize against the opened passwords file. Return 1 if authorized. */
static int
authorize(struct mg_connection *conn, struct mg_file *filep, const char *realm) {
    struct read_auth_file_struct workdata;
    char buf[MG_BUF_LEN];

    if (!conn || !conn->dom_ctx) {
        return 0;
    }

    memset(&workdata, 0, sizeof(workdata));
    workdata.conn = conn;

    if (!parse_auth_header(conn, buf, sizeof(buf), &workdata.ah)) {
        return 0;
    }

    if (realm) {
        workdata.domain = realm;
    } else {
        workdata.domain = conn->dom_ctx->config[AUTHENTICATION_DOMAIN];
    }

    return read_auth_file(filep, &workdata, INITIAL_DEPTH);
}


/* Public function to check http digest authentication header */
int
mg_check_digest_access_authentication(struct mg_connection *conn,
                                      const char *realm,
                                      const char *filename) {
    struct mg_file file = STRUCT_FILE_INITIALIZER;
    int auth;

    if (!conn || !filename) {
        return -1;
    }
    if (!mg_fopen(conn, filename, MG_FOPEN_MODE_READ, &file)) {
        return -2;
    }

    auth = authorize(conn, &file, realm);

    mg_fclose(&file.access);

    return auth;
}


/* Return 1 if request is authorised, 0 otherwise. */
static int
check_authorization(struct mg_connection *conn, const char *path) {
    char fname[PATH_MAX];
    struct vec uri_vec, filename_vec;
    const char *list;
    struct mg_file file = STRUCT_FILE_INITIALIZER;
    int authorized = 1, truncated;

    if (!conn || !conn->dom_ctx) {
        return 0;
    }

    list = conn->dom_ctx->config[PROTECT_URI];
    while ((list = next_option(list, &uri_vec, &filename_vec)) != NULL) {
        if (!memcmp(conn->request_info.local_uri, uri_vec.ptr, uri_vec.len)) {
            mg_snprintf(conn,
                        &truncated,
                        fname,
                        sizeof(fname),
                        "%.*s",
                        (int) filename_vec.len,
                        filename_vec.ptr);

            if (truncated
                || !mg_fopen(conn, fname, MG_FOPEN_MODE_READ, &file)) {
                mg_cry_internal(conn,
                                "%s: cannot open %s: %s",
                                __func__,
                                fname,
                                strerror(errno));
            }
            break;
        }
    }

    if (!is_file_opened(&file.access)) {
        open_auth_file(conn, path, &file);
    }

    if (is_file_opened(&file.access)) {
        authorized = authorize(conn, &file, NULL);
        (void) mg_fclose(&file.access); /* ignore error on read only file */
    }

    return authorized;
}


/* Internal function. Assumes conn is valid */
static void
send_authorization_request(struct mg_connection *conn, const char *realm) {
    char date[64];
    time_t curtime = time(NULL);
    uint64_t nonce = (uint64_t) (conn->phys_ctx->start_time);

    if (!realm) {
        realm = conn->dom_ctx->config[AUTHENTICATION_DOMAIN];
    }

    (void) pthread_mutex_lock(&conn->phys_ctx->nonce_mutex);
    nonce += conn->dom_ctx->nonce_count;
    ++conn->dom_ctx->nonce_count;
    (void) pthread_mutex_unlock(&conn->phys_ctx->nonce_mutex);

    nonce ^= conn->dom_ctx->auth_nonce_mask;
    conn->status_code = 401;
    conn->must_close = 1;

    gmt_time_string(date, sizeof(date), &curtime);

    mg_printf(conn, "HTTP/1.1 401 Unauthorized\r\n");
    send_no_cache_header(conn);
    send_additional_header(conn);
    mg_printf(conn,
              "Date: %s\r\n"
              "Connection: %s\r\n"
              "Content-Length: 0\r\n"
              "WWW-Authenticate: Digest qop=\"auth\", realm=\"%s\", "
              "nonce=\"%" UINT64_FMT "\"\r\n\r\n",
              date,
              suggest_connection_header(conn),
              realm,
              nonce);
}


/* Interface function. Parameters are provided by the user, so do
 * at least some basic checks.
 */
int
mg_send_digest_access_authentication_request(struct mg_connection *conn,
                                             const char *realm) {
    if (conn && conn->dom_ctx) {
        send_authorization_request(conn, realm);
        return 0;
    }
    return -1;
}


#if !defined(NO_FILES)
static int
is_authorized_for_put(struct mg_connection *conn)
{
if (conn) {
struct mg_file file = STRUCT_FILE_INITIALIZER;
const char *passfile = conn->dom_ctx->config[PUT_DELETE_PASSWORDS_FILE];
int ret = 0;

if (passfile != NULL
&& mg_fopen(conn, passfile, MG_FOPEN_MODE_READ, &file)) {
ret = authorize(conn, &file, NULL);
(void)mg_fclose(&file.access); /* ignore error on read only file */
}

return ret;
}
return 0;
}
#endif


int
mg_modify_passwords_file(const char *fname,
                         const char *domain,
                         const char *user,
                         const char *pass) {
    int found, i;
    char line[512], u[512] = "", d[512] = "", ha1[33], tmp[PATH_MAX + 8];
    FILE *fp, *fp2;

    found = 0;
    fp = fp2 = NULL;

/* Regard empty password as no password - remove user record. */
    if ((pass != NULL) && (pass[0] == '\0')) {
        pass = NULL;
    }

/* Other arguments must not be empty */
    if ((fname == NULL) || (domain == NULL) || (user == NULL)) {
        return 0;
    }

/* Using the given file format, user name and domain must not contain
	 * ':'
	 */
    if (strchr(user, ':') != NULL) {
        return 0;
    }
    if (strchr(domain, ':') != NULL) {
        return 0;
    }

/* Do not allow control characters like newline in user name and domain.
	 * Do not allow excessively long names either. */
    for (i = 0; ((i < 255) && (user[i] != 0)); i++) {
        if (iscntrl(user[i])) {
            return 0;
        }
    }
    if (user[i]) {
        return 0;
    }
    for (i = 0; ((i < 255) && (domain[i] != 0)); i++) {
        if (iscntrl(domain[i])) {
            return 0;
        }
    }
    if (domain[i]) {
        return 0;
    }

/* The maximum length of the path to the password file is limited */
    if ((strlen(fname) + 4) >= PATH_MAX) {
        return 0;
    }

/* Create a temporary file name. Length has been checked before. */
    strcpy(tmp, fname);
    strcat(tmp, ".tmp");

/* Create the file if does not exist */
/* Use of fopen here is OK, since fname is only ASCII */
    if ((fp = fopen(fname, "a+")) != NULL) {
        (void) fclose(fp);
    }

/* Open the given file and temporary file */
    if ((fp = fopen(fname, "r")) == NULL) {
        return 0;
    } else if ((fp2 = fopen(tmp, "w+")) == NULL) {
        fclose(fp);
        return 0;
    }

/* Copy the stuff to temporary file */
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%255[^:]:%255[^:]:%*s", u, d) != 2) {
            continue;
        }
        u[255] = 0;
        d[255] = 0;

        if (!strcmp(u, user) && !strcmp(d, domain)) {
            found++;
            if (pass != NULL) {
                mg_md5(ha1, user, ":", domain, ":", pass, NULL);
                fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
            }
        } else {
            fprintf(fp2, "%s", line);
        }
    }

/* If new user, just add it */
    if (!found && (pass != NULL)) {
        mg_md5(ha1, user, ":", domain, ":", pass, NULL);
        fprintf(fp2, "%s:%s:%s\n", user, domain, ha1);
    }

/* Close files */
    fclose(fp);
    fclose(fp2);

/* Put the temp file in place of real file */
    IGNORE_UNUSED_RESULT(remove(fname));
    IGNORE_UNUSED_RESULT(rename(tmp, fname));

    return 1;
}


static int
is_valid_port(unsigned long port) {
    return (port <= 0xffff);
}


static int
mg_inet_pton(int af, const char *src, void *dst, size_t dstlen) {
    struct addrinfo hints, *res, *ressave;
    int func_ret = 0;
    int gai_ret;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = af;

    gai_ret = getaddrinfo(src, NULL, &hints, &res);
    if (gai_ret != 0) {
/* gai_strerror could be used to convert gai_ret to a string */
/* POSIX return values: see
		 * http://pubs.opengroup.org/onlinepubs/9699919799/functions/freeaddrinfo.html
		 */
/* Windows return values: see
		 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms738520%28v=vs.85%29.aspx
		 */
        return 0;
    }

    ressave = res;

    while (res) {
        if (dstlen >= (size_t) res->ai_addrlen) {
            memcpy(dst, res->ai_addr, res->ai_addrlen);
            func_ret = 1;
        }
        res = res->ai_next;
    }

    freeaddrinfo(ressave);
    return func_ret;
}


static int
connect_socket(struct mg_context *ctx /* may be NULL */,
               const char *host,
               int port,
               int use_ssl,
               char *ebuf,
               size_t ebuf_len,
               SOCKET *sock /* output: socket, must not be NULL */,
               union usa *sa /* output: socket address, must not be NULL  */
) {
    int ip_ver = 0;
    int conn_ret = -1;
    int ret;
    *sock = INVALID_SOCKET;
    memset(sa, 0, sizeof(*sa));

    if (ebuf_len > 0) {
        *ebuf = 0;
    }

    if (host == NULL) {
        mg_snprintf(NULL,
                    NULL, /* No truncation check for ebuf */
                    ebuf,
                    ebuf_len,
                    "%s",
                    "NULL host");
        return 0;
    }

    if ((port <= 0) || !is_valid_port((unsigned) port)) {
        mg_snprintf(NULL,
                    NULL, /* No truncation check for ebuf */
                    ebuf,
                    ebuf_len,
                    "%s",
                    "invalid port");
        return 0;
    }

#if !defined(NO_SSL)
#if !defined(NO_SSL_DL)
#if defined(OPENSSL_API_1_1)
    if (use_ssl && (TLS_client_method == NULL)) {
mg_snprintf(NULL,
NULL, /* No truncation check for ebuf */
ebuf,
ebuf_len,
"%s",
"SSL is not initialized");
return 0;
}
#else
    if (use_ssl && (SSLv23_client_method == NULL)) {
        mg_snprintf(NULL,
                    NULL, /* No truncation check for ebuf */
                    ebuf,
                    ebuf_len,
                    "%s",
                    "SSL is not initialized");
        return 0;
    }

#endif /* OPENSSL_API_1_1 */
#else
    (void)use_ssl;
#endif /* NO_SSL_DL */
#else
    (void)use_ssl;
#endif /* !defined(NO_SSL) */

    if (mg_inet_pton(AF_INET, host, &sa->sin, sizeof(sa->sin))) {
        sa->sin.sin_family = AF_INET;
        sa->sin.sin_port = htons((uint16_t) port);
        ip_ver = 4;
#if defined(USE_IPV6)
        } else if (mg_inet_pton(AF_INET6, host, &sa->sin6, sizeof(sa->sin6))) {
sa->sin6.sin6_family = AF_INET6;
sa->sin6.sin6_port = htons((uint16_t)port);
ip_ver = 6;
} else if (host[0] == '[') {
/* While getaddrinfo on Windows will work with [::1],
         * getaddrinfo on Linux only works with ::1 (without []). */
size_t l = strlen(host + 1);
char *h = (l > 1) ? mg_strdup_ctx(host + 1, ctx) : NULL;
if (h) {
h[l - 1] = 0;
if (mg_inet_pton(AF_INET6, h, &sa->sin6, sizeof(sa->sin6))) {
sa->sin6.sin6_family = AF_INET6;
sa->sin6.sin6_port = htons((uint16_t)port);
ip_ver = 6;
}
mg_free(h);
}
