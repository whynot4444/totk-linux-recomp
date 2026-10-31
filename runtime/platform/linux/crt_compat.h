// The MSVC C runtime names the runtime uses, for Linux. tools/build_game.py force-includes this header (-include) in
// every runtime file on Linux, as these names come with the C headers on Windows. It declares what it needs itself
// rather than including <unistd.h>, whose names (acct, ...) would clash with the runtime's own.
#pragma once
#ifndef _WIN32
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

int fsync(int fd);
void _exit(int code) __attribute__((noreturn));
int setenv(const char *name, const char *value, int overwrite);
int unsetenv(const char *name);

#define _strdup strdup
#define _wcsdup wcsdup
#define _stricmp strcasecmp
#define _strnicmp strncasecmp
#define _wcsicmp wcscasecmp
#define strtok_s strtok_r
#define _fseeki64 fseeko
#define _ftelli64 ftello
#define _fileno fileno
#define _commit fsync
#define _tzset tzset
#define _snprintf snprintf
#define _vsnprintf vsnprintf
static inline int _putenv_s(const char *name, const char *value) {
    return *value ? setenv(name, value, 1) : unsetenv(name);   // an empty value removes the variable, as on Windows
}
static inline int localtime_s(struct tm *out, const time_t *t) { return localtime_r(t, out) ? 0 : 22; }
static inline int gmtime_s(struct tm *out, const time_t *t) { return gmtime_r(t, out) ? 0 : 22; }
// _aligned_malloc memory goes back through _aligned_free; aligned_alloc memory is freed with free.
static inline void *_aligned_malloc(size_t n, size_t align) {
    return aligned_alloc(align, (n + align - 1) / align * align);
}
static inline void _aligned_free(void *p) { free(p); }
// Seconds west of UTC, as _get_timezone gives them (time.h's timezone after tzset).
static inline int _get_timezone(long *seconds) {
    tzset();
    *seconds = timezone;
    return 0;
}
char *_fullpath(char *out, const char *path, size_t cap);
// Paths the stand-in hands out (the executable's, temporary and full paths) use '\' as on Windows, since the runtime
// cuts them there; every call that reaches the system converts back. These two are the C library's that the runtime
// calls with such paths (a function-like macro: "(fopen)(...)" still names the C library's own).
FILE *w32_fopen(const char *path, const char *mode);
int w32_remove(const char *path);
#define fopen(path, mode) w32_fopen(path, mode)
#define remove(path) w32_remove(path)
FILE *_wfopen(const wchar_t *path, const wchar_t *mode);

#ifdef __cplusplus
}
#endif
#endif
