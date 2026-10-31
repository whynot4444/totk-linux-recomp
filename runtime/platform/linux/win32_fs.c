// Linux Win32 stand-in, part 2: strings, paths, file handles, directory searches, file mappings.
//
// Paths: wide strings are converted to UTF-8, '\' becomes '/', a "\\?\" prefix is dropped and "NUL" is /dev/null.
// Windows file systems ignore case, so a path that does not exist as spelled is looked up again component by
// component without regard to case (files the game names in another case than the folder holds them).
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "w32_internal.h"

// ---- UTF-8 and UTF-32

size_t w32_utf8_to_wide(const char *s, size_t n, wchar_t *out, size_t cap) {
    size_t k = 0;
    const unsigned char *p = (const unsigned char *)s, *e = p + n;
    while (p < e) {
        uint32_t c = *p++;
        int more = c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc0 ? 1 : 0;
        if (more) c &= 0x3fu >> more;
        while (more-- && p < e && (*p & 0xc0) == 0x80) c = c << 6 | (*p++ & 0x3f);
        if (out) {
            if (k >= cap) return k;
            out[k] = (wchar_t)c;
        }
        k++;
    }
    return k;
}

size_t w32_wide_to_utf8(const wchar_t *w, size_t n, char *out, size_t cap) {
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t c = (uint32_t)w[i];
        char b[4];
        int m;
        if (c < 0x80) b[0] = (char)c, m = 1;
        else if (c < 0x800) b[0] = (char)(0xc0 | c >> 6), b[1] = (char)(0x80 | (c & 0x3f)), m = 2;
        else if (c < 0x10000)
            b[0] = (char)(0xe0 | c >> 12), b[1] = (char)(0x80 | (c >> 6 & 0x3f)), b[2] = (char)(0x80 | (c & 0x3f)), m = 3;
        else
            b[0] = (char)(0xf0 | c >> 18), b[1] = (char)(0x80 | (c >> 12 & 0x3f)), b[2] = (char)(0x80 | (c >> 6 & 0x3f)),
            b[3] = (char)(0x80 | (c & 0x3f)), m = 4;
        if (out) {
            if (k + (size_t)m > cap) return k;
            memcpy(out + k, b, (size_t)m);
        }
        k += (size_t)m;
    }
    return k;
}

// n -1: NUL-terminated, the NUL converted too (and counted), as Windows does.
int MultiByteToWideChar(UINT cp, DWORD flags, LPCSTR s, int n, LPWSTR out, int cap) {
    (void)cp, (void)flags;
    size_t len = n < 0 ? strlen(s) + 1 : (size_t)n;
    size_t need = w32_utf8_to_wide(s, len, NULL, 0);
    if (!cap || !out) return (int)need;
    if (need > (size_t)cap) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    return (int)w32_utf8_to_wide(s, len, out, (size_t)cap);
}

int WideCharToMultiByte(UINT cp, DWORD flags, LPCWSTR w, int n, LPSTR out, int cap, LPCSTR def, LPBOOL used) {
    (void)cp, (void)flags, (void)def;
    if (used) *used = FALSE;
    size_t len = n < 0 ? wcslen(w) + 1 : (size_t)n;
    size_t need = w32_wide_to_utf8(w, len, NULL, 0);
    if (!cap || !out) return (int)need;
    if (need > (size_t)cap) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    return (int)w32_wide_to_utf8(w, len, out, (size_t)cap);
}

// ---- paths

static char *fix_path(char *p) {
    for (char *c = p; *c; c++)
        if (*c == '\\') *c = '/';
    if (!strncmp(p, "//?/", 4)) memmove(p, p + 4, strlen(p + 4) + 1);
    if (!strcasecmp(p, "NUL") || !strcasecmp(p, "NUL:")) strcpy(p, "/dev/null");
    return p;
}

char *w32_path_a(LPCSTR s, char *out, size_t cap) {
    if (!s) return NULL;
    size_t n = strlen(s);
    if (n + 1 > cap || cap < 16) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    memcpy(out, s, n + 1);
    return fix_path(out);
}

char *w32_path_w(LPCWSTR w, char *out, size_t cap) {
    if (!w) return NULL;
    size_t k = w32_wide_to_utf8(w, wcslen(w), out, cap - 1);
    if (k >= cap - 1 && wcslen(w)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    out[k] = 0;
    return fix_path(out);
}

// Resolves p (PATH_MAX buffer) in place ignoring case, from the first component that does not exist as spelled.
// parent_only: leave the last component (a file about to be created) as it is. Returns 1 when p now exists (or its
// parent, with parent_only).
static int ci_resolve(char *p, int parent_only) {
    struct stat st;
    if (!lstat(p, &st)) return 1;
    char out[PATH_MAX];
    size_t on = 0;
    const char *s = p;
    if (*s == '/') out[on++] = '/', s++;
    out[on] = 0;
    while (*s) {
        const char *e = strchr(s, '/');
        size_t n = e ? (size_t)(e - s) : strlen(s);
        int last = !e || !e[1];
        char comp[NAME_MAX + 1];
        if (n > NAME_MAX) return 0;
        memcpy(comp, s, n);
        comp[n] = 0;
        char probe[PATH_MAX];
        snprintf(probe, sizeof probe, "%s%s", on ? out : "", comp);
        if (n && lstat(probe, &st)) {
            DIR *d = opendir(on ? out : ".");
            int found = 0;
            if (d) {
                for (struct dirent *de; (de = readdir(d));)
                    if (!strcasecmp(de->d_name, comp)) {
                        snprintf(comp, sizeof comp, "%s", de->d_name);
                        found = 1;
                        break;
                    }
                closedir(d);
            }
            if (!found && !(last && parent_only)) return 0;   // a file about to be created keeps its spelling
        }
        if (on + n + 2 >= sizeof out) return 0;
        memcpy(out + on, comp, strlen(comp));
        on += strlen(comp);
        if (e) out[on++] = '/';
        out[on] = 0;
        s = e ? e + 1 : s + n;
    }
    strcpy(p, out);
    return 1;
}

// UTF-8 system path of w (wide) or a (narrow) into out (PATH_MAX), resolved ignoring case. parent_only: the last
// component may not exist yet (a file to create); an existing one is still matched without regard to case.
// A "<name>.exe" that does not exist names the Linux build of the program, which has no suffix (totk_xlate).
static char *sys_path(LPCWSTR w, LPCSTR a, char *out, int parent_only) {
    if (!(w ? w32_path_w(w, out, PATH_MAX) : w32_path_a(a, out, PATH_MAX))) return NULL;
    if (!ci_resolve(out, parent_only) && !parent_only) {
        size_t n = strlen(out);
        if (n > 4 && !strcasecmp(out + n - 4, ".exe")) {
            out[n - 4] = 0;
            if (!ci_resolve(out, 0)) out[n - 4] = '.';   // neither exists: keep the name asked for
        }
    }
    return out;
}

char *w32_sys_path(const char *utf8, char *out, int create) { return sys_path(NULL, utf8, out, create); }

// ---- file handles

typedef struct {
    W32Obj o;
    int fd, append_fd, close_fd, delete_on_close;
    char *path;
} W32File;

static void file_destroy(W32Obj *o) {
    W32File *f = (W32File *)o;
    if (f->delete_on_close && f->path) unlink(f->path);
    if (f->close_fd && f->fd >= 0) close(f->fd);
    if (f->append_fd >= 0) close(f->append_fd);
    free(f->path);
}

static W32File *file_new(int fd, int close_fd, const char *path) {
    W32File *f = calloc(1, sizeof *f);
    if (!f) return NULL;
    f->o = (W32Obj){W32_FILE, 1, file_destroy};
    f->fd = fd;
    f->append_fd = -1;
    f->close_fd = close_fd;
    f->path = path ? strdup(path) : NULL;
    return f;
}

HANDLE w32_fd_handle(int fd, int close_on_free) { return file_new(fd, close_on_free, NULL); }

static W32File *std_files[3];

HANDLE GetStdHandle(DWORD which) {
    int fd = which == STD_INPUT_HANDLE ? 0 : which == STD_OUTPUT_HANDLE ? 1 : which == STD_ERROR_HANDLE ? 2 : -1;
    if (fd < 0) return INVALID_HANDLE_VALUE;
    if (!std_files[fd]) {
        W32File *f = file_new(fd, 0, NULL), *z = NULL;
        f->o.refs = 1 << 30;   // never freed by CloseHandle
        if (!__atomic_compare_exchange_n(&std_files[fd], &z, f, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) free(f);
    }
    return std_files[fd];
}

int w32_handle_fd(HANDLE h) {
    if (!h || h == INVALID_HANDLE_VALUE || (uintptr_t)h < 0x10000) return -1;
    W32File *f = h;
    return f->o.magic == W32_FILE ? f->fd : -1;
}

static HANDLE create_file(const char *p, DWORD access, DWORD disp, DWORD flags) {
    int acc = (access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA))
                  ? ((access & (GENERIC_READ | GENERIC_ALL | FILE_READ_DATA)) ? O_RDWR : O_WRONLY)
                  : O_RDONLY;
    int of = acc | O_CLOEXEC;
    switch (disp) {
    case CREATE_NEW: of |= O_CREAT | O_EXCL; break;
    case CREATE_ALWAYS: of |= O_CREAT | O_TRUNC; break;
    case OPEN_ALWAYS: of |= O_CREAT; break;
    case TRUNCATE_EXISTING: of |= O_TRUNC; break;
    default: break;
    }
    struct stat st;
    int existed = !stat(p, &st);
    if (existed && S_ISREG(st.st_mode) && !(st.st_mode & 0222) &&
        (access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA))) {
        SetLastError(ERROR_ACCESS_DENIED);   // the read-only attribute holds for every user on Windows, root included
        return INVALID_HANDLE_VALUE;
    }
    if (existed && S_ISDIR(st.st_mode)) {
        if (!(flags & FILE_FLAG_BACKUP_SEMANTICS)) {
            SetLastError(ERROR_ACCESS_DENIED);
            return INVALID_HANDLE_VALUE;
        }
        of = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
    }
    int fd = open(p, of, 0666);
    if (fd < 0 && errno == EISDIR && (flags & FILE_FLAG_BACKUP_SEMANTICS)) fd = open(p, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        w32_set_errno();
        if (errno == EEXIST) SetLastError(ERROR_FILE_EXISTS);
        if (errno == ENOENT && disp != OPEN_EXISTING && disp != TRUNCATE_EXISTING) SetLastError(ERROR_PATH_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    if (flags & FILE_FLAG_SEQUENTIAL_SCAN) posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    if (flags & FILE_FLAG_RANDOM_ACCESS) posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM);
    W32File *f = file_new(fd, 1, p);
    if (!f) {
        close(fd);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return INVALID_HANDLE_VALUE;
    }
    f->delete_on_close = (flags & FILE_FLAG_DELETE_ON_CLOSE) != 0;
    // As on Windows: OPEN_ALWAYS and CREATE_ALWAYS tell whether the file was there
    SetLastError((existed && (disp == OPEN_ALWAYS || disp == CREATE_ALWAYS)) ? ERROR_ALREADY_EXISTS : ERROR_SUCCESS);
    return f;
}

HANDLE CreateFileW(LPCWSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags,
                   HANDLE tmpl) {
    (void)share, (void)sa, (void)tmpl;
    char p[PATH_MAX];
    if (!sys_path(path, NULL, p, disp != OPEN_EXISTING && disp != TRUNCATE_EXISTING)) return INVALID_HANDLE_VALUE;
    return create_file(p, access, disp, flags);
}

HANDLE CreateFileA(LPCSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags,
                   HANDLE tmpl) {
    (void)share, (void)sa, (void)tmpl;
    char p[PATH_MAX];
    if (!sys_path(NULL, path, p, disp != OPEN_EXISTING && disp != TRUNCATE_EXISTING)) return INVALID_HANDLE_VALUE;
    return create_file(p, access, disp, flags);
}

static W32File *file_of(HANDLE h) { return (W32File *)w32_obj(h, W32_FILE); }

BOOL ReadFile(HANDLE h, LPVOID buf, DWORD n, LPDWORD got, LPOVERLAPPED o) {
    W32File *f = file_of(h);
    if (got) *got = 0;
    if (!f) return FALSE;
    w32_ww_prepare_write(buf, n);
    size_t done = 0;
    off_t at = o ? (off_t)((uint64_t)o->OffsetHigh << 32 | o->Offset) : 0;
    while (done < n) {
        ssize_t k = o ? pread(f->fd, (char *)buf + done, n - done, at + (off_t)done)
                      : read(f->fd, (char *)buf + done, n - done);
        if (k < 0) {
            if (errno == EINTR) continue;
            w32_set_errno();
            if (got) *got = (DWORD)done;
            return FALSE;
        }
        if (!k) break;
        done += (size_t)k;
        if (!o) break;   // a pipe or console returns what it has
    }
    if (got) *got = (DWORD)done;
    if (o) o->InternalHigh = done, o->Internal = 0;
    if (o && !done && n) {
        SetLastError(ERROR_HANDLE_EOF);
        return FALSE;
    }
    return TRUE;
}

BOOL WriteFile(HANDLE h, LPCVOID buf, DWORD n, LPDWORD put, LPOVERLAPPED o) {
    W32File *f = file_of(h);
    if (put) *put = 0;
    if (!f) return FALSE;
    int fd = f->fd;
    int append = o && o->Offset == 0xffffffffu && o->OffsetHigh == 0xffffffffu;
    if (append) {   // all-ones offset: at the end of the file, atomically against other writers
        if (f->append_fd < 0 && f->path) {
            int a = open(f->path, O_WRONLY | O_APPEND | O_CLOEXEC);
            int z = -1;
            if (a >= 0 && !__atomic_compare_exchange_n(&f->append_fd, &z, a, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                close(a);
        }
        if (f->append_fd >= 0) fd = f->append_fd;
    }
    off_t at = (o && !append) ? (off_t)((uint64_t)o->OffsetHigh << 32 | o->Offset) : 0;
    size_t done = 0;
    while (done < n) {
        ssize_t k = (o && !append) ? pwrite(fd, (const char *)buf + done, n - done, at + (off_t)done)
                                   : write(fd, (const char *)buf + done, n - done);
        if (k < 0) {
            if (errno == EINTR) continue;
            w32_set_errno();
            if (put) *put = (DWORD)done;
            return FALSE;
        }
        done += (size_t)k;
    }
    if (put) *put = (DWORD)done;
    if (o) o->InternalHigh = done, o->Internal = 0;
    return TRUE;
}

BOOL GetOverlappedResult(HANDLE h, LPOVERLAPPED o, LPDWORD n, BOOL wait) {
    (void)h, (void)wait;
    *n = (DWORD)o->InternalHigh;   // every operation here completed synchronously
    return TRUE;
}

BOOL GetFileSizeEx(HANDLE h, PLARGE_INTEGER size) {
    W32File *f = file_of(h);
    struct stat st;
    if (!f) return FALSE;
    if (fstat(f->fd, &st)) {
        w32_set_errno();
        return FALSE;
    }
    size->QuadPart = st.st_size;
    return TRUE;
}

DWORD GetFileSize(HANDLE h, LPDWORD high) {
    LARGE_INTEGER s;
    if (!GetFileSizeEx(h, &s)) return INVALID_FILE_SIZE;
    if (high) *high = (DWORD)((uint64_t)s.QuadPart >> 32);
    return (DWORD)s.QuadPart;
}

BOOL SetFilePointerEx(HANDLE h, LARGE_INTEGER to, PLARGE_INTEGER now, DWORD how) {
    W32File *f = file_of(h);
    if (!f) return FALSE;
    off_t r = lseek(f->fd, (off_t)to.QuadPart, how == FILE_END ? SEEK_END : how == FILE_CURRENT ? SEEK_CUR : SEEK_SET);
    if (r < 0) {
        w32_set_errno();
        return FALSE;
    }
    if (now) now->QuadPart = r;
    return TRUE;
}

BOOL SetEndOfFile(HANDLE h) {
    W32File *f = file_of(h);
    if (!f) return FALSE;
    off_t at = lseek(f->fd, 0, SEEK_CUR);
    if (at < 0 || ftruncate(f->fd, at)) {
        w32_set_errno();
        return FALSE;
    }
    return TRUE;
}

BOOL FlushFileBuffers(HANDLE h) {
    W32File *f = file_of(h);
    if (!f) return FALSE;
    if (fsync(f->fd) && errno != EINVAL && errno != EROFS) {   // pipes and consoles: nothing to flush
        w32_set_errno();
        return FALSE;
    }
    return TRUE;
}

DWORD GetFileType(HANDLE h) {
    int fd = w32_handle_fd(h);
    struct stat st;
    if (fd < 0 || fstat(fd, &st)) return FILE_TYPE_UNKNOWN;
    if (S_ISREG(st.st_mode) || S_ISDIR(st.st_mode)) return FILE_TYPE_DISK;
    if (S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode)) return FILE_TYPE_PIPE;
    if (S_ISCHR(st.st_mode)) return FILE_TYPE_CHAR;
    return FILE_TYPE_UNKNOWN;
}

BOOL SetHandleInformation(HANDLE h, DWORD mask, DWORD flags) {
    int fd = w32_handle_fd(h);
    if (fd < 0) return FALSE;
    if (mask & HANDLE_FLAG_INHERIT) {
        int fl = fcntl(fd, F_GETFD);
        fcntl(fd, F_SETFD, (flags & HANDLE_FLAG_INHERIT) ? fl & ~FD_CLOEXEC : fl | FD_CLOEXEC);
    }
    return TRUE;
}

DWORD GetFinalPathNameByHandleW(HANDLE h, LPWSTR out, DWORD cap, DWORD flags) {
    (void)flags;
    int fd = w32_handle_fd(h);
    char link[64], p[PATH_MAX];
    if (fd < 0) return 0;
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, p, sizeof p - 1);
    if (n <= 0) return 0;
    p[n] = 0;
    size_t need = w32_utf8_to_wide(p, (size_t)n, NULL, 0);
    if (need + 1 > cap) return (DWORD)need + 1;
    out[w32_utf8_to_wide(p, (size_t)n, out, cap - 1)] = 0;
    w32_win_sep_w(out);
    return (DWORD)need;
}

static void ft_from_ts(const struct timespec *ts, FILETIME *ft) {
    uint64_t v = 116444736000000000ull + (uint64_t)ts->tv_sec * 10000000u + (uint64_t)ts->tv_nsec / 100u;
    ft->dwLowDateTime = (DWORD)v, ft->dwHighDateTime = (DWORD)(v >> 32);
}

static DWORD attrs_of(const struct stat *st, const char *name) {
    DWORD a = 0;
    if (S_ISDIR(st->st_mode)) a |= FILE_ATTRIBUTE_DIRECTORY;
    if (!(st->st_mode & 0222)) a |= FILE_ATTRIBUTE_READONLY;
    if (name && name[0] == '.' && strcmp(name, ".") && strcmp(name, "..")) a |= FILE_ATTRIBUTE_HIDDEN;
    return a ? a : FILE_ATTRIBUTE_NORMAL;
}

BOOL GetFileInformationByHandle(HANDLE h, LPBY_HANDLE_FILE_INFORMATION info) {
    int fd = w32_handle_fd(h);
    struct stat st;
    if (fd < 0 || fstat(fd, &st)) {
        w32_set_errno();
        return FALSE;
    }
    memset(info, 0, sizeof *info);
    info->dwFileAttributes = attrs_of(&st, NULL);
    ft_from_ts(&st.st_mtim, &info->ftCreationTime);
    ft_from_ts(&st.st_atim, &info->ftLastAccessTime);
    ft_from_ts(&st.st_mtim, &info->ftLastWriteTime);
    info->dwVolumeSerialNumber = (DWORD)st.st_dev;
    info->nFileSizeHigh = (DWORD)((uint64_t)st.st_size >> 32);
    info->nFileSizeLow = (DWORD)st.st_size;
    info->nNumberOfLinks = (DWORD)st.st_nlink;
    info->nFileIndexHigh = (DWORD)((uint64_t)st.st_ino >> 32);
    info->nFileIndexLow = (DWORD)st.st_ino;
    return TRUE;
}

BOOL SetFileInformationByHandle(HANDLE h, FILE_INFO_BY_HANDLE_CLASS cls, LPVOID info, DWORD size) {
    (void)size;
    W32File *f = file_of(h);
    if (!f) return FALSE;
    switch (cls) {
    case FileEndOfFileInfo:
        if (ftruncate(f->fd, (off_t)((FILE_END_OF_FILE_INFO *)info)->EndOfFile.QuadPart)) break;
        return TRUE;
    case FileAllocationInfo: {
        off_t n = (off_t)((FILE_ALLOCATION_INFO *)info)->AllocationSize.QuadPart;
        struct stat st;
        if (!fstat(f->fd, &st) && n < st.st_size && ftruncate(f->fd, n)) break;
        return TRUE;
    }
    case FileDispositionInfo:
        f->delete_on_close = ((FILE_DISPOSITION_INFO *)info)->DeleteFile != 0;
        return TRUE;
    case FileBasicInfo: return TRUE;   // times and attributes: nothing the runtime depends on
    default: SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
    }
    w32_set_errno();
    return FALSE;
}

// ---- attributes and directory operations

static DWORD get_attrs(const char *p) {
    struct stat st;
    if (stat(p, &st)) {
        w32_set_errno();
        return INVALID_FILE_ATTRIBUTES;
    }
    const char *name = strrchr(p, '/');
    return attrs_of(&st, name ? name + 1 : p);
}

DWORD GetFileAttributesW(LPCWSTR path) {
    char p[PATH_MAX];
    return sys_path(path, NULL, p, 0) ? get_attrs(p) : INVALID_FILE_ATTRIBUTES;
}

DWORD GetFileAttributesA(LPCSTR path) {
    char p[PATH_MAX];
    return sys_path(NULL, path, p, 0) ? get_attrs(p) : INVALID_FILE_ATTRIBUTES;
}

static BOOL get_attrs_ex(const char *p, LPVOID out) {
    struct stat st;
    if (stat(p, &st)) {
        w32_set_errno();
        return FALSE;
    }
    WIN32_FILE_ATTRIBUTE_DATA *d = out;
    const char *name = strrchr(p, '/');
    d->dwFileAttributes = attrs_of(&st, name ? name + 1 : p);
    ft_from_ts(&st.st_mtim, &d->ftCreationTime);
    ft_from_ts(&st.st_atim, &d->ftLastAccessTime);
    ft_from_ts(&st.st_mtim, &d->ftLastWriteTime);
    d->nFileSizeHigh = (DWORD)((uint64_t)st.st_size >> 32);
    d->nFileSizeLow = (DWORD)st.st_size;
    return TRUE;
}

BOOL GetFileAttributesExW(LPCWSTR path, GET_FILEEX_INFO_LEVELS level, LPVOID out) {
    (void)level;
    char p[PATH_MAX];
    return sys_path(path, NULL, p, 0) && get_attrs_ex(p, out);
}

BOOL GetFileAttributesExA(LPCSTR path, GET_FILEEX_INFO_LEVELS level, LPVOID out) {
    (void)level;
    char p[PATH_MAX];
    return sys_path(NULL, path, p, 0) && get_attrs_ex(p, out);
}

static BOOL set_attrs(const char *p, DWORD a) {
    struct stat st;
    if (stat(p, &st)) {
        w32_set_errno();
        return FALSE;
    }
    mode_t m = st.st_mode & 07777;
    m = (a & FILE_ATTRIBUTE_READONLY) ? m & ~(mode_t)0222 : m | 0200;
    if (chmod(p, m)) {
        w32_set_errno();
        return FALSE;
    }
    return TRUE;
}

BOOL SetFileAttributesW(LPCWSTR path, DWORD a) {
    char p[PATH_MAX];
    return sys_path(path, NULL, p, 0) && set_attrs(p, a);
}

BOOL SetFileAttributesA(LPCSTR path, DWORD a) {
    char p[PATH_MAX];
    return sys_path(NULL, path, p, 0) && set_attrs(p, a);
}

static BOOL ret_errno(int r) {
    if (r) {
        w32_set_errno();
        return FALSE;
    }
    return TRUE;
}

BOOL CreateDirectoryW(LPCWSTR path, LPSECURITY_ATTRIBUTES sa) {
    (void)sa;
    char p[PATH_MAX];
    return sys_path(path, NULL, p, 1) && ret_errno(mkdir(p, 0777));
}

BOOL CreateDirectoryA(LPCSTR path, LPSECURITY_ATTRIBUTES sa) {
    (void)sa;
    char p[PATH_MAX];
    return sys_path(NULL, path, p, 1) && ret_errno(mkdir(p, 0777));
}

BOOL RemoveDirectoryW(LPCWSTR path) {
    char p[PATH_MAX];
    return sys_path(path, NULL, p, 0) && ret_errno(rmdir(p));
}

BOOL RemoveDirectoryA(LPCSTR path) {
    char p[PATH_MAX];
    return sys_path(NULL, path, p, 0) && ret_errno(rmdir(p));
}

// Windows refuses to delete a read-only file; unlink does not look at the mode, so check it here.
static BOOL delete_file(const char *p) {
    struct stat st;
    if (!stat(p, &st) && !(st.st_mode & 0222)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    return ret_errno(unlink(p));
}

BOOL DeleteFileW(LPCWSTR path) {
    char p[PATH_MAX];
    return sys_path(path, NULL, p, 0) && delete_file(p);
}

BOOL DeleteFileA(LPCSTR path) {
    char p[PATH_MAX];
    return sys_path(NULL, path, p, 0) && delete_file(p);
}

static int read_only_file(const char *p) {
    struct stat st;
    return !stat(p, &st) && S_ISREG(st.st_mode) && !(st.st_mode & 0222);
}

static BOOL move_file(const char *a, const char *b, DWORD flags) {
    if (read_only_file(b)) {   // Windows will not replace a read-only file; rename(2) would
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    if (!(flags & MOVEFILE_REPLACE_EXISTING)) {
        struct stat st;
        if (!lstat(b, &st)) {
            SetLastError(ERROR_ALREADY_EXISTS);
            return FALSE;
        }
    }
    if (rename(a, b)) {
        w32_set_errno();
        return FALSE;
    }
    if (flags & MOVEFILE_WRITE_THROUGH) {   // the rename reaches the disk: sync the directory
        char d[PATH_MAX];
        snprintf(d, sizeof d, "%s", b);
        char *s = strrchr(d, '/');
        if (s) *s = 0;
        else strcpy(d, ".");
        int fd = open(*d ? d : "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0) fsync(fd), close(fd);
    }
    return TRUE;
}

BOOL MoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags) {
    char a[PATH_MAX], b[PATH_MAX];
    return sys_path(from, NULL, a, 0) && sys_path(to, NULL, b, 1) && move_file(a, b, flags);
}

BOOL MoveFileExA(LPCSTR from, LPCSTR to, DWORD flags) {
    char a[PATH_MAX], b[PATH_MAX];
    return sys_path(NULL, from, a, 0) && sys_path(NULL, to, b, 1) && move_file(a, b, flags);
}

BOOL CopyFileW(LPCWSTR from, LPCWSTR to, BOOL fail_if_exists) {
    char a[PATH_MAX], b[PATH_MAX];
    if (!sys_path(from, NULL, a, 0) || !sys_path(to, NULL, b, 1)) return FALSE;
    int in = open(a, O_RDONLY | O_CLOEXEC);
    if (in < 0) return ret_errno(-1);
    int out = open(b, O_WRONLY | O_CREAT | O_CLOEXEC | (fail_if_exists ? O_EXCL : O_TRUNC), 0666);
    if (out < 0) {
        close(in);
        return ret_errno(-1);
    }
    char buf[1 << 16];
    ssize_t n;
    int ok = 1;
    while ((n = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, (size_t)n) != n) ok = 0;
    if (n < 0) ok = 0;
    close(in);
    close(out);
    return ok ? TRUE : ret_errno(-1);
}

BOOL CreateHardLinkW(LPCWSTR link_, LPCWSTR target, LPSECURITY_ATTRIBUTES sa) {
    (void)sa;
    char a[PATH_MAX], b[PATH_MAX];
    return sys_path(link_, NULL, a, 1) && sys_path(target, NULL, b, 0) && ret_errno(link(b, a));
}

static const char *tmp_dir(void) {
    const char *t = getenv("TMPDIR");
    return t && *t ? t : "/tmp";
}

DWORD GetTempPathA(DWORD cap, LPSTR out) {
    int n = snprintf(out, cap, "%s/", tmp_dir());
    if (n >= 0 && (DWORD)n < cap) w32_win_sep(out);
    return n < 0 || (DWORD)n >= cap ? (DWORD)n + 1 : (DWORD)n;
}

DWORD GetTempPathW(DWORD cap, LPWSTR out) {
    char a[PATH_MAX];
    int n = snprintf(a, sizeof a, "%s/", tmp_dir());
    size_t need = w32_utf8_to_wide(a, (size_t)n, NULL, 0);
    if (need + 1 > cap) return (DWORD)need + 1;
    out[w32_utf8_to_wide(a, (size_t)n, out, cap)] = 0;
    w32_win_sep_w(out);
    return (DWORD)need;
}

UINT GetTempFileNameA(LPCSTR dir, LPCSTR prefix, UINT unique, LPSTR out) {
    char d[PATH_MAX];
    if (!w32_path_a(dir, d, sizeof d)) return 0;
    size_t dl = strlen(d);
    while (dl > 1 && d[dl - 1] == '/') d[--dl] = 0;
    if (unique) {
        snprintf(out, MAX_PATH, "%s/%.3s%X.tmp", d, prefix, unique & 0xffff);
        return unique;
    }
    for (UINT u = (UINT)(w32_now_ns() & 0xffff) | 1, tries = 0; tries < 0x10000; tries++, u = (u + 1) & 0xffff) {
        if (!u) continue;
        snprintf(out, MAX_PATH, "%s/%.3s%X.tmp", d, prefix, u);
        int fd = open(out, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
        if (fd >= 0) {
            close(fd);
            return u;
        }
        if (errno != EEXIST) break;
    }
    w32_set_errno();
    return 0;
}

DWORD GetFullPathNameA(LPCSTR path, DWORD cap, LPSTR out, LPSTR *file) {
    char p[PATH_MAX], full[PATH_MAX];
    if (!w32_path_a(path, p, sizeof p)) return 0;
    if (p[0] == '/') snprintf(full, sizeof full, "%s", p);
    else {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof cwd)) return 0;
        snprintf(full, sizeof full, "%s/%s", cwd, p);
    }
    size_t n = strlen(full);
    if (n + 1 > cap) return (DWORD)n + 1;
    memcpy(out, full, n + 1);
    w32_win_sep(out);
    if (file) {
        char *s = strrchr(out, '\\');
        *file = s ? s + 1 : out;
    }
    return (DWORD)n;
}

DWORD GetFullPathNameW(LPCWSTR path, DWORD cap, LPWSTR out, LPWSTR *file) {
    char a[PATH_MAX], full[PATH_MAX];
    if (!w32_path_w(path, a, sizeof a) || !GetFullPathNameA(a, sizeof full, full, NULL)) return 0;
    size_t need = w32_utf8_to_wide(full, strlen(full), NULL, 0);
    if (need + 1 > cap) return (DWORD)need + 1;
    out[w32_utf8_to_wide(full, strlen(full), out, cap)] = 0;
    w32_win_sep_w(out);
    if (file) {
        wchar_t *s = wcsrchr(out, L'\\');
        *file = s ? s + 1 : out;
    }
    return (DWORD)need;
}

DWORD GetCurrentDirectoryA(DWORD cap, LPSTR out) {
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd)) return 0;
    size_t n = strlen(cwd);
    if (n + 1 > cap) return (DWORD)n + 1;
    memcpy(out, cwd, n + 1);
    w32_win_sep(out);
    return (DWORD)n;
}

// The runtime looks for fonts under <Windows>\Fonts; on Linux plat_font_path answers instead. A directory that does
// not exist keeps such lookups failing cleanly.
UINT GetWindowsDirectoryW(LPWSTR out, UINT cap) {
    const wchar_t *w = L"/nonexistent-windows";
    size_t n = wcslen(w);
    if (n + 1 > cap) return (UINT)n + 1;
    wcscpy(out, w);
    return (UINT)n;
}

// ---- directory searches

typedef struct {
    W32Obj o;
    DIR *d;
    char dir[PATH_MAX];
    char pat[NAME_MAX + 1];
    int dirs_only;
} W32Find;

static void find_destroy(W32Obj *o) {
    W32Find *f = (W32Find *)o;
    if (f->d) closedir(f->d);
}

// The next entry of f matching its pattern: name and stat. 0 when there are no more.
static int find_next(W32Find *f, char *name, struct stat *st) {
    for (struct dirent *de; (de = readdir(f->d));) {
        if (fnmatch(f->pat, de->d_name, FNM_CASEFOLD)) continue;
        char full[PATH_MAX * 2];
        snprintf(full, sizeof full, "%s/%s", f->dir, de->d_name);
        if (stat(full, st)) memset(st, 0, sizeof *st);
        if (f->dirs_only && !S_ISDIR(st->st_mode)) continue;
        snprintf(name, NAME_MAX + 1, "%s", de->d_name);
        return 1;
    }
    return 0;
}

static void fill_a(LPWIN32_FIND_DATAA fd, const char *name, const struct stat *st) {
    memset(fd, 0, sizeof *fd);
    fd->dwFileAttributes = attrs_of(st, name);
    ft_from_ts(&st->st_mtim, &fd->ftCreationTime);
    ft_from_ts(&st->st_atim, &fd->ftLastAccessTime);
    ft_from_ts(&st->st_mtim, &fd->ftLastWriteTime);
    fd->nFileSizeHigh = (DWORD)((uint64_t)st->st_size >> 32);
    fd->nFileSizeLow = (DWORD)st->st_size;
    snprintf(fd->cFileName, sizeof fd->cFileName, "%s", name);
}

static void fill_w(LPWIN32_FIND_DATAW fd, const char *name, const struct stat *st) {
    memset(fd, 0, sizeof *fd);
    fd->dwFileAttributes = attrs_of(st, name);
    ft_from_ts(&st->st_mtim, &fd->ftCreationTime);
    ft_from_ts(&st->st_atim, &fd->ftLastAccessTime);
    ft_from_ts(&st->st_mtim, &fd->ftLastWriteTime);
    fd->nFileSizeHigh = (DWORD)((uint64_t)st->st_size >> 32);
    fd->nFileSizeLow = (DWORD)st->st_size;
    fd->cFileName[w32_utf8_to_wide(name, strlen(name), fd->cFileName, MAX_PATH - 1)] = 0;
}

static W32Find *find_open(const char *pattern, int dirs_only) {
    W32Find *f = calloc(1, sizeof *f);
    if (!f) return NULL;
    f->o = (W32Obj){W32_FIND, 1, find_destroy};
    f->dirs_only = dirs_only;
    const char *s = strrchr(pattern, '/');
    if (s) {
        snprintf(f->dir, sizeof f->dir, "%.*s", (int)(s - pattern), pattern);
        if (!f->dir[0]) strcpy(f->dir, "/");
        snprintf(f->pat, sizeof f->pat, "%s", s + 1);
    } else {
        strcpy(f->dir, ".");
        snprintf(f->pat, sizeof f->pat, "%s", pattern);
    }
    if (!strcmp(f->pat, "*.*")) strcpy(f->pat, "*");   // matches names without a dot on Windows
    ci_resolve(f->dir, 0);
    f->d = opendir(f->dir);
    if (!f->d) {
        w32_set_errno();
        if (GetLastError() == ERROR_FILE_NOT_FOUND) SetLastError(ERROR_PATH_NOT_FOUND);
        free(f);
        return NULL;
    }
    return f;
}

static HANDLE find_first(const char *pattern, void *fd, int wide, int dirs_only) {
    W32Find *f = find_open(pattern, dirs_only);
    if (!f) return INVALID_HANDLE_VALUE;
    char name[NAME_MAX + 1];
    struct stat st;
    if (!find_next(f, name, &st)) {
        w32_obj_unref(&f->o);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    if (wide) fill_w(fd, name, &st);
    else fill_a(fd, name, &st);
    return f;
}

HANDLE FindFirstFileW(LPCWSTR pattern, LPWIN32_FIND_DATAW fd) {
    char p[PATH_MAX];
    if (!w32_path_w(pattern, p, sizeof p)) return INVALID_HANDLE_VALUE;
    return find_first(p, fd, 1, 0);
}

HANDLE FindFirstFileA(LPCSTR pattern, LPWIN32_FIND_DATAA fd) {
    char p[PATH_MAX];
    if (!w32_path_a(pattern, p, sizeof p)) return INVALID_HANDLE_VALUE;
    return find_first(p, fd, 0, 0);
}

HANDLE FindFirstFileExA(LPCSTR pattern, FINDEX_INFO_LEVELS lvl, LPVOID fd, FINDEX_SEARCH_OPS op, LPVOID filter,
                        DWORD flags) {
    (void)lvl, (void)filter, (void)flags;
    char p[PATH_MAX];
    if (!w32_path_a(pattern, p, sizeof p)) return INVALID_HANDLE_VALUE;
    // FindExSearchLimitToDirectories is only advisory on Windows; honouring it is allowed.
    return find_first(p, fd, 0, op == FindExSearchLimitToDirectories);
}

HANDLE FindFirstFileExW(LPCWSTR pattern, FINDEX_INFO_LEVELS lvl, LPVOID fd, FINDEX_SEARCH_OPS op, LPVOID filter,
                        DWORD flags) {
    (void)lvl, (void)filter, (void)flags;
    char p[PATH_MAX];
    if (!w32_path_w(pattern, p, sizeof p)) return INVALID_HANDLE_VALUE;
    return find_first(p, fd, 1, op == FindExSearchLimitToDirectories);
}

BOOL FindNextFileW(HANDLE h, LPWIN32_FIND_DATAW fd) {
    W32Find *f = (W32Find *)w32_obj(h, W32_FIND);
    char name[NAME_MAX + 1];
    struct stat st;
    if (!f) return FALSE;
    if (!find_next(f, name, &st)) {
        SetLastError(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    fill_w(fd, name, &st);
    return TRUE;
}

BOOL FindNextFileA(HANDLE h, LPWIN32_FIND_DATAA fd) {
    W32Find *f = (W32Find *)w32_obj(h, W32_FIND);
    char name[NAME_MAX + 1];
    struct stat st;
    if (!f) return FALSE;
    if (!find_next(f, name, &st)) {
        SetLastError(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    fill_a(fd, name, &st);
    return TRUE;
}

BOOL FindClose(HANDLE h) {
    W32Find *f = (W32Find *)w32_obj(h, W32_FIND);
    if (!f) return FALSE;
    w32_obj_unref(&f->o);
    return TRUE;
}

// ---- file mappings

typedef struct {
    W32Obj o;
    int fd;        // dup of the file's descriptor, or -1 for anonymous memory
    uint64_t size;
    int writable;
} W32Mapping;

static void mapping_destroy(W32Obj *o) {
    W32Mapping *m = (W32Mapping *)o;
    if (m->fd >= 0) close(m->fd);
}

HANDLE CreateFileMappingW(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD prot, DWORD size_hi, DWORD size_lo,
                          LPCWSTR name) {
    (void)sa, (void)name;
    W32Mapping *m = calloc(1, sizeof *m);
    if (!m) return NULL;
    m->o = (W32Obj){W32_MAPPING, 1, mapping_destroy};
    m->size = (uint64_t)size_hi << 32 | size_lo;
    m->writable = (prot & 0xff) == PAGE_READWRITE || (prot & 0xff) == PAGE_EXECUTE_READWRITE;
    m->fd = -1;
    if (file && file != INVALID_HANDLE_VALUE) {
        int fd = w32_handle_fd(file);
        if (fd < 0 || (m->fd = fcntl(fd, F_DUPFD_CLOEXEC, 3)) < 0) {
            free(m);
            SetLastError(ERROR_INVALID_HANDLE);
            return NULL;
        }
        struct stat st;
        if (!fstat(m->fd, &st)) {
            if (m->size > (uint64_t)st.st_size && m->writable) {
                if (ftruncate(m->fd, (off_t)m->size)) {
                    w32_set_errno();
                    close(m->fd);
                    free(m);
                    return NULL;
                }
            } else if (!m->size) m->size = (uint64_t)st.st_size;
        }
    } else {
        m->fd = memfd_create("w32-mapping", MFD_CLOEXEC);
        if (m->fd < 0 || ftruncate(m->fd, (off_t)m->size)) {
            w32_set_errno();
            if (m->fd >= 0) close(m->fd);
            free(m);
            return NULL;
        }
        m->writable = 1;
    }
    return m;
}

HANDLE CreateFileMappingA(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD prot, DWORD size_hi, DWORD size_lo,
                          LPCSTR name) {
    (void)name;
    return CreateFileMappingW(file, sa, prot, size_hi, size_lo, NULL);
}

// View sizes per address, for UnmapViewOfFile.
#define VIEWS 256
static struct { void *p; size_t n; } views[VIEWS];
static SRWLOCK views_lock = SRWLOCK_INIT;

LPVOID MapViewOfFile(HANDLE h, DWORD access, DWORD off_hi, DWORD off_lo, SIZE_T n) {
    W32Mapping *m = (W32Mapping *)w32_obj(h, W32_MAPPING);
    if (!m) return NULL;
    uint64_t off = (uint64_t)off_hi << 32 | off_lo;
    if (!n) n = (SIZE_T)(m->size - off);
    int prot = PROT_READ | ((access & FILE_MAP_WRITE) && m->writable ? PROT_WRITE : 0);   // ALL_ACCESS has the write bit
    int flags = (access & FILE_MAP_COPY) ? MAP_PRIVATE : MAP_SHARED;
    if (access & FILE_MAP_COPY) prot |= PROT_WRITE;
    void *p = mmap(NULL, n, prot, flags, m->fd, (off_t)off);
    if (p == MAP_FAILED) {
        w32_set_errno();
        return NULL;
    }
    AcquireSRWLockExclusive(&views_lock);
    for (int i = 0; i < VIEWS; i++)
        if (!views[i].p) {
            views[i].p = p, views[i].n = n;
            break;
        }
    ReleaseSRWLockExclusive(&views_lock);
    return p;
}

BOOL UnmapViewOfFile(LPCVOID p) {
    size_t n = 0;
    AcquireSRWLockExclusive(&views_lock);
    for (int i = 0; i < VIEWS; i++)
        if (views[i].p == p) {
            n = views[i].n;
            views[i].p = NULL;
            break;
        }
    ReleaseSRWLockExclusive(&views_lock);
    if (!n) {
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }
    return munmap((void *)p, n) == 0;
}

// ---- C runtime

char *_fullpath(char *out, const char *path, size_t cap) {
    char tmp[PATH_MAX];
    if (!GetFullPathNameA(path, sizeof tmp, tmp, NULL) || strlen(tmp) + 1 > cap) return NULL;
    strcpy(out, tmp);
    return out;
}

FILE *_wfopen(const wchar_t *path, const wchar_t *mode) {
    char p[PATH_MAX], m[16];
    int create = wcschr(mode, L'w') || wcschr(mode, L'a');
    if (!sys_path(path, NULL, p, create)) return NULL;
    m[w32_wide_to_utf8(mode, wcslen(mode), m, sizeof m - 1)] = 0;
    return (fopen)(p, m);
}

FILE *w32_fopen(const char *path, const char *mode) {
    char p[PATH_MAX];
    int create = strchr(mode, 'w') || strchr(mode, 'a');
    if (!sys_path(NULL, path, p, create)) return NULL;
    return (fopen)(p, mode);
}

int w32_remove(const char *path) {
    char p[PATH_MAX];
    if (!sys_path(NULL, path, p, 0)) return -1;
    return (remove)(p);
}

void w32_win_sep(char *p) {
    for (; *p; p++)
        if (*p == '/') *p = '\\';
}

void w32_win_sep_w(wchar_t *p) {
    for (; *p; p++)
        if (*p == L'/') *p = L'\\';
}
