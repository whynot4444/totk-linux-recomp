// Linux Win32 stand-in, part 4: modules and libraries, the command line and environment, child processes and pipes,
// locale, debugger output, SHA-256 and random numbers (bcrypt.h), and the few window-system calls non-window files make.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include <dirent.h>

#include "bcrypt.h"
#include "tlhelp32.h"
#include "w32_internal.h"

extern char **environ;

// ---- modules

static int exe_range(uintptr_t *base, uintptr_t *size) {
    static uintptr_t b, s;
    if (!b) {
        Dl_info di;
        if (!dladdr((void *)exe_range, &di) || !di.dli_fbase) return 0;
        uintptr_t lo = (uintptr_t)di.dli_fbase, hi = lo;
        // The executable's PT_LOAD segments: the image ends at the last one
        const ElfW(Ehdr) *eh = di.dli_fbase;
        const ElfW(Phdr) *ph = (const ElfW(Phdr) *)((const char *)eh + eh->e_phoff);
        uintptr_t bias = eh->e_type == ET_DYN ? lo : 0;
        for (int i = 0; i < eh->e_phnum; i++)
            if (ph[i].p_type == PT_LOAD && bias + ph[i].p_vaddr + ph[i].p_memsz > hi)
                hi = bias + ph[i].p_vaddr + ph[i].p_memsz;
        s = hi - lo;
        b = lo;
    }
    *base = b, *size = s;
    return 1;
}

HMODULE GetModuleHandleW(LPCWSTR name) {
    if (!name) {
        uintptr_t b, s;
        return exe_range(&b, &s) ? (HMODULE)b : NULL;
    }
    char n[PATH_MAX];
    if (!w32_path_w(name, n, sizeof n)) return NULL;
    return GetModuleHandleA(n);
}

HMODULE GetModuleHandleA(LPCSTR name) {
    if (!name) return GetModuleHandleW(NULL);
    void *h = dlopen(name, RTLD_NOW | RTLD_NOLOAD);
    if (h) dlclose(h);
    return h;
}

BOOL GetModuleHandleExW(DWORD flags, LPCWSTR name, HMODULE *out) {
    *out = NULL;
    if (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) {
        Dl_info di;
        if (!dladdr((const void *)name, &di) || !di.dli_fbase) return FALSE;
        *out = di.dli_fbase;
        return TRUE;
    }
    *out = GetModuleHandleW(name);
    return *out != NULL;
}

// The file of module m: the executable for NULL or its base, else the library loaded at m.
static int module_path(HMODULE m, char *out, size_t cap) {
    uintptr_t b, s;
    if (!m || (exe_range(&b, &s) && (uintptr_t)m == b)) {
        ssize_t n = readlink("/proc/self/exe", out, cap - 1);
        if (n <= 0) return 0;
        out[n] = 0;
    } else {
        Dl_info di;
        if (!dladdr(m, &di) || !di.dli_fname) return 0;
        snprintf(out, cap, "%s", di.dli_fname);
    }
    w32_win_sep(out);   // as Windows gives it: the runtime cuts the folder off at the last '\\'
    return 1;
}

DWORD GetModuleFileNameA(HMODULE m, LPSTR out, DWORD cap) {
    char p[PATH_MAX];
    if (!cap || !module_path(m, p, sizeof p)) return 0;
    size_t n = strlen(p);
    if (n >= cap) {
        memcpy(out, p, cap - 1);
        out[cap - 1] = 0;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return cap;
    }
    memcpy(out, p, n + 1);
    return (DWORD)n;
}

DWORD GetModuleFileNameW(HMODULE m, LPWSTR out, DWORD cap) {
    char p[PATH_MAX];
    if (!cap || !module_path(m, p, sizeof p)) return 0;
    size_t n = w32_utf8_to_wide(p, strlen(p), out, cap - 1);
    out[n] = 0;
    if (n >= cap - 1 && w32_utf8_to_wide(p, strlen(p), NULL, 0) >= cap) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return cap;
    }
    return (DWORD)n;
}

BOOL GetModuleInformation(HANDLE p, HMODULE m, LPMODULEINFO mi, DWORD n) {
    (void)p, (void)n;
    uintptr_t b, s;
    if (!exe_range(&b, &s)) return FALSE;
    if (!m || (uintptr_t)m == b) {
        mi->lpBaseOfDll = (void *)b;
        mi->SizeOfImage = (DWORD)s;
        mi->EntryPoint = NULL;
        return TRUE;
    }
    Dl_info di;
    if (!dladdr(m, &di)) return FALSE;
    mi->lpBaseOfDll = di.dli_fbase;
    mi->SizeOfImage = 0;
    mi->EntryPoint = NULL;
    return TRUE;
}

BOOL EnumProcessModules(HANDLE p, HMODULE *mods, DWORD cap, LPDWORD need) {
    (void)p;
    *need = sizeof(HMODULE);
    if (cap >= sizeof(HMODULE)) mods[0] = GetModuleHandleW(NULL);
    return TRUE;
}

BOOL GetProcessMemoryInfo(HANDLE p, PPROCESS_MEMORY_COUNTERS c, DWORD n) {
    (void)p;
    memset(c, 0, n < sizeof *c ? n : sizeof *c);
    FILE *f = fopen("/proc/self/statm", "r");
    if (!f) return FALSE;
    unsigned long long size = 0, res = 0;
    int k = fscanf(f, "%llu %llu", &size, &res);
    fclose(f);
    if (k != 2) return FALSE;
    long pg = sysconf(_SC_PAGESIZE);
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    c->cb = n;
    c->WorkingSetSize = (SIZE_T)(res * (unsigned long long)pg);
    c->PeakWorkingSetSize = (SIZE_T)ru.ru_maxrss * 1024u;
    c->PagefileUsage = c->PrivateUsage = c->WorkingSetSize;
    c->PageFaultCount = (DWORD)(ru.ru_minflt + ru.ru_majflt);
    return TRUE;
}

// "foo.dll" names: the Linux library of the same stem is tried too ("libfoo.so").
HMODULE LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags) {
    (void)file, (void)flags;
    char p[PATH_MAX];
    if (!w32_path_a(name, p, sizeof p)) return NULL;
    void *h = dlopen(p, RTLD_NOW | RTLD_LOCAL);
    size_t n = strlen(p);
    if (!h && n > 4 && !strcasecmp(p + n - 4, ".dll")) {
        char q[PATH_MAX];
        const char *base = strrchr(p, '/') ? strrchr(p, '/') + 1 : p;
        snprintf(q, sizeof q, "lib%.*s.so", (int)(strlen(base) - 4), base);
        h = dlopen(q, RTLD_NOW | RTLD_LOCAL);
    }
    if (!h) SetLastError(ERROR_FILE_NOT_FOUND);
    return h;
}

HMODULE LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags) {
    char p[PATH_MAX];
    if (!w32_path_w(name, p, sizeof p)) return NULL;
    return LoadLibraryExA(p, file, flags);
}

HMODULE LoadLibraryA(LPCSTR name) { return LoadLibraryExA(name, NULL, 0); }
HMODULE LoadLibraryW(LPCWSTR name) { return LoadLibraryExW(name, NULL, 0); }
BOOL FreeLibrary(HMODULE m) { return m && !dlclose(m); }

FARPROC GetProcAddress(HMODULE m, LPCSTR name) {
    if (!m) return NULL;
    uintptr_t b, s;
    void *h = m;
    if (exe_range(&b, &s) && (uintptr_t)m == b) h = RTLD_DEFAULT;
    return (FARPROC)dlsym(h, name);
}

// ---- command line and environment

// Quotes one argument the way CommandLineToArgvW reads it back.
static size_t quote_arg(const char *a, char *out, size_t cap) {
    size_t k = 0;
#define PUT(c) do { if (k + 1 < cap) out[k] = (c); k++; } while (0)
    int need = !*a || strpbrk(a, " \t\"") != NULL;
    if (!need) {
        for (const char *p = a; *p; p++) PUT(*p);
    } else {
        PUT('"');
        for (const char *p = a;; p++) {
            size_t bs = 0;
            while (*p == '\\') bs++, p++;
            if (!*p) {
                for (size_t i = 0; i < bs * 2; i++) PUT('\\');
                break;
            }
            if (*p == '"') {
                for (size_t i = 0; i < bs * 2 + 1; i++) PUT('\\');
            } else
                for (size_t i = 0; i < bs; i++) PUT('\\');
            PUT(*p);
        }
        PUT('"');
    }
#undef PUT
    if (cap) out[k < cap ? k : cap - 1] = 0;
    return k;
}

static char *cmdline_a;
static wchar_t *cmdline_w;

LPSTR GetCommandLineA(void) {
    if (cmdline_a) return cmdline_a;
    FILE *f = fopen("/proc/self/cmdline", "rb");
    char raw[32768];
    size_t n = f ? fread(raw, 1, sizeof raw - 1, f) : 0;
    if (f) fclose(f);
    raw[n] = 0;
    size_t cap = n * 3 + 64, k = 0;
    char *out = malloc(cap);
    if (!out) return (char *)"";
    for (size_t i = 0; i < n;) {
        if (k) out[k++] = ' ';
        k += quote_arg(raw + i, out + k, cap - k);
        if (k >= cap) k = cap - 1;
        i += strlen(raw + i) + 1;
    }
    out[k] = 0;
    cmdline_a = out;
    return out;
}

LPWSTR GetCommandLineW(void) {
    if (cmdline_w) return cmdline_w;
    const char *a = GetCommandLineA();
    size_t n = strlen(a), need = w32_utf8_to_wide(a, n, NULL, 0);
    wchar_t *w = malloc((need + 1) * sizeof *w);
    if (!w) return (wchar_t *)L"";
    w[w32_utf8_to_wide(a, n, w, need)] = 0;
    cmdline_w = w;
    return w;
}

// Splits a Windows command line (CommandLineToArgvW rules) into a NULL-terminated, malloc'd argv.
static char **split_cmdline(const char *s) {
    size_t cap = 8, n = 0;
    char **argv = malloc(cap * sizeof *argv);
    char *buf = malloc(strlen(s) + 1);
    if (!argv || !buf) return NULL;
    while (*s) {
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) break;
        size_t k = 0;
        int inq = 0;
        while (*s && (inq || (*s != ' ' && *s != '\t'))) {
            if (*s == '\\') {   // backslashes count only before a quote
                size_t bs = 0;
                while (*s == '\\') bs++, s++;
                if (*s == '"') {
                    for (size_t i = 0; i < bs / 2; i++) buf[k++] = '\\';
                    if (bs % 2) buf[k++] = '"', s++;   // an escaped quote; an even count leaves the quote to toggle
                } else
                    for (size_t i = 0; i < bs; i++) buf[k++] = '\\';
            } else if (*s == '"') {
                if (inq && s[1] == '"') buf[k++] = '"', s += 2;
                else inq = !inq, s++;
            } else
                buf[k++] = *s++;
        }
        buf[k] = 0;
        if (n + 2 > cap) {
            cap *= 2;
            char **g = realloc(argv, cap * sizeof *argv);
            if (!g) return NULL;
            argv = g;
        }
        argv[n++] = strdup(buf);
    }
    argv[n] = NULL;
    free(buf);
    return argv;
}

DWORD GetEnvironmentVariableA(LPCSTR name, LPSTR out, DWORD cap) {
    const char *v = getenv(name);
    if (!v) {
        SetLastError(203);   // ERROR_ENVVAR_NOT_FOUND
        return 0;
    }
    size_t n = strlen(v);
    if (n + 1 > cap) return (DWORD)n + 1;
    memcpy(out, v, n + 1);
    return (DWORD)n;
}

DWORD GetEnvironmentVariableW(LPCWSTR name, LPWSTR out, DWORD cap) {
    char n[256];
    size_t k = w32_wide_to_utf8(name, wcslen(name), n, sizeof n - 1);
    n[k] = 0;
    const char *v = getenv(n);
    if (!v) {
        SetLastError(203);
        return 0;
    }
    size_t need = w32_utf8_to_wide(v, strlen(v), NULL, 0);
    if (need + 1 > cap) return (DWORD)need + 1;
    out[w32_utf8_to_wide(v, strlen(v), out, cap - 1)] = 0;
    return (DWORD)need;
}

BOOL SetEnvironmentVariableA(LPCSTR name, LPCSTR value) {
    return (value ? setenv(name, value, 1) : unsetenv(name)) == 0;
}

BOOL SetEnvironmentVariableW(LPCWSTR name, LPCWSTR value) {
    char n[256], v[32768];
    n[w32_wide_to_utf8(name, wcslen(name), n, sizeof n - 1)] = 0;
    if (!value) return unsetenv(n) == 0;
    v[w32_wide_to_utf8(value, wcslen(value), v, sizeof v - 1)] = 0;
    return setenv(n, v, 1) == 0;
}

// ---- child processes

typedef struct {
    W32Obj o;
    volatile uint32_t seq;
    pid_t pid;
    int exited;
    DWORD code;
} W32Process;

int w32_process_poll(HANDLE h, int consume) {
    (void)consume;
    W32Process *p = h;
    if (!p || p->o.magic != W32_PROCESS) return -1;
    if (p->exited) return 1;
    int st;
    pid_t r = waitpid(p->pid, &st, WNOHANG);
    if (r == p->pid) {
        p->exited = 1;
        p->code = WIFEXITED(st) ? (DWORD)WEXITSTATUS(st) : WIFSIGNALED(st) ? 0xC0000000u | (DWORD)WTERMSIG(st) : 1;
        return 1;
    }
    if (r < 0 && errno == ECHILD) {
        p->exited = 1;
        return 1;
    }
    return 0;
}

volatile uint32_t *w32_process_seq(HANDLE h) { return &((W32Process *)h)->seq; }

BOOL GetExitCodeProcess(HANDLE h, LPDWORD code) {
    W32Process *p = (W32Process *)w32_obj(h, W32_PROCESS);
    if (!p) return FALSE;
    pthread_mutex_lock(&w32_wait_lock);
    int done = w32_process_poll(h, 0) > 0;
    pthread_mutex_unlock(&w32_wait_lock);
    *code = done ? p->code : STILL_ACTIVE;
    return TRUE;
}

BOOL TerminateProcess(HANDLE h, UINT code) {
    if (h == (HANDLE)(intptr_t)-1) {
        fflush(NULL);
        _exit((int)code);
    }
    W32Process *p = (W32Process *)w32_obj(h, W32_PROCESS);
    if (!p) return FALSE;
    if (!p->exited) kill(p->pid, SIGKILL);
    return TRUE;
}

void ExitProcess(UINT code) {
    fflush(NULL);
    _exit((int)code);
}

BOOL CreatePipe(HANDLE *rd, HANDLE *wr, LPSECURITY_ATTRIBUTES sa, DWORD size) {
    (void)sa, (void)size;
    int fds[2];
    if (pipe2(fds, O_CLOEXEC)) {
        w32_set_errno();
        return FALSE;
    }
    *rd = w32_fd_handle(fds[0], 1);
    *wr = w32_fd_handle(fds[1], 1);
    return TRUE;
}

BOOL CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
                    DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    (void)pa, (void)ta, (void)inherit, (void)flags, (void)env;
    size_t n = cmd ? wcslen(cmd) : 0;
    char *line = malloc(n * 4 + 1);
    if (!line) return FALSE;
    line[w32_wide_to_utf8(cmd ? cmd : L"", n, line, n * 4)] = 0;
    char **argv = split_cmdline(line);
    free(line);
    if (!argv || !argv[0]) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    char prog[PATH_MAX];
    if (app) w32_path_w(app, prog, sizeof prog);
    else w32_path_a(argv[0], prog, sizeof prog);
    // "x.exe" that does not exist: the Linux build of the same program has no suffix
    size_t pl = strlen(prog);
    if (pl > 4 && !strcasecmp(prog + pl - 4, ".exe") && access(prog, X_OK)) prog[pl - 4] = 0;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (si && (si->dwFlags & STARTF_USESTDHANDLES)) {
        HANDLE hs[3] = {si->hStdInput, si->hStdOutput, si->hStdError};
        for (int i = 0; i < 3; i++) {
            int fd = w32_handle_fd(hs[i]);
            if (fd >= 0) posix_spawn_file_actions_adddup2(&fa, fd, i);   // dup2 clears close-on-exec on the copy
        }
    }
    if (dir) {
        char d[PATH_MAX];
        if (w32_path_w(dir, d, sizeof d)) posix_spawn_file_actions_addchdir_np(&fa, d);
    }
    pid_t pid;
    int e = posix_spawn(&pid, prog, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    for (char **a = argv; *a; a++) free(*a);
    free(argv);
    if (e) {
        SetLastError(w32_errno_to_win(e));
        return FALSE;
    }
    W32Process *p = calloc(1, sizeof *p);
    if (!p) return FALSE;
    p->o = (W32Obj){W32_PROCESS, 1, NULL};
    p->pid = pid;
    pi->hProcess = p;
    pi->hThread = CreateEventW(NULL, TRUE, FALSE, NULL);   // something CloseHandle accepts
    pi->dwProcessId = (DWORD)pid;
    pi->dwThreadId = (DWORD)pid;
    return TRUE;
}

// ---- debugger

void OutputDebugStringA(LPCSTR s) {
    static int on = -1;
    if (on < 0) on = getenv("TOTK_DEBUG_OUTPUT") != NULL;   // Windows sends these to a debugger only
    if (on) fputs(s, stderr);
}

void OutputDebugStringW(LPCWSTR s) {
    char b[4096];
    b[w32_wide_to_utf8(s, wcslen(s), b, sizeof b - 1)] = 0;
    OutputDebugStringA(b);
}

BOOL IsDebuggerPresent(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[128];
    int pid = 0;
    while (f && fgets(line, sizeof line, f))
        if (sscanf(line, "TracerPid: %d", &pid) == 1) break;
    if (f) fclose(f);
    return pid != 0;
}

void DebugBreak(void) { raise(SIGTRAP); }

// ---- locale: LANG / LC_ALL / LC_MESSAGES as a BCP-47 tag

static const char *locale_tag(void) {
    static char tag[LOCALE_NAME_MAX_LENGTH];
    if (tag[0]) return tag;
    const char *v = getenv("LC_ALL");
    if (!v || !*v) v = getenv("LC_MESSAGES");
    if (!v || !*v) v = getenv("LANG");
    if (!v || !*v || !strcmp(v, "C") || !strcmp(v, "POSIX")) v = "en_US";
    size_t k = 0;
    for (; v[k] && v[k] != '.' && v[k] != '@' && k + 1 < sizeof tag; k++) tag[k] = v[k] == '_' ? '-' : v[k];
    tag[k] = 0;
    return tag;
}

LANGID GetUserDefaultUILanguage(void) { return 0x0409; }   // the tag is what callers convert it to

int LCIDToLocaleName(LCID lcid, LPWSTR out, int cap, DWORD flags) {
    (void)lcid, (void)flags;
    const char *t = locale_tag();
    size_t n = strlen(t);
    if ((int)n + 1 > cap) return 0;
    out[w32_utf8_to_wide(t, n, out, (size_t)cap - 1)] = 0;
    return (int)n + 1;
}

int GetUserDefaultLocaleName(LPWSTR out, int cap) { return LCIDToLocaleName(0, out, cap, 0); }

// ---- window-system calls made outside the window code

HWND (*w32_foreground_hook)(void);
SHORT (*w32_keystate_hook)(int vk);
HWND GetForegroundWindow(void) { return w32_foreground_hook ? w32_foreground_hook() : NULL; }
SHORT GetAsyncKeyState(int vk) { return w32_keystate_hook ? w32_keystate_hook(vk) : 0; }

int MessageBoxA(HWND w, LPCSTR text, LPCSTR caption, UINT type) {
    (void)w, (void)type;
    fprintf(stderr, "%s: %s\n", caption ? caption : "TotK", text ? text : "");
    return IDYES;
}

int MessageBoxW(HWND w, LPCWSTR text, LPCWSTR caption, UINT type) {
    char t[4096], c[256];
    t[w32_wide_to_utf8(text ? text : L"", text ? wcslen(text) : 0, t, sizeof t - 1)] = 0;
    c[w32_wide_to_utf8(caption ? caption : L"", caption ? wcslen(caption) : 0, c, sizeof c - 1)] = 0;
    return MessageBoxA(w, t, c, type);
}

// ---- SHA-256 (FIPS 180-4) and random numbers

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t n;
} Sha256;

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2};

#define ROR(x, n) ((x) >> (n) | (x) << (32 - (n)))

static void sha_block(Sha256 *s, const uint8_t *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g, g = f, f = e, e = d + t1, d = c, c = b, b = a, a = t1 + t2;
    }
    s->h[0] += a, s->h[1] += b, s->h[2] += c, s->h[3] += d, s->h[4] += e, s->h[5] += f, s->h[6] += g, s->h[7] += h;
}

static void sha_init(Sha256 *s) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    memcpy(s->h, iv, sizeof iv);
    s->len = 0;
    s->n = 0;
}

static void sha_update(Sha256 *s, const uint8_t *p, size_t n) {
    s->len += n;
    if (s->n) {
        size_t k = 64 - s->n < n ? 64 - s->n : n;
        memcpy(s->buf + s->n, p, k);
        s->n += k, p += k, n -= k;
        if (s->n < 64) return;   // the buffer took all of it
        sha_block(s, s->buf);
        s->n = 0;
    }
    for (; n >= 64; p += 64, n -= 64) sha_block(s, p);
    memcpy(s->buf, p, n);
    s->n = n;
}

static void sha_final(Sha256 *s, uint8_t out[32]) {
    uint64_t bits = s->len * 8;
    uint8_t pad = 0x80, z = 0;
    sha_update(s, &pad, 1);
    while (s->n != 56) sha_update(s, &z, 1);
    uint8_t l[8];
    for (int i = 0; i < 8; i++) l[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(s, l, 8);
    for (int i = 0; i < 8; i++)
        out[4 * i] = (uint8_t)(s->h[i] >> 24), out[4 * i + 1] = (uint8_t)(s->h[i] >> 16),
        out[4 * i + 2] = (uint8_t)(s->h[i] >> 8), out[4 * i + 3] = (uint8_t)s->h[i];
}

NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *alg, LPCWSTR id, LPCWSTR impl, ULONG flags) {
    (void)impl, (void)flags;
    if (wcscmp(id, BCRYPT_SHA256_ALGORITHM)) return (NTSTATUS)0xC00000BB;   // STATUS_NOT_SUPPORTED
    *alg = (void *)1;
    return 0;
}

NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE alg, ULONG flags) {
    (void)alg, (void)flags;
    return 0;
}

NTSTATUS BCryptCreateHash(BCRYPT_ALG_HANDLE alg, BCRYPT_HASH_HANDLE *h, PUCHAR obj, ULONG objn, PUCHAR secret,
                          ULONG secretn, ULONG flags) {
    (void)alg, (void)obj, (void)objn, (void)secret, (void)secretn, (void)flags;
    Sha256 *s = malloc(sizeof *s);
    if (!s) return (NTSTATUS)0xC0000017;   // STATUS_NO_MEMORY
    sha_init(s);
    *h = s;
    return 0;
}

NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE h, PUCHAR p, ULONG n, ULONG flags) {
    (void)flags;
    sha_update(h, p, n);
    return 0;
}

NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE h, PUCHAR out, ULONG n, ULONG flags) {
    (void)flags;
    if (n != 32) return (NTSTATUS)0xC000000D;   // STATUS_INVALID_PARAMETER
    sha_final(h, out);
    return 0;
}

NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE h) {
    free(h);
    return 0;
}

NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE alg, PUCHAR out, ULONG n, ULONG flags) {
    (void)alg, (void)flags;
    for (ULONG done = 0; done < n;) {
        ssize_t k = getrandom(out + done, n - done, 0);
        if (k < 0) {
            if (errno == EINTR) continue;
            return (NTSTATUS)0xC0000001;
        }
        done += (ULONG)k;
    }
    return 0;
}

// ---- thread snapshots: the thread ids of /proc/self/task, taken at the call. The snapshot is a file handle-free
// object; it is freed by CloseHandle like any other.

typedef struct {
    W32Obj o;
    int n, next;
    DWORD tids[];
} W32Snap;

HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD pid) {
    if (!(flags & TH32CS_SNAPTHREAD) || (pid && pid != (DWORD)getpid())) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return INVALID_HANDLE_VALUE;
    }
    DIR *d = opendir("/proc/self/task");
    if (!d) return INVALID_HANDLE_VALUE;
    int cap = 256, n = 0;
    W32Snap *s = calloc(1, sizeof *s + (size_t)cap * sizeof(DWORD));
    for (struct dirent *de; s && (de = readdir(d));) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        if (n == cap) {
            cap *= 2;
            W32Snap *g = realloc(s, sizeof *s + (size_t)cap * sizeof(DWORD));
            if (!g) break;
            s = g;
        }
        s->tids[n++] = (DWORD)atoi(de->d_name);
    }
    closedir(d);
    if (!s) return INVALID_HANDLE_VALUE;
    s->o = (W32Obj){W32_FIND, 1, NULL};   // a kind CloseHandle frees; never handed to FindNextFile
    s->n = n;
    return s;
}

static BOOL snap_entry(HANDLE h, LPTHREADENTRY32 te) {
    W32Snap *s = h;
    if (!s || h == INVALID_HANDLE_VALUE || s->next >= s->n) {
        SetLastError(ERROR_NO_MORE_FILES);
        return FALSE;
    }
    te->th32ThreadID = s->tids[s->next++];
    te->th32OwnerProcessID = (DWORD)getpid();
    te->cntUsage = 0;
    te->tpBasePri = 8;
    te->tpDeltaPri = 0;
    te->dwFlags = 0;
    return TRUE;
}

BOOL Thread32First(HANDLE h, LPTHREADENTRY32 te) {
    ((W32Snap *)h)->next = 0;
    return snap_entry(h, te);
}

BOOL Thread32Next(HANDLE h, LPTHREADENTRY32 te) { return snap_entry(h, te); }

// ---- processor cores: logical processors that share a (package, core) pair form one core

BOOL GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP rel, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX buf,
                                      PDWORD len) {
    if (rel != RelationProcessorCore) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    KAFFINITY masks[64] = {0};
    long keys[64];
    int ncores = 0;
    for (int cpu = 0; cpu < 64; cpu++) {
        char p[96];
        long pkg = 0, core = -1;
        FILE *f;
        snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/topology/core_id", cpu);
        if (!(f = fopen(p, "r"))) continue;
        if (fscanf(f, "%ld", &core) != 1) core = cpu;
        fclose(f);
        snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
        if ((f = fopen(p, "r"))) {
            if (fscanf(f, "%ld", &pkg) != 1) pkg = 0;
            fclose(f);
        }
        long key = pkg << 20 | core;
        int k = 0;
        while (k < ncores && keys[k] != key) k++;
        if (k == ncores) keys[ncores++] = key;
        masks[k] |= (KAFFINITY)1 << cpu;
    }
    DWORD need = (DWORD)ncores * (DWORD)sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX);
    if (!buf || *len < need) {
        *len = need;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    memset(buf, 0, need);
    for (int k = 0; k < ncores; k++) {
        buf[k].Relationship = RelationProcessorCore;
        buf[k].Size = sizeof *buf;
        buf[k].Processor.Flags = __builtin_popcountll(masks[k]) > 1;   // LTP_PC_SMT
        buf[k].Processor.GroupCount = 1;
        buf[k].Processor.GroupMask[0].Mask = masks[k];
    }
    *len = need;
    return TRUE;
}
