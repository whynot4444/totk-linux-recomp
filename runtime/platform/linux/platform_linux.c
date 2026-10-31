// Linux implementation of platform.h. Locks and condition variables are the futex ones of the Win32 stand-in
// (win32_sync.c): one word each, zero-initialised storage valid, as platform.h requires.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

#include "../platform.h"
#include "w32_internal.h"

_Static_assert(sizeof(PlatMutex) == sizeof(SRWLOCK), "PlatMutex holds an SRWLOCK");
_Static_assert(sizeof(PlatCond) == sizeof(CONDITION_VARIABLE), "PlatCond holds a CONDITION_VARIABLE");

extern char **environ;

// The main thread's stack grows up to RLIMIT_STACK, checked at each growth: raise it to the 16 MiB totk.exe is linked
// with on Windows (lifted code recurses on the host stack). The kernel leaves at least 128 MiB below the stack.
#include <sys/resource.h>
__attribute__((constructor)) static void main_stack_16mib(void) {
    struct rlimit r;
    if (!getrlimit(RLIMIT_STACK, &r) && r.rlim_cur != RLIM_INFINITY && r.rlim_cur < (16u << 20)) {
        r.rlim_cur = r.rlim_max == RLIM_INFINITY || r.rlim_max >= (16u << 20) ? (16u << 20) : r.rlim_max;
        setrlimit(RLIMIT_STACK, &r);
    }
}

// ---- threads

struct PlatThread {
    pthread_t t;
    PlatThreadFn fn;
    void *arg;
    char name[16];
};

static void *thread_main(void *p) {
    PlatThread *t = p;
    if (t->name[0]) pthread_setname_np(pthread_self(), t->name);
    w32_thread_install_altstack();
    t->fn(t->arg);
    return NULL;
}

PlatThread *plat_thread_new(PlatThreadFn fn, void *arg, const char *name) {
    PlatThread *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->fn = fn;
    t->arg = arg;
    if (name) snprintf(t->name, sizeof t->name, "%s", name);   // Linux keeps 15 bytes
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setstacksize(&a, 16u << 20);   // as CreateThread here: lifted code recurses on the host stack
    int e = pthread_create(&t->t, &a, thread_main, t);
    pthread_attr_destroy(&a);
    if (e) {
        free(t);
        return NULL;
    }
    return t;
}

void plat_thread_join(PlatThread *t) {
    pthread_join(t->t, NULL);
    free(t);
}

// The thread keeps using t->fn and t->arg, so the struct stays allocated (a few bytes per detached thread).
void plat_thread_detach(PlatThread *t) { pthread_detach(t->t); }

uint64_t plat_thread_affinity(PlatThread *t, uint64_t mask) {
    pthread_t th = t ? t->t : pthread_self();
    cpu_set_t old, set;
    if (pthread_getaffinity_np(th, sizeof old, &old)) return 0;
    CPU_ZERO(&set);
    for (int i = 0; i < 64; i++)
        if (mask >> i & 1) CPU_SET(i, &set);
    if (pthread_setaffinity_np(th, sizeof set, &set)) return 0;
    uint64_t prev = 0;
    for (int i = 0; i < 64; i++)
        if (CPU_ISSET(i, &old)) prev |= 1ull << i;
    return prev ? prev : 1;
}

uint32_t plat_cpu_count(void) {
    cpu_set_t set;
    if (!sched_getaffinity(0, sizeof set, &set) && CPU_COUNT(&set) > 0) return (uint32_t)CPU_COUNT(&set);
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (uint32_t)n : 1;
}

// ---- time

uint64_t plat_now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

// clock_nanosleep on an absolute deadline wakes within tens of microseconds on current kernels; the last
// PLAT_SPIN_NS are spent yielding so the deadline is met closely, as on Windows.
#define PLAT_SPIN_NS 100000u

void plat_sleep_ns(uint64_t ns) {
    uint64_t end = plat_now_ns() + ns;
    if (ns > PLAT_SPIN_NS) {
        uint64_t at = end - PLAT_SPIN_NS;
        struct timespec ts = {(time_t)(at / 1000000000u), (long)(at % 1000000000u)};
        while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) == EINTR) {}
    }
    while (plat_now_ns() < end) sched_yield();
}

// ---- locks and condition variables

void plat_mutex_init(PlatMutex *m) { InitializeSRWLock((PSRWLOCK)m); }
void plat_mutex_lock(PlatMutex *m) { AcquireSRWLockExclusive((PSRWLOCK)m); }
int plat_mutex_trylock(PlatMutex *m) { return TryAcquireSRWLockExclusive((PSRWLOCK)m) != 0; }
void plat_mutex_unlock(PlatMutex *m) { ReleaseSRWLockExclusive((PSRWLOCK)m); }

void plat_cond_init(PlatCond *c) { InitializeConditionVariable((PCONDITION_VARIABLE)c); }
void plat_cond_wait(PlatCond *c, PlatMutex *m) {
    SleepConditionVariableSRW((PCONDITION_VARIABLE)c, (PSRWLOCK)m, INFINITE, 0);
}

int plat_cond_wait_ns(PlatCond *c, PlatMutex *m, uint64_t ns) {
    uint64_t ms = (ns + 999999) / 1000000;
    DWORD to = ms >= INFINITE ? INFINITE - 1 : (DWORD)ms;
    return SleepConditionVariableSRW((PCONDITION_VARIABLE)c, (PSRWLOCK)m, to, 0) ? 1 : GetLastError() != ERROR_TIMEOUT;
}

void plat_cond_signal(PlatCond *c) { WakeConditionVariable((PCONDITION_VARIABLE)c); }
void plat_cond_broadcast(PlatCond *c) { WakeAllConditionVariable((PCONDITION_VARIABLE)c); }

// ---- files

static char *sys(const char *path, char *out) { return w32_sys_path(path, out, 1); }

int plat_file_exists(const char *path) {
    char p[PATH_MAX];
    struct stat st;
    return sys(path, p) && !stat(p, &st) && !S_ISDIR(st.st_mode);
}

void plat_file_mkdir_p(const char *path) {
    char p[PATH_MAX];
    if (!sys(path, p)) return;
    for (char *c = p + 1; *c; c++)
        if (*c == '/') {
            *c = 0;
            mkdir(p, 0777);
            *c = '/';
        }
    mkdir(p, 0777);
}

uint8_t *plat_file_read(const char *path, uint64_t *size) {
    char p[PATH_MAX];
    if (!sys(path, p)) return NULL;
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat st;
    uint8_t *buf = NULL;
    if (!fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size > 0 && st.st_size < (1ll << 30)) {
        buf = malloc((size_t)st.st_size + 1);
        size_t got = 0;
        while (buf && got < (size_t)st.st_size) {
            ssize_t k = read(fd, buf + got, (size_t)st.st_size - got);
            if (k < 0 && errno == EINTR) continue;
            if (k <= 0) break;
            got += (size_t)k;
        }
        if (buf && got != (size_t)st.st_size) {
            free(buf);
            buf = NULL;
        }
        if (buf) {
            buf[st.st_size] = 0;
            *size = (uint64_t)st.st_size;
        }
    }
    close(fd);
    return buf;
}

static int write_all(int fd, const void *data, size_t n) {
    const char *p = data;
    while (n) {
        ssize_t k = write(fd, p, n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) return 0;
        p += k;
        n -= (size_t)k;
    }
    return 1;
}

// Windows refuses to write, replace or rename over a file with the read-only attribute (the settings menu relies on it
// for a totk.ini the player locked); rename(2) would replace it, and root ignores modes, so check the mode first.
static int read_only(const char *p) {
    struct stat st;
    return !stat(p, &st) && S_ISREG(st.st_mode) && !(st.st_mode & 0222);
}

int plat_file_write(const char *path, const void *data, size_t n) {
    char p[PATH_MAX];
    if (!sys(path, p) || read_only(p)) return 0;
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) return 0;
    int ok = write_all(fd, data, n);
    return close(fd) == 0 && ok;
}

struct PlatAppend { int fd; };

PlatAppend *plat_append_open(const char *path) {
    char p[PATH_MAX];
    if (!sys(path, p)) return NULL;
    // O_APPEND: each write lands whole at the end, from any thread or process
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND | O_CLOEXEC, 0666);
    if (fd < 0) return NULL;
    PlatAppend *f = malloc(sizeof *f);
    if (!f) {
        close(fd);
        return NULL;
    }
    f->fd = fd;
    return f;
}

int plat_append_write(PlatAppend *f, const void *data, size_t n) { return write_all(f->fd, data, n); }

static void sync_dir_of(const char *p) {
    char d[PATH_MAX];
    snprintf(d, sizeof d, "%s", p);
    char *s = strrchr(d, '/');
    if (s) *s = 0;
    int fd = open(s ? (*d ? d : "/") : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0) fsync(fd), close(fd);
}

int plat_file_replace(const char *from, const char *to) {
    char a[PATH_MAX], b[PATH_MAX];
    if (!sys(from, a) || !sys(to, b) || read_only(b) || rename(a, b)) return 0;
    sync_dir_of(b);
    return 1;
}

int plat_file_write_atomic(const char *path, const void *data, size_t n) {
    char p[PATH_MAX], tmp[PATH_MAX + 48];
    if (!sys(path, p) || read_only(p)) return 0;
    int len = snprintf(tmp, sizeof tmp, "%s.%d.%u.tmp", p, (int)getpid(), plat_thread_id());
    if (len < 0 || len >= (int)sizeof tmp) return 0;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) return 0;
    int ok = write_all(fd, data, n) && !fsync(fd);
    ok = !close(fd) && ok;
    if (ok && !rename(tmp, p)) {
        sync_dir_of(p);
        return 1;
    }
    unlink(tmp);
    return 0;
}

int plat_file_flush(const char *path) {
    char p[PATH_MAX];
    if (!sys(path, p)) return 0;
    int fd = open(p, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    int ok = !fsync(fd);
    close(fd);
    return ok;
}

void plat_file_delete(const char *path) {
    char p[PATH_MAX];
    if (sys(path, p)) unlink(p);
}

int plat_file_truncate(const char *path, uint64_t size) {
    char p[PATH_MAX];
    return sys(path, p) && !read_only(p) && !truncate(p, (off_t)size);
}

int64_t plat_file_size(const char *path) {
    char p[PATH_MAX];
    struct stat st;
    if (!sys(path, p) || stat(p, &st)) return -1;
    return (int64_t)st.st_size;
}

int plat_file_set_readonly(const char *path, int on) {
    char p[PATH_MAX];
    struct stat st;
    if (!sys(path, p) || stat(p, &st)) return 0;
    mode_t m = st.st_mode & 07777;
    return !chmod(p, on ? m & ~(mode_t)0222 : m | 0200);
}

int plat_file_list(const char *dir, const char *ext, int (*cb)(const char *name, void *ctx), void *ctx) {
    char p[PATH_MAX];
    if (!sys(dir, p)) return 0;
    DIR *d = opendir(p);
    if (!d) return 0;
    size_t el = strlen(ext);
    for (struct dirent *de; (de = readdir(d));) {
        size_t n = strlen(de->d_name);
        if (n < el || strcasecmp(de->d_name + n - el, ext)) continue;   // Windows matches without regard to case
        if (de->d_type == DT_DIR) continue;
        if (!cb(de->d_name, ctx)) break;
    }
    closedir(d);
    return 1;
}

int plat_mem_commit(uint64_t addr, size_t n) {
    return VirtualAlloc((void *)(uintptr_t)addr, n, MEM_COMMIT, PAGE_READWRITE) != NULL;
}

int plat_mem_read(uint64_t addr, void *out, size_t n) {
    struct iovec l = {out, n}, r = {(void *)(uintptr_t)addr, n};
    return process_vm_readv(getpid(), &l, 1, &r, 1, 0) == (ssize_t)n;
}

int plat_exe_path(char *out, size_t cap) {
    ssize_t n = readlink("/proc/self/exe", out, cap - 1);
    if (n <= 0 || (size_t)n >= cap - 1) return 0;
    out[n] = 0;
    w32_win_sep(out);   // the runtime takes the folder up to the last '\\'; every path call converts back
    return 1;
}

size_t plat_getenv(const char *name, char *out, size_t cap) {
    const char *v = getenv(name);
    if (!v || !*v) return 0;
    size_t n = strlen(v);
    if (n + 1 > cap) return 0;
    memcpy(out, v, n + 1);
    return n;
}

uint32_t plat_thread_id(void) { return GetCurrentThreadId(); }

const char *plat_ui_language(void) {
    static char tag[LOCALE_NAME_MAX_LENGTH];
    static int done;
    if (!done) {
        const char *v = getenv("LC_ALL");
        if (!v || !*v) v = getenv("LC_MESSAGES");
        if (!v || !*v) v = getenv("LANG");
        size_t k = 0;
        if (v && strcmp(v, "C") && strcmp(v, "POSIX"))
            for (; v[k] && v[k] != '.' && v[k] != '@' && k + 1 < sizeof tag; k++) tag[k] = v[k] == '_' ? '-' : v[k];
        tag[k] = 0;
        done = 1;
    }
    return tag;
}

// A font with the language's glyphs: fontconfig's answer when fc-match is installed, else the usual Noto CJK files.
int plat_font_path(const char *lang, char *out, size_t cap) {
    static const struct { const char *lang, *fc; const char *files[4]; } fonts[] = {
        {"ja", "ja", {"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                      "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
                      "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc", NULL}},
        {"ko", "ko", {"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                      "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
                      "/usr/share/fonts/truetype/nanum/NanumGothic.ttf", NULL}},
        {"zh-Hans", "zh-cn", {"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                              "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
                              "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc", NULL}},
        {"zh-Hant", "zh-tw", {"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
                              "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc", NULL, NULL}},
    };
    for (size_t i = 0; i < sizeof fonts / sizeof *fonts; i++) {
        if (strcmp(fonts[i].lang, lang)) continue;
        char cmd[128];
        snprintf(cmd, sizeof cmd, "fc-match -f '%%{file}' ':lang=%s' 2>/dev/null", fonts[i].fc);
        FILE *f = popen(cmd, "r");
        if (f) {
            char p[1024];
            size_t n = fread(p, 1, sizeof p - 1, f);
            pclose(f);
            p[n] = 0;
            struct stat st;
            if (n && n < cap && !stat(p, &st) && (strstr(p, ".tt") || strstr(p, ".otf") || strstr(p, ".otc"))) {
                memcpy(out, p, n + 1);
                return 1;
            }
        }
        for (int k = 0; k < 4 && fonts[i].files[k]; k++) {
            struct stat st;
            if (!stat(fonts[i].files[k], &st) && strlen(fonts[i].files[k]) < cap) {
                strcpy(out, fonts[i].files[k]);
                return 1;
            }
        }
    }
    return 0;
}

int plat_os_version(char *out, size_t cap) {
    char name[128] = "Linux";
    FILE *f = fopen("/etc/os-release", "r");
    if (f) {   // PRETTY_NAME="Ubuntu 24.04 LTS"
        char line[256];
        while (fgets(line, sizeof line, f))
            if (!strncmp(line, "PRETTY_NAME=", 12)) {
                char *v = line + 12, *e;
                if (*v == '"') v++;
                if ((e = strpbrk(v, "\"\n"))) *e = 0;
                snprintf(name, sizeof name, "%s", v);
                break;
            }
        fclose(f);
    }
    struct utsname u;
    if (uname(&u)) return 0;
    snprintf(out, cap, "%s (Linux %s)", name, u.release);
    return 1;
}

int plat_stderr_path(char *out, size_t cap) {
    struct stat st;
    if (fstat(2, &st) || !S_ISREG(st.st_mode)) return 0;
    ssize_t n = readlink("/proc/self/fd/2", out, cap - 1);
    if (n <= 0) return 0;
    out[n] = 0;
    w32_win_sep(out);
    return 1;
}

// ---- desktop

// Runs argv with data on its stdin (NULL: none), detached from our stdout; 1 when it exited with 0.
static int run_tool(char *const argv[], const char *data) {
    int fds[2] = {-1, -1};
    if (data && pipe2(fds, O_CLOEXEC)) return 0;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (data) posix_spawn_file_actions_adddup2(&fa, fds[0], 0);
    posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    pid_t pid;
    int e = posix_spawnp(&pid, argv[0], &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (data) close(fds[0]);
    if (e) {
        if (data) close(fds[1]);
        return 0;
    }
    if (data) {
        write_all(fds[1], data, strlen(data));
        close(fds[1]);
    }
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

// The menu's text goes through SDL's clipboard when the game window is up (input_sdl.c sets this hook); otherwise
// wl-copy or xclip.
int (*plat_clipboard_hook)(const char *utf8);

int plat_clipboard_set(const char *utf8) {
    if (plat_clipboard_hook && plat_clipboard_hook(utf8)) return 1;
    char *wl[] = {"wl-copy", NULL}, *xc[] = {"xclip", "-selection", "clipboard", NULL},
         *xs[] = {"xsel", "--clipboard", "--input", NULL};
    if (getenv("WAYLAND_DISPLAY") && run_tool(wl, utf8)) return 1;
    return run_tool(xc, utf8) || run_tool(xs, utf8);
}

static void open_folder_main(void *arg) {
    char *argv[] = {"xdg-open", arg, NULL};
    run_tool(argv, NULL);
    free(arg);
}

int plat_open_folder(const char *path) {
    char p[PATH_MAX];
    struct stat st;
    if (!sys(path, p) || stat(p, &st) || !S_ISDIR(st.st_mode)) return 0;
    char *copy = strdup(p);
    if (!copy) return 0;
    // the file manager can take a while to answer: not on the caller's thread (the present path)
    PlatThread *t = plat_thread_new(open_folder_main, copy, "open-folder");
    if (!t) return free(copy), 0;
    plat_thread_detach(t);
    return 1;
}

// ---- dynamic libraries

void *plat_lib_open(const char *name) {
    // A Windows library name stands for its Linux build ("foo.dll" -> "libfoo.so")
    char buf[PATH_MAX];
    size_t n = strlen(name);
    if (n > 4 && !strcasecmp(name + n - 4, ".dll") && !strchr(name, '/') && !strchr(name, '\\')) {
        snprintf(buf, sizeof buf, "lib%.*s.so", (int)(n - 4), name);
        name = buf;
    }
    return dlopen(name, RTLD_NOW | RTLD_LOCAL);
}

void *plat_lib_sym(void *lib, const char *name) { return lib ? dlsym(lib, name) : NULL; }

// ---- machine load: /proc/stat for the CPU, /sys/class/hwmon and thermal zones for the temperature, the amdgpu sysfs
// counters for the GPU (other vendors: -1).

struct PlatLoad {
    uint64_t busy, total, proc;   // the previous call's ticks; total 0 before the first
    char gpu_dir[256];            // /sys/class/drm/cardN/device of an amdgpu card, "" when none
};

PlatLoad *plat_load_open(const uint8_t *gpu_luid) {
    (void)gpu_luid;   // Linux has no LUIDs; the first card with the amdgpu counters
    PlatLoad *l = calloc(1, sizeof *l);
    if (!l) return NULL;
    for (int i = 0; i < 8 && !l->gpu_dir[0]; i++) {
        char p[256];
        snprintf(p, sizeof p, "/sys/class/drm/card%d/device/gpu_busy_percent", i);
        if (!access(p, R_OK)) snprintf(l->gpu_dir, sizeof l->gpu_dir, "/sys/class/drm/card%d/device", i);
    }
    return l;
}

void plat_load_close(PlatLoad *l) { free(l); }

static long long read_ll(const char *path) {
    FILE *f = fopen(path, "r");
    long long v = -1;
    if (f) {
        if (fscanf(f, "%lld", &v) != 1) v = -1;
        fclose(f);
    }
    return v;
}

void plat_cpu_load(PlatLoad *l, float *total_pct, float *proc_pct, float *temp_c) {
    *total_pct = *proc_pct = *temp_c = -1;
    if (!l) return;
    FILE *f = fopen("/proc/stat", "r");
    unsigned long long v[8] = {0};
    int n = f ? fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5],
                       &v[6], &v[7])
              : 0;
    if (f) fclose(f);
    FILETIME k, u, c, e;
    uint64_t proc = 0;
    if (GetProcessTimes(GetCurrentProcess(), &c, &e, &k, &u)) {
        uint64_t ns100 = ((uint64_t)k.dwHighDateTime << 32 | k.dwLowDateTime) +
                         ((uint64_t)u.dwHighDateTime << 32 | u.dwLowDateTime);
        proc = ns100 * 100u / (1000000000u / (uint64_t)sysconf(_SC_CLK_TCK));   // in ticks
    }
    if (n >= 4) {
        uint64_t idle = v[3] + v[4], total = 0;
        for (int i = 0; i < 8; i++) total += v[i];
        uint64_t busy = total - idle;
        if (l->total && total > l->total) {
            *total_pct = 100.0f * (float)(busy - l->busy) / (float)(total - l->total);
            *proc_pct = 100.0f * (float)(proc - l->proc) / (float)(total - l->total);
        }
        l->busy = busy, l->total = total, l->proc = proc;
    }
    // the hottest thermal zone, millidegrees
    for (int i = 0; i < 32; i++) {
        char p[96];
        snprintf(p, sizeof p, "/sys/class/thermal/thermal_zone%d/temp", i);
        long long t = read_ll(p);
        if (t < 0 && i > 0) break;
        if (t > 0 && t < 150000 && t / 1000.0f > *temp_c) *temp_c = (float)t / 1000.0f;
    }
}

void plat_gpu_load(PlatLoad *l, float *load_pct, float *vram_used_mb) {
    *load_pct = *vram_used_mb = -1;
    if (!l || !l->gpu_dir[0]) return;
    char p[320];
    snprintf(p, sizeof p, "%s/gpu_busy_percent", l->gpu_dir);
    long long b = read_ll(p);
    if (b >= 0) *load_pct = (float)b;
    snprintf(p, sizeof p, "%s/mem_info_vram_used", l->gpu_dir);
    long long m = read_ll(p);
    if (m >= 0) *vram_used_mb = (float)((double)m / 1048576.0);
}

void plat_mem_info(float *used_mb, float *total_mb, float *proc_mb) {
    *used_mb = *total_mb = *proc_mb = -1;
    MEMORYSTATUSEX ms = {.dwLength = sizeof ms};
    if (GlobalMemoryStatusEx(&ms)) {
        *total_mb = (float)(ms.ullTotalPhys >> 20);
        *used_mb = (float)((ms.ullTotalPhys - ms.ullAvailPhys) >> 20);
    }
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof pmc)) *proc_mb = (float)(pmc.WorkingSetSize >> 20);
}

// ---- child processes

struct PlatChild {
    pid_t pid;
    int in, out;   // in: our write end, out: our read end
};

PlatChild *plat_child_start(const char *exe, const char *arg, uint32_t *err) {
    if (err) *err = 0;
    char prog[PATH_MAX];
    if (!sys(exe, prog)) return NULL;
    size_t pl = strlen(prog);   // "tool.exe": the Linux build has no suffix
    if (pl > 4 && !strcasecmp(prog + pl - 4, ".exe") && access(prog, X_OK)) prog[pl - 4] = 0;
    int in[2], out[2];
    if (pipe2(in, O_CLOEXEC)) return NULL;
    if (pipe2(out, O_CLOEXEC)) {
        close(in[0]), close(in[1]);
        return NULL;
    }
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, in[0], 0);
    posix_spawn_file_actions_adddup2(&fa, out[1], 1);
    posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0);
    char *argv[3] = {prog, (char *)arg, NULL};
    pid_t pid;
    int e = posix_spawn(&pid, prog, &fa, NULL, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    close(in[0]);
    close(out[1]);
    if (e) {
        close(in[1]), close(out[0]);
        if (err) *err = (uint32_t)e;
        return NULL;
    }
    PlatChild *c = malloc(sizeof *c);
    if (!c) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        close(in[1]), close(out[0]);
        return NULL;
    }
    c->pid = pid, c->in = in[1], c->out = out[0];
    return c;
}

void plat_child_stop(PlatChild *c) {
    if (!c) return;
    close(c->in);
    close(c->out);
    kill(c->pid, SIGKILL);
    while (waitpid(c->pid, NULL, 0) < 0 && errno == EINTR) {}
    free(c);
}

int plat_child_write(PlatChild *c, const void *data, size_t n) {
    // A child that died must not kill us with SIGPIPE
    static int once;
    if (!once) once = 1, signal(SIGPIPE, SIG_IGN);
    return write_all(c->in, data, n);
}

long plat_child_read(PlatChild *c, void *buf, size_t cap) {
    for (;;) {
        ssize_t k = read(c->out, buf, cap);
        if (k < 0 && errno == EINTR) continue;
        return (long)k;
    }
}
