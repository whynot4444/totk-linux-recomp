// Linux Win32 stand-in, part 1: errors, time, SRW locks, condition variables, critical sections, one-time init,
// handles and waits (events, semaphores, waitable timers), threads with suspension and register access, fibers.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "w32_internal.h"

// ---- errors

static __thread DWORD last_error;
DWORD GetLastError(void) { return last_error; }
void SetLastError(DWORD e) { last_error = e; }

DWORD w32_errno_to_win(int e) {
    switch (e) {
    case 0: return ERROR_SUCCESS;
    case ENOENT: return ERROR_FILE_NOT_FOUND;
    case ENOTDIR: return ERROR_PATH_NOT_FOUND;
    case EACCES: case EPERM: case EROFS: return ERROR_ACCESS_DENIED;
    case EBADF: return ERROR_INVALID_HANDLE;
    case ENOMEM: return ERROR_NOT_ENOUGH_MEMORY;
    case EEXIST: return ERROR_ALREADY_EXISTS;
    case ENOTEMPTY: return ERROR_DIR_NOT_EMPTY;
    case ENOSPC: return ERROR_DISK_FULL;
    case EINVAL: return ERROR_INVALID_PARAMETER;
    case EPIPE: return ERROR_BROKEN_PIPE;
    case ETIMEDOUT: return ERROR_TIMEOUT;
    case EFAULT: return ERROR_NOACCESS;
    case EBUSY: case ETXTBSY: return ERROR_SHARING_VIOLATION;
    case ENOSYS: case EOPNOTSUPP: return ERROR_NOT_SUPPORTED;
    default: return 1000u + (DWORD)e;   // stays recognisable in a log line
    }
}

void w32_set_errno(void) { last_error = w32_errno_to_win(errno); }

// ---- time and futexes

uint64_t w32_now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}

int w32_futex_wait_until(volatile uint32_t *addr, uint32_t val, uint64_t deadline_ns) {
    if (deadline_ns == UINT64_MAX) {
        w32_futex(addr, FUTEX_WAIT, val, NULL);
        return 1;
    }
    uint64_t now = w32_now_ns();
    if (now >= deadline_ns) return 0;
    uint64_t left = deadline_ns - now;
    struct timespec ts = {(time_t)(left / 1000000000u), (long)(left % 1000000000u)};
    if (w32_futex(addr, FUTEX_WAIT, val, &ts) < 0 && errno == ETIMEDOUT) return 0;
    return 1;
}

int w32_futex_wait_ms(volatile uint32_t *addr, uint32_t val, DWORD ms) {
    return w32_futex_wait_until(addr, val, ms == INFINITE ? UINT64_MAX : w32_now_ns() + (uint64_t)ms * 1000000u);
}

BOOL QueryPerformanceCounter(LARGE_INTEGER *t) {
    t->QuadPart = (LONGLONG)w32_now_ns();
    return TRUE;
}

BOOL QueryPerformanceFrequency(LARGE_INTEGER *f) {
    f->QuadPart = 1000000000;
    return TRUE;
}

ULONGLONG GetTickCount64(void) { return w32_now_ns() / 1000000u; }
DWORD GetTickCount(void) { return (DWORD)GetTickCount64(); }

void Sleep(DWORD ms) {
    if (!ms) {
        sched_yield();
        return;
    }
    struct timespec ts = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    while (nanosleep(&ts, &ts) && errno == EINTR) {}
}

DWORD SleepEx(DWORD ms, BOOL alertable) {
    (void)alertable;
    Sleep(ms);
    return 0;
}

BOOL SwitchToThread(void) {
    sched_yield();
    return TRUE;
}

UINT timeBeginPeriod(UINT ms) { (void)ms; return 0; }   // Linux timers are already fine-grained
UINT timeEndPeriod(UINT ms) { (void)ms; return 0; }

#define FT_UNIX_EPOCH 116444736000000000ull   // 1970-01-01 in 100 ns units since 1601-01-01

static void ft_from_unix(const struct timespec *ts, LPFILETIME ft) {
    uint64_t v = FT_UNIX_EPOCH + (uint64_t)ts->tv_sec * 10000000u + (uint64_t)ts->tv_nsec / 100u;
    ft->dwLowDateTime = (DWORD)v;
    ft->dwHighDateTime = (DWORD)(v >> 32);
}

void GetSystemTimeAsFileTime(LPFILETIME ft) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ft_from_unix(&ts, ft);
}

void GetSystemTimePreciseAsFileTime(LPFILETIME ft) { GetSystemTimeAsFileTime(ft); }

static void st_from_tm(const struct tm *tm, long ms, LPSYSTEMTIME st) {
    st->wYear = (WORD)(tm->tm_year + 1900);
    st->wMonth = (WORD)(tm->tm_mon + 1);
    st->wDayOfWeek = (WORD)tm->tm_wday;
    st->wDay = (WORD)tm->tm_mday;
    st->wHour = (WORD)tm->tm_hour;
    st->wMinute = (WORD)tm->tm_min;
    st->wSecond = (WORD)(tm->tm_sec > 59 ? 59 : tm->tm_sec);
    st->wMilliseconds = (WORD)ms;
}

void GetSystemTime(LPSYSTEMTIME st) {
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    gmtime_r(&ts.tv_sec, &tm);
    st_from_tm(&tm, ts.tv_nsec / 1000000, st);
}

void GetLocalTime(LPSYSTEMTIME st) {
    struct timespec ts;
    struct tm tm;
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    st_from_tm(&tm, ts.tv_nsec / 1000000, st);
}

BOOL FileTimeToSystemTime(const FILETIME *ft, LPSYSTEMTIME st) {
    uint64_t v = (uint64_t)ft->dwHighDateTime << 32 | ft->dwLowDateTime;
    if (v < FT_UNIX_EPOCH) return FALSE;
    v -= FT_UNIX_EPOCH;
    time_t s = (time_t)(v / 10000000u);
    struct tm tm;
    gmtime_r(&s, &tm);
    st_from_tm(&tm, (long)(v % 10000000u / 10000u), st);
    return TRUE;
}

BOOL SystemTimeToFileTime(const SYSTEMTIME *st, LPFILETIME ft) {
    struct tm tm = {.tm_year = st->wYear - 1900, .tm_mon = st->wMonth - 1, .tm_mday = st->wDay,
                    .tm_hour = st->wHour, .tm_min = st->wMinute, .tm_sec = st->wSecond};
    struct timespec ts = {timegm(&tm), (long)st->wMilliseconds * 1000000L};
    ft_from_unix(&ts, ft);
    return TRUE;
}

// ---- SRW locks: word 0 the state (bit 31 a writer, the rest the readers), word 1 the number of sleepers.

#define SRW_WRITER 0x80000000u
#define SPIN 64

static volatile uint32_t *srw_state(PSRWLOCK l) { return (volatile uint32_t *)l; }
static volatile uint32_t *srw_waiters(PSRWLOCK l) { return (volatile uint32_t *)l + 1; }

void InitializeSRWLock(PSRWLOCK l) { l->Ptr = NULL; }

BOOLEAN TryAcquireSRWLockExclusive(PSRWLOCK l) {
    uint32_t z = 0;
    return __atomic_compare_exchange_n(srw_state(l), &z, SRW_WRITER, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

BOOLEAN TryAcquireSRWLockShared(PSRWLOCK l) {
    uint32_t s = __atomic_load_n(srw_state(l), __ATOMIC_RELAXED);
    while (!(s & SRW_WRITER))
        if (__atomic_compare_exchange_n(srw_state(l), &s, s + 1, 1, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return 1;
    return 0;
}

// The sleeper counts itself before it reads the state it sleeps on, and releasers wake after they changed the state
// and then read the count (both sequentially consistent), so a release never misses a sleeper.
void AcquireSRWLockExclusive(PSRWLOCK l) {
    for (int i = 0; i < SPIN; i++) {
        if (TryAcquireSRWLockExclusive(l)) return;
        __builtin_ia32_pause();
    }
    for (;;) {
        __atomic_add_fetch(srw_waiters(l), 1, __ATOMIC_SEQ_CST);
        uint32_t s = __atomic_load_n(srw_state(l), __ATOMIC_SEQ_CST);
        if (s) w32_futex(srw_state(l), FUTEX_WAIT, s, NULL);
        __atomic_sub_fetch(srw_waiters(l), 1, __ATOMIC_SEQ_CST);
        if (TryAcquireSRWLockExclusive(l)) return;
    }
}

void AcquireSRWLockShared(PSRWLOCK l) {
    for (int i = 0; i < SPIN; i++) {
        if (TryAcquireSRWLockShared(l)) return;
        __builtin_ia32_pause();
    }
    for (;;) {
        __atomic_add_fetch(srw_waiters(l), 1, __ATOMIC_SEQ_CST);
        uint32_t s = __atomic_load_n(srw_state(l), __ATOMIC_SEQ_CST);
        if (s & SRW_WRITER) w32_futex(srw_state(l), FUTEX_WAIT, s, NULL);
        __atomic_sub_fetch(srw_waiters(l), 1, __ATOMIC_SEQ_CST);
        if (TryAcquireSRWLockShared(l)) return;
    }
}

void ReleaseSRWLockExclusive(PSRWLOCK l) {
    __atomic_store_n(srw_state(l), 0, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(srw_waiters(l), __ATOMIC_SEQ_CST)) w32_futex_wake(srw_state(l), INT_MAX);
}

void ReleaseSRWLockShared(PSRWLOCK l) {
    if (__atomic_sub_fetch(srw_state(l), 1, __ATOMIC_SEQ_CST) == 0 &&
        __atomic_load_n(srw_waiters(l), __ATOMIC_SEQ_CST))
        w32_futex_wake(srw_state(l), INT_MAX);
}

// ---- condition variables: a sequence number

static volatile uint32_t *cv_seq(PCONDITION_VARIABLE c) { return (volatile uint32_t *)c; }

void InitializeConditionVariable(PCONDITION_VARIABLE c) { c->Ptr = NULL; }

BOOL SleepConditionVariableSRW(PCONDITION_VARIABLE c, PSRWLOCK l, DWORD ms, ULONG flags) {
    int shared = flags & CONDITION_VARIABLE_LOCKMODE_SHARED;
    uint32_t seq = __atomic_load_n(cv_seq(c), __ATOMIC_SEQ_CST);
    if (shared) ReleaseSRWLockShared(l);
    else ReleaseSRWLockExclusive(l);
    int woke = w32_futex_wait_ms(cv_seq(c), seq, ms);
    if (shared) AcquireSRWLockShared(l);
    else AcquireSRWLockExclusive(l);
    if (!woke) {
        last_error = ERROR_TIMEOUT;
        return FALSE;
    }
    return TRUE;
}

void WakeConditionVariable(PCONDITION_VARIABLE c) {
    __atomic_add_fetch(cv_seq(c), 1, __ATOMIC_SEQ_CST);
    w32_futex_wake(cv_seq(c), 1);
}

void WakeAllConditionVariable(PCONDITION_VARIABLE c) {
    __atomic_add_fetch(cv_seq(c), 1, __ATOMIC_SEQ_CST);
    w32_futex_wake(cv_seq(c), INT_MAX);
}

// ---- critical sections (recursive)

static __thread int self_tid;
DWORD GetCurrentThreadId(void) {
    if (!self_tid) self_tid = (int)syscall(SYS_gettid);
    return (DWORD)self_tid;
}
DWORD GetCurrentProcessId(void) { return (DWORD)getpid(); }

void InitializeCriticalSection(LPCRITICAL_SECTION cs) { memset(cs, 0, sizeof *cs); }
BOOL InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION cs, DWORD spin) {
    (void)spin;
    InitializeCriticalSection(cs);
    return TRUE;
}
BOOL InitializeCriticalSectionEx(LPCRITICAL_SECTION cs, DWORD spin, DWORD flags) {
    (void)spin, (void)flags;
    InitializeCriticalSection(cs);
    return TRUE;
}
void DeleteCriticalSection(LPCRITICAL_SECTION cs) { (void)cs; }

void EnterCriticalSection(LPCRITICAL_SECTION cs) {
    int me = (int)GetCurrentThreadId();
    if (__atomic_load_n(&cs->owner, __ATOMIC_RELAXED) == me) {
        cs->count++;
        return;
    }
    AcquireSRWLockExclusive(&cs->lock);
    __atomic_store_n(&cs->owner, me, __ATOMIC_RELAXED);
    cs->count = 1;
}

BOOL TryEnterCriticalSection(LPCRITICAL_SECTION cs) {
    int me = (int)GetCurrentThreadId();
    if (__atomic_load_n(&cs->owner, __ATOMIC_RELAXED) == me) {
        cs->count++;
        return TRUE;
    }
    if (!TryAcquireSRWLockExclusive(&cs->lock)) return FALSE;
    __atomic_store_n(&cs->owner, me, __ATOMIC_RELAXED);
    cs->count = 1;
    return TRUE;
}

void LeaveCriticalSection(LPCRITICAL_SECTION cs) {
    if (--cs->count) return;
    __atomic_store_n(&cs->owner, 0, __ATOMIC_RELAXED);
    ReleaseSRWLockExclusive(&cs->lock);
}

BOOL SleepConditionVariableCS(PCONDITION_VARIABLE c, LPCRITICAL_SECTION cs, DWORD ms) {
    int count = cs->count;
    cs->count = 0;
    __atomic_store_n(&cs->owner, 0, __ATOMIC_RELAXED);
    BOOL ok = SleepConditionVariableSRW(c, &cs->lock, ms, 0);
    __atomic_store_n(&cs->owner, (int)GetCurrentThreadId(), __ATOMIC_RELAXED);
    cs->count = count;
    return ok;
}

// ---- one-time initialisation: state 0 new, 1 running, 2 done

BOOL InitOnceExecuteOnce(PINIT_ONCE o, PINIT_ONCE_FN fn, PVOID param, LPVOID *ctx) {
    for (;;) {
        int s = __atomic_load_n(&o->state, __ATOMIC_ACQUIRE);
        if (s == 2) break;
        if (s == 0 && __atomic_compare_exchange_n(&o->state, &s, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            void *c = NULL;
            BOOL ok = fn(o, param, &c);
            o->ctx = c;
            __atomic_store_n(&o->state, ok ? 2 : 0, __ATOMIC_RELEASE);
            w32_futex_wake(&o->state, INT_MAX);
            if (!ok) return FALSE;
            break;
        }
        if (s == 1) w32_futex((volatile uint32_t *)&o->state, FUTEX_WAIT, 1, NULL);
    }
    if (ctx) *ctx = o->ctx;
    return TRUE;
}

BOOL InitOnceBeginInitialize(LPINIT_ONCE o, DWORD flags, PBOOL pending, LPVOID *ctx) {
    for (;;) {
        int s = __atomic_load_n(&o->state, __ATOMIC_ACQUIRE);
        if (s == 2) {
            *pending = FALSE;
            if (ctx) *ctx = o->ctx;
            return TRUE;
        }
        if (flags & INIT_ONCE_CHECK_ONLY) {
            last_error = ERROR_INVALID_PARAMETER;
            return FALSE;
        }
        if (s == 0 && __atomic_compare_exchange_n(&o->state, &s, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            *pending = TRUE;
            return TRUE;
        }
        if (s == 1) w32_futex((volatile uint32_t *)&o->state, FUTEX_WAIT, 1, NULL);
    }
}

BOOL InitOnceComplete(LPINIT_ONCE o, DWORD flags, LPVOID ctx) {
    int ok = !(flags & INIT_ONCE_INIT_FAILED);
    if (ok) o->ctx = ctx;
    __atomic_store_n(&o->state, ok ? 2 : 0, __ATOMIC_RELEASE);
    w32_futex_wake(&o->state, INT_MAX);
    return TRUE;
}

// ---- WaitOnAddress: a futex on the aligned 32-bit word that holds the value

BOOL WaitOnAddress(volatile void *addr, PVOID cmp, SIZE_T size, DWORD ms) {
    uintptr_t a = (uintptr_t)addr;
    volatile uint32_t *word = (volatile uint32_t *)(a & ~(uintptr_t)3);
    if (size == 8) word = (volatile uint32_t *)a;   // the low half; a change elsewhere wakes through WakeByAddress
    uint32_t w = __atomic_load_n(word, __ATOMIC_SEQ_CST);
    if (memcmp((const void *)addr, cmp, size)) return TRUE;
    if (!w32_futex_wait_ms(word, w, ms)) {
        last_error = ERROR_TIMEOUT;
        return FALSE;
    }
    return TRUE;
}

void WakeByAddressSingle(PVOID addr) { w32_futex_wake((void *)((uintptr_t)addr & ~(uintptr_t)3), INT_MAX); }
void WakeByAddressAll(PVOID addr) { w32_futex_wake((void *)((uintptr_t)addr & ~(uintptr_t)3), INT_MAX); }

// ---- handles

W32Obj *w32_obj(HANDLE h, uint32_t kind) {
    W32Obj *o = h;
    if (!o || h == INVALID_HANDLE_VALUE || (uintptr_t)h < 0x10000 || o->magic != kind) {
        last_error = ERROR_INVALID_HANDLE;
        return NULL;
    }
    return o;
}

void w32_obj_ref(W32Obj *o) { __atomic_add_fetch(&o->refs, 1, __ATOMIC_ACQ_REL); }

void w32_obj_unref(W32Obj *o) {
    if (__atomic_sub_fetch(&o->refs, 1, __ATOMIC_ACQ_REL)) return;
    if (o->destroy) o->destroy(o);
    o->magic = 0;
    free(o);
}

static int obj_kind_ok(W32Obj *o) {
    return o && (uintptr_t)o >= 0x10000 && o != INVALID_HANDLE_VALUE && o->magic >= W32_THREAD &&
           o->magic <= W32_FIND;
}

#define PSEUDO_PROCESS ((HANDLE)(intptr_t)-1)
#define PSEUDO_THREAD ((HANDLE)(intptr_t)-2)

BOOL CloseHandle(HANDLE h) {
    if (h == PSEUDO_PROCESS || h == PSEUDO_THREAD) return TRUE;
    W32Obj *o = h;
    if (!obj_kind_ok(o)) {
        last_error = ERROR_INVALID_HANDLE;
        return FALSE;
    }
    w32_obj_unref(o);
    return TRUE;
}

BOOL DuplicateHandle(HANDLE sp, HANDLE s, HANDLE tp, HANDLE *t, DWORD access, BOOL inherit, DWORD opts) {
    (void)sp, (void)tp, (void)access, (void)inherit, (void)opts;
    if (s == PSEUDO_THREAD) s = GetCurrentThread();
    W32Obj *o = s;
    if (!obj_kind_ok(o)) {
        last_error = ERROR_INVALID_HANDLE;
        return FALSE;
    }
    w32_obj_ref(o);
    *t = s;
    return TRUE;
}

// ---- waitable objects

pthread_mutex_t w32_wait_lock = PTHREAD_MUTEX_INITIALIZER;
volatile uint32_t w32_any_seq;

void w32_signal_changed(volatile uint32_t *seq) {
    __atomic_add_fetch(seq, 1, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&w32_any_seq, 1, __ATOMIC_SEQ_CST);
    w32_futex_wake(seq, INT_MAX);
    w32_futex_wake(&w32_any_seq, INT_MAX);
}

typedef struct {
    W32Obj o;
    volatile uint32_t seq;
    int manual, set;
} W32Event;

typedef struct {
    W32Obj o;
    volatile uint32_t seq;
    LONG count, max;
} W32Sem;

typedef struct {
    W32Obj o;
    volatile uint32_t seq;
    int manual, armed, set;
    uint64_t due_ns, period_ns;
} W32Timer;

struct W32Thread {
    W32Obj o;
    volatile uint32_t seq;
    pthread_t pt;
    int has_pt;
    volatile int tid;
    LPTHREAD_START_ROUTINE fn;
    void *arg;
    volatile int done;
    DWORD exit_code;
    // suspension
    pthread_mutex_t smu;
    int suspend_count;
    volatile uint32_t gate;         // CREATE_SUSPENDED: 0 until the first ResumeThread lets the thread start
    volatile uint32_t susp_state;   // 0 running, 2 stopped in the signal handler
    volatile uint32_t resume_gen;
    ucontext_t *uc;                 // the stopped thread's registers, while susp_state is 2
    // fibers
    void *fiber, *base_fiber;
    // registry
    int slot;
};

// Defined in win32_proc.c: process objects are waitable too.
int w32_process_poll(HANDLE h, int consume);   // -1 not a process, 1 exited, 0 running
volatile uint32_t *w32_process_seq(HANDLE h);

// 1 when o is signaled; consumes it (auto-reset event, semaphore count, auto-reset timer) when consume.
// *deadline gets the time a timer becomes signaled. w32_wait_lock held.
static int obj_signaled(W32Obj *o, int consume, uint64_t now, uint64_t *deadline) {
    switch (o->magic) {
    case W32_EVENT: {
        W32Event *e = (W32Event *)o;
        if (!e->set) return 0;
        if (consume && !e->manual) e->set = 0;
        return 1;
    }
    case W32_SEM: {
        W32Sem *s = (W32Sem *)o;
        if (s->count <= 0) return 0;
        if (consume) s->count--;
        return 1;
    }
    case W32_TIMER: {
        W32Timer *t = (W32Timer *)o;
        if (!t->set && t->armed && now >= t->due_ns) {
            t->set = 1;
            if (t->period_ns) {
                while (t->due_ns <= now) t->due_ns += t->period_ns;
            } else t->armed = 0;
        }
        if (!t->set) {
            if (t->armed && t->due_ns < *deadline) *deadline = t->due_ns;
            return 0;
        }
        if (consume && !t->manual) t->set = 0;
        return 1;
    }
    case W32_THREAD: return ((W32Thread *)o)->done;
    case W32_PROCESS: {
        int r = w32_process_poll((HANDLE)o, consume);
        if (!r && now + 2000000u < *deadline) *deadline = now + 2000000u;   // polled every 2 ms
        return r > 0;
    }
    default: return 0;
    }
}

static volatile uint32_t *obj_seq(W32Obj *o) {
    switch (o->magic) {
    case W32_EVENT: return &((W32Event *)o)->seq;
    case W32_SEM: return &((W32Sem *)o)->seq;
    case W32_TIMER: return &((W32Timer *)o)->seq;
    case W32_THREAD: return &((W32Thread *)o)->seq;
    case W32_PROCESS: return w32_process_seq((HANDLE)o);
    default: return &w32_any_seq;
    }
}

DWORD WaitForMultipleObjects(DWORD n, const HANDLE *hs, BOOL all, DWORD ms) {
    if (!n || n > MAXIMUM_WAIT_OBJECTS) {
        last_error = ERROR_INVALID_PARAMETER;
        return WAIT_FAILED;
    }
    W32Obj *objs[MAXIMUM_WAIT_OBJECTS];
    for (DWORD i = 0; i < n; i++) {
        HANDLE h = hs[i] == PSEUDO_THREAD ? GetCurrentThread() : hs[i];
        objs[i] = h;
        if (!obj_kind_ok(objs[i])) {
            last_error = ERROR_INVALID_HANDLE;
            return WAIT_FAILED;
        }
    }
    uint64_t end = ms == INFINITE ? UINT64_MAX : w32_now_ns() + (uint64_t)ms * 1000000u;
    volatile uint32_t *seq = n == 1 ? obj_seq(objs[0]) : &w32_any_seq;
    for (;;) {
        uint32_t s = __atomic_load_n(seq, __ATOMIC_SEQ_CST);
        uint64_t now = w32_now_ns(), deadline = end;
        pthread_mutex_lock(&w32_wait_lock);
        if (all) {
            int ready = 1;
            for (DWORD i = 0; i < n; i++) ready &= obj_signaled(objs[i], 0, now, &deadline);
            if (ready) {
                for (DWORD i = 0; i < n; i++) obj_signaled(objs[i], 1, now, &deadline);
                pthread_mutex_unlock(&w32_wait_lock);
                return WAIT_OBJECT_0;
            }
        } else {
            for (DWORD i = 0; i < n; i++)
                if (obj_signaled(objs[i], 1, now, &deadline)) {
                    pthread_mutex_unlock(&w32_wait_lock);
                    return WAIT_OBJECT_0 + i;
                }
        }
        pthread_mutex_unlock(&w32_wait_lock);
        if (now >= end) return WAIT_TIMEOUT;
        w32_futex_wait_until(seq, s, deadline);
    }
}

DWORD WaitForSingleObject(HANDLE h, DWORD ms) { return WaitForMultipleObjects(1, &h, FALSE, ms); }
DWORD WaitForSingleObjectEx(HANDLE h, DWORD ms, BOOL alertable) {
    (void)alertable;
    return WaitForSingleObject(h, ms);
}

HANDLE CreateEventW(LPSECURITY_ATTRIBUTES sa, BOOL manual, BOOL initial, LPCWSTR name) {
    (void)sa, (void)name;
    W32Event *e = calloc(1, sizeof *e);
    if (!e) return NULL;
    e->o = (W32Obj){W32_EVENT, 1, NULL};
    e->manual = manual != 0;
    e->set = initial != 0;
    return e;
}

HANDLE CreateEventA(LPSECURITY_ATTRIBUTES sa, BOOL manual, BOOL initial, LPCSTR name) {
    (void)name;
    return CreateEventW(sa, manual, initial, NULL);
}

HANDLE CreateEventExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access) {
    (void)access;
    return CreateEventW(sa, (flags & CREATE_EVENT_MANUAL_RESET) != 0, (flags & CREATE_EVENT_INITIAL_SET) != 0, name);
}

static BOOL event_set(HANDLE h, int on) {
    W32Event *e = (W32Event *)w32_obj(h, W32_EVENT);
    if (!e) return FALSE;
    pthread_mutex_lock(&w32_wait_lock);
    e->set = on;
    pthread_mutex_unlock(&w32_wait_lock);
    if (on) w32_signal_changed(&e->seq);
    return TRUE;
}

BOOL SetEvent(HANDLE h) { return event_set(h, 1); }
BOOL ResetEvent(HANDLE h) { return event_set(h, 0); }

HANDLE CreateSemaphoreW(LPSECURITY_ATTRIBUTES sa, LONG initial, LONG max, LPCWSTR name) {
    (void)sa, (void)name;
    W32Sem *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->o = (W32Obj){W32_SEM, 1, NULL};
    s->count = initial;
    s->max = max;
    return s;
}

BOOL ReleaseSemaphore(HANDLE h, LONG n, LPLONG prev) {
    W32Sem *s = (W32Sem *)w32_obj(h, W32_SEM);
    if (!s) return FALSE;
    pthread_mutex_lock(&w32_wait_lock);
    if (prev) *prev = s->count;
    int ok = s->count + n <= s->max;
    if (ok) s->count += n;
    pthread_mutex_unlock(&w32_wait_lock);
    if (!ok) {
        last_error = ERROR_INVALID_PARAMETER;
        return FALSE;
    }
    w32_signal_changed(&s->seq);
    return TRUE;
}

HANDLE CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access) {
    (void)sa, (void)name, (void)access;
    W32Timer *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->o = (W32Obj){W32_TIMER, 1, NULL};
    t->manual = (flags & CREATE_WAITABLE_TIMER_MANUAL_RESET) != 0;
    return t;
}

HANDLE CreateWaitableTimerW(LPSECURITY_ATTRIBUTES sa, BOOL manual, LPCWSTR name) {
    return CreateWaitableTimerExW(sa, name, manual ? CREATE_WAITABLE_TIMER_MANUAL_RESET : 0, TIMER_ALL_ACCESS);
}

BOOL SetWaitableTimer(HANDLE h, const LARGE_INTEGER *due, LONG period, PTIMERAPCROUTINE apc, LPVOID arg, BOOL resume) {
    (void)apc, (void)arg, (void)resume;
    W32Timer *t = (W32Timer *)w32_obj(h, W32_TIMER);
    if (!t) return FALSE;
    uint64_t now = w32_now_ns(), at;
    if (due->QuadPart < 0) at = now + (uint64_t)(-due->QuadPart) * 100u;
    else {   // absolute FILETIME: convert through the wall clock
        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        int64_t wall = (int64_t)((uint64_t)ft.dwHighDateTime << 32 | ft.dwLowDateTime);
        int64_t d = (due->QuadPart - wall) * 100;
        at = d > 0 ? now + (uint64_t)d : now;
    }
    pthread_mutex_lock(&w32_wait_lock);
    t->due_ns = at;
    t->period_ns = period > 0 ? (uint64_t)period * 1000000u : 0;
    t->armed = 1;
    t->set = 0;
    pthread_mutex_unlock(&w32_wait_lock);
    w32_signal_changed(&t->seq);   // waiters recompute their deadline
    return TRUE;
}

BOOL SetWaitableTimerEx(HANDLE t, const LARGE_INTEGER *due, LONG period, PTIMERAPCROUTINE apc, LPVOID arg, PVOID wake,
                        ULONG delay) {
    (void)wake, (void)delay;
    return SetWaitableTimer(t, due, period, apc, arg, FALSE);
}

BOOL CancelWaitableTimer(HANDLE h) {
    W32Timer *t = (W32Timer *)w32_obj(h, W32_TIMER);
    if (!t) return FALSE;
    pthread_mutex_lock(&w32_wait_lock);
    t->armed = 0;
    pthread_mutex_unlock(&w32_wait_lock);
    return TRUE;
}

// ---- threads

// Registry by kernel thread id, for OpenThread and for the suspension handler (which may not take locks): a fixed
// array, slots claimed with a compare-and-swap and read without locks.
#define REG_SLOTS 4096
static W32Thread *volatile reg[REG_SLOTS];
static __thread W32Thread *tself;

static void reg_add(W32Thread *t) {
    for (int i = 0; i < REG_SLOTS; i++) {
        W32Thread *z = NULL;
        if (__atomic_compare_exchange_n(&reg[i], &z, t, 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            t->slot = i;
            return;
        }
    }
    t->slot = -1;
}

static void reg_remove(W32Thread *t) {
    if (t->slot >= 0) __atomic_store_n(&reg[t->slot], NULL, __ATOMIC_RELEASE);
    t->slot = -1;
}

static W32Thread *reg_find(int tid) {
    for (int i = 0; i < REG_SLOTS; i++) {
        W32Thread *t = __atomic_load_n(&reg[i], __ATOMIC_ACQUIRE);
        if (t && t->tid == tid) return t;
    }
    return NULL;
}

static void thread_destroy(W32Obj *o) {
    W32Thread *t = (W32Thread *)o;
    reg_remove(t);
    if (t->has_pt && !t->done) pthread_detach(t->pt);
    else if (t->has_pt) pthread_join(t->pt, NULL);
    pthread_mutex_destroy(&t->smu);
}

static W32Thread *thread_new(void) {
    W32Thread *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->o = (W32Obj){W32_THREAD, 1, thread_destroy};
    pthread_mutex_init(&t->smu, NULL);
    t->slot = -1;
    return t;
}

W32Thread *w32_thread_self(void) {
    if (tself) return tself;
    W32Thread *t = thread_new();
    if (!t) abort();
    t->pt = pthread_self();
    t->tid = (int)GetCurrentThreadId();
    t->gate = 1;
    t->o.refs = 1 << 30;   // a thread we did not start: its record lives as long as the process
    reg_add(t);
    tself = t;
    return t;
}

static void *thread_start(void *p) {
    W32Thread *t = p;
    tself = t;
    t->tid = (int)GetCurrentThreadId();
    reg_add(t);
    while (!__atomic_load_n(&t->gate, __ATOMIC_ACQUIRE)) w32_futex(&t->gate, FUTEX_WAIT, 0, NULL);
    w32_thread_install_altstack();
    DWORD code = t->fn(t->arg);
    t->exit_code = code;
    pthread_mutex_lock(&w32_wait_lock);
    t->done = 1;
    pthread_mutex_unlock(&w32_wait_lock);
    w32_signal_changed(&t->seq);
    reg_remove(t);
    w32_obj_unref(&t->o);   // the thread's own reference
    return NULL;
}

HANDLE CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE fn, LPVOID arg, DWORD flags,
                    LPDWORD tid) {
    (void)sa;
    W32Thread *t = thread_new();
    if (!t) return NULL;
    t->fn = fn;
    t->arg = arg;
    t->o.refs = 2;   // the handle and the running thread
    t->gate = (flags & CREATE_SUSPENDED) ? 0 : 1;
    t->suspend_count = (flags & CREATE_SUSPENDED) ? 1 : 0;
    pthread_attr_t a;
    pthread_attr_init(&a);
    // Lifted code recurses deeply on the host stack; Windows builds link totk.exe with a 16 MiB stack.
    pthread_attr_setstacksize(&a, stack >= (1u << 20) ? stack : (16u << 20));
    int e = pthread_create(&t->pt, &a, thread_start, t);
    pthread_attr_destroy(&a);
    if (e) {
        free(t);
        last_error = w32_errno_to_win(e);
        return NULL;
    }
    t->has_pt = 1;
    if (tid) {   // the kernel id is known once the thread runs
        while (!__atomic_load_n(&t->tid, __ATOMIC_ACQUIRE)) sched_yield();
        *tid = (DWORD)t->tid;
    }
    return t;
}

HANDLE GetCurrentThread(void) {   // a pseudo handle, as on Windows: closing it does nothing
    w32_thread_self();
    return PSEUDO_THREAD;
}
HANDLE GetCurrentProcess(void) { return PSEUDO_PROCESS; }

static W32Thread *thread_of(HANDLE h) {
    if (h == PSEUDO_THREAD) return w32_thread_self();
    return (W32Thread *)w32_obj(h, W32_THREAD);
}

DWORD GetThreadId(HANDLE h) {
    W32Thread *t = thread_of(h);
    if (!t) return 0;
    while (!__atomic_load_n(&t->tid, __ATOMIC_ACQUIRE) && !t->done) sched_yield();
    return (DWORD)t->tid;
}

HANDLE OpenThread(DWORD access, BOOL inherit, DWORD tid) {
    (void)access, (void)inherit;
    W32Thread *t = tid == GetCurrentThreadId() ? w32_thread_self() : reg_find((int)tid);
    if (!t) {
        last_error = ERROR_INVALID_PARAMETER;
        return NULL;
    }
    w32_obj_ref(&t->o);
    return t;
}

BOOL GetExitCodeThread(HANDLE h, LPDWORD code) {
    W32Thread *t = thread_of(h);
    if (!t) return FALSE;
    *code = t->done ? t->exit_code : STILL_ACTIVE;
    return TRUE;
}

void ExitThread(DWORD code) {
    W32Thread *t = tself;
    if (t && t->has_pt) {
        t->exit_code = code;
        pthread_mutex_lock(&w32_wait_lock);
        t->done = 1;
        pthread_mutex_unlock(&w32_wait_lock);
        w32_signal_changed(&t->seq);
        reg_remove(t);
        w32_obj_unref(&t->o);
    }
    pthread_exit(NULL);
}

// Suspension: SuspendThread sends SIG_SUSPEND and waits until the target stopped in the handler, which publishes its
// ucontext and sleeps until ResumeThread moves resume_gen on. Get/SetThreadContext read and write that ucontext, so
// the registers SetThreadContext changed are the ones the handler's return restores.
#define SIG_SUSPEND (SIGRTMIN + 6)

static void suspend_handler(int sig, siginfo_t *si, void *ucv) {
    (void)sig, (void)si;
    int saved_errno = errno;
    W32Thread *t = tself;
    if (!t) t = reg_find((int)syscall(SYS_gettid));
    if (!t) {
        errno = saved_errno;
        return;
    }
    uint32_t gen = __atomic_load_n(&t->resume_gen, __ATOMIC_ACQUIRE);
    t->uc = ucv;
    __atomic_store_n(&t->susp_state, 2, __ATOMIC_RELEASE);
    w32_futex_wake(&t->susp_state, INT_MAX);
    while (__atomic_load_n(&t->resume_gen, __ATOMIC_ACQUIRE) == gen) w32_futex(&t->resume_gen, FUTEX_WAIT, gen, NULL);
    t->uc = NULL;
    __atomic_store_n(&t->susp_state, 0, __ATOMIC_RELEASE);
    w32_futex_wake(&t->susp_state, INT_MAX);
    errno = saved_errno;
}

static pthread_once_t suspend_once = PTHREAD_ONCE_INIT;
static void suspend_init(void) {
    struct sigaction sa = {0};
    sa.sa_sigaction = suspend_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigfillset(&sa.sa_mask);   // nothing else runs on the stopped thread
    sigdelset(&sa.sa_mask, SIGSEGV);
    sigdelset(&sa.sa_mask, SIGBUS);
    sigaction(SIG_SUSPEND, &sa, NULL);
}

DWORD SuspendThread(HANDLE h) {
    W32Thread *t = thread_of(h);
    if (!t) return (DWORD)-1;
    pthread_once(&suspend_once, suspend_init);
    pthread_mutex_lock(&t->smu);
    int prev = t->suspend_count++;
    if (prev == 0 && t->gate && !t->done && t->tid != (int)GetCurrentThreadId()) {
        if (syscall(SYS_tgkill, getpid(), t->tid, SIG_SUSPEND)) {
            t->suspend_count--;
            pthread_mutex_unlock(&t->smu);
            w32_set_errno();
            return (DWORD)-1;
        }
        for (uint32_t s; (s = __atomic_load_n(&t->susp_state, __ATOMIC_ACQUIRE)) != 2;)
            w32_futex(&t->susp_state, FUTEX_WAIT, s, &(struct timespec){0, 1000000});
    }
    pthread_mutex_unlock(&t->smu);
    return (DWORD)prev;
}

DWORD ResumeThread(HANDLE h) {
    W32Thread *t = thread_of(h);
    if (!t) return (DWORD)-1;
    pthread_mutex_lock(&t->smu);
    int prev = t->suspend_count;
    if (prev > 0 && --t->suspend_count == 0) {
        if (!t->gate) {
            __atomic_store_n(&t->gate, 1, __ATOMIC_RELEASE);
            w32_futex_wake(&t->gate, INT_MAX);
        } else if (__atomic_load_n(&t->susp_state, __ATOMIC_ACQUIRE) == 2) {
            __atomic_add_fetch(&t->resume_gen, 1, __ATOMIC_ACQ_REL);
            w32_futex_wake(&t->resume_gen, INT_MAX);
            // The handler acknowledges before the next SuspendThread may count on a new stop.
            while (__atomic_load_n(&t->susp_state, __ATOMIC_ACQUIRE) == 2)
                w32_futex(&t->susp_state, FUTEX_WAIT, 2, NULL);
        }
    }
    pthread_mutex_unlock(&t->smu);
    return (DWORD)prev;
}

static void ctx_from_uc(const ucontext_t *uc, CONTEXT *c) {
    const greg_t *g = uc->uc_mcontext.gregs;
    c->Rax = (DWORD64)g[REG_RAX], c->Rcx = (DWORD64)g[REG_RCX], c->Rdx = (DWORD64)g[REG_RDX];
    c->Rbx = (DWORD64)g[REG_RBX], c->Rsp = (DWORD64)g[REG_RSP], c->Rbp = (DWORD64)g[REG_RBP];
    c->Rsi = (DWORD64)g[REG_RSI], c->Rdi = (DWORD64)g[REG_RDI], c->R8 = (DWORD64)g[REG_R8];
    c->R9 = (DWORD64)g[REG_R9], c->R10 = (DWORD64)g[REG_R10], c->R11 = (DWORD64)g[REG_R11];
    c->R12 = (DWORD64)g[REG_R12], c->R13 = (DWORD64)g[REG_R13], c->R14 = (DWORD64)g[REG_R14];
    c->R15 = (DWORD64)g[REG_R15], c->Rip = (DWORD64)g[REG_RIP], c->EFlags = (DWORD)g[REG_EFL];
    c->MxCsr = uc->uc_mcontext.fpregs ? uc->uc_mcontext.fpregs->mxcsr : 0x1f80;
}

static void ctx_to_uc(const CONTEXT *c, ucontext_t *uc) {
    greg_t *g = uc->uc_mcontext.gregs;
    if ((c->ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
        g[REG_RAX] = (greg_t)c->Rax, g[REG_RCX] = (greg_t)c->Rcx, g[REG_RDX] = (greg_t)c->Rdx;
        g[REG_RBX] = (greg_t)c->Rbx, g[REG_RSI] = (greg_t)c->Rsi, g[REG_RDI] = (greg_t)c->Rdi;
        g[REG_R8] = (greg_t)c->R8, g[REG_R9] = (greg_t)c->R9, g[REG_R10] = (greg_t)c->R10;
        g[REG_R11] = (greg_t)c->R11, g[REG_R12] = (greg_t)c->R12, g[REG_R13] = (greg_t)c->R13;
        g[REG_R14] = (greg_t)c->R14, g[REG_R15] = (greg_t)c->R15;
    }
    if ((c->ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
        g[REG_RSP] = (greg_t)c->Rsp, g[REG_RBP] = (greg_t)c->Rbp, g[REG_RIP] = (greg_t)c->Rip;
        g[REG_EFL] = (greg_t)c->EFlags;
    }
}

void w32_context_from_uc(const void *uc, CONTEXT *c) { ctx_from_uc(uc, c); }
void w32_context_to_uc(const CONTEXT *c, void *uc) { ctx_to_uc(c, uc); }

BOOL GetThreadContext(HANDLE h, LPCONTEXT c) {
    W32Thread *t = thread_of(h);
    if (!t) return FALSE;
    DWORD flags = c->ContextFlags;
    if (t->tid == (int)GetCurrentThreadId()) {
        ucontext_t uc;
        getcontext(&uc);
        ctx_from_uc(&uc, c);
        c->ContextFlags = flags;
        return TRUE;
    }
    if (__atomic_load_n(&t->susp_state, __ATOMIC_ACQUIRE) != 2 || !t->uc) {
        last_error = ERROR_INVALID_PARAMETER;   // not suspended
        return FALSE;
    }
    ctx_from_uc(t->uc, c);
    c->ContextFlags = flags;
    return TRUE;
}

BOOL SetThreadContext(HANDLE h, const CONTEXT *c) {
    W32Thread *t = thread_of(h);
    if (!t) return FALSE;
    if (__atomic_load_n(&t->susp_state, __ATOMIC_ACQUIRE) != 2 || !t->uc) {
        last_error = ERROR_INVALID_PARAMETER;
        return FALSE;
    }
    ctx_to_uc(c, t->uc);
    return TRUE;
}

void RtlCaptureContext(PCONTEXT c) {
    ucontext_t uc;
    getcontext(&uc);
    ctx_from_uc(&uc, c);
    c->ContextFlags = CONTEXT_FULL;
}

// Windows priorities as nice values. Raising above normal needs CAP_SYS_NICE (or an RLIMIT_NICE); without it the
// thread stays at normal, as the call is a hint here.
BOOL SetThreadPriority(HANDLE h, int prio) {
    W32Thread *t = thread_of(h);
    if (!t) return FALSE;
    int nice_v = prio >= THREAD_PRIORITY_TIME_CRITICAL ? -10 : prio <= THREAD_PRIORITY_IDLE ? 19 : -prio * 2;
    if (setpriority(PRIO_PROCESS, (id_t)t->tid, nice_v) && nice_v < 0) setpriority(PRIO_PROCESS, (id_t)t->tid, 0);
    return TRUE;
}

int GetThreadPriority(HANDLE h) {
    W32Thread *t = thread_of(h);
    if (!t) return THREAD_PRIORITY_ERROR_RETURN;
    errno = 0;
    int n = getpriority(PRIO_PROCESS, (id_t)t->tid);
    if (errno) return THREAD_PRIORITY_NORMAL;
    if (n <= -10) return THREAD_PRIORITY_TIME_CRITICAL;
    if (n >= 19) return THREAD_PRIORITY_IDLE;
    return -n / 2;
}

DWORD_PTR SetThreadAffinityMask(HANDLE h, DWORD_PTR mask) {
    W32Thread *t = thread_of(h);
    if (!t) return 0;
    cpu_set_t old, set;
    CPU_ZERO(&set);
    if (sched_getaffinity(t->tid, sizeof old, &old)) return 0;
    for (int i = 0; i < 64; i++)
        if (mask >> i & 1) CPU_SET(i, &set);
    if (sched_setaffinity(t->tid, sizeof set, &set)) {
        w32_set_errno();
        return 0;
    }
    DWORD_PTR prev = 0;
    for (int i = 0; i < 64; i++)
        if (CPU_ISSET(i, &old)) prev |= (DWORD_PTR)1 << i;
    return prev ? prev : 1;
}

BOOL GetProcessAffinityMask(HANDLE p, PDWORD_PTR proc, PDWORD_PTR sys) {
    (void)p;
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof set, &set)) return FALSE;
    DWORD_PTR m = 0;
    for (int i = 0; i < 64; i++)
        if (CPU_ISSET(i, &set)) m |= (DWORD_PTR)1 << i;
    long n = sysconf(_SC_NPROCESSORS_CONF);
    *proc = m;
    *sys = n >= 64 ? ~(DWORD_PTR)0 : (((DWORD_PTR)1 << n) - 1);
    return TRUE;
}

BOOL SetProcessAffinityMask(HANDLE p, DWORD_PTR mask) {
    (void)p;
    cpu_set_t set;
    CPU_ZERO(&set);
    for (int i = 0; i < 64; i++)
        if (mask >> i & 1) CPU_SET(i, &set);
    return sched_setaffinity(0, sizeof set, &set) == 0;
}

HRESULT SetThreadDescription(HANDLE h, LPCWSTR name) {
    W32Thread *t = thread_of(h);
    if (!t || (!t->has_pt && t != tself)) return 0;
    char n[16];
    size_t k = w32_wide_to_utf8(name, wcslen(name), n, sizeof n - 1);
    n[k] = 0;
    pthread_setname_np(t->has_pt ? t->pt : pthread_self(), n);   // 15 bytes at most
    return 0;
}

DWORD GetActiveProcessorCount(WORD group) {
    (void)group;
    cpu_set_t set;
    if (!sched_getaffinity(0, sizeof set, &set)) return (DWORD)CPU_COUNT(&set);
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (DWORD)n : 1;
}

static void ft_from_ns(uint64_t ns, LPFILETIME ft) {
    uint64_t v = ns / 100u;
    ft->dwLowDateTime = (DWORD)v;
    ft->dwHighDateTime = (DWORD)(v >> 32);
}

// utime and stime of /proc/self/task/<tid>/stat (or /proc/self/stat), in clock ticks.
static int stat_times(int tid, uint64_t *ut, uint64_t *st) {
    char path[64], buf[1024];
    if (tid) snprintf(path, sizeof path, "/proc/self/task/%d/stat", tid);
    else snprintf(path, sizeof path, "/proc/self/stat");
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    if (!p) return 0;
    unsigned long long u, s;
    // after ") ": state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime stime
    if (sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu", &u, &s) != 2) return 0;
    *ut = u, *st = s;
    return 1;
}

BOOL GetThreadTimes(HANDLE h, LPFILETIME create, LPFILETIME exit_, LPFILETIME kernel, LPFILETIME user) {
    W32Thread *t = thread_of(h);
    if (!t) return FALSE;
    memset(create, 0, sizeof *create);
    memset(exit_, 0, sizeof *exit_);
    uint64_t u, s, hz = (uint64_t)sysconf(_SC_CLK_TCK);
    clockid_t cid;
    struct timespec ts;
    if (t->has_pt && !t->done && !pthread_getcpuclockid(t->pt, &cid) && !clock_gettime(cid, &ts) &&
        stat_times(t->tid, &u, &s)) {
        // the CPU clock is exact; the kernel/user split comes from the tick counts
        uint64_t total = (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec, k = u + s;
        uint64_t kern = k ? total / k * s : 0;
        ft_from_ns(kern, kernel);
        ft_from_ns(total - kern, user);
        return TRUE;
    }
    if (!stat_times(t->tid, &u, &s)) return FALSE;
    ft_from_ns(s * 1000000000u / hz, kernel);
    ft_from_ns(u * 1000000000u / hz, user);
    return TRUE;
}

BOOL GetProcessTimes(HANDLE p, LPFILETIME create, LPFILETIME exit_, LPFILETIME kernel, LPFILETIME user) {
    (void)p;
    struct rusage ru;
    memset(create, 0, sizeof *create);
    memset(exit_, 0, sizeof *exit_);
    if (getrusage(RUSAGE_SELF, &ru)) return FALSE;
    ft_from_ns((uint64_t)ru.ru_stime.tv_sec * 1000000000u + (uint64_t)ru.ru_stime.tv_usec * 1000u, kernel);
    ft_from_ns((uint64_t)ru.ru_utime.tv_sec * 1000000000u + (uint64_t)ru.ru_utime.tv_usec * 1000u, user);
    return TRUE;
}

// /proc/stat's first line: user nice system idle iowait irq softirq steal. Kernel time includes idle, as on Windows.
BOOL GetSystemTimes(LPFILETIME idle, LPFILETIME kernel, LPFILETIME user) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return FALSE;
    unsigned long long us = 0, ni = 0, sy = 0, id = 0, io = 0, irq = 0, sirq = 0, st = 0;
    int n = fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu %llu", &us, &ni, &sy, &id, &io, &irq, &sirq, &st);
    fclose(f);
    if (n < 4) return FALSE;
    uint64_t hz = (uint64_t)sysconf(_SC_CLK_TCK), ns = 1000000000u / hz;
    ft_from_ns((id + io) * ns, idle);
    ft_from_ns((sy + irq + sirq + id + io) * ns, kernel);
    ft_from_ns((us + ni + st) * ns, user);
    return TRUE;
}

BOOL QueryThreadCycleTime(HANDLE h, PULONG64 cycles) {
    W32Thread *t = thread_of(h);
    clockid_t cid;
    struct timespec ts;
    if (!t || !t->has_pt || pthread_getcpuclockid(t->pt, &cid) || clock_gettime(cid, &ts)) {
        if (t == tself && !clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts)) goto ok;
        return FALSE;
    }
ok:
    *cycles = (ULONG64)ts.tv_sec * 1000000000u + (ULONG64)ts.tv_nsec;   // nanoseconds stand in for cycles
    return TRUE;
}

// ---- fibers

typedef struct {
    ucontext_t uc;
    void *stack;
    size_t stack_size;
    LPFIBER_START_ROUTINE fn;
    void *param;
    int is_thread;   // the converted thread's own context
} W32Fiber;

static __thread W32Fiber *cur_fiber;

LPVOID ConvertThreadToFiberEx(LPVOID param, DWORD flags) {
    (void)flags;   // ucontext switches always carry the FP control state
    if (cur_fiber) return cur_fiber;
    W32Fiber *f = calloc(1, sizeof *f);
    if (!f) return NULL;
    f->param = param;
    f->is_thread = 1;
    cur_fiber = f;
    return f;
}

LPVOID ConvertThreadToFiber(LPVOID param) { return ConvertThreadToFiberEx(param, 0); }

BOOL ConvertFiberToThread(void) {
    if (!cur_fiber) return FALSE;
    if (cur_fiber->is_thread) free(cur_fiber);
    cur_fiber = NULL;
    return TRUE;
}

static void fiber_entry(void) {
    W32Fiber *f = cur_fiber;
    f->fn(f->param);
    // A fiber function that returns ends its thread, as on Windows.
    ExitThread(0);
}

LPVOID CreateFiberEx(SIZE_T commit, SIZE_T reserve, DWORD flags, LPFIBER_START_ROUTINE fn, LPVOID param) {
    (void)flags;
    size_t n = reserve > commit ? reserve : commit;
    if (n < (256u << 10)) n = 1u << 20;
    n = (n + 0xffff) & ~(size_t)0xffff;
    W32Fiber *f = calloc(1, sizeof *f);
    if (!f) return NULL;
    // A guard page below the stack
    void *mem = mmap(NULL, n + 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (mem == MAP_FAILED) {
        free(f);
        last_error = ERROR_NOT_ENOUGH_MEMORY;
        return NULL;
    }
    mprotect(mem, 0x1000, PROT_NONE);
    f->stack = mem;
    f->stack_size = n + 0x1000;
    f->fn = fn;
    f->param = param;
    getcontext(&f->uc);
    f->uc.uc_stack.ss_sp = (char *)mem + 0x1000;
    f->uc.uc_stack.ss_size = n;
    f->uc.uc_link = NULL;
    makecontext(&f->uc, fiber_entry, 0);
    return f;
}

LPVOID CreateFiber(SIZE_T stack, LPFIBER_START_ROUTINE fn, LPVOID param) { return CreateFiberEx(stack, 0, 0, fn, param); }

void SwitchToFiber(LPVOID to) {
    W32Fiber *from = cur_fiber, *f = to;
    if (!from || from == f) return;
    cur_fiber = f;
    swapcontext(&from->uc, &f->uc);
}

void DeleteFiber(LPVOID p) {
    W32Fiber *f = p;
    if (!f) return;
    if (f == cur_fiber) ExitThread(0);
    if (f->stack) munmap(f->stack, f->stack_size);
    free(f);
}

PVOID GetCurrentFiber(void) { return cur_fiber; }
PVOID GetFiberData(void) { return cur_fiber ? cur_fiber->param : NULL; }
