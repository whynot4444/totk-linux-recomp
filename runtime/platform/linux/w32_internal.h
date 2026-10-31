// Internals shared by the win32_*.c files of the Linux Win32 stand-in (windows.h in this folder).
#pragma once
#include <limits.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include "windows.h"

// ---- futex
static inline long w32_futex(volatile void *addr, int op, uint32_t val, const struct timespec *ts) {
    return syscall(SYS_futex, addr, op | FUTEX_PRIVATE_FLAG, val, ts, NULL, 0);
}
static inline void w32_futex_wake(volatile void *addr, int n) { w32_futex(addr, FUTEX_WAKE, (uint32_t)n, NULL); }
// Waits while *addr == val, at most ms (INFINITE: no limit). 0 on timeout, 1 otherwise (woken, changed, spurious).
int w32_futex_wait_ms(volatile uint32_t *addr, uint32_t val, DWORD ms);
// Same with an absolute CLOCK_MONOTONIC deadline in ns (UINT64_MAX: none).
int w32_futex_wait_until(volatile uint32_t *addr, uint32_t val, uint64_t deadline_ns);

uint64_t w32_now_ns(void);   // CLOCK_MONOTONIC
void w32_set_errno(void);    // SetLastError(w32_errno_to_win(errno))

// ---- handles. Every HANDLE the stand-in hands out points at one of these (pseudo handles excepted).
enum { W32_THREAD = 0x54485244, W32_EVENT, W32_SEM, W32_TIMER, W32_FILE, W32_MAPPING, W32_PROCESS, W32_FIND };
typedef struct W32Obj {
    uint32_t magic;          // one of the kinds above; 0 once freed
    volatile int refs;       // CloseHandle drops one; a thread's own reference keeps its object alive until it exits
    void (*destroy)(struct W32Obj *);
} W32Obj;
W32Obj *w32_obj(HANDLE h, uint32_t kind);   // NULL (and ERROR_INVALID_HANDLE) when h is not of that kind
void w32_obj_ref(W32Obj *o);
void w32_obj_unref(W32Obj *o);

// Waitable objects (threads, events, semaphores, timers, processes) share one lock; seq is the futex word their
// waiters sleep on, bumped by every change of state. g_any_seq is bumped too, for waits on several objects.
extern pthread_mutex_t w32_wait_lock;
extern volatile uint32_t w32_any_seq;
void w32_signal_changed(volatile uint32_t *seq);   // bumps seq and w32_any_seq, wakes their waiters

// ---- threads
typedef struct W32Thread W32Thread;
W32Thread *w32_thread_self(void);   // the record of the calling thread, created for threads we did not start
void w32_thread_install_altstack(void);

// ---- files: the fd behind a file handle (or a std handle), -1 when h is none
int w32_handle_fd(HANDLE h);
HANDLE w32_fd_handle(int fd, int close_on_free);   // a file handle around fd

// ---- memory: a write about to land in [p, p+n) from a system call (read into guest memory): the write-watch
// fallback opens those pages first, as the kernel cannot fault them in.
void w32_ww_prepare_write(void *p, size_t n);
// Called first by the fault handler: 1 when the fault was a write-watch fault, now resolved.
int w32_ww_fault(void *addr, int is_write);
void w32_exceptions_init(void);

// ---- paths: utf8 (either separator) as the system path into out (PATH_MAX), resolved ignoring case; create: the
// last component may not exist yet.
char *w32_sys_path(const char *utf8, char *out, int create);

void w32_win_sep(char *p);        // '/' to '\\' in a path handed to the runtime
void w32_win_sep_w(wchar_t *p);

// ---- strings
size_t w32_utf8_to_wide(const char *s, size_t n, wchar_t *out, size_t cap);   // characters written, no NUL added
size_t w32_wide_to_utf8(const wchar_t *w, size_t n, char *out, size_t cap);   // bytes written, no NUL added
