// Linux Win32 stand-in, part 3: virtual memory with Windows' reserve/commit model, write watching, and vectored
// exception handlers fed by the fault signals.
//
// Reservations. VirtualAlloc(MEM_RESERVE) maps PROT_NONE (MAP_NORESERVE) and keeps a byte per page: committed,
// protection, and the write-watch state. Commit is mprotect; decommit is MADV_DONTNEED plus PROT_NONE, so a page
// committed again reads as zeros, as on Windows. VirtualQuery answers from those bytes; for memory nobody reserved
// through here (libraries, malloc) it reads /proc/self/maps.
//
// Write watching (MEM_WRITE_WATCH, GetWriteWatch). Preferred: userfaultfd asynchronous write protection with the
// PAGEMAP_SCAN ioctl (Linux 6.7+), the mechanism Wine uses for the same API. The kernel tracks written pages without
// a fault reaching user space, kernel writes (read() into the region) are tracked too, and a scan can re-protect what
// it reports in the same call. Fallback (older kernels, userfaultfd disallowed): watched pages are kept read-only until
// written; the first write faults, is recorded and opens the page; ReadFile opens the pages of its buffer first
// (w32_ww_prepare_write), as the kernel will not take that fault for us.
//
// Each change of protection can split a kernel mapping, and Linux limits a process to vm.max_map_count mappings
// (65530 by default on some distributions): docs/linux.md says how to raise it.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/userfaultfd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <ucontext.h>
#include <unistd.h>

#include "w32_internal.h"

#define PAGE 0x1000ull
#define GRAN 0x10000ull   // allocation granularity, as on Windows

// Page byte: protection index (bits 0-2), committed (bit 3), fallback write watch: written (bit 4), armed (bit 5:
// logically writable, mapped read-only until written).
enum { P_NA, P_RO, P_RW, P_RX, P_RWX, P_WC, P_WCX };
#define PG_PROT 7u
#define PG_COMMIT 8u
#define PG_DIRTY 16u
#define PG_ARMED 32u

typedef struct {
    uintptr_t base;
    size_t size;
    uint8_t *pages;    // size / PAGE bytes, mmap'd lazily
    int watch;         // MEM_WRITE_WATCH: 1 userfaultfd, 2 fallback
} Res;

#define MAX_RES 8192
static Res g_res[MAX_RES];   // sorted by base
static int g_nres;
static SRWLOCK g_vm = SRWLOCK_INIT;   // futex-based: the fault handler may take it shared

static int g_uffd = -2;    // -2 not tried, -1 unavailable
static int g_pagemap = -1;
static SRWLOCK g_uffd_lock = SRWLOCK_INIT;

static int prot_index(DWORD p) {
    switch (p & 0xffu) {
    case PAGE_READONLY: return P_RO;
    case PAGE_READWRITE: return P_RW;
    case PAGE_EXECUTE: case PAGE_EXECUTE_READ: return P_RX;
    case PAGE_EXECUTE_READWRITE: return P_RWX;
    case PAGE_WRITECOPY: return P_WC;
    case 0x80: return P_WCX;   // PAGE_EXECUTE_WRITECOPY
    case PAGE_NOACCESS: return P_NA;
    default: return -1;
    }
}

static DWORD prot_win(int i) {
    static const DWORD t[] = {PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
                              PAGE_WRITECOPY, 0x80};
    return t[i & 7];
}

static int prot_unix(int i) {
    static const int t[] = {PROT_NONE, PROT_READ, PROT_READ | PROT_WRITE, PROT_READ | PROT_EXEC,
                            PROT_READ | PROT_WRITE | PROT_EXEC, PROT_READ | PROT_WRITE,
                            PROT_READ | PROT_WRITE | PROT_EXEC};
    return t[i & 7];
}

static int writable(int i) { return i == P_RW || i == P_RWX || i == P_WC || i == P_WCX; }

// g_vm held (either mode). The reservation holding a, or NULL.
static Res *res_find(uintptr_t a) {
    int lo = 0, hi = g_nres;
    while (lo < hi) {
        int mid = (lo + hi) / 2;
        if (g_res[mid].base <= a) lo = mid + 1;
        else hi = mid;
    }
    if (!lo) return NULL;
    Res *r = &g_res[lo - 1];
    return a - r->base < r->size ? r : NULL;
}

// ---- userfaultfd

static int uffd_init(void) {
    if (g_uffd != -2) return g_uffd >= 0;
    AcquireSRWLockExclusive(&g_uffd_lock);
    if (g_uffd == -2) {
        g_uffd = -1;
        const char *off = getenv("TOTK_WRITE_WATCH");   // "mprotect": force the fallback
        int fd = off && !strcmp(off, "mprotect") ? -1
                 : (int)syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
        if (fd >= 0) {
            struct uffdio_api api = {.api = UFFD_API, .features = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_UNPOPULATED};
            int pm = open("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
            if (!ioctl(fd, UFFDIO_API, &api) && pm >= 0) {
                g_uffd = fd;
                g_pagemap = pm;
            } else {
                close(fd);
                if (pm >= 0) close(pm);
            }
        }
        if (g_uffd < 0)
            fprintf(stderr, "win32 shim: userfaultfd write protection unavailable; write watching uses mprotect "
                            "(slower; see docs/linux.md)\n");
    }
    ReleaseSRWLockExclusive(&g_uffd_lock);
    return g_uffd >= 0;
}

static int uffd_register(uintptr_t a, size_t n) {
    struct uffdio_register r = {.range = {a, n}, .mode = UFFDIO_REGISTER_MODE_WP};
    return !ioctl(g_uffd, UFFDIO_REGISTER, &r);
}

static void uffd_protect(uintptr_t a, size_t n) {
    struct uffdio_writeprotect wp = {.range = {a, n}, .mode = UFFDIO_WRITEPROTECT_MODE_WP};
    ioctl(g_uffd, UFFDIO_WRITEPROTECT, &wp);
}

// ---- page state helpers (g_vm held exclusively unless noted)

// Applies the actual protection of pages [i, j) of r from their bytes, in runs.
static int apply_prot(Res *r, size_t i, size_t j) {
    while (i < j) {
        uint8_t b = r->pages[i];
        int up = (b & PG_COMMIT) ? prot_unix(b & PG_PROT) : PROT_NONE;
        if ((b & PG_ARMED)) up &= ~PROT_WRITE;
        size_t k = i + 1;
        while (k < j) {
            uint8_t c = r->pages[k];
            int uq = (c & PG_COMMIT) ? prot_unix(c & PG_PROT) : PROT_NONE;
            if (c & PG_ARMED) uq &= ~PROT_WRITE;
            if (uq != up) break;
            k++;
        }
        if (mprotect((void *)(r->base + i * PAGE), (k - i) * PAGE, up)) {
            w32_set_errno();
            if (errno == ENOMEM)
                fprintf(stderr, "win32 shim: mprotect failed with ENOMEM: too many mappings; raise vm.max_map_count "
                                "(docs/linux.md)\n");
            return 0;
        }
        i = k;
    }
    return 1;
}

static int res_add(uintptr_t base, size_t size, int watch) {
    if (g_nres == MAX_RES) return 0;
    uint8_t *pages = mmap(NULL, size / PAGE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (pages == MAP_FAILED) return 0;
    int i = g_nres;
    while (i > 0 && g_res[i - 1].base > base) {
        g_res[i] = g_res[i - 1];
        i--;
    }
    g_res[i] = (Res){base, size, pages, watch};
    g_nres++;
    return 1;
}

static void res_remove(Res *r) {
    munmap(r->pages, r->size / PAGE);
    int i = (int)(r - g_res);
    memmove(&g_res[i], &g_res[i + 1], (size_t)(g_nres - i - 1) * sizeof *g_res);
    g_nres--;
}

// Commits pages [a, a+n) of r with protection index pi. g_vm exclusive.
static int commit_range(Res *r, uintptr_t a, size_t n, int pi) {
    size_t i = (a - r->base) / PAGE, j = i + n / PAGE;
    for (size_t k = i; k < j; k++) {
        uint8_t b = r->pages[k];
        if (!(b & PG_COMMIT)) b = PG_COMMIT;   // fresh: not written yet
        b = (uint8_t)((b & ~PG_PROT) | (unsigned)pi);
        if (r->watch == 2) b = writable(pi) && !(b & PG_DIRTY) ? (b | PG_ARMED) : (b & ~PG_ARMED);
        r->pages[k] = b;
    }
    if (!apply_prot(r, i, j)) return 0;
    if (r->watch == 1) uffd_protect(a, n);   // newly populated pages start unwritten
    return 1;
}

static int decommit_range(Res *r, uintptr_t a, size_t n) {
    size_t i = (a - r->base) / PAGE, j = i + n / PAGE;
    if (madvise((void *)a, n, MADV_DONTNEED) || mprotect((void *)a, n, PROT_NONE)) {
        w32_set_errno();
        return 0;
    }
    memset(r->pages + i, 0, j - i);
    if (r->watch == 1) uffd_protect(a, n);   // the zapped pages lost their markers
    return 1;
}

// ---- VirtualAlloc and friends

static void *map_anywhere(size_t n) {
    // Over-map by the granularity and trim, for the 64 KiB alignment Windows gives
    uint8_t *p = mmap(NULL, n + GRAN, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) return NULL;
    uintptr_t a = ((uintptr_t)p + GRAN - 1) & ~(uintptr_t)(GRAN - 1);
    if (a > (uintptr_t)p) munmap(p, a - (uintptr_t)p);
    uintptr_t end = (uintptr_t)p + n + GRAN;
    if (end > a + n) munmap((void *)(a + n), end - (a + n));
    return (void *)a;
}

LPVOID VirtualAlloc(LPVOID addr, SIZE_T n, DWORD type, DWORD prot) {
    int pi = prot_index(prot);
    if (!n || pi < 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (type & MEM_RESET) return addr;   // contents may be discarded: keeping them is allowed
    if (type & MEM_RESERVE) {
        uintptr_t a = (uintptr_t)addr & ~(uintptr_t)(GRAN - 1);
        size_t size = (size_t)((((uintptr_t)addr + n + PAGE - 1) & ~(uintptr_t)(PAGE - 1)) - (a ? a : 0));
        if (!a) size = (n + PAGE - 1) & ~(size_t)(PAGE - 1);
        void *p;
        if (a) {
            p = mmap((void *)a, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
            if (p != MAP_FAILED && p != (void *)a) {   // a kernel without MAP_FIXED_NOREPLACE took it as a hint
                munmap(p, size);
                p = MAP_FAILED;
                errno = EEXIST;
            }
            if (p == MAP_FAILED) {
                SetLastError(ERROR_INVALID_ADDRESS);
                return NULL;
            }
        } else if (!(p = map_anywhere(size))) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        int watch = 0;
        if (type & MEM_WRITE_WATCH) watch = uffd_init() && uffd_register((uintptr_t)p, size) ? 1 : 2;
        if (watch == 1) uffd_protect((uintptr_t)p, size);   // markers on every page: none counts as written yet
        AcquireSRWLockExclusive(&g_vm);
        int ok = res_add((uintptr_t)p, size, watch);
        Res *r = ok ? res_find((uintptr_t)p) : NULL;
        if (r && (type & MEM_COMMIT)) ok = commit_range(r, (uintptr_t)p, size, pi);
        if (!ok && r) res_remove(r);
        ReleaseSRWLockExclusive(&g_vm);
        if (!ok) {
            munmap(p, size);
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return NULL;
        }
        return p;
    }
    if (type & MEM_COMMIT) {
        if (!addr) {   // MEM_COMMIT alone with no address reserves too
            return VirtualAlloc(NULL, n, MEM_RESERVE | MEM_COMMIT | (type & MEM_WRITE_WATCH), prot);
        }
        uintptr_t a = (uintptr_t)addr & ~(uintptr_t)(PAGE - 1);
        size_t size = (((uintptr_t)addr + n + PAGE - 1) & ~(uintptr_t)(PAGE - 1)) - a;
        AcquireSRWLockExclusive(&g_vm);
        Res *r = res_find(a);
        int ok = r && a + size <= r->base + r->size && commit_range(r, a, size, pi);
        ReleaseSRWLockExclusive(&g_vm);
        if (!ok) {
            if (!r) SetLastError(ERROR_INVALID_ADDRESS);
            return NULL;
        }
        return (void *)a;
    }
    SetLastError(ERROR_INVALID_PARAMETER);
    return NULL;
}

BOOL VirtualFree(LPVOID addr, SIZE_T n, DWORD type) {
    uintptr_t a = (uintptr_t)addr;
    AcquireSRWLockExclusive(&g_vm);
    Res *r = res_find(a);
    int ok = 0;
    if (!r) SetLastError(ERROR_INVALID_ADDRESS);
    else if (type & MEM_RELEASE) {
        if (n || a != r->base) SetLastError(ERROR_INVALID_PARAMETER);
        else {
            munmap((void *)r->base, r->size);
            res_remove(r);
            ok = 1;
        }
    } else if (type & MEM_DECOMMIT) {
        uintptr_t s = a & ~(uintptr_t)(PAGE - 1);
        size_t size = n ? (((a + n + PAGE - 1) & ~(uintptr_t)(PAGE - 1)) - s) : r->base + r->size - s;
        if (s + size > r->base + r->size) SetLastError(ERROR_INVALID_PARAMETER);
        else ok = decommit_range(r, s, size);
    } else SetLastError(ERROR_INVALID_PARAMETER);
    ReleaseSRWLockExclusive(&g_vm);
    return ok;
}

// Memory outside our reservations: the protection of the mapping holding a from /proc/self/maps.
static int maps_lookup(uintptr_t a, uintptr_t *lo, uintptr_t *hi, DWORD *prot) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return -1;
    char line[512];
    uintptr_t prev_end = 0;
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long s, e;
        char perm[8];
        if (sscanf(line, "%lx-%lx %7s", &s, &e, perm) != 3) continue;
        if (a < s) {   // in the gap before this mapping
            *lo = prev_end, *hi = s;
            found = 0;
            fclose(f);
            return 0;
        }
        if (a < e) {
            *lo = s, *hi = e;
            int r = perm[0] == 'r', w = perm[1] == 'w', x = perm[2] == 'x';
            *prot = x ? (w ? PAGE_EXECUTE_READWRITE : r ? PAGE_EXECUTE_READ : PAGE_EXECUTE)
                      : w ? PAGE_READWRITE : r ? PAGE_READONLY : PAGE_NOACCESS;
            found = 1;
            break;
        }
        prev_end = e;
    }
    fclose(f);
    if (!found) *lo = prev_end, *hi = (uintptr_t)0x800000000000ull;
    return found;
}

SIZE_T VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T n) {
    if (n < sizeof *mbi) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    uintptr_t a = (uintptr_t)addr & ~(uintptr_t)(PAGE - 1);
    if (a >= 0x800000000000ull) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    memset(mbi, 0, sizeof *mbi);
    AcquireSRWLockShared(&g_vm);
    Res *r = res_find(a);
    if (r) {
        size_t i = (a - r->base) / PAGE, end = r->size / PAGE;
        uint8_t key = r->pages[i] & (PG_COMMIT | PG_PROT);
        if (!(key & PG_COMMIT)) key = 0;
        size_t j = i + 1;
        if (!key)   // reserved pages are zero bytes: skip them 8 at a time
            while (j + 8 <= end && !*(const uint64_t *)(const void *)(r->pages + j)) j += 8;
        while (j < end) {
            uint8_t b = r->pages[j] & (PG_COMMIT | PG_PROT);
            if (!(b & PG_COMMIT)) b = 0;
            if (b != key) break;
            j++;
        }
        mbi->BaseAddress = (void *)a;
        mbi->AllocationBase = (void *)r->base;
        mbi->AllocationProtect = PAGE_NOACCESS;
        mbi->RegionSize = (j - i) * PAGE;
        mbi->State = (key & PG_COMMIT) ? MEM_COMMIT : MEM_RESERVE;
        mbi->Protect = (key & PG_COMMIT) ? prot_win(key & PG_PROT) : 0;
        mbi->Type = MEM_PRIVATE;
        ReleaseSRWLockShared(&g_vm);
        return sizeof *mbi;
    }
    // Clip a free or foreign range at the next reservation
    uintptr_t next_res = 0x800000000000ull;
    for (int k = 0; k < g_nres; k++)
        if (g_res[k].base > a) {
            next_res = g_res[k].base;
            break;
        }
    uintptr_t prev_res_end = 0;
    for (int k = 0; k < g_nres && g_res[k].base < a; k++) prev_res_end = g_res[k].base + g_res[k].size;
    ReleaseSRWLockShared(&g_vm);
    uintptr_t lo, hi;
    DWORD prot = 0;
    int m = maps_lookup(a, &lo, &hi, &prot);
    if (m < 0) {
        SetLastError(ERROR_ACCESS_DENIED);
        return 0;
    }
    if (hi > next_res) hi = next_res;
    if (lo < prev_res_end) lo = prev_res_end;
    mbi->BaseAddress = (void *)a;
    mbi->RegionSize = hi - a;
    if (m) {
        mbi->AllocationBase = (void *)lo;
        mbi->AllocationProtect = prot;
        mbi->State = MEM_COMMIT;
        mbi->Protect = prot;
        mbi->Type = MEM_PRIVATE;
    } else {
        mbi->State = MEM_FREE;
        mbi->Protect = PAGE_NOACCESS;
    }
    return sizeof *mbi;
}

BOOL VirtualProtect(LPVOID addr, SIZE_T n, DWORD prot, PDWORD old) {
    int pi = prot_index(prot);
    uintptr_t a = (uintptr_t)addr & ~(uintptr_t)(PAGE - 1);
    size_t size = (((uintptr_t)addr + n + PAGE - 1) & ~(uintptr_t)(PAGE - 1)) - a;
    if (pi < 0 || !n) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    AcquireSRWLockExclusive(&g_vm);
    Res *r = res_find(a);
    if (!r) {   // not ours (a library's pages): plain mprotect
        ReleaseSRWLockExclusive(&g_vm);
        MEMORY_BASIC_INFORMATION mbi;
        if (old) *old = VirtualQuery(addr, &mbi, sizeof mbi) ? mbi.Protect : PAGE_NOACCESS;
        if (mprotect((void *)a, size, prot_unix(pi))) {
            w32_set_errno();
            return FALSE;
        }
        return TRUE;
    }
    size_t i = (a - r->base) / PAGE, j = i + size / PAGE;
    int ok = a + size <= r->base + r->size;
    for (size_t k = i; ok && k < j; k++) ok = (r->pages[k] & PG_COMMIT) != 0;   // every page committed
    if (!ok) {
        ReleaseSRWLockExclusive(&g_vm);
        SetLastError(ERROR_INVALID_ADDRESS);
        return FALSE;
    }
    if (old) *old = prot_win(r->pages[i] & PG_PROT);
    for (size_t k = i; k < j; k++) {
        uint8_t b = (uint8_t)((r->pages[k] & ~PG_PROT) | (unsigned)pi);
        if (r->watch == 2) b = writable(pi) && !(b & PG_DIRTY) ? (b | PG_ARMED) : (b & ~PG_ARMED);
        r->pages[k] = b;
    }
    ok = apply_prot(r, i, j);
    ReleaseSRWLockExclusive(&g_vm);
    return ok;
}

// ---- write watch

UINT GetWriteWatch(DWORD flags, PVOID base, SIZE_T n, PVOID *addrs, ULONG_PTR *count, ULONG *gran) {
    uintptr_t a = (uintptr_t)base & ~(uintptr_t)(PAGE - 1);
    uintptr_t end = ((uintptr_t)base + n + PAGE - 1) & ~(uintptr_t)(PAGE - 1);
    ULONG_PTR max = *count, got = 0;
    if (gran) *gran = (ULONG)PAGE;
    AcquireSRWLockShared(&g_vm);
    Res *r = res_find(a);
    if (!r || !r->watch || end > r->base + r->size) {
        ReleaseSRWLockShared(&g_vm);
        SetLastError(ERROR_INVALID_PARAMETER);
        return 1;
    }
    if (r->watch == 1) {
        struct page_region reg[64];
        uint64_t at = a;
        while (at < end && got < max) {
            struct pm_scan_arg s = {
                .size = sizeof s,
                .flags = (flags & WRITE_WATCH_FLAG_RESET) ? (PM_SCAN_WP_MATCHING | PM_SCAN_CHECK_WPASYNC) : 0,
                .start = at, .end = end, .vec = (uint64_t)(uintptr_t)reg, .vec_len = 64,
                .max_pages = max - got,
                .category_mask = PAGE_IS_WRITTEN, .return_mask = PAGE_IS_WRITTEN};
            long k = ioctl(g_pagemap, PAGEMAP_SCAN, &s);
            if (k < 0) {
                ReleaseSRWLockShared(&g_vm);
                w32_set_errno();
                return 1;
            }
            for (long i = 0; i < k; i++)
                for (uint64_t p = reg[i].start; p < reg[i].end && got < max; p += PAGE)
                    if (r->pages[(p - r->base) / PAGE] & PG_COMMIT) addrs[got++] = (void *)p;
            if (!s.walk_end || s.walk_end <= at) break;
            at = s.walk_end;
        }
        ReleaseSRWLockShared(&g_vm);
        *count = got;
        return 0;
    }
    // Fallback: the dirty bits. Re-arming changes protection, so take the lock exclusively for a reset.
    ReleaseSRWLockShared(&g_vm);
    int reset = (flags & WRITE_WATCH_FLAG_RESET) != 0;
    if (reset) AcquireSRWLockExclusive(&g_vm);
    else AcquireSRWLockShared(&g_vm);
    r = res_find(a);
    size_t i0 = (a - r->base) / PAGE, i1 = (end - r->base) / PAGE, last = i0;
    for (size_t i = i0; i < i1 && got < max; i++) {
        uint8_t *b = &r->pages[i];
        if (!(__atomic_load_n(b, __ATOMIC_ACQUIRE) & PG_DIRTY)) continue;
        addrs[got++] = (void *)(r->base + i * PAGE);
        if (reset) {
            uint8_t v = *b & ~PG_DIRTY;
            if ((v & PG_COMMIT) && writable(v & PG_PROT)) v |= PG_ARMED;
            __atomic_store_n(b, v, __ATOMIC_RELEASE);
        }
        last = i + 1;
    }
    if (reset && last > i0) apply_prot(r, i0, last);
    if (reset) ReleaseSRWLockExclusive(&g_vm);
    else ReleaseSRWLockShared(&g_vm);
    *count = got;
    return 0;
}

UINT ResetWriteWatch(LPVOID base, SIZE_T n) {
    enum { CHUNK = 4096 };
    PVOID tmp[CHUNK];
    for (;;) {
        ULONG_PTR c = CHUNK;
        if (GetWriteWatch(WRITE_WATCH_FLAG_RESET, base, n, tmp, &c, NULL)) return 1;
        if (c < CHUNK) return 0;
    }
}

// Fallback write watch: a fault on an armed page. Called from the signal handler.
int w32_ww_fault(void *addr, int is_write) {
    if (!is_write || !g_nres) return 0;
    uintptr_t a = (uintptr_t)addr;
    AcquireSRWLockShared(&g_vm);
    Res *r = res_find(a);
    int ok = 0;
    if (r && r->watch == 2) {
        size_t i = (a - r->base) / PAGE;
        uint8_t b = __atomic_load_n(&r->pages[i], __ATOMIC_ACQUIRE);
        if ((b & PG_COMMIT) && writable(b & PG_PROT)) {
            __atomic_store_n(&r->pages[i], (uint8_t)((b | PG_DIRTY) & ~PG_ARMED), __ATOMIC_RELEASE);
            ok = !mprotect((void *)(a & ~(uintptr_t)(PAGE - 1)), PAGE, prot_unix(b & PG_PROT));
        }
    }
    ReleaseSRWLockShared(&g_vm);
    return ok;
}

void w32_ww_prepare_write(void *p, size_t n) {
    if (!n || !g_nres) return;
    uintptr_t a = (uintptr_t)p & ~(uintptr_t)(PAGE - 1), end = (uintptr_t)p + n;
    for (; a < end; a += PAGE) {
        AcquireSRWLockShared(&g_vm);
        Res *r = res_find(a);
        int armed = r && r->watch == 2 && (r->pages[(a - r->base) / PAGE] & PG_ARMED);
        ReleaseSRWLockShared(&g_vm);
        if (armed) w32_ww_fault((void *)a, 1);
    }
}

BOOL ReadProcessMemory(HANDLE p, LPCVOID from, LPVOID to, SIZE_T n, SIZE_T *got) {
    (void)p;
    struct iovec l = {to, n}, r = {(void *)from, n};
    ssize_t k = process_vm_readv(getpid(), &l, 1, &r, 1, 0);
    if (got) *got = k > 0 ? (SIZE_T)k : 0;
    if (k != (ssize_t)n) {
        SetLastError(ERROR_NOACCESS);   // partial copy
        return FALSE;
    }
    return TRUE;
}

BOOL FlushInstructionCache(HANDLE p, LPCVOID a, SIZE_T n) {
    (void)p, (void)a, (void)n;
    return TRUE;   // x86 keeps caches coherent
}

BOOL GlobalMemoryStatusEx(LPMEMORYSTATUSEX ms) {
    unsigned long long total = 0, avail = 0, swap = 0, swapfree = 0;
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return FALSE;
    char line[128];
    while (fgets(line, sizeof line, f)) {
        unsigned long long v;
        if (sscanf(line, "MemTotal: %llu", &v) == 1) total = v << 10;
        else if (sscanf(line, "MemAvailable: %llu", &v) == 1) avail = v << 10;
        else if (sscanf(line, "SwapTotal: %llu", &v) == 1) swap = v << 10;
        else if (sscanf(line, "SwapFree: %llu", &v) == 1) swapfree = v << 10;
    }
    fclose(f);
    ms->dwMemoryLoad = total ? (DWORD)(100 - avail * 100 / total) : 0;
    ms->ullTotalPhys = total;
    ms->ullAvailPhys = avail;
    ms->ullTotalPageFile = total + swap;
    ms->ullAvailPageFile = avail + swapfree;
    ms->ullTotalVirtual = 0x800000000000ull;
    ms->ullAvailVirtual = 0x800000000000ull;
    ms->ullAvailExtendedVirtual = 0;
    return TRUE;
}

void GetSystemInfo(LPSYSTEM_INFO si) {
    memset(si, 0, sizeof *si);
    si->wProcessorArchitecture = 9;   // PROCESSOR_ARCHITECTURE_AMD64
    si->dwPageSize = (DWORD)PAGE;
    si->lpMinimumApplicationAddress = (void *)0x10000;
    si->lpMaximumApplicationAddress = (void *)0x7ffffffeffffull;
    si->dwNumberOfProcessors = GetActiveProcessorCount(0);
    si->dwActiveProcessorMask = si->dwNumberOfProcessors >= 64 ? ~(DWORD_PTR)0
                                                               : (((DWORD_PTR)1 << si->dwNumberOfProcessors) - 1);
    si->dwProcessorType = 8664;
    si->dwAllocationGranularity = (DWORD)GRAN;
}

// ---- exceptions

#define MAX_VEH 16
static struct { PVECTORED_EXCEPTION_HANDLER fn; } g_veh[MAX_VEH];
static volatile int g_nveh;
static SRWLOCK g_veh_lock = SRWLOCK_INIT;
static LPTOP_LEVEL_EXCEPTION_FILTER g_unhandled;
static struct sigaction g_old[32];

PVOID AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn) {
    w32_exceptions_init();
    AcquireSRWLockExclusive(&g_veh_lock);
    PVOID h = NULL;
    if (g_nveh < MAX_VEH) {
        if (first) {
            memmove(&g_veh[1], &g_veh[0], (size_t)g_nveh * sizeof *g_veh);
            g_veh[0].fn = fn;
        } else g_veh[g_nveh].fn = fn;
        g_nveh++;
        h = (PVOID)fn;
    }
    ReleaseSRWLockExclusive(&g_veh_lock);
    return h;
}

ULONG RemoveVectoredExceptionHandler(PVOID h) {
    AcquireSRWLockExclusive(&g_veh_lock);
    ULONG ok = 0;
    for (int i = 0; i < g_nveh; i++)
        if ((PVOID)g_veh[i].fn == h) {
            memmove(&g_veh[i], &g_veh[i + 1], (size_t)(g_nveh - i - 1) * sizeof *g_veh);
            g_nveh--;
            ok = 1;
            break;
        }
    ReleaseSRWLockExclusive(&g_veh_lock);
    return ok;
}

LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER fn) {
    w32_exceptions_init();
    LPTOP_LEVEL_EXCEPTION_FILTER old = g_unhandled;
    g_unhandled = fn;
    return old;
}

UINT SetErrorMode(UINT mode) { (void)mode; return 0; }

void w32_context_from_uc(const void *uc, CONTEXT *c);
void w32_context_to_uc(const CONTEXT *c, void *uc);

static void fault_handler(int sig, siginfo_t *si, void *ucv) {
    ucontext_t *uc = ucv;
    int saved_errno = errno;
    uint64_t err = (uint64_t)uc->uc_mcontext.gregs[REG_ERR];
    if (sig == SIGSEGV && w32_ww_fault(si->si_addr, (err & 2) != 0)) {
        errno = saved_errno;
        return;
    }
    EXCEPTION_RECORD er = {0};
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    w32_context_from_uc(uc, &ctx);
    er.ExceptionAddress = (void *)(uintptr_t)ctx.Rip;
    switch (sig) {
    case SIGSEGV:
        er.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
        er.NumberParameters = 2;
        er.ExceptionInformation[0] = (err & 16) ? 8 : (err & 2) ? 1 : 0;
        er.ExceptionInformation[1] = (ULONG_PTR)si->si_addr;
        break;
    case SIGBUS:
        er.ExceptionCode = EXCEPTION_IN_PAGE_ERROR;
        er.NumberParameters = 2;
        er.ExceptionInformation[1] = (ULONG_PTR)si->si_addr;
        break;
    case SIGILL: er.ExceptionCode = si->si_code == ILL_PRVOPC ? EXCEPTION_PRIV_INSTRUCTION : EXCEPTION_ILLEGAL_INSTRUCTION; break;
    case SIGFPE: er.ExceptionCode = si->si_code == FPE_INTOVF ? EXCEPTION_INT_OVERFLOW : EXCEPTION_INT_DIVIDE_BY_ZERO; break;
    case SIGTRAP: er.ExceptionCode = EXCEPTION_BREAKPOINT; break;
    }
    EXCEPTION_POINTERS ep = {&er, &ctx};
    int n = __atomic_load_n(&g_nveh, __ATOMIC_ACQUIRE);
    for (int i = 0; i < n; i++) {
        PVECTORED_EXCEPTION_HANDLER fn = g_veh[i].fn;
        if (fn && fn(&ep) == EXCEPTION_CONTINUE_EXECUTION) {
            w32_context_to_uc(&ctx, uc);
            errno = saved_errno;
            return;
        }
    }
    if (g_unhandled && g_unhandled(&ep) == EXCEPTION_CONTINUE_EXECUTION) {
        w32_context_to_uc(&ctx, uc);
        errno = saved_errno;
        return;
    }
    // Nobody wanted it: the handler that was there before, else the default action (the fault repeats on return).
    struct sigaction *old = &g_old[sig];
    if ((old->sa_flags & SA_SIGINFO) && old->sa_sigaction) {
        old->sa_sigaction(sig, si, ucv);
        return;
    }
    if (old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN && old->sa_handler) {
        old->sa_handler(sig);
        return;
    }
    signal(sig, SIG_DFL);
}

void w32_thread_install_altstack(void) {
    stack_t cur;
    if (!sigaltstack(NULL, &cur) && !(cur.ss_flags & SS_DISABLE) && cur.ss_sp) return;
    size_t n = 256u << 10;   // the handlers log and walk guest frames
    void *p = mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) return;
    stack_t ss = {.ss_sp = p, .ss_size = n, .ss_flags = 0};
    sigaltstack(&ss, NULL);   // freed with the process; a few per thread is fine
}

void w32_exceptions_init(void) {
    static volatile int done;
    if (__atomic_exchange_n(&done, 1, __ATOMIC_ACQ_REL)) return;
    w32_thread_install_altstack();
    struct sigaction sa = {0};
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    const int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE};
    for (size_t i = 0; i < sizeof sigs / sizeof *sigs; i++) sigaction(sigs[i], &sa, &g_old[sigs[i]]);
}

__attribute__((constructor)) static void mem_ctor(void) { w32_exceptions_init(); }
