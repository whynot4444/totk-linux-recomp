// Checks the Linux Win32 stand-in (runtime/platform/linux) against the Windows behaviour the runtime relies on.
// No game files. Build and run (Linux):
//   clang -O1 -g -D_GNU_SOURCE -Iruntime/platform/linux -Iruntime/platform -Iruntime \
//         -include runtime/platform/linux/crt_compat.h tests/linux_shim_test.c \
//         runtime/platform/linux/*.c -ldl -lpthread -o build/linux_shim_test && build/linux_shim_test
// TOTK_WRITE_WATCH=mprotect runs the write-watch checks against the fallback.
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

#include "platform.h"

static int failures;
#define CHECK(c, ...) do { if (!(c)) { failures++; printf("  FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); putchar('\n'); } } while (0)

// ---- locks
static SRWLOCK lk = SRWLOCK_INIT;
static CONDITION_VARIABLE cv = CONDITION_VARIABLE_INIT;
static volatile long counter, ready;

static DWORD WINAPI bump(LPVOID p) {
    for (int i = 0; i < 200000; i++) {
        if (i % 3) {
            AcquireSRWLockExclusive(&lk);
            counter++;
            ReleaseSRWLockExclusive(&lk);
        } else {
            AcquireSRWLockShared(&lk);
            (void)counter;
            ReleaseSRWLockShared(&lk);
            InterlockedIncrement(&ready);
        }
    }
    return (DWORD)(uintptr_t)p;
}

static void test_locks(void) {
    HANDLE t[4];
    for (int i = 0; i < 4; i++) t[i] = CreateThread(NULL, 0, bump, (void *)(uintptr_t)(i + 10), 0, NULL);
    CHECK(WaitForMultipleObjects(4, t, TRUE, 20000) == WAIT_OBJECT_0, "threads did not finish");
    DWORD code;
    CHECK(GetExitCodeThread(t[2], &code) && code == 12, "exit code %u", code);
    for (int i = 0; i < 4; i++) CloseHandle(t[i]);
    long want = 4 * (200000 - (200000 + 2) / 3);
    CHECK(counter == want, "counter %ld want %ld", counter, want);
    // condition variable with timeout
    AcquireSRWLockExclusive(&lk);
    uint64_t t0 = plat_now_ns();
    BOOL ok = SleepConditionVariableSRW(&cv, &lk, 30, 0);
    uint64_t dt = plat_now_ns() - t0;
    ReleaseSRWLockExclusive(&lk);
    CHECK(!ok && GetLastError() == ERROR_TIMEOUT && dt >= 29000000, "cv timeout %d err %u dt %llu", ok, GetLastError(),
          (unsigned long long)dt);
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    EnterCriticalSection(&cs);
    EnterCriticalSection(&cs);
    CHECK(TryEnterCriticalSection(&cs), "recursive try");
    LeaveCriticalSection(&cs), LeaveCriticalSection(&cs), LeaveCriticalSection(&cs);
    long v = 5;
    CHECK(InterlockedCompareExchange(&v, 9L, 5L) == 5 && v == 9, "cas");
    printf("locks: ok\n");
}

// ---- events and timers
static void test_waits(void) {
    HANDLE e = CreateEventW(NULL, FALSE, FALSE, NULL);
    CHECK(WaitForSingleObject(e, 10) == WAIT_TIMEOUT, "unset event");
    SetEvent(e);
    CHECK(WaitForSingleObject(e, 0) == WAIT_OBJECT_0, "set event");
    CHECK(WaitForSingleObject(e, 0) == WAIT_TIMEOUT, "auto reset");
    HANDLE tm = CreateWaitableTimerExW(NULL, NULL, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    LARGE_INTEGER due = {.QuadPart = -20 * 10000};   // 20 ms
    uint64_t t0 = plat_now_ns();
    SetWaitableTimerEx(tm, &due, 0, NULL, NULL, NULL, 0);
    CHECK(WaitForSingleObject(tm, 1000) == WAIT_OBJECT_0, "timer");
    double ms = (plat_now_ns() - t0) / 1e6;
    CHECK(ms >= 19.5 && ms < 60, "timer took %.2f ms", ms);
    HANDLE both[2] = {e, tm};
    SetEvent(e);
    CHECK(WaitForMultipleObjects(2, both, FALSE, 100) == WAIT_OBJECT_0, "any");
    CloseHandle(e), CloseHandle(tm);
    t0 = plat_now_ns();
    plat_sleep_ns(2500000);
    ms = (plat_now_ns() - t0) / 1e6;
    CHECK(ms >= 2.5 && ms < 4, "plat_sleep_ns 2.5 ms took %.3f", ms);
    printf("waits: ok (timer %.2f ms, sleep %.3f ms)\n", ms, ms);
}

// ---- suspension and register access
static volatile int spin_go = 1;
static volatile uint64_t spins;
static volatile int redirected;

static void landing(void) {
    redirected = 1;
    for (;;) Sleep(1000);
}

static DWORD WINAPI spinner(LPVOID p) {
    (void)p;
    while (spin_go) spins++;
    return 0;
}

static void test_suspend(void) {
    HANDLE t = CreateThread(NULL, 0, spinner, NULL, 0, NULL);
    Sleep(20);
    CHECK(SuspendThread(t) == 0, "suspend");
    uint64_t s = spins;
    Sleep(20);
    CHECK(spins == s, "thread ran while suspended");
    CONTEXT c = {.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER};
    CHECK(GetThreadContext(t, &c) && c.Rip && c.Rsp, "context");
    CHECK(SuspendThread(t) == 1 && ResumeThread(t) == 2, "nested counts");
    CHECK(ResumeThread(t) == 1, "resume");
    Sleep(20);
    CHECK(spins != s, "thread did not resume");
    // redirect it
    SuspendThread(t);
    GetThreadContext(t, &c);
    c.Rip = (DWORD64)(uintptr_t)landing;
    c.Rsp = (c.Rsp - 256) & ~15ull;
    c.Rsp -= 8;   // as after a call
    CHECK(SetThreadContext(t, &c), "set context");
    ResumeThread(t);
    for (int i = 0; i < 100 && !redirected; i++) Sleep(5);
    CHECK(redirected, "SetThreadContext did not move the thread");
    HANDLE o = OpenThread(THREAD_ALL_ACCESS, FALSE, GetThreadId(t));
    CHECK(o == t, "OpenThread by id");
    CloseHandle(o);
    // a CREATE_SUSPENDED thread starts on ResumeThread
    spins = 0;
    spin_go = 1;
    HANDLE u = CreateThread(NULL, 0, spinner, NULL, CREATE_SUSPENDED, NULL);
    Sleep(10);
    CHECK(spins == 0, "suspended thread ran");
    ResumeThread(u);
    Sleep(10);
    CHECK(spins != 0, "resumed thread did not run");
    spin_go = 0;
    WaitForSingleObject(u, INFINITE);
    printf("suspend: ok\n");
}

// ---- fibers
static void *main_fiber, *f2;
static int fiber_steps;
static void WINAPI fiber_fn(LPVOID p) {
    fiber_steps += (int)(uintptr_t)p;
    SwitchToFiber(main_fiber);
    fiber_steps += 10;
    SwitchToFiber(main_fiber);
}

static void test_fibers(void) {
    main_fiber = ConvertThreadToFiberEx(NULL, FIBER_FLAG_FLOAT_SWITCH);
    f2 = CreateFiberEx(0, 1 << 20, FIBER_FLAG_FLOAT_SWITCH, fiber_fn, (void *)(uintptr_t)3);
    SwitchToFiber(f2);
    CHECK(fiber_steps == 3 && GetCurrentFiber() == main_fiber, "fiber step 1");
    SwitchToFiber(f2);
    CHECK(fiber_steps == 13, "fiber step 2");
    DeleteFiber(f2);
    ConvertFiberToThread();
    printf("fibers: ok\n");
}

// ---- memory, write watch, exceptions
static volatile int veh_hits;
static uintptr_t veh_page;
static LONG CALLBACK veh(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    if (er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || er->ExceptionInformation[1] - veh_page >= 0x1000)
        return EXCEPTION_CONTINUE_SEARCH;
    veh_hits++;
    DWORD old;
    VirtualProtect((void *)veh_page, 0x1000, PAGE_READWRITE, &old);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void test_memory(void) {
    uint64_t at = 0x2000000000ull;   // 128 GiB
    uint8_t *p = VirtualAlloc((void *)at, 64ull << 30, MEM_RESERVE | MEM_WRITE_WATCH, PAGE_NOACCESS);
    CHECK(p == (void *)at, "reserve at fixed address: %p", (void *)p);
    CHECK(!VirtualAlloc((void *)at, 0x10000, MEM_RESERVE, PAGE_NOACCESS), "a taken range was reserved twice");
    MEMORY_BASIC_INFORMATION mbi;
    CHECK(VirtualQuery(p, &mbi, sizeof mbi) && mbi.State == MEM_RESERVE && mbi.RegionSize == (64ull << 30),
          "query reserved: state %x size %llx", mbi.State, (unsigned long long)mbi.RegionSize);
    CHECK(VirtualAlloc(p + 0x10000, 0x20000, MEM_COMMIT, PAGE_READWRITE) == p + 0x10000, "commit");
    CHECK(VirtualQuery(p + 0x10000, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE &&
          mbi.RegionSize == 0x20000 && mbi.AllocationBase == p, "query committed");
    PVOID pages[16];
    ULONG_PTR n = 16;
    ULONG gran;
    GetWriteWatch(WRITE_WATCH_FLAG_RESET, p, 0x40000, pages, &n, &gran);
    CHECK(n == 0, "fresh commit reported %lu pages", (unsigned long)n);
    p[0x12000] = 1;
    p[0x15000] = 1;
    p[0x16000] = 1;
    n = 2;
    CHECK(!GetWriteWatch(WRITE_WATCH_FLAG_RESET, p, 0x40000, pages, &n, &gran) && n == 2 &&
          pages[0] == p + 0x12000 && pages[1] == p + 0x15000, "write watch max 2: %lu", (unsigned long)n);
    n = 16;
    GetWriteWatch(WRITE_WATCH_FLAG_RESET, p, 0x40000, pages, &n, &gran);
    CHECK(n == 1 && pages[0] == p + 0x16000, "the third page later: %lu", (unsigned long)n);
    n = 16;
    GetWriteWatch(0, p, 0x40000, pages, &n, &gran);
    CHECK(n == 0, "nothing left: %lu", (unsigned long)n);
    // a file read into watched memory is recorded
    HANDLE f = CreateFileA("/proc/self/stat", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    DWORD got = 0;
    CHECK(f != INVALID_HANDLE_VALUE && ReadFile(f, p + 0x18000, 16, &got, NULL) && got == 16, "ReadFile into watch");
    CloseHandle(f);
    n = 16;
    GetWriteWatch(WRITE_WATCH_FLAG_RESET, p, 0x40000, pages, &n, &gran);
    CHECK(n == 1 && pages[0] == p + 0x18000, "kernel write reported %lu", (unsigned long)n);
    // decommit gives zeroed pages
    CHECK(VirtualFree(p + 0x10000, 0x20000, MEM_DECOMMIT), "decommit");
    VirtualAlloc(p + 0x10000, 0x20000, MEM_COMMIT, PAGE_READWRITE);
    CHECK(p[0x12000] == 0, "decommitted page not zero");
    // protection and a vectored handler
    DWORD old;
    CHECK(VirtualProtect(p + 0x11000, 0x1000, PAGE_READONLY, &old) && old == PAGE_READWRITE, "protect");
    CHECK(VirtualQuery(p + 0x10000, &mbi, sizeof mbi) && mbi.RegionSize == 0x1000, "split region %llx",
          (unsigned long long)mbi.RegionSize);
    veh_page = (uintptr_t)(p + 0x11000);
    PVOID h = AddVectoredExceptionHandler(1, veh);
    p[0x11010] = 42;
    CHECK(veh_hits == 1 && p[0x11010] == 42, "vectored handler: hits %d", veh_hits);
    RemoveVectoredExceptionHandler(h);
    CHECK(VirtualFree(p, 0, MEM_RELEASE), "release");
    CHECK(VirtualQuery(p, &mbi, sizeof mbi) && mbi.State == MEM_FREE, "released state %x", mbi.State);
    void *q = VirtualAlloc(NULL, 1 << 20, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    CHECK(q && ((uintptr_t)q & 0xffff) == 0, "anywhere, 64 KiB aligned: %p", q);
    uint8_t buf[8];
    CHECK(!plat_mem_read(0x10, buf, 8), "plat_mem_read of unmapped memory");
    printf("memory: ok (write watch: %s)\n", getenv("TOTK_WRITE_WATCH") ? "mprotect" : "userfaultfd if available");
}

// ---- files, processes, strings, hashing
static void test_files(void) {
    char dir[64];
    snprintf(dir, sizeof dir, "/tmp/w32test.%u", (unsigned)GetCurrentProcessId());
    CHECK(CreateDirectoryA(dir, NULL), "mkdir");
    char path[128];
    snprintf(path, sizeof path, "%s\\Save.Bin", dir);   // backslash and case
    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD put;
    CHECK(f != INVALID_HANDLE_VALUE && WriteFile(f, "hello", 5, &put, NULL) && put == 5, "write");
    CloseHandle(f);
    char lower[128];
    snprintf(lower, sizeof lower, "%s/save.bin", dir);
    CHECK(GetFileAttributesA(lower) == FILE_ATTRIBUTE_NORMAL, "case-insensitive lookup");
    wchar_t wpat[128];
    swprintf(wpat, 128, L"%s\\*.bin", dir);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(wpat, &fd);
    CHECK(h != INVALID_HANDLE_VALUE && !wcscmp(fd.cFileName, L"Save.Bin") && fd.nFileSizeLow == 5, "find");
    if (h != INVALID_HANDLE_VALUE) FindClose(h);
    CHECK(plat_file_write_atomic(lower, "abc", 3) && plat_file_size(lower) == 3, "atomic write");
    PlatAppend *a = plat_append_open(lower);
    CHECK(a && plat_append_write(a, "x", 1) && plat_append_write(a, "y", 1), "append");
    CHECK(plat_file_size(lower) == 2, "append size");
    CHECK(DeleteFileA(path) && RemoveDirectoryA(dir), "cleanup");
    // a child process with pipes
    HANDLE rd, wr;
    SECURITY_ATTRIBUTES sa = {sizeof sa, NULL, TRUE};
    CreatePipe(&rd, &wr, &sa, 0);
    STARTUPINFOW si = {.cb = sizeof si, .dwFlags = STARTF_USESTDHANDLES, .hStdOutput = wr,
                       .hStdError = GetStdHandle(STD_ERROR_HANDLE)};
    PROCESS_INFORMATION pi;
    wchar_t cmd[] = L"/bin/sh -c \"echo \\\"quoted arg\\\"; exit 3\"";
    CHECK(CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi), "CreateProcess");
    CloseHandle(wr);
    char out[64] = {0};
    DWORD got = 0;
    ReadFile(rd, out, sizeof out - 1, &got, NULL);
    CHECK(!strcmp(out, "quoted arg\n"), "child output '%s'", out);   // sh sees: echo "quoted arg"; exit 3
    CHECK(WaitForSingleObject(pi.hProcess, 5000) == WAIT_OBJECT_0, "child exit");
    DWORD code;
    CHECK(GetExitCodeProcess(pi.hProcess, &code) && code == 3, "child code %u", code);
    // strings
    wchar_t w[16];
    CHECK(MultiByteToWideChar(CP_UTF8, 0, "Đà Nẵng", -1, w, 16) == 8 && w[0] == 0x110, "utf8 to wide");
    char back[32];
    CHECK(WideCharToMultiByte(CP_UTF8, 0, w, -1, back, 32, NULL, NULL) && !strcmp(back, "Đà Nẵng"), "wide to utf8");
    // SHA-256("abc")
    BCRYPT_ALG_HANDLE alg;
    BCRYPT_HASH_HANDLE hh;
    uint8_t d[32];
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(alg, &hh, NULL, 0, NULL, 0, 0);
    BCryptHashData(hh, (PUCHAR)"abc", 3, 0);
    BCryptFinishHash(hh, d, 32, 0);
    BCryptDestroyHash(hh);
    CHECK(d[0] == 0xba && d[1] == 0x78 && d[31] == 0xad, "sha256");
    char os[160];
    CHECK(plat_os_version(os, sizeof os), "os version");
    printf("files, processes, strings, sha-256: ok (%s, language '%s')\n", os, plat_ui_language());
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    test_locks();
    test_waits();
    test_suspend();
    test_fibers();
    test_memory();
    test_files();
    printf(failures ? "%d FAILED\n" : "all passed\n", failures);
    return failures != 0;
}
