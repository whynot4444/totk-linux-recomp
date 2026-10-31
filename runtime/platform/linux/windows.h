// Linux stand-in for <windows.h>: the subset of the Win32 API the runtime still calls directly, on POSIX threads,
// futexes, mmap and signals. Only Linux builds put runtime/platform/linux on the include path (tools/build_game.py),
// so `#include <windows.h>` in a runtime file reaches this header there and the real one on Windows.
//
// The goal is behavioural parity for what the runtime relies on, not a general Win32: SRW locks, condition variables
// and critical sections; the Interlocked family (type-generic, so LONG, LONG64 and plain long all work); handles for
// threads, events, waitable timers, files, file mappings and child processes; VirtualAlloc/Protect/Query/Free with
// MEM_WRITE_WATCH and GetWriteWatch; vectored exception handlers (fed by SIGSEGV, SIGBUS, SIGILL, SIGFPE); thread
// suspension and Get/SetThreadContext (a signal handshake); fibers (ucontext); and the file, time, module and process
// calls listed below. Wide strings are wchar_t (UTF-32 on Linux), converted to UTF-8 at the system call; '\' in a path
// becomes '/'.
//
// tools/check_platform.py tracks the files that still need this header; new code goes through platform.h.
#pragma once
#ifndef _WIN32

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "crt_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---- base types (LLP64 widths: LONG and DWORD stay 32-bit)
typedef int BOOL;
typedef unsigned char BYTE, BOOLEAN, UCHAR;
typedef uint16_t WORD, USHORT;
typedef uint32_t DWORD, UINT, ULONG;
typedef int32_t LONG, INT;
typedef int64_t LONG64, LONGLONG, INT64;
typedef uint64_t ULONG64, ULONGLONG, DWORD64, UINT64, DWORDLONG;
typedef intptr_t INT_PTR, LONG_PTR;
typedef uintptr_t UINT_PTR, ULONG_PTR, DWORD_PTR, SIZE_T;
typedef intptr_t SSIZE_T;
typedef void VOID, *PVOID, *LPVOID, *HANDLE, *HMODULE, *HINSTANCE, *HWND, *HGLOBAL, *HKEY, *HMONITOR, *HDC;
typedef const void *LPCVOID;
typedef wchar_t WCHAR, *LPWSTR;
typedef const wchar_t *LPCWSTR;
typedef char CHAR, *LPSTR;
typedef const char *LPCSTR;
typedef DWORD *LPDWORD, *PDWORD;
typedef LONG *PLONG;
typedef BOOL *LPBOOL;
typedef PVOID *PPVOID;
typedef LONG HRESULT;
typedef DWORD LCID;
typedef SIZE_T *PSIZE_T;
typedef ULONG_PTR *PULONG_PTR;
typedef BOOL *PBOOL;
typedef LONG *LPLONG;
typedef int16_t SHORT;
typedef DWORD_PTR *PDWORD_PTR;
typedef ULONG64 *PULONG64;
typedef DWORD64 *PDWORD64;

#define WINAPI
#define CALLBACK
#define APIENTRY
#define WINBASEAPI
#define TRUE 1
#define FALSE 0
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#define INFINITE 0xFFFFFFFFu
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define LOCALE_NAME_MAX_LENGTH 85
#define CP_UTF8 65001
#define CP_ACP 0
#define MB_ERR_INVALID_CHARS 8u
#define WC_ERR_INVALID_CHARS 0x80u

typedef union {
    struct { DWORD LowPart; LONG HighPart; };
    struct { DWORD LowPart; LONG HighPart; } u;
    LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;
typedef union {
    struct { DWORD LowPart; DWORD HighPart; };
    ULONGLONG QuadPart;
} ULARGE_INTEGER;
typedef struct { DWORD dwLowDateTime, dwHighDateTime; } FILETIME, *LPFILETIME;
typedef struct {
    WORD wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds;
} SYSTEMTIME, *LPSYSTEMTIME;
typedef struct { DWORD LowPart; LONG HighPart; } LUID;
typedef struct { LONG left, top, right, bottom; } RECT;
typedef struct { LONG x, y; } POINT;

// ---- errors
#define ERROR_SUCCESS 0u
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_NO_MORE_FILES 18u
#define ERROR_SHARING_VIOLATION 32u
#define ERROR_HANDLE_EOF 38u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_FILE_EXISTS 80u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_BROKEN_PIPE 109u
#define ERROR_DISK_FULL 112u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_DIR_NOT_EMPTY 145u
#define ERROR_ALREADY_EXISTS 183u
#define ERROR_DIRECTORY 267u
#define ERROR_MORE_DATA 234u
#define ERROR_TIMEOUT 1460u
#define ERROR_IO_PENDING 997u
#define ERROR_NOACCESS 998u
#define ERROR_INVALID_ADDRESS 487u
#define ERROR_COMMITMENT_LIMIT 1455u
DWORD GetLastError(void);
void SetLastError(DWORD e);
DWORD w32_errno_to_win(int e);   // errno to the nearest Win32 error

// ---- atomics: type-generic, full barriers, returning what the Win32 function returns
#define InterlockedIncrement(p) __atomic_add_fetch((p), 1, __ATOMIC_SEQ_CST)
#define InterlockedDecrement(p) __atomic_sub_fetch((p), 1, __ATOMIC_SEQ_CST)
#define InterlockedIncrement64 InterlockedIncrement
#define InterlockedDecrement64 InterlockedDecrement
#define InterlockedIncrementNoFence InterlockedIncrement
#define InterlockedExchange(p, v) __atomic_exchange_n((p), (v), __ATOMIC_SEQ_CST)
#define InterlockedExchange64 InterlockedExchange
#define InterlockedExchange8 InterlockedExchange
#define InterlockedExchange16 InterlockedExchange
#define InterlockedExchangePointer(p, v) __atomic_exchange_n((p), (v), __ATOMIC_SEQ_CST)
#define InterlockedExchangeAdd(p, v) __atomic_fetch_add((p), (v), __ATOMIC_SEQ_CST)
#define InterlockedExchangeAdd64 InterlockedExchangeAdd
#define InterlockedAdd(p, v) __atomic_add_fetch((p), (v), __ATOMIC_SEQ_CST)
#define InterlockedAdd64 InterlockedAdd
#define InterlockedOr(p, v) __atomic_fetch_or((p), (v), __ATOMIC_SEQ_CST)
#define InterlockedOr64 InterlockedOr
#define InterlockedOr8 InterlockedOr
#define InterlockedAnd(p, v) __atomic_fetch_and((p), (v), __ATOMIC_SEQ_CST)
#define InterlockedAnd64 InterlockedAnd
#define InterlockedXor(p, v) __atomic_fetch_xor((p), (v), __ATOMIC_SEQ_CST)
#define InterlockedCompareExchange(p, x, c) w32_cas((p), (x), (c))
#define InterlockedCompareExchange64 InterlockedCompareExchange
#define InterlockedCompareExchange16 InterlockedCompareExchange
#define InterlockedCompareExchangePointer(p, x, c) w32_cas((p), (x), (c))
// Win32 order (dest, exchange, comparand); returns the initial value. The __sync builtin takes any width and a
// volatile target, as the Win32 functions do.
#define w32_cas(p, x, c) __sync_val_compare_and_swap((p), (c), (x))
#define MemoryBarrier() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define YieldProcessor() __builtin_ia32_pause()
#define ReadAcquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define WriteRelease(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)

// ---- SRW locks and condition variables: one pointer-sized futex word each, zero is unlocked / empty
typedef struct { void *Ptr; } SRWLOCK, *PSRWLOCK;
typedef struct { void *Ptr; } CONDITION_VARIABLE, *PCONDITION_VARIABLE;
#define SRWLOCK_INIT {0}
#define CONDITION_VARIABLE_INIT {0}
#define CONDITION_VARIABLE_LOCKMODE_SHARED 1u
void InitializeSRWLock(PSRWLOCK l);
void AcquireSRWLockExclusive(PSRWLOCK l);
void AcquireSRWLockShared(PSRWLOCK l);
BOOLEAN TryAcquireSRWLockExclusive(PSRWLOCK l);
BOOLEAN TryAcquireSRWLockShared(PSRWLOCK l);
void ReleaseSRWLockExclusive(PSRWLOCK l);
void ReleaseSRWLockShared(PSRWLOCK l);
void InitializeConditionVariable(PCONDITION_VARIABLE c);
BOOL SleepConditionVariableSRW(PCONDITION_VARIABLE c, PSRWLOCK l, DWORD ms, ULONG flags);
void WakeConditionVariable(PCONDITION_VARIABLE c);
void WakeAllConditionVariable(PCONDITION_VARIABLE c);

// Recursive, like the real one.
typedef struct { SRWLOCK lock; volatile int owner; int count; } CRITICAL_SECTION, *LPCRITICAL_SECTION;
void InitializeCriticalSection(LPCRITICAL_SECTION cs);
BOOL InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION cs, DWORD spin);
BOOL InitializeCriticalSectionEx(LPCRITICAL_SECTION cs, DWORD spin, DWORD flags);
void DeleteCriticalSection(LPCRITICAL_SECTION cs);
void EnterCriticalSection(LPCRITICAL_SECTION cs);
BOOL TryEnterCriticalSection(LPCRITICAL_SECTION cs);
void LeaveCriticalSection(LPCRITICAL_SECTION cs);
BOOL SleepConditionVariableCS(PCONDITION_VARIABLE c, LPCRITICAL_SECTION cs, DWORD ms);

typedef struct { volatile int state; void *ctx; } INIT_ONCE, *PINIT_ONCE, *LPINIT_ONCE;
#define INIT_ONCE_STATIC_INIT {0, 0}
typedef BOOL(CALLBACK *PINIT_ONCE_FN)(PINIT_ONCE, PVOID, PVOID *);
BOOL InitOnceExecuteOnce(PINIT_ONCE o, PINIT_ONCE_FN fn, PVOID param, LPVOID *ctx);
BOOL InitOnceBeginInitialize(LPINIT_ONCE o, DWORD flags, PBOOL pending, LPVOID *ctx);
BOOL InitOnceComplete(LPINIT_ONCE o, DWORD flags, LPVOID ctx);
#define INIT_ONCE_CHECK_ONLY 1u
#define INIT_ONCE_INIT_FAILED 4u

BOOL WaitOnAddress(volatile void *addr, PVOID cmp, SIZE_T size, DWORD ms);
void WakeByAddressSingle(PVOID addr);
void WakeByAddressAll(PVOID addr);

// ---- time
BOOL QueryPerformanceCounter(LARGE_INTEGER *t);
BOOL QueryPerformanceFrequency(LARGE_INTEGER *f);
ULONGLONG GetTickCount64(void);
DWORD GetTickCount(void);
void Sleep(DWORD ms);
DWORD SleepEx(DWORD ms, BOOL alertable);
BOOL SwitchToThread(void);
void GetSystemTimeAsFileTime(LPFILETIME ft);
void GetSystemTimePreciseAsFileTime(LPFILETIME ft);
void GetSystemTime(LPSYSTEMTIME st);
void GetLocalTime(LPSYSTEMTIME st);
BOOL FileTimeToSystemTime(const FILETIME *ft, LPSYSTEMTIME st);
BOOL SystemTimeToFileTime(const SYSTEMTIME *st, LPFILETIME ft);
UINT timeBeginPeriod(UINT ms);
UINT timeEndPeriod(UINT ms);

// ---- handles: threads, events, waitable timers, files, mappings, processes
typedef DWORD(WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);
typedef struct { DWORD nLength; LPVOID lpSecurityDescriptor; BOOL bInheritHandle; } SECURITY_ATTRIBUTES,
    *LPSECURITY_ATTRIBUTES;
#define CREATE_SUSPENDED 0x4u
#define STACK_SIZE_PARAM_IS_A_RESERVATION 0x10000u
HANDLE CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE fn, LPVOID arg, DWORD flags,
                    LPDWORD tid);
HANDLE GetCurrentThread(void);     // pseudo handle of the calling thread
HANDLE GetCurrentProcess(void);    // pseudo handle
DWORD GetCurrentThreadId(void);    // the kernel thread id (gettid)
DWORD GetCurrentProcessId(void);
DWORD GetThreadId(HANDLE t);
#define THREAD_ALL_ACCESS 0x1FFFFFu
#define THREAD_SUSPEND_RESUME 0x2u
#define THREAD_GET_CONTEXT 0x8u
#define THREAD_SET_CONTEXT 0x10u
#define THREAD_QUERY_INFORMATION 0x40u
#define THREAD_QUERY_LIMITED_INFORMATION 0x800u
#define THREAD_SET_INFORMATION 0x20u
HANDLE OpenThread(DWORD access, BOOL inherit, DWORD tid);
DWORD SuspendThread(HANDLE t);
DWORD ResumeThread(HANDLE t);
BOOL GetExitCodeThread(HANDLE t, LPDWORD code);
__attribute__((noreturn)) void ExitThread(DWORD code);
__attribute__((noreturn)) void ExitProcess(UINT code);
BOOL TerminateProcess(HANDLE p, UINT code);
#define THREAD_PRIORITY_IDLE (-15)
#define THREAD_PRIORITY_LOWEST (-2)
#define THREAD_PRIORITY_BELOW_NORMAL (-1)
#define THREAD_PRIORITY_NORMAL 0
#define THREAD_PRIORITY_ABOVE_NORMAL 1
#define THREAD_PRIORITY_HIGHEST 2
#define THREAD_PRIORITY_TIME_CRITICAL 15
#define THREAD_PRIORITY_ERROR_RETURN 0x7fffffff
BOOL SetThreadPriority(HANDLE t, int prio);   // nice values; raising above normal needs CAP_SYS_NICE, quietly kept
int GetThreadPriority(HANDLE t);
DWORD_PTR SetThreadAffinityMask(HANDLE t, DWORD_PTR mask);
BOOL GetProcessAffinityMask(HANDLE p, PDWORD_PTR proc, PDWORD_PTR sys);
BOOL SetProcessAffinityMask(HANDLE p, DWORD_PTR mask);
HRESULT SetThreadDescription(HANDLE t, LPCWSTR name);
#define ALL_PROCESSOR_GROUPS 0xffff
DWORD GetActiveProcessorCount(WORD group);
BOOL GetThreadTimes(HANDLE t, LPFILETIME create, LPFILETIME exit, LPFILETIME kernel, LPFILETIME user);
BOOL GetProcessTimes(HANDLE p, LPFILETIME create, LPFILETIME exit, LPFILETIME kernel, LPFILETIME user);
BOOL GetSystemTimes(LPFILETIME idle, LPFILETIME kernel, LPFILETIME user);
BOOL QueryThreadCycleTime(HANDLE t, PULONG64 cycles);

#define WAIT_OBJECT_0 0u
#define WAIT_ABANDONED 0x80u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xFFFFFFFFu
#define MAXIMUM_WAIT_OBJECTS 64
DWORD WaitForSingleObject(HANDLE h, DWORD ms);
DWORD WaitForSingleObjectEx(HANDLE h, DWORD ms, BOOL alertable);
DWORD WaitForMultipleObjects(DWORD n, const HANDLE *hs, BOOL all, DWORD ms);
BOOL CloseHandle(HANDLE h);
BOOL DuplicateHandle(HANDLE sp, HANDLE s, HANDLE tp, HANDLE *t, DWORD access, BOOL inherit, DWORD opts);

HANDLE CreateEventW(LPSECURITY_ATTRIBUTES sa, BOOL manual, BOOL initial, LPCWSTR name);
HANDLE CreateEventA(LPSECURITY_ATTRIBUTES sa, BOOL manual, BOOL initial, LPCSTR name);
#define CreateEvent CreateEventW
#define CREATE_EVENT_MANUAL_RESET 1u
#define CREATE_EVENT_INITIAL_SET 2u
HANDLE CreateEventExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access);
BOOL SetEvent(HANDLE e);
BOOL ResetEvent(HANDLE e);
HANDLE CreateSemaphoreW(LPSECURITY_ATTRIBUTES sa, LONG initial, LONG max, LPCWSTR name);
#define CreateSemaphore CreateSemaphoreW
BOOL ReleaseSemaphore(HANDLE s, LONG n, LPLONG prev);

#define CREATE_WAITABLE_TIMER_MANUAL_RESET 1u
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 2u
#define TIMER_ALL_ACCESS 0x1F0003u
#define TIMER_MODIFY_STATE 2u
#define SYNCHRONIZE 0x100000u
#define EVENT_ALL_ACCESS 0x1F0003u
#define EVENT_MODIFY_STATE 2u
HANDLE CreateWaitableTimerW(LPSECURITY_ATTRIBUTES sa, BOOL manual, LPCWSTR name);
HANDLE CreateWaitableTimerExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access);
typedef void(CALLBACK *PTIMERAPCROUTINE)(LPVOID, DWORD, DWORD);
// due < 0: relative, 100 ns units; due >= 0: absolute FILETIME. period in ms (0: one-shot).
BOOL SetWaitableTimer(HANDLE t, const LARGE_INTEGER *due, LONG period, PTIMERAPCROUTINE apc, LPVOID arg, BOOL resume);
BOOL SetWaitableTimerEx(HANDLE t, const LARGE_INTEGER *due, LONG period, PTIMERAPCROUTINE apc, LPVOID arg, PVOID wake,
                        ULONG delay);
BOOL CancelWaitableTimer(HANDLE t);

// ---- files
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_ALL 0x10000000u
#define FILE_READ_DATA 1u
#define FILE_WRITE_DATA 2u
#define FILE_APPEND_DATA 4u
#define FILE_READ_ATTRIBUTES 0x80u
#define FILE_WRITE_ATTRIBUTES 0x100u
#define DELETE 0x10000u
#define FILE_SHARE_READ 1u
#define FILE_SHARE_WRITE 2u
#define FILE_SHARE_DELETE 4u
#define CREATE_NEW 1u
#define CREATE_ALWAYS 2u
#define OPEN_EXISTING 3u
#define OPEN_ALWAYS 4u
#define TRUNCATE_EXISTING 5u
#define FILE_ATTRIBUTE_READONLY 0x1u
#define FILE_ATTRIBUTE_HIDDEN 0x2u
#define FILE_ATTRIBUTE_SYSTEM 0x4u
#define FILE_ATTRIBUTE_DIRECTORY 0x10u
#define FILE_ATTRIBUTE_ARCHIVE 0x20u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define FILE_ATTRIBUTE_TEMPORARY 0x100u
#define FILE_ATTRIBUTE_REPARSE_POINT 0x400u
#define INVALID_FILE_ATTRIBUTES 0xFFFFFFFFu
#define INVALID_FILE_SIZE 0xFFFFFFFFu
#define FILE_FLAG_WRITE_THROUGH 0x80000000u
#define FILE_FLAG_OVERLAPPED 0x40000000u
#define FILE_FLAG_NO_BUFFERING 0x20000000u
#define FILE_FLAG_RANDOM_ACCESS 0x10000000u
#define FILE_FLAG_SEQUENTIAL_SCAN 0x08000000u
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000u
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000u
#define FILE_BEGIN 0u
#define FILE_CURRENT 1u
#define FILE_END 2u
#define FILE_TYPE_UNKNOWN 0u
#define FILE_TYPE_DISK 1u
#define FILE_TYPE_CHAR 2u
#define FILE_TYPE_PIPE 3u
#define FILE_NAME_NORMALIZED 0u
#define VOLUME_NAME_DOS 0u
#define MOVEFILE_REPLACE_EXISTING 1u
#define MOVEFILE_COPY_ALLOWED 2u
#define MOVEFILE_WRITE_THROUGH 8u
#define STD_INPUT_HANDLE ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE ((DWORD)-12)
#define HANDLE_FLAG_INHERIT 1u

typedef struct {
    ULONG_PTR Internal, InternalHigh;
    union { struct { DWORD Offset, OffsetHigh; }; PVOID Pointer; };
    HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

HANDLE CreateFileW(LPCWSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags,
                   HANDLE tmpl);
HANDLE CreateFileA(LPCSTR path, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags,
                   HANDLE tmpl);
// With an OVERLAPPED, reads and writes at its offset (all ones: at the end, atomically) and complete synchronously.
BOOL ReadFile(HANDLE h, LPVOID buf, DWORD n, LPDWORD got, LPOVERLAPPED o);
BOOL WriteFile(HANDLE h, LPCVOID buf, DWORD n, LPDWORD put, LPOVERLAPPED o);
BOOL GetOverlappedResult(HANDLE h, LPOVERLAPPED o, LPDWORD n, BOOL wait);
BOOL GetFileSizeEx(HANDLE h, PLARGE_INTEGER size);
DWORD GetFileSize(HANDLE h, LPDWORD high);
BOOL SetFilePointerEx(HANDLE h, LARGE_INTEGER to, PLARGE_INTEGER now, DWORD how);
BOOL SetEndOfFile(HANDLE h);
BOOL FlushFileBuffers(HANDLE h);
DWORD GetFileType(HANDLE h);
HANDLE GetStdHandle(DWORD which);
BOOL SetHandleInformation(HANDLE h, DWORD mask, DWORD flags);
DWORD GetFinalPathNameByHandleW(HANDLE h, LPWSTR out, DWORD cap, DWORD flags);

typedef struct {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
    DWORD dwVolumeSerialNumber, nFileSizeHigh, nFileSizeLow, nNumberOfLinks, nFileIndexHigh, nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION, *LPBY_HANDLE_FILE_INFORMATION;
BOOL GetFileInformationByHandle(HANDLE h, LPBY_HANDLE_FILE_INFORMATION info);
typedef enum { FileBasicInfo = 0, FileStandardInfo = 1, FileRenameInfo = 3, FileDispositionInfo = 4,
               FileAllocationInfo = 5, FileEndOfFileInfo = 6 } FILE_INFO_BY_HANDLE_CLASS;
typedef struct { LARGE_INTEGER CreationTime, LastAccessTime, LastWriteTime, ChangeTime; DWORD FileAttributes; }
    FILE_BASIC_INFO;
typedef struct { LARGE_INTEGER EndOfFile; } FILE_END_OF_FILE_INFO;
typedef struct { LARGE_INTEGER AllocationSize; } FILE_ALLOCATION_INFO;
typedef struct { BOOLEAN DeleteFile; } FILE_DISPOSITION_INFO;
BOOL SetFileInformationByHandle(HANDLE h, FILE_INFO_BY_HANDLE_CLASS cls, LPVOID info, DWORD size);

typedef enum { GetFileExInfoStandard } GET_FILEEX_INFO_LEVELS;
typedef struct {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
    DWORD nFileSizeHigh, nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA;
DWORD GetFileAttributesW(LPCWSTR path);
DWORD GetFileAttributesA(LPCSTR path);
BOOL GetFileAttributesExW(LPCWSTR path, GET_FILEEX_INFO_LEVELS level, LPVOID out);
BOOL GetFileAttributesExA(LPCSTR path, GET_FILEEX_INFO_LEVELS level, LPVOID out);
BOOL SetFileAttributesW(LPCWSTR path, DWORD attrs);
BOOL SetFileAttributesA(LPCSTR path, DWORD attrs);
BOOL CreateDirectoryW(LPCWSTR path, LPSECURITY_ATTRIBUTES sa);
BOOL CreateDirectoryA(LPCSTR path, LPSECURITY_ATTRIBUTES sa);
BOOL RemoveDirectoryW(LPCWSTR path);
BOOL RemoveDirectoryA(LPCSTR path);
BOOL DeleteFileW(LPCWSTR path);
BOOL DeleteFileA(LPCSTR path);
BOOL MoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags);
BOOL MoveFileExA(LPCSTR from, LPCSTR to, DWORD flags);
BOOL CopyFileW(LPCWSTR from, LPCWSTR to, BOOL fail_if_exists);
BOOL CreateHardLinkW(LPCWSTR link, LPCWSTR target, LPSECURITY_ATTRIBUTES sa);
DWORD GetTempPathW(DWORD cap, LPWSTR out);
DWORD GetTempPathA(DWORD cap, LPSTR out);
UINT GetTempFileNameA(LPCSTR dir, LPCSTR prefix, UINT unique, LPSTR out);
DWORD GetFullPathNameA(LPCSTR path, DWORD cap, LPSTR out, LPSTR *file);
DWORD GetFullPathNameW(LPCWSTR path, DWORD cap, LPWSTR out, LPWSTR *file);
DWORD GetCurrentDirectoryA(DWORD cap, LPSTR out);
UINT GetWindowsDirectoryW(LPWSTR out, UINT cap);

typedef struct {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
    DWORD nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
    WCHAR cFileName[MAX_PATH];
    WCHAR cAlternateFileName[14];
} WIN32_FIND_DATAW, *LPWIN32_FIND_DATAW;
typedef struct {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
    DWORD nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
    CHAR cFileName[MAX_PATH * 4];   // UTF-8: room for any 260-character name
    CHAR cAlternateFileName[14];
} WIN32_FIND_DATAA, *LPWIN32_FIND_DATAA;
typedef enum { FindExInfoStandard, FindExInfoBasic } FINDEX_INFO_LEVELS;
typedef enum { FindExSearchNameMatch, FindExSearchLimitToDirectories } FINDEX_SEARCH_OPS;
#define FIND_FIRST_EX_LARGE_FETCH 2u
// Patterns: a directory, then a last component with * and ? wildcards.
HANDLE FindFirstFileW(LPCWSTR pattern, LPWIN32_FIND_DATAW fd);
HANDLE FindFirstFileA(LPCSTR pattern, LPWIN32_FIND_DATAA fd);
HANDLE FindFirstFileExA(LPCSTR pattern, FINDEX_INFO_LEVELS lvl, LPVOID fd, FINDEX_SEARCH_OPS op, LPVOID filter,
                        DWORD flags);
HANDLE FindFirstFileExW(LPCWSTR pattern, FINDEX_INFO_LEVELS lvl, LPVOID fd, FINDEX_SEARCH_OPS op, LPVOID filter,
                        DWORD flags);
BOOL FindNextFileW(HANDLE h, LPWIN32_FIND_DATAW fd);
BOOL FindNextFileA(HANDLE h, LPWIN32_FIND_DATAA fd);
BOOL FindClose(HANDLE h);

#define PAGE_NOACCESS 0x01u
#define PAGE_READONLY 0x02u
#define PAGE_READWRITE 0x04u
#define PAGE_WRITECOPY 0x08u
#define PAGE_EXECUTE 0x10u
#define PAGE_EXECUTE_READ 0x20u
#define PAGE_EXECUTE_READWRITE 0x40u
#define PAGE_GUARD 0x100u
#define PAGE_NOCACHE 0x200u
#define FILE_MAP_WRITE 2u
#define FILE_MAP_READ 4u
#define FILE_MAP_ALL_ACCESS 0xF001Fu
#define FILE_MAP_COPY 1u
#define SEC_COMMIT 0x8000000u
HANDLE CreateFileMappingW(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD prot, DWORD size_hi, DWORD size_lo,
                          LPCWSTR name);
HANDLE CreateFileMappingA(HANDLE file, LPSECURITY_ATTRIBUTES sa, DWORD prot, DWORD size_hi, DWORD size_lo,
                          LPCSTR name);
LPVOID MapViewOfFile(HANDLE map, DWORD access, DWORD off_hi, DWORD off_lo, SIZE_T n);
BOOL UnmapViewOfFile(LPCVOID p);

// ---- strings
int MultiByteToWideChar(UINT cp, DWORD flags, LPCSTR s, int n, LPWSTR out, int cap);
int WideCharToMultiByte(UINT cp, DWORD flags, LPCWSTR s, int n, LPSTR out, int cap, LPCSTR def, LPBOOL used);
// UTF-8 path for the system: wide to UTF-8, '\' to '/'. Returns out, or NULL when it does not fit.
char *w32_path_w(LPCWSTR w, char *out, size_t cap);
char *w32_path_a(LPCSTR s, char *out, size_t cap);

// ---- virtual memory
#define MEM_COMMIT 0x1000u
#define MEM_RESERVE 0x2000u
#define MEM_DECOMMIT 0x4000u
#define MEM_RELEASE 0x8000u
#define MEM_FREE 0x10000u
#define MEM_PRIVATE 0x20000u
#define MEM_MAPPED 0x40000u
#define MEM_RESET 0x80000u
#define MEM_TOP_DOWN 0x100000u
#define MEM_WRITE_WATCH 0x200000u
#define MEM_LARGE_PAGES 0x20000000u
#define MEM_IMAGE 0x1000000u
#define WRITE_WATCH_FLAG_RESET 1u
typedef struct {
    PVOID BaseAddress, AllocationBase;
    DWORD AllocationProtect;
    WORD PartitionId;
    SIZE_T RegionSize;
    DWORD State, Protect, Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
// Reservations are mmap'd PROT_NONE and tracked (per-page state and protection), so VirtualQuery answers for them
// like Windows does; other memory gets an answer from /proc/self/maps. An address given to MEM_RESERVE is taken
// exactly or not at all.
LPVOID VirtualAlloc(LPVOID addr, SIZE_T n, DWORD type, DWORD prot);
BOOL VirtualFree(LPVOID addr, SIZE_T n, DWORD type);
BOOL VirtualProtect(LPVOID addr, SIZE_T n, DWORD prot, PDWORD old);
SIZE_T VirtualQuery(LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T n);
// MEM_WRITE_WATCH regions are kept read-only until written; the first write to a page marks it and opens it again (a
// SIGSEGV handled before any vectored handler). Same contract as Windows: pages written since the last reset.
UINT GetWriteWatch(DWORD flags, PVOID base, SIZE_T n, PVOID *addrs, ULONG_PTR *count, ULONG *gran);
UINT ResetWriteWatch(LPVOID base, SIZE_T n);
BOOL ReadProcessMemory(HANDLE p, LPCVOID from, LPVOID to, SIZE_T n, SIZE_T *got);
BOOL FlushInstructionCache(HANDLE p, LPCVOID a, SIZE_T n);

typedef struct {
    DWORD dwLength, dwMemoryLoad;
    DWORDLONG ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual,
        ullAvailExtendedVirtual;
} MEMORYSTATUSEX, *LPMEMORYSTATUSEX;
BOOL GlobalMemoryStatusEx(LPMEMORYSTATUSEX ms);
typedef struct {
    WORD wProcessorArchitecture, wReserved;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress, lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors, dwProcessorType, dwAllocationGranularity;
    WORD wProcessorLevel, wProcessorRevision;
} SYSTEM_INFO, *LPSYSTEM_INFO;
void GetSystemInfo(LPSYSTEM_INFO si);

// ---- exceptions: vectored handlers, called from the signal handler of SIGSEGV, SIGBUS, SIGILL and SIGFPE
#define EXCEPTION_ACCESS_VIOLATION 0xC0000005u
#define EXCEPTION_IN_PAGE_ERROR 0xC0000006u
#define EXCEPTION_ILLEGAL_INSTRUCTION 0xC000001Du
#define EXCEPTION_PRIV_INSTRUCTION 0xC0000096u
#define EXCEPTION_INT_DIVIDE_BY_ZERO 0xC0000094u
#define EXCEPTION_INT_OVERFLOW 0xC0000095u
#define EXCEPTION_FLT_DIVIDE_BY_ZERO 0xC000008Eu
#define EXCEPTION_FLT_INVALID_OPERATION 0xC0000090u
#define EXCEPTION_STACK_OVERFLOW 0xC00000FDu
#define EXCEPTION_BREAKPOINT 0x80000003u
#define EXCEPTION_GUARD_PAGE 0x80000001u
#define EXCEPTION_CONTINUE_EXECUTION (-1)
#define EXCEPTION_CONTINUE_SEARCH 0
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_MAXIMUM_PARAMETERS 15
typedef struct _EXCEPTION_RECORD {
    DWORD ExceptionCode, ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];   // [0]: 0 read, 1 write, 8 execute; [1]: address
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;

#define CONTEXT_AMD64 0x100000u
#define CONTEXT_CONTROL (CONTEXT_AMD64 | 1u)
#define CONTEXT_INTEGER (CONTEXT_AMD64 | 2u)
#define CONTEXT_SEGMENTS (CONTEXT_AMD64 | 4u)
#define CONTEXT_FLOATING_POINT (CONTEXT_AMD64 | 8u)
#define CONTEXT_FULL (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
#define CONTEXT_ALL (CONTEXT_FULL | CONTEXT_SEGMENTS)
// The general registers of an x86-64 thread. The vector registers are not part of it: a suspended thread keeps its
// own, and SetThreadContext changes only these.
typedef struct {
    DWORD ContextFlags, MxCsr, EFlags;
    DWORD64 Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15, Rip;
} CONTEXT, *PCONTEXT, *LPCONTEXT;
typedef struct { PEXCEPTION_RECORD ExceptionRecord; PCONTEXT ContextRecord; } EXCEPTION_POINTERS,
    *PEXCEPTION_POINTERS;
typedef LONG(CALLBACK *PVECTORED_EXCEPTION_HANDLER)(EXCEPTION_POINTERS *);
PVOID AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn);
ULONG RemoveVectoredExceptionHandler(PVOID h);
typedef LONG(WINAPI *LPTOP_LEVEL_EXCEPTION_FILTER)(EXCEPTION_POINTERS *);
LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER fn);
// Suspends t at a signal and copies its registers; t stays stopped until ResumeThread. On the calling thread itself
// only the stack and instruction pointers are approximate.
BOOL GetThreadContext(HANDLE t, LPCONTEXT ctx);
BOOL SetThreadContext(HANDLE t, const CONTEXT *ctx);   // only while t is suspended
void RtlCaptureContext(PCONTEXT ctx);
#define SEM_FAILCRITICALERRORS 1u
#define SEM_NOGPFAULTERRORBOX 2u
UINT SetErrorMode(UINT mode);

// ---- processor topology (prof_win.c's one-per-core placement): cores of /sys/devices/system/cpu
typedef ULONG_PTR KAFFINITY;
typedef enum { RelationProcessorCore = 0, RelationNumaNode = 1, RelationCache = 2, RelationProcessorPackage = 3,
               RelationGroup = 4, RelationAll = 0xffff } LOGICAL_PROCESSOR_RELATIONSHIP;
typedef struct { KAFFINITY Mask; WORD Group; WORD Reserved[3]; } GROUP_AFFINITY;
typedef struct { BYTE Flags, EfficiencyClass, Reserved[20]; WORD GroupCount; GROUP_AFFINITY GroupMask[1]; }
    PROCESSOR_RELATIONSHIP;
typedef struct {
    LOGICAL_PROCESSOR_RELATIONSHIP Relationship;
    DWORD Size;
    union { PROCESSOR_RELATIONSHIP Processor; };
} SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX, *PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX;
BOOL GetLogicalProcessorInformationEx(LOGICAL_PROCESSOR_RELATIONSHIP rel, PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX buf,
                                      PDWORD len);

// ---- stack unwinding: Windows reads the .pdata tables; ELF has no equivalent the stand-in reads, so every function
// looks like a leaf and a profile's call chains stop at the sampled frame.
typedef struct { DWORD BeginAddress, EndAddress, UnwindData; } RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
#define UNW_FLAG_NHANDLER 0u
static inline PRUNTIME_FUNCTION RtlLookupFunctionEntry(DWORD64 pc, PDWORD64 base, PVOID table) {
    (void)pc, (void)table;
    *base = 0;
    return NULL;
}
static inline PVOID RtlVirtualUnwind(DWORD type, DWORD64 base, DWORD64 pc, PRUNTIME_FUNCTION f, PCONTEXT c,
                                     PVOID *data, PDWORD64 frame, PVOID ctx) {
    (void)type, (void)base, (void)pc, (void)f, (void)c, (void)data, (void)frame, (void)ctx;
    return NULL;
}

// ---- fibers (ucontext)
typedef void(WINAPI *LPFIBER_START_ROUTINE)(LPVOID);
#define FIBER_FLAG_FLOAT_SWITCH 1u
LPVOID ConvertThreadToFiber(LPVOID param);
LPVOID ConvertThreadToFiberEx(LPVOID param, DWORD flags);
BOOL ConvertFiberToThread(void);
LPVOID CreateFiber(SIZE_T stack, LPFIBER_START_ROUTINE fn, LPVOID param);
LPVOID CreateFiberEx(SIZE_T commit, SIZE_T reserve, DWORD flags, LPFIBER_START_ROUTINE fn, LPVOID param);
void SwitchToFiber(LPVOID fiber);
void DeleteFiber(LPVOID fiber);
PVOID GetCurrentFiber(void);
PVOID GetFiberData(void);

// ---- modules and the process
// The executable: its handle is its load address; its file is /proc/self/exe. Other names go to dlopen.
HMODULE GetModuleHandleW(LPCWSTR name);
HMODULE GetModuleHandleA(LPCSTR name);
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 2u
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 4u
BOOL GetModuleHandleExW(DWORD flags, LPCWSTR name, HMODULE *out);
DWORD GetModuleFileNameW(HMODULE m, LPWSTR out, DWORD cap);
DWORD GetModuleFileNameA(HMODULE m, LPSTR out, DWORD cap);
typedef struct { LPVOID lpBaseOfDll; DWORD SizeOfImage; LPVOID EntryPoint; } MODULEINFO, *LPMODULEINFO;
BOOL GetModuleInformation(HANDLE p, HMODULE m, LPMODULEINFO mi, DWORD n);
#define K32GetModuleInformation GetModuleInformation
BOOL EnumProcessModules(HANDLE p, HMODULE *mods, DWORD cap, LPDWORD need);
#define K32EnumProcessModules EnumProcessModules
typedef struct {
    DWORD cb, PageFaultCount;
    SIZE_T PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage,
        QuotaNonPagedPoolUsage, PagefileUsage, PeakPagefileUsage, PrivateUsage;
} PROCESS_MEMORY_COUNTERS, PROCESS_MEMORY_COUNTERS_EX, *PPROCESS_MEMORY_COUNTERS;
BOOL GetProcessMemoryInfo(HANDLE p, PPROCESS_MEMORY_COUNTERS c, DWORD n);
#define K32GetProcessMemoryInfo GetProcessMemoryInfo
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x800u
#define LOAD_WITH_ALTERED_SEARCH_PATH 0x8u
#define LOAD_LIBRARY_SEARCH_DEFAULT_DIRS 0x1000u
#define LOAD_LIBRARY_SEARCH_APPLICATION_DIR 0x200u
HMODULE LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags);
HMODULE LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags);
HMODULE LoadLibraryA(LPCSTR name);
HMODULE LoadLibraryW(LPCWSTR name);
BOOL FreeLibrary(HMODULE m);
typedef intptr_t(WINAPI *FARPROC)(void);
FARPROC GetProcAddress(HMODULE m, LPCSTR name);

LPWSTR GetCommandLineW(void);   // the process's arguments, quoted Windows-style
LPSTR GetCommandLineA(void);
DWORD GetEnvironmentVariableW(LPCWSTR name, LPWSTR out, DWORD cap);
DWORD GetEnvironmentVariableA(LPCSTR name, LPSTR out, DWORD cap);
BOOL SetEnvironmentVariableA(LPCSTR name, LPCSTR value);
BOOL SetEnvironmentVariableW(LPCWSTR name, LPCWSTR value);

typedef struct {
    DWORD cb;
    LPWSTR lpReserved, lpDesktop, lpTitle;
    DWORD dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    WORD wShowWindow, cbReserved2;
    BYTE *lpReserved2;
    HANDLE hStdInput, hStdOutput, hStdError;
} STARTUPINFOW, STARTUPINFOA, *LPSTARTUPINFOW;
typedef struct { HANDLE hProcess, hThread; DWORD dwProcessId, dwThreadId; } PROCESS_INFORMATION,
    *LPPROCESS_INFORMATION;
#define STARTF_USESTDHANDLES 0x100u
#define CREATE_NO_WINDOW 0x8000000u
#define DETACHED_PROCESS 0x8u
#define CREATE_NEW_CONSOLE 0x10u
#define CREATE_UNICODE_ENVIRONMENT 0x400u
#define STILL_ACTIVE 259u
// The command line is split Windows-style (quotes, backslashes); the first word is the program unless app is given.
BOOL CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
                    DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi);
BOOL GetExitCodeProcess(HANDLE p, LPDWORD code);
BOOL CreatePipe(HANDLE *rd, HANDLE *wr, LPSECURITY_ATTRIBUTES sa, DWORD size);
void OutputDebugStringA(LPCSTR s);
void OutputDebugStringW(LPCWSTR s);
#define OutputDebugString OutputDebugStringA
BOOL IsDebuggerPresent(void);
void DebugBreak(void);

// ---- locale
typedef WORD LANGID;
LANGID GetUserDefaultUILanguage(void);
int GetUserDefaultLocaleName(LPWSTR out, int cap);
int LCIDToLocaleName(LCID lcid, LPWSTR out, int cap, DWORD flags);

// ---- the few window-system calls non-window files make; the window lives in gfx_window_sdl.c on Linux.
HWND GetForegroundWindow(void);
SHORT GetAsyncKeyState(int vk);
int MessageBoxA(HWND w, LPCSTR text, LPCSTR caption, UINT type);
int MessageBoxW(HWND w, LPCWSTR text, LPCWSTR caption, UINT type);
#define MB_OK 0u
#define MB_ICONERROR 0x10u
#define MB_ICONWARNING 0x30u
#define MB_ICONINFORMATION 0x40u
#define MB_YESNO 4u
#define IDYES 6
#define IDNO 7
// Set by the SDL window code (gfx_window.c on Linux): the game window while it has focus, and the state of a virtual
// key (bit 15 down). Without a window: NULL and 0.
extern HWND (*w32_foreground_hook)(void);
extern SHORT (*w32_keystate_hook)(int vk);

// Virtual-key codes. Letters and digits are their ASCII capitals and digits.
#define VK_LBUTTON 0x01
#define VK_RBUTTON 0x02
#define VK_MBUTTON 0x04
#define VK_XBUTTON1 0x05
#define VK_XBUTTON2 0x06
#define VK_BACK 0x08
#define VK_TAB 0x09
#define VK_RETURN 0x0D
#define VK_SHIFT 0x10
#define VK_CONTROL 0x11
#define VK_MENU 0x12
#define VK_PAUSE 0x13
#define VK_CAPITAL 0x14
#define VK_ESCAPE 0x1B
#define VK_SPACE 0x20
#define VK_PRIOR 0x21
#define VK_NEXT 0x22
#define VK_END 0x23
#define VK_HOME 0x24
#define VK_LEFT 0x25
#define VK_UP 0x26
#define VK_RIGHT 0x27
#define VK_DOWN 0x28
#define VK_SNAPSHOT 0x2C
#define VK_INSERT 0x2D
#define VK_DELETE 0x2E
#define VK_LWIN 0x5B
#define VK_RWIN 0x5C
#define VK_APPS 0x5D
#define VK_NUMPAD0 0x60
#define VK_NUMPAD1 0x61
#define VK_NUMPAD2 0x62
#define VK_NUMPAD3 0x63
#define VK_NUMPAD4 0x64
#define VK_NUMPAD5 0x65
#define VK_NUMPAD6 0x66
#define VK_NUMPAD7 0x67
#define VK_NUMPAD8 0x68
#define VK_NUMPAD9 0x69
#define VK_MULTIPLY 0x6A
#define VK_ADD 0x6B
#define VK_SEPARATOR 0x6C
#define VK_SUBTRACT 0x6D
#define VK_DECIMAL 0x6E
#define VK_DIVIDE 0x6F
#define VK_F1 0x70
#define VK_F2 0x71
#define VK_F3 0x72
#define VK_F4 0x73
#define VK_F5 0x74
#define VK_F6 0x75
#define VK_F7 0x76
#define VK_F8 0x77
#define VK_F9 0x78
#define VK_F10 0x79
#define VK_F11 0x7A
#define VK_F12 0x7B
#define VK_NUMLOCK 0x90
#define VK_SCROLL 0x91
#define VK_LSHIFT 0xA0
#define VK_RSHIFT 0xA1
#define VK_LCONTROL 0xA2
#define VK_RCONTROL 0xA3
#define VK_LMENU 0xA4
#define VK_RMENU 0xA5
#define VK_OEM_1 0xBA
#define VK_OEM_PLUS 0xBB
#define VK_OEM_COMMA 0xBC
#define VK_OEM_MINUS 0xBD
#define VK_OEM_PERIOD 0xBE
#define VK_OEM_2 0xBF
#define VK_OEM_3 0xC0
#define VK_OEM_4 0xDB
#define VK_OEM_5 0xDC
#define VK_OEM_6 0xDD
#define VK_OEM_7 0xDE
#define VK_OEM_102 0xE2


#ifdef __cplusplus
}
#endif
#endif   // !_WIN32
