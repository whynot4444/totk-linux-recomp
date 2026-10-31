// Linux stand-in for <tlhelp32.h>: thread snapshots of this process (/proc/self/task). Implemented in win32_proc.c.
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TH32CS_SNAPTHREAD 4u
typedef struct {
    DWORD dwSize, cntUsage, th32ThreadID, th32OwnerProcessID;
    LONG tpBasePri, tpDeltaPri;
    DWORD dwFlags;
} THREADENTRY32, *LPTHREADENTRY32;
// Only TH32CS_SNAPTHREAD of the calling process (pid 0 or our own).
HANDLE CreateToolhelp32Snapshot(DWORD flags, DWORD pid);
BOOL Thread32First(HANDLE snap, LPTHREADENTRY32 te);
BOOL Thread32Next(HANDLE snap, LPTHREADENTRY32 te);

#ifdef __cplusplus
}
#endif
