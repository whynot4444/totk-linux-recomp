// Linux stand-in for <bcrypt.h>: SHA-256 hashing (our own implementation, win32_shim.c) and the system RNG
// (getrandom). Only the calls the runtime makes.
#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef LONG NTSTATUS;
typedef void *BCRYPT_ALG_HANDLE;
typedef void *BCRYPT_HASH_HANDLE;
typedef UCHAR *PUCHAR;
#define BCRYPT_SHA256_ALGORITHM L"SHA256"
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 2u
#define BCRYPT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *alg, LPCWSTR id, LPCWSTR impl, ULONG flags);
NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE alg, ULONG flags);
NTSTATUS BCryptCreateHash(BCRYPT_ALG_HANDLE alg, BCRYPT_HASH_HANDLE *h, PUCHAR obj, ULONG objn, PUCHAR secret,
                          ULONG secretn, ULONG flags);
NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE h, PUCHAR p, ULONG n, ULONG flags);
NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE h, PUCHAR out, ULONG n, ULONG flags);
NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE h);
NTSTATUS BCryptGenRandom(BCRYPT_ALG_HANDLE alg, PUCHAR out, ULONG n, ULONG flags);

#ifdef __cplusplus
}
#endif
