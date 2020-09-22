#pragma once

#define RID 9999

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef void (WINAPI* fnRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

typedef NTSYSAPI BOOLEAN(NTAPI *fnRtlEqualUnicodeString)(
    PUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN CaseInSensitive
    );

typedef LONG KPRIORITY;

typedef struct _SYSTEM_PROCESSES {
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    ULONG Reserved1[6];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

HMODULE hNTDLL;

DWORD GetPID(const wchar_t* cProcessName);
