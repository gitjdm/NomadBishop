## NomadBishop

### Background

In the beginning, there was UrbanBishop, part of [@FuzzySec](https://twitter.com/FuzzySec)'s [Sharp-Suite](https://github.com/FuzzySecurity/Sharp-Suite). Then came [RuralBishop](https://github.com/rasta-mouse/RuralBishop) by [@\_RastaMouse](https://twitter.com/_RastaMouse), which uses [D/Invoke](https://thewover.github.io/Dynamic-Invoke/) instead of P/Invoke. These C# tools perform the following remote process injection procedure:

1. Open the target process
2. Create a RWX memory section
3. Map a RW view of the section in the local process
4. Map a RX view of the section in the target process
5. Copy payload to the local view of the section
6. Create suspended thread in the target process at `RtlExitUserThread`
7. Queue APC for the thread at the RX view mapped in step 4
8. Resume the suspended thread, triggering the APC (i.e. payload)

NomadBishop is a C/C++ proof-of-concept that implements the same procedure and supports both x64 and x86 operation. The x64 version is designed to use system call macros generated by [@Jackson\_T](https://twitter.com/Jackson_T)'s [SysWhispers](https://github.com/jthuraisamy/SysWhispers) script. The x86 version statically links `ntdll.lib` and uses Native API functions. Thanks to `NtCreateThreadEx`, it is possible inject across desktop sessions. Cross-architecture injection is not currently implemented.

[@SolomonSklash](https://www.solomonsklash.io) also has an implementation in C worth checking out: [SeasideBishop](https://github.com/SolomonSklash/SeasideBishop). The associated [blog post](https://www.solomonsklash.io/seaside-bishop.html) is a great breakdown of the technique.

### Usage

The NomadBishop Visual Studio 2019 project, as provided, produces a console application (EXE). The path to the binary payload (i.e. shellcode) is specified in the `Resource.rc` file and the payload is packed into the PE's resource header at compile-time. The resulting NomadBishop executable takes a single argument specifying the name of the target process to attempt to inject into, e.g.:

```
PS C:\> .\NomadBishop.exe powershell.exe
[+] Located payload: 272 bytes at 0x00007FF6AF731070
[+] Located target PID: 2024
[+] Process handle: 0x0000000000000090
[+] Section handle: 0x0000000000000094
[+] Local view: 0x00000264F5AD0000
[+] Remote view: 0x0000018365FA0000
[+] Copied 272 bytes to section
[+] Thread handle: 0x0000000000000098
[+] Thread ID: 9688
[+] Queued APC at remote view (0x0000018365FA0000)
[+] Payload successfully injected into PID 2024
```

Syscall macros are not included, but can be quickly generated using the aforementioned [SysWhispers](https://github.com/jthuraisamy/SysWhispers) script:

```
$ python3 syswhispers.py -v 8,10 \
-f NtQuerySystemInformation,NtWriteVirtualMemory,NtOpenProcess,NtCreateSection, \
NtMapViewOfSection,NtUnmapViewOfSection,NtQueueApcThread,NtAlertResumeThread, \
NtCreateThreadEx,NtClose -o whisper
```

The resulting `whisper.asm` file should be placed into the `NomadBishop` directory. The above example `syswhispers.py` command will create macros for both Windows 8 and Windows 10, but NomadBishop has only been tested on Windows 10. Please refer to the [SysWhispers](https://github.com/jthuraisamy/SysWhispers) project for additional guidance as needed. Alternative methods of utilizing syscalls could also be integrated relatively easily. The x86 project configuration does not compile `whisper.asm` and instead statically links `ntdll.lib`. Preprocessor directives in `NomadBishop.h` ensure the `Nt*` functions are declared appropriately for the architecture at compile-time.

### Credit/Thanks

* [@FuzzySec](https://twitter.com/FuzzySec)
* [@\_RastaMouse](https://twitter.com/_RastaMouse)
* [@Jackson\_T](https://twitter.com/Jackson_T)
