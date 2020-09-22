## NomadBishop

### Background

In the beginning, there was UrbanBishop, part of [@FuzzySec](https://twitter.com/FuzzySec)'s [Sharp-Suite](https://github.com/FuzzySecurity/Sharp-Suite). Then came [RuralBishop](https://github.com/rasta-mouse/RuralBishop) by [@_RastaMouse](https://twitter.com/_RastaMouse), which uses [D/Invoke](https://thewover.github.io/Dynamic-Invoke/) instead of P/Invoke. These C# tools perform the following remote process injection procedure:

1. Open the target process
2. Create a RWX memory section
3. Map a RW view of the section in the local process
4. Map a RX view of the section in the target process
5. Copy payload to the local view of the section
6. Create suspended thread in the target process
7. Queue APC thread at the RX view mapped in step 4
8. Resume the suspended thread, triggering the payload

NomadBishop is a rough C/C++ proof-of-concept that implements the same procedure using system call macros generated by [@Jackson_T](https://twitter.com/Jackson_T)'s [SysWhispers](https://github.com/jthuraisamy/SysWhispers) script. The actual procedure as implemented is largely identical to UrbanBishop/RuralBishop with some minor tweaks. Notably, after step 4, the section handle is closed and, after step 5, the local view of the section is unmapped. This is based on my interpretation of [MSDN documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/managing-memory-sections):

> Note that after the view is mapped and no other views are going to be mapped, it is safe to immediately call ZwClose on the section handle; the view (and section object) continue to exist until the view is unmapped.

In practical terms, this means that the local process (i.e. NomadBishop) can close its section handle, unmap its view, and exit normally after the remote thread is executed. What could possibly go wrong?

### Usage

Syscall macros are not included, but can be quickly generated using the aforementioned [SysWhispers](https://github.com/jthuraisamy/SysWhispers) script:

```console
$ python3 syswhispers.py -v 8,10 \
-f NtQuerySystemInformation,NtWriteVirtualMemory,NtOpenProcess,NtCreateSection, \
NtMapViewOfSection,NtUnmapViewOfSection,NtQueueApcThread,NtAlertResumeThread, \
NtCreateThreadEx,NtClose -o whisper
```

The resulting `whisper.asm` and `whisper.h` files should be placed into the `NomadBishop` directory. The above command will create macros for both Windows 8 and Windows 10, but NomadBishop has only been tested on Windows 10. Please refer to the [SysWhispers](https://github.com/jthuraisamy/SysWhispers) project for additional guidance as needed. Alternative methods of utilizing syscalls could also be integrated relatively easily.

The NomadBishop Visual Studio 2019 project, as provided, produces a console application (EXE). The path to the binary payload (i.e. shellcode) is specified in the `Resource.rc` file and the payload is packed into the PE's resource header at compile-time. The resulting NomadBishop executable takes a single argument specifying the name of the target process to attempt to inject into, e.g.:

```console
C:\>NomadBishop.exe explorer.exe
```

### Considerations

* 64-bit only

### Credit/Thanks

* [@FuzzySec](https://twitter.com/FuzzySec)
* [@_RastaMouse](https://twitter.com/_RastaMouse)
* [@Jackson_T](https://twitter.com/Jackson_T)