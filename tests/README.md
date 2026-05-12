# RecursiveDelegation tests

Three layers of GoogleTest coverage for the helpers and the delegation engine
in [RecursiveDelegation/](../RecursiveDelegation/). GoogleTest is fetched
automatically via CMake `FetchContent` — no submodules, no vcpkg.

## Prerequisites

- Visual Studio 2022 (the C++ workload includes CMake and ml64)
- Network access on the first configure (downloads GoogleTest v1.14.0)

## Build & run

From a Developer PowerShell:

```powershell
$cmake = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
& $cmake -S tests -B build\tests -G "Visual Studio 17 2022" -A x64
& $cmake --build build\tests --config Debug

# All tests:
.\build\tests\Debug\rd_core_tests.exe

# Quiet mode (only failures + summary):
.\build\tests\Debug\rd_core_tests.exe --gtest_brief=1
```

The same `rd_core_tests.exe` plays two roles: as the test runner when launched
without args, and as a delegation child process when launched by the Layer 3
tests themselves. Dispatch happens in `main()` based on argv shape.

## Coverage

| Layer | Suites | Notes |
|---|---|---|
| 1 — pure helpers | `GenerateRandomBinaryName`, `ResolveFunction`, `PrepareStackForApiCall`, `CreateCloneExecutable`, `FindProcessPid`, `CreateIPCPipe`, `ApiCallStructs` | In-process, no external state |
| 2 — IPC wire format | `IpcWireFormat` | Round-trips `ApiCallParams`, `numStackArgs`, stack args, and `ApiCallResultResponse` over a real named pipe between two threads. Also verifies the parent's `ReadFile` returns a clean failure when the client closes the pipe early. |
| 3 — end-to-end delegation | `E2EDelegation` | Calls `RecursiveDelegate` for real, spawning clone child processes. Verifies `GetTickCount64` returns within the host time window, that `VirtualAllocEx` at depth 1 and depth 2 produces a `MEM_COMMIT` region the parent can `VirtualQuery`, and that `SetEvent` delegated through a child process actually signals the event. |

Current count: **27 tests across 9 suites**.

## Notepad shellcode injection demo

The same binaries also support a live demo where a real MessageBox shellcode is
injected into notepad via three independent delegation chains
(VirtualAllocEx → WriteProcessMemory → CreateRemoteThread), each running in a
fresh child process.

```powershell
# Build the EXE if you haven't:
$msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
& $msbuild RecursiveDelegation\RecursiveDelegation.vcxproj /p:Configuration=Debug /p:Platform=x64

# Make sure notepad is running, then:
.\RecursiveDelegation\x64\Debug\RecursiveDelegation.exe --inject-notepad 2
```

`--inject-notepad <level>` runs the shellcode injection at the given recursion
depth and exits when done. A MessageBox appears inside notepad's process.

Other flags: `--inject-dll`, `--selftest`. Running with no args replays the
original interactive demo.

## Per-API process attribution (`tools/Capture-DelegationTrace.ps1`)

This script runs the notepad shellcode injection and reports which child PID
actually performed each of the three cross-process Win32 APIs.

- **Elevated PowerShell**: starts an NT Kernel Logger ETW session with the
  Process, Thread, and VirtualAlloc flags, runs the demo, decodes the `.etl`
  with `tracerpt`, and prints one line per `VirtualAlloc`/`CreateRemoteThread`
  event that targets notepad — including the caller's PID and image name.
- **Non-elevated PowerShell**: parses the demo's own stdout to reconstruct the
  same chain. Produces output like:

  ```
  Kernel32!VirtualAllocEx
    PID 24320 [spoolsv_*.exe lvl=2]  ->  PID 35604 [services_*.exe lvl=1]
    RAX (return value) = 0x1FAE9DD0000

  Kernel32!WriteProcessMemory
    PID 24320 [dwm_*.exe lvl=2]  ->  PID 45532 [spoolsv_*.exe lvl=1]
    RAX (return value) = 0x1

  Kernel32!CreateRemoteThread
    PID 24320 [iexplore_*.exe lvl=2]  ->  PID 7352 [taskmgr_*.exe lvl=1]
    RAX (return value) = 0xB4

  Root injector PID(s)  : 24320
  Executor PIDs (final) : 45532, 35604, 7352
  notepad target PID    : 20212
  ```

  Each API touching notepad runs in a different process from the root injector,
  and each clone uses a randomly chosen Microsoft binary name as a decoy.

```powershell
& .\tools\Capture-DelegationTrace.ps1 -Level 2
```
