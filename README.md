# RecursiveDelegation

> **Offensive-security PoC.** A Windows x64 process-injection technique that splits a single
> `VirtualAllocEx → WriteProcessMemory → CreateRemoteThread` chain across an arbitrary number of
> ephemeral child processes — each one a self-copy with a random Microsoft-binary-looking name —
> so that no single PID makes more than one cross-process Win32 call. The actual API is executed
> by warping a thread's `CONTEXT` into the target function via `NtContinue`, with a hand-built
> stack and an assembly stub that captures `RAX`.
> The main goal is to troll the analyst a bit and make him be like wtf?...


---

## What it does, in one breath

1. The injector opens an **inheritable** handle to the victim (`notepad.exe`).
2. To invoke any cross-process Win32 API (say, `VirtualAllocEx`) the injector calls
   `RecursiveDelegate(level, params, …)`.
3. `RecursiveDelegate` clones the running EXE to a randomly named sibling file
   (`svchost_<tickcount>.exe`, `winlogon_<tickcount>.exe`, …), spawns it with the inheritable
   handle and a level-decremented command line, and sets up a named pipe.
4. The child does the same thing at one lower level. The chain unwinds until **level 0**.
5. The level-0 child receives the API parameters over the pipe, builds a fake stack with
   `PrepareStackForApiCall`, captures its own `CONTEXT` with `RtlCaptureContext`, rewrites
   `RIP/RCX/RDX/R8/R9/RSP` to point at the target API + its arguments, and calls `NtContinue`.
6. `NtContinue` "warps" the thread into the target API. When the API returns, it rets into an
   assembly stub `CaptureRAX_And_CallHelper` which moves `RAX` into `RCX` and calls
   `ProcessResultAndExit`. That helper writes the result back up the pipe chain and
   `TerminateProcess`'s its own host.
7. Each parent reads the result from its pipe and forwards it up. The original injector sees the
   API's return value as if it had called the API directly — except *a different process made
   each call*.

End result: for the full DLL/shellcode injection sequence
(`VirtualAllocEx → WriteProcessMemory → CreateRemoteThread`), **three independent delegation
chains** are spawned. Each cross-process API originates from a different ephemeral PID with a
different masquerading image name. A defender looking at a single process's API call history
sees one call against `notepad.exe`, not three; the attribution is intentionally diffused.

---

## How a single API call flows

```mermaid
sequenceDiagram
    autonumber
    participant Injector as RecursiveDelegation.exe<br/>(root, PID A)
    participant L2 as svchost_*.exe<br/>(level 2, PID B)
    participant L1 as winlogon_*.exe<br/>(level 1, PID C)
    participant L0 as lsass_*.exe<br/>(level 0, PID D)
    participant Target as notepad.exe<br/>(victim)

    Note over Injector,Target: User calls RecursiveDelegate(level=3,<br/>"Kernel32!VirtualAllocEx", args…)
    Injector->>L2: CreateProcess clone with level=2,<br/>inherits notepad handle
    Injector->>L2: pipe: ApiCallParams + stack args
    L2->>L1: CreateProcess clone with level=1
    L2->>L1: pipe: ApiCallParams + stack args
    L1->>L0: CreateProcess clone with level=0
    L1->>L0: pipe: ApiCallParams + stack args

    Note over L0: PrepareStackForApiCall<br/>RtlCaptureContext<br/>rewrite RIP/RCX/RDX/R8/R9/RSP
    L0->>Target: NtContinue → VirtualAllocEx(hNotepad, …)
    Target-->>L0: ret → CaptureRAX_And_CallHelper
    Note over L0: ProcessResultAndExit captures RAX,<br/>writes ApiCallResultResponse,<br/>TerminateProcess(self)

    L0->>L1: pipe: ApiCallResultResponse
    L1->>L2: pipe: ApiCallResultResponse
    L2->>Injector: pipe: ApiCallResultResponse
    Note over Injector: gets back the API's RAX and<br/>GetLastError(), as if it<br/>had called the API itself
```

The full DLL/shellcode injection runs this whole flow **three times** — once each for
`VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` — with three fresh clone
chains. No clone process makes more than one cross-process API call in its life.

```mermaid
flowchart LR
    Root["root injector<br/>RecursiveDelegation.exe"]
    Root --> A1["clone chain #1<br/>(svchost_x → rundll32_y)"] --> APIa["VirtualAllocEx"]
    Root --> A2["clone chain #2<br/>(smss_x → spoolsv_y)"] --> APIb["WriteProcessMemory"]
    Root --> A3["clone chain #3<br/>(dllhost_x → explorer_y)"] --> APIc["CreateRemoteThread"]
    APIa -.-> NP["notepad.exe"]
    APIb -.-> NP
    APIc -.-> NP
```

---

## Repository layout

```
RecursiveDelegation/                 ← the EXE project (MSBuild + MASM)
  RecursiveDelegation.cpp            main(), demos, --inject-notepad / --inject-dll / --selftest
  RecursiveDelegationCore.h          shared structs + helper declarations
  RecursiveDelegationCore.cpp        ResolveFunction, CreateIPCPipe, CreateCloneExecutable,
                                     FindProcessPid, PrepareStackForApiCall, …
  RecursiveDelegationEngine.cpp      RecursiveDelegate, ExecuteApiCallAtLevelZero,
                                     ProcessChildMode, ProcessResultAndExit
  CaptureStub.asm                    assembly stub that captures RAX from the warped API

ClassicInjectRemoteThread/           reference: plain OpenProcess + VAE + WPM + CRT
ContextFunctionCall/                 reference: CONTEXT-based call into one API
ContextFunctionCallNtContinue/       reference: NtContinue-based call (predecessor to this PoC)

tests/                               GoogleTest suite (CMake + FetchContent)
  CMakeLists.txt                     pulls gtest 1.14.0, builds rd_core static lib + test EXE
  test_core.cpp                      27 tests across L1 (helpers), L2 (pipe wire format),
                                     L3 (real end-to-end delegation through child processes)
  README.md                          test-specific build / run notes

tools/                               PowerShell tracing + demo tooling
  Watch-InjectionEvents.ps1          live tail (admin) — NT Kernel Logger + Sysmon
  Capture-DelegationTrace.ps1        one-shot kernel ETW capture, decode, report
  Capture-SysmonInjection.ps1        one-shot Sysmon-log report for a single run
  Run-InjectionDemo.ps1              programmatic harness: inject + verify MessageBox owner
```

---

## Build

### The EXE (Visual Studio / MSBuild)

```powershell
msbuild RecursiveDelegation\RecursiveDelegation.vcxproj /p:Configuration=Debug /p:Platform=x64
```

Produces `RecursiveDelegation\x64\Debug\RecursiveDelegation.exe`.

### The tests (CMake; uses the CMake bundled with Visual Studio 2022)

```powershell
$cmake = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
& $cmake -S tests -B build\tests -G "Visual Studio 17 2022" -A x64
& $cmake --build build\tests --config Debug
```

First configure downloads GoogleTest 1.14.0 via `FetchContent`.

---

## Run

### Self-test (delegation through clones to harmless self-target APIs)

```powershell
.\RecursiveDelegation\x64\Debug\RecursiveDelegation.exe --selftest
```

### Shellcode-into-notepad demo (the visible one — pops MessageBox in notepad)

```powershell
Start-Process notepad.exe                                           # ensure notepad is running
.\RecursiveDelegation\x64\Debug\RecursiveDelegation.exe --inject-notepad 2
```

The `2` is the recursion depth (root → 2 clones → executor). The MessageBox titled `Injected`
appears inside notepad's window.

### LoadLibrary-DLL-into-notepad demo

```powershell
.\RecursiveDelegation\x64\Debug\RecursiveDelegation.exe --inject-dll 2
```

(Edit `dllPath` in `InjectDllToNotepadTest` first — currently hard-coded to a path on the
author's machine.)

### Run the test suite

```powershell
.\build\tests\Debug\rd_core_tests.exe
# or quiet mode:
.\build\tests\Debug\rd_core_tests.exe --gtest_brief=1
```

27 tests across 9 suites:

| Layer | Suites | Notes |
|---|---|---|
| **1 — pure helpers** | `GenerateRandomBinaryName`, `ResolveFunction`, `PrepareStackForApiCall`, `CreateCloneExecutable`, `FindProcessPid`, `CreateIPCPipe`, `ApiCallStructs` | No external state |
| **2 — IPC wire format** | `IpcWireFormat` | Full round-trip of `ApiCallParams` + var-length stack args + `ApiCallResultResponse` over a real named pipe between two threads. Includes the "client closes early" failure path. |
| **3 — E2E delegation** | `E2EDelegation` | Spawns the test EXE as its own child. Asserts: `GetTickCount64` falls in the host window, `VirtualAllocEx` at depth 1 and 2 produces a `MEM_COMMIT` region the parent can `VirtualQuery`, and a delegated `SetEvent` actually signals an inheritable event. |


