#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <random>   
#include <sstream>  
#include <memory>   

#ifdef _DEBUG
#define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#define DEBUG_COUT(x) std::cout << x
#else
#define DEBUG_PRINTF(...) do {} while (0)
#define DEBUG_COUT(x) do {} while (0)
#endif

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
typedef NTSTATUS(NTAPI* NtContinue_t)(PCONTEXT ContextRecord, BOOLEAN TestAlert);

const std::vector<std::string> MS_BINARY_NAMES = {
    "svchost", "wininit", "csrss", "lsass", "winlogon", "spoolsv", "dwm",
    "explorer", "taskmgr", "msiexec", "conhost", "rundll32", "services",
    "smss", "ntoskrnl", "regsvr32", "mmc", "dllhost", "wuauclt", "iexplore"
};
std::string GenerateRandomBinaryName() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, MS_BINARY_NAMES.size() - 1);
    std::stringstream ss;
    ss << MS_BINARY_NAMES[distrib(gen)] << "_" << distrib(gen) << ".exe";
    return ss.str();
}
FARPROC ResolveFunction(const std::string& funcNameWithModule) {
    size_t pos = funcNameWithModule.find('!');
    if (pos == std::string::npos) {
        std::cerr << "ResolveFunction: Invalid format. Expected 'Module!Function', got '" << funcNameWithModule << "'" << std::endl;
        return nullptr;
    }
    std::string moduleName = funcNameWithModule.substr(0, pos);
    std::string functionName = funcNameWithModule.substr(pos + 1);
    HMODULE hModule = GetModuleHandleA(moduleName.c_str());
    if (!hModule) {
        hModule = LoadLibraryA(moduleName.c_str());
        if (!hModule) {
            std::cerr << "ResolveFunction: Failed to load module: " << moduleName << " Error: " << GetLastError() << std::endl;
            return nullptr;
        }
    }
    FARPROC procAddr = GetProcAddress(hModule, functionName.c_str());
    if (!procAddr) {
        std::cerr << "ResolveFunction: Failed to resolve function: " << functionName << " in " << moduleName << " Error: " << GetLastError() << std::endl;
    }
    return procAddr;
}
HANDLE CreateIPCPipe(const std::string& pipeName, bool isServer) {
    std::string fullPipeName = "\\\\.\\pipe\\" + pipeName;
    if (isServer) {
        return CreateNamedPipeA(fullPipeName.c_str(), PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
    }
    else {
        HANDLE hPipe = INVALID_HANDLE_VALUE;
        for (int i = 0; i < 10; ++i) { // Retry connecting for a short period
            hPipe = CreateFileA(fullPipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
                OPEN_EXISTING, 0, NULL);
            if (hPipe != INVALID_HANDLE_VALUE) break;
            if (GetLastError() != ERROR_PIPE_BUSY) break;
            Sleep(100); // Wait and retry if busy
        }
        return hPipe;
    }
}
std::string CreateCloneExecutable() {
    char currentPath[MAX_PATH];
    GetModuleFileNameA(NULL, currentPath, MAX_PATH);
    std::string newName = GenerateRandomBinaryName();
    std::string newPath = std::string(currentPath);
    size_t lastSlash = newPath.find_last_of('\\');
    if (lastSlash != std::string::npos) {
        newPath = newPath.substr(0, lastSlash + 1) + newName;
    }
    else {
        newPath = newName; // Should not happen if GetModuleFileNameA gives full path
    }
    if (!CopyFileA(currentPath, newPath.c_str(), FALSE)) {
        std::cerr << "CreateCloneExecutable: Failed to copy file to " << newPath << " Error: " << GetLastError() << std::endl;
        return ""; // Return empty on failure
    }

    // Set temporary attribute in case cleaup fails
    if (!SetFileAttributesA(newPath.c_str(), FILE_ATTRIBUTE_TEMPORARY)) {
        DEBUG_PRINTF("CreateCloneExecutable: Warning - Failed to set TEMPORARY attribute on %s. Error: %lu\n",
            newPath.c_str(), GetLastError());
    }
    return newPath;
}

extern "C" void CaptureRAX_And_CallHelper();  // Assembly stub

// Data to be sent back over the pipe from the C++ helper
struct ApiCallResultResponse {
    BOOL    wasApiCallConsideredSuccess;
    DWORD64 apiReturnValue;
    DWORD   lastErrorValue;
};

HANDLE g_hPipeForChildResponse = INVALID_HANDLE_VALUE;
// C++ helper function, to be called from assembly.
extern "C" __declspec(noinline) void NTAPI ProcessResultAndExit(DWORD64 raxFromApi) {
    DEBUG_PRINTF("ProcessResultAndExit: Captured RAX from target API = 0x%llX\n", raxFromApi);


    DWORD lastError = 0;
    bool apiCallSuccess = true; // Assume success initially

	// Debug some failures. Should be removed later when the actual response is sent back to the parent.
    if (raxFromApi == 0 || raxFromApi == (DWORD64)INVALID_HANDLE_VALUE) {
        apiCallSuccess = false;
        lastError = GetLastError(); // Get error code if API indicated failure
        DEBUG_PRINTF("ProcessResultAndExit: Target API call appears to have failed. LastError: %lu\n", lastError);
    }
    else {
        DEBUG_COUT("ProcessResultAndExit: Target API call appears to have succeeded." << std::endl);
    }
    
	std::string pipeName = "RecursiveDelegationPipe_" + std::to_string(GetCurrentProcessId()) + "_0"; // Level 0 pipe name
	
    if (g_hPipeForChildResponse == INVALID_HANDLE_VALUE) {
        lastError = GetLastError(); // Get error code if API indicated failure
        DEBUG_PRINTF("ProcessResultAndExit: Failed to connect to pipe. LastError: %lu\n", lastError, lastError);
    }

    DEBUG_COUT("Child: Connected to pipe." << std::endl);
	BOOL result = TRUE; // reaching here means api was called. up to the original caller to look at rax return value and decide what the results mean
    DWORD bytesWritten;
    if (!WriteFile(g_hPipeForChildResponse, &result, sizeof(BOOL), &bytesWritten, NULL) || bytesWritten != sizeof(BOOL)) {
        std::cerr << "Child: Failed to write result to pipe. Error: " << GetLastError() << std::endl;
    }
    DEBUG_COUT("Child: Sent result to parent." << std::endl);
	Sleep(10000); // Give time for parent to read before closing
    DEBUG_COUT("CppHelper_ProcessResultAndExit: Terminating process." << std::endl);
    TerminateProcess(GetCurrentProcess(), apiCallSuccess ? 0 : 1); // Exit code based on API success
    ExitProcess(apiCallSuccess ? 0 : 2); // Fallback if TerminateProcess somehow returns/fails
}

void* PrepareStackForApiCall(
    const std::vector<DWORD64>& stackArgs_in_order,
    FARPROC pRetAddressForApi,
    void** outStackAllocationBase
) {
    if (!pRetAddressForApi || !outStackAllocationBase) {
        std::cerr << "PrepareStackForApiCall: ERROR - Null pRetAddressForApi or outStackAllocationBase." << std::endl;
        return nullptr;
    }
    const size_t shadowSpaceSize = 32;
    const size_t retAddrSlotSize = 8;
    const size_t firstStackArgOffset = 0x28;
    size_t numStackArgs = stackArgs_in_order.size();
    size_t totalStackArgsSizeBytes = numStackArgs * sizeof(DWORD64);
    SIZE_T allocationSize = (2 << 20);  // not just for our functions but enough for everything else that runs in the thread such as the thread cleanup routine
    SIZE_T minRequiredForOurData = retAddrSlotSize + shadowSpaceSize + totalStackArgsSizeBytes + 16;
    if (allocationSize < minRequiredForOurData) {
        allocationSize = minRequiredForOurData + 4096;
        DEBUG_COUT("  INFO: Increased allocationSize to " << allocationSize << " due to argument data size." << std::endl);
    }
    void* stackBase = VirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stackBase) {
        std::cerr << "PrepareStackForApiCall: ERROR - VirtualAlloc failed. Error: " << GetLastError() << std::endl;
        return nullptr;
    }
    *outStackAllocationBase = stackBase;
    DEBUG_COUT("  DEBUG: PrepareStackForApiCall - stackBase = " << stackBase
        << ", allocationSize = " << allocationSize << std::endl);
    char* pStackHighWatermark = (char*)stackBase + allocationSize;
    char* pTentative_Addr_5th_Arg_Slot = pStackHighWatermark - totalStackArgsSizeBytes;
    char* pProspectiveRsp = pTentative_Addr_5th_Arg_Slot - shadowSpaceSize - retAddrSlotSize;
    DEBUG_COUT("  DEBUG: pStackHighWatermark (initial top for calc) = " << (void*)pStackHighWatermark << std::endl);
    DEBUG_COUT("  DEBUG: pTentative_Addr_5th_Arg_Slot (if args pushed from top) = " << (void*)pTentative_Addr_5th_Arg_Slot << std::endl);
    DEBUG_COUT("  DEBUG: pProspectiveRsp (unaligned RSP target) = " << (void*)pProspectiveRsp << std::endl);
    DWORD64 finalRspVal = ((DWORD64)pProspectiveRsp - 8ULL) & ~15ULL;
    finalRspVal += 8ULL;
    DEBUG_COUT("  DEBUG: finalRspVal (calculated and aligned RSP) = " << (void*)finalRspVal << std::endl);
    if (finalRspVal < (DWORD64)stackBase || (finalRspVal + retAddrSlotSize) >((DWORD64)stackBase + allocationSize)) {
        std::cerr << "PrepareStackForApiCall: ERROR - finalRspVal is outside allocated stack region after alignment." << std::endl;
        std::cerr << "  stackBase: " << stackBase << ", stackEnd: " << (void*)((char*)stackBase + allocationSize - 1) << std::endl;
        std::cerr << "  finalRspVal: " << (void*)finalRspVal << std::endl;
        VirtualFree(stackBase, 0, MEM_RELEASE); *outStackAllocationBase = nullptr; return nullptr;
    }
    *(DWORD64*)finalRspVal = (DWORD64)pRetAddressForApi;
    DEBUG_PRINTF("  DEBUG: PLACED Return Address (value 0x%llX) to actual RSP %p\n",
        (unsigned long long)(DWORD64)pRetAddressForApi, (void*)finalRspVal);
    char* pArgWriter = (char*)finalRspVal + firstStackArgOffset;
    DEBUG_COUT("  DEBUG: Placing stack arguments relative to finalRspVal:" << std::endl);
    for (size_t i = 0; i < numStackArgs; ++i) {
        if ((pArgWriter + sizeof(DWORD64)) > ((char*)stackBase + allocationSize)) {
            std::cerr << "PrepareStackForApiCall: ERROR - About to write stack argument #" << (i + 5)
                << " out of allocated stack bounds." << std::endl;
            std::cerr << "  pArgWriter: " << (void*)pArgWriter << ", stackEnd: "
                << (void*)((char*)stackBase + allocationSize - 1) << std::endl;
            VirtualFree(stackBase, 0, MEM_RELEASE); *outStackAllocationBase = nullptr; return nullptr;
        }
        *(DWORD64*)pArgWriter = stackArgs_in_order[i];
        DEBUG_PRINTF("  DEBUG: PLACED arg #%zu (value 0x%llX) to address %p (RSP+0x%X)\n",
            i + 5, (unsigned long long)stackArgs_in_order[i], (void*)pArgWriter,
            (unsigned int)(firstStackArgOffset + i * sizeof(DWORD64)));
        pArgWriter += sizeof(DWORD64);
    }
    std::cout << "Prepared stack. Final New RSP will be: " << (void*)finalRspVal
        << " (RSP % 16 = " << (finalRspVal % 16) << ")" << std::endl;
    std::cout << "  Return address for API set to: " << (void*)pRetAddressForApi << std::endl;
    if (!stackArgs_in_order.empty()) {
        DEBUG_PRINTF("  VERIFICATION: 5th arg (value 0x%llX) is at %p (RSP+0x%X)\n",
            (unsigned long long)stackArgs_in_order[0], (void*)(finalRspVal + firstStackArgOffset),
            (unsigned int)firstStackArgOffset);
        if (numStackArgs > 1) {
            DEBUG_PRINTF("  VERIFICATION: 6th arg (value 0x%llX) is at %p (RSP+0x%X)\n",
                (unsigned long long)stackArgs_in_order[1], (void*)(finalRspVal + firstStackArgOffset + sizeof(DWORD64)),
                (unsigned int)(firstStackArgOffset + sizeof(DWORD64)));
        }
    }
    else {
        std::cout << "  No stack arguments were provided for the API call." << std::endl;
    }
    return (void*)finalRspVal;
}


struct ApiCallParams {
    char funcNameWithModule[256]; // e.g., "Kernel32!VirtualAllocEx"
    DWORD64 rcx_val;
    DWORD64 rdx_val;
    DWORD64 r8_val;
    DWORD64 r9_val;
    // Stack arguments will be sent as a vector separately
};

// Renamed and refactored version of your old ExecuteFunction
// This is called at level 0 to actually perform the API call.
bool ExecuteApiCallAtLevelZero(
    const ApiCallParams* pCallParams,
    const std::vector<DWORD64>* pStackArgs,
    NtContinue_t pNtContinueFunc, // Resolved NtContinue
    FARPROC pExitThreadFunc       // Resolved ExitThread
) {
    DEBUG_COUT("ExecuteApiCallAtLevelZero: Preparing to execute API: " << pCallParams->funcNameWithModule << std::endl);

    FARPROC targetApi = ResolveFunction(pCallParams->funcNameWithModule);
    if (!targetApi) {
        std::cerr << "ExecuteApiCallAtLevelZero: Failed to resolve target API." << std::endl;
        return false;
    }

    void* stackAllocationBase = nullptr;
    void* pNewStackTopForTargetApi = PrepareStackForApiCall(
        *pStackArgs,
        (FARPROC)CaptureRAX_And_CallHelper, // Target API will "return" to our terminator function
        &stackAllocationBase
    );

    if (!pNewStackTopForTargetApi) {
        std::cerr << "ExecuteApiCallAtLevelZero: ERROR - Failed to prepare stack for target API." << std::endl;
        if (stackAllocationBase) VirtualFree(stackAllocationBase, 0, MEM_RELEASE);
        return false;
    }

    CONTEXT targetContext;
    ZeroMemory(&targetContext, sizeof(CONTEXT));
    // For NtContinue, explicitly set segments if not relying on current thread's.
    // A common practice is to get current context, modify, then pass to NtContinue.
    // However, for a fresh "warp", minimal context might work, but can be risky.
    // To be safer, let's capture the current thread's full context and modify that.
    // This is especially important for segment registers (CS, DS, ES, SS, FS, GS).
    // Since this function *is* the thread that will be warped, this is appropriate.

    // Get current context as a base
    RtlCaptureContext(&targetContext); // Or GetThreadContext(GetCurrentThread(), &targetContext)
    // RtlCaptureContext is often preferred for current thread.

    // Now, overwrite the parts we need for the target API call
    // The ContextFlags field for NtContinue should reflect what we are providing
    // and what the system might need to correctly switch.
    //targetContext.ContextFlags = CONTEXT_CONTROL |
    //    CONTEXT_INTEGER |
    //    CONTEXT_SEGMENTS |
    //    CONTEXT_FLOATING_POINT; // Add FPU/XMM state

    //// Check if XState is enabled and used, then include it.
    //// This requires careful handling of the XState save area.
    //// RtlCaptureContext *should* have populated it correctly.
    //ULONG64 xstateFeatures = GetEnabledXStateFeatures();
    //if (xstateFeatures != 0) { // If any XState features are enabled. AVX and SSE stuff is nasty and confusing.
    //    targetContext.ContextFlags |= CONTEXT_XSTATE;
    //    // Ensure the XSTATE_SAVE_AREA is properly aligned and large enough.
    //    // RtlCaptureContext populates the XState features in the CONTEXT structure.
    //    // The CONTEXT structure itself contains space for this.
    //}

    targetContext.Rip = (DWORD64)targetApi;
    targetContext.Rcx = pCallParams->rcx_val;
    targetContext.Rdx = pCallParams->rdx_val;
    targetContext.R8 = pCallParams->r8_val;
    targetContext.R9 = pCallParams->r9_val;
    targetContext.Rsp = (DWORD64)pNewStackTopForTargetApi;
    targetContext.Rbp = targetContext.Rsp; // Set RBP to new RSP

    // EFlags: The original code set it to 0x202.
    // RtlCaptureContext will have the current EFlags. Modifying IF (Interrupt Flag)
    // is generally not needed unless specifically intended. For now, let's trust
    // what RtlCaptureContext provides, or set a known-good default if issues arise.
    // targetContext.EFlags = 0x202; // Overwrite if necessary, but usually not.
    DEBUG_PRINTF("ExecuteApiCallAtLevelZero: Prepared CONTEXT for NtContinue:\n");
    DEBUG_PRINTF("  RIP: 0x%llX\n", targetContext.Rip);
    DEBUG_PRINTF("  RCX: 0x%llX, RDX: 0x%llX, R8: 0x%llX, R9: 0x%llX\n",
        targetContext.Rcx, targetContext.Rdx, targetContext.R8, targetContext.R9);
    DEBUG_PRINTF("  RSP: 0x%llX, RBP: 0x%llX\n", targetContext.Rsp, targetContext.Rbp);
    DEBUG_PRINTF("  EFlags: 0x%X\n", targetContext.EFlags); // Can be noisy, current EFlags is fine.

    DEBUG_COUT("ExecuteApiCallAtLevelZero: Calling NtContinue..." << std::endl);
    NTSTATUS status = pNtContinueFunc(&targetContext, FALSE);

    std::cerr << "ExecuteApiCallAtLevelZero: ERROR - NtContinue returned with status 0x"
        << std::hex << status << std::dec << ". This is unexpected." << std::endl;
    if (stackAllocationBase) {
        VirtualFree(stackAllocationBase, 0, MEM_RELEASE);
    }
    // This return is only hit if NtContinue fails, which means the thread did not warp.
    return NT_SUCCESS(status);
}

bool RecursiveDelegate(
    int level,
    const ApiCallParams* pCallParams,
    const std::vector<DWORD64>* pStackArgs,
    NtContinue_t pNtContinueFunc, // Pass these down
    FARPROC pExitThreadFunc
) {
    std::cout << "Process " << GetCurrentProcessId() << " at recursion level: " << level
        << ", target: " << pCallParams->funcNameWithModule << std::endl;

    if (level <= 0) {
        std::cout << "Executing function at level 0: " << pCallParams->funcNameWithModule << std::endl;
        return ExecuteApiCallAtLevelZero(pCallParams, pStackArgs, pNtContinueFunc, pExitThreadFunc);
    }

    std::string clonePath = CreateCloneExecutable();
    if (clonePath.empty()) {
        std::cerr << "RecursiveDelegate: Failed to create clone executable." << std::endl;
        return false;
    }

    std::stringstream pipeNameSs;
    pipeNameSs << "RecursiveDelegationPipe_" << GetCurrentProcessId() << "_" << level;
    std::string pipeName = pipeNameSs.str();

    HANDLE hPipe = CreateIPCPipe(pipeName, true);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "RecursiveDelegate: Failed to create pipe server '" << pipeName << "'. Error: " << GetLastError() << std::endl;
        DeleteFileA(clonePath.c_str()); // Clean up clone
        return false;
    }
    DEBUG_COUT("RecursiveDelegate: Pipe server created: " << pipeName << std::endl);

    std::stringstream cmdLine;
    // Quote clonePath in case it has spaces
    cmdLine << "\"" << clonePath << "\" " << (level - 1)
        << " \"" << pCallParams->funcNameWithModule << "\" " // Pass original func name string
        << pipeName; // Pipe name for child to connect to

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;

    DEBUG_COUT("RecursiveDelegate: Creating child process: " << cmdLine.str() << std::endl);
    if (!CreateProcessA(NULL, const_cast<LPSTR>(cmdLine.str().c_str()), NULL, NULL,
        TRUE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "RecursiveDelegate: Failed to create child process. Error: " << GetLastError() << std::endl;
        CloseHandle(hPipe);
        DeleteFileA(clonePath.c_str());
        return false;
    }
    DEBUG_COUT("RecursiveDelegate: Child process created. PID: " << pi.dwProcessId << std::endl);


    // Mark the clone for deletion once all handles to it are closed.
    // The child process will have a handle to its own executable image while it's running.
    HANDLE hCloneFileForDelete = CreateFileA(
        clonePath.c_str(),
        DELETE,                          // Request delete access
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, // Allow child to run
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_DELETE_ON_CLOSE,       // Mark for deletion
        NULL
    );

    if (hCloneFileForDelete == INVALID_HANDLE_VALUE) {
        std::cerr << "RecursiveDelegate: Warning - Failed to open clone " << clonePath
            << " with FILE_FLAG_DELETE_ON_CLOSE. Error: " << GetLastError()
            << ". Manual deletion might be required." << std::endl;
            // Continue without this auto-delete feature, manual DeleteFileA will still try
    }
    else {
        DEBUG_COUT("RecursiveDelegate: Clone " << clonePath << " marked with FILE_FLAG_DELETE_ON_CLOSE." << std::endl);
        CloseHandle(hCloneFileForDelete); // Close our handle; system now manages deletion.
    }

    DEBUG_COUT("RecursiveDelegate: Waiting for pipe client to connect..." << std::endl);
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        std::cerr << "RecursiveDelegate: Failed to connect to client on pipe. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1); // Terminate child if pipe connection fails
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hPipe);
        DeleteFileA(clonePath.c_str());
        return false;
    }
    DEBUG_COUT("RecursiveDelegate: Pipe client connected." << std::endl);

    DWORD bytesWritten;
    // Send ApiCallParams (fixed size structure)
    if (!WriteFile(hPipe, pCallParams, sizeof(ApiCallParams), &bytesWritten, NULL) || bytesWritten != sizeof(ApiCallParams)) {
        std::cerr << "RecursiveDelegate: Failed to write ApiCallParams to pipe. Error: " << GetLastError() << std::endl;
        return false;
    }
    DEBUG_COUT("RecursiveDelegate: Sent ApiCallParams." << std::endl);


    // Send number of stack arguments
    SIZE_T numStackArgs = pStackArgs->size();
    if (!WriteFile(hPipe, &numStackArgs, sizeof(SIZE_T), &bytesWritten, NULL) || bytesWritten != sizeof(SIZE_T)) {
        std::cerr << "RecursiveDelegate: Failed to write numStackArgs to pipe. Error: " << GetLastError() << std::endl;
        return false;
    }
    DEBUG_COUT("RecursiveDelegate: Sent numStackArgs: " << numStackArgs << std::endl);


    // Send stack argument data (if any)
    if (numStackArgs > 0) {
        SIZE_T stackArgsDataSize = numStackArgs * sizeof(DWORD64);
        if (!WriteFile(hPipe, pStackArgs->data(), stackArgsDataSize, &bytesWritten, NULL) || bytesWritten != stackArgsDataSize) {
            std::cerr << "RecursiveDelegate: Failed to write stackArgs data to pipe. Error: " << GetLastError() << std::endl;
            TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hPipe); DeleteFileA(clonePath.c_str());
            return false;
        }
        DEBUG_COUT("RecursiveDelegate: Sent stackArgs data." << std::endl);
    }


    DEBUG_COUT("RecursiveDelegate: Waiting for result from child..." << std::endl);
    BOOL resultFromChild;
    DWORD bytesRead;
    if (!ReadFile(hPipe, &resultFromChild, sizeof(BOOL), &bytesRead, NULL) || bytesRead != sizeof(BOOL)) {
        std::cerr << "RecursiveDelegate: Failed to read result from child. Error: " << GetLastError() << std::endl;
        resultFromChild = FALSE; // Assume failure
    }
    DEBUG_COUT("RecursiveDelegate: Received result from child: " << (resultFromChild ? "TRUE " : "FALSE ") << std::endl);

    // Wait for child process to terminate fully
    WaitForSingleObject(pi.hProcess, INFINITE);
    DEBUG_COUT("RecursiveDelegate: Child process terminated." << std::endl);


    CloseHandle(hPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (!DeleteFileA(clonePath.c_str())) {
        std::cerr << "RecursiveDelegate: Warning - Failed to delete clone " << clonePath << ". Error: " << GetLastError() << std::endl;
    }


    return resultFromChild == TRUE;
}

bool ProcessChildMode(
    int argc, char* argv[],
    NtContinue_t pNtContinueFunc, // Pass these down
    FARPROC pExitThreadFunc
) {
    if (argc < 4) { // ExecutableName, Level, FuncName, PipeName
        std::cerr << "Child: Insufficient arguments." << std::endl;
        return false;
    }

    int level = atoi(argv[1]);
    // argv[2] is funcNameWithModule, argv[3] is pipeName
    // We don't need funcNameWithModule directly here, as it's inside ApiCallParams

    std::string pipeName = argv[3];
    DEBUG_COUT("Child (PID " << GetCurrentProcessId() << "): Connecting to pipe: " << pipeName << std::endl);


    HANDLE hPipe = CreateIPCPipe(pipeName, false);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Child: Failed to connect to pipe '" << pipeName << "'. Error: " << GetLastError() << std::endl;
        return false;
    }
    g_hPipeForChildResponse = hPipe;
    DEBUG_COUT("Child: Connected to pipe." << std::endl);

    ApiCallParams receivedApiParams;
    std::vector<DWORD64> receivedStackArgs;
    DWORD bytesRead;

    if (!ReadFile(hPipe, &receivedApiParams, sizeof(ApiCallParams), &bytesRead, NULL) || bytesRead != sizeof(ApiCallParams)) {
        std::cerr << "Child: Failed to read ApiCallParams. Error: " << GetLastError() << std::endl;
        CloseHandle(hPipe); return false;
    }
    DEBUG_COUT("Child: Received ApiCallParams for: " << receivedApiParams.funcNameWithModule << std::endl);

    SIZE_T numStackArgs;
    if (!ReadFile(hPipe, &numStackArgs, sizeof(SIZE_T), &bytesRead, NULL) || bytesRead != sizeof(SIZE_T)) {
        std::cerr << "Child: Failed to read numStackArgs. Error: " << GetLastError() << std::endl;
        CloseHandle(hPipe); return false;
    }
    DEBUG_COUT("Child: Received numStackArgs: " << numStackArgs << std::endl);


    if (numStackArgs > 0) {
        receivedStackArgs.resize(numStackArgs);
        SIZE_T stackArgsDataSize = numStackArgs * sizeof(DWORD64);
        if (!ReadFile(hPipe, receivedStackArgs.data(), stackArgsDataSize, &bytesRead, NULL) || bytesRead != stackArgsDataSize) {
            std::cerr << "Child: Failed to read stackArgs data. Error: " << GetLastError() << std::endl;
            CloseHandle(hPipe); return false;
        }
        DEBUG_COUT("Child: Received stackArgs data." << std::endl);
    }

    // Call RecursiveDelegate with the received data
    BOOL result = RecursiveDelegate(level, &receivedApiParams, &receivedStackArgs, pNtContinueFunc, pExitThreadFunc);
    DEBUG_COUT("Child: RecursiveDelegate result: " << (result ? "TRUE" : "FALSE") << std::endl);


    DWORD bytesWritten;
    if (!WriteFile(hPipe, &result, sizeof(BOOL), &bytesWritten, NULL) || bytesWritten != sizeof(BOOL)) {
        std::cerr << "Child: Failed to write result to pipe. Error: " << GetLastError() << std::endl;
        // Continue to close pipe
    }
    DEBUG_COUT("Child: Sent result to parent." << std::endl);

    CloseHandle(hPipe);
    DEBUG_COUT("Child: Exiting." << std::endl);
    return result == TRUE; // The return value of ProcessChildMode determines main's exit code for child
}

int main(int argc, char* argv[]) {
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

    if (!pNtContinue || !pExitThread) {
        std::cerr << "main: CRITICAL - Failed to resolve NtContinue or ExitThread. Error: "
            << (!pNtContinue ? "NtContinue " : "") << (!pExitThread ? "ExitThread " : "")
            << GetLastError() << std::endl;
        return 1;
    }
    DEBUG_PRINTF("main: NtContinue at %p, ExitThread at %p\n", (void*)pNtContinue, (void*)pExitThread);


    if (argc > 1) { // Arguments suggest it's a child process
        DEBUG_COUT("main: Detected child mode." << std::endl);
        // Child process returns 0 on success, 1 on internal failure path
        return ProcessChildMode(argc, argv, pNtContinue, pExitThread) ? 0 : 1;
    }

    // ---- Parent Process Logic ----
    DEBUG_COUT("main: Detected parent mode." << std::endl);
    LoadLibraryA("user32.dll"); // For MessageBoxA example, if used directly by parent

    // Example: Call Kernel32!VirtualAllocEx(GetCurrentProcess(), NULL, 20480, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    // RCX = hProcess, RDX = lpAddress, R8 = dwSize, R9 = flAllocationType
    // Stack Arg 5 = flProtect

    // --- Test 2: VirtualAllocEx using an INHERITED OpenProcess handle ---
    std::cout << "\n--- TESTING VirtualAllocEx (Self, Inherited OpenProcess Handle) ---" << std::endl;
    HANDLE hSelfProcessInheritable = NULL;
    SECURITY_ATTRIBUTES sa_inherit;
    sa_inherit.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa_inherit.lpSecurityDescriptor = NULL;
    sa_inherit.bInheritHandle = TRUE; // Make the handle inheritable

    // Open a handle to the current process with specific rights needed by VirtualAllocEx
    // PROCESS_VM_OPERATION is required for VirtualAllocEx.
    hSelfProcessInheritable = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, // Desired access
        TRUE,                       // bInheritHandle (already set in sa, but OpenProcess also has this flag)
        GetCurrentProcessId()       // Process ID
    );

    if (hSelfProcessInheritable == NULL) {
        std::cerr << "main: ERROR - OpenProcess failed: " << GetLastError() << std::endl;
    }
    else {
        DEBUG_PRINTF("main: Opened inheritable handle to self: 0x%llX\n", (DWORD64)hSelfProcessInheritable);

        ApiCallParams initialCallParams = {}; // Zero initialize
        strncpy_s(initialCallParams.funcNameWithModule, "Kernel32!VirtualAllocEx", _TRUNCATE);
        initialCallParams.rcx_val = (DWORD64)hSelfProcessInheritable;
        initialCallParams.rdx_val = (DWORD64)NULL; // Let OS choose address
        initialCallParams.r8_val = 20480;          // dwSize
        initialCallParams.r9_val = MEM_COMMIT | MEM_RESERVE; // flAllocationType

        std::vector<DWORD64> initialStackArgs;
        initialStackArgs.push_back(PAGE_EXECUTE_READWRITE); // 5th param: flProtect

        const int MAX_RECURSION = 1; // Set recursion depth (e.g., 2 levels deep)
        DEBUG_COUT("main: Starting recursive delegation. Max depth: " << MAX_RECURSION << std::endl);
        bool overallResult = RecursiveDelegate(MAX_RECURSION, &initialCallParams, &initialStackArgs, pNtContinue, pExitThread);

        std::cout << "Overall recursive delegation " << (overallResult ? "succeeded" : "failed") << std::endl;
        if (overallResult && MAX_RECURSION == 0 && strcmp(initialCallParams.funcNameWithModule, "Kernel32!VirtualAllocEx") == 0) {
            std::cout << "  (Note: VirtualAllocEx was called. Result capture isn't implemented." << std::endl;
        }

        // --- Test 1: VirtualAllocEx (as before with recurse level 2) ---
        ApiCallParams vaParams = {};
        strncpy_s(vaParams.funcNameWithModule, "Kernel32!VirtualAllocEx", _TRUNCATE);
        vaParams.rcx_val = (DWORD64)hSelfProcessInheritable;
        vaParams.rdx_val = (DWORD64)NULL;
        vaParams.r8_val = (2 << 14);
        vaParams.r9_val = MEM_COMMIT | MEM_RESERVE;
        std::vector<DWORD64> vaStackArgs;
        vaStackArgs.push_back(PAGE_EXECUTE_READWRITE);

        RecursiveDelegate(2, &vaParams, &vaStackArgs, pNtContinue, pExitThread); // Test at level 0

        // --- Test 2: SetEvent with an inherited handle ---
        std::cout << "\n--- TESTING SetEvent with Inherited Handle ---" << std::endl;

        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = NULL;
        sa.bInheritHandle = TRUE; // Make the event handle inheritable

        HANDLE hEventForChild = CreateEventA(&sa, TRUE, FALSE, "MyRecursiveEventTest"); // Manual-reset, initially non-signaled
        if (hEventForChild == NULL) {
            std::cerr << "main: ERROR - CreateEventA failed: " << GetLastError() << std::endl;
        }
        else {
            DEBUG_PRINTF("main: Created inheritable event handle: 0x%llX\n", (DWORD64)hEventForChild);

            ApiCallParams seParams = {};
            strncpy_s(seParams.funcNameWithModule, "Kernel32!SetEvent", _TRUNCATE);
            // SetEvent takes one argument: HANDLE hEvent (in RCX)
            seParams.rcx_val = (DWORD64)hEventForChild; // Pass the parent's handle value
            seParams.rdx_val = 0;
            seParams.r8_val = 0;
            seParams.r9_val = 0;
            std::vector<DWORD64> seStackArgs; // SetEvent has no stack arguments

            std::cout << "main: Delegating SetEvent. Parent will wait on the event." << std::endl;
            bool delegateResult = RecursiveDelegate(5, &seParams, &seStackArgs, pNtContinue, pExitThread);

            if (delegateResult) {
                DEBUG_COUT("main: RecursiveDelegate for SetEvent reported success indication from child pipe." << std::endl);
                DWORD waitResult = WaitForSingleObject(hEventForChild, 5000); // Wait for 5 seconds
                if (waitResult == WAIT_OBJECT_0) {
                    std::cout << "main: SUCCESS - Event was signaled by a delegated process!" << std::endl;
                }
                else if (waitResult == WAIT_TIMEOUT) {
                    std::cout << "main: TIMEOUT - Event was NOT signaled by delegated process." << std::endl;
                }
                else {
                    std::cout << "main: ERROR - WaitForSingleObject on event failed: " << GetLastError() << std::endl;
                }
            }
            else {
                std::cout << "main: RecursiveDelegate for SetEvent failed to complete." << std::endl;
            }
            CloseHandle(hEventForChild);
        }
        std::cout << "--- SetEvent Test Complete ---\n" << std::endl;


        DEBUG_COUT("main: Parent process finished. Press any key to close..." << std::endl);
        std::cin.get(); // Uncomment if you want to pause before exit
        return overallResult ? 0 : 1;
    }
}