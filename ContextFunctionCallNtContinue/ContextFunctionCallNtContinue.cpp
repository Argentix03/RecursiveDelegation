#include <windows.h>
#include <iostream> // For std::cerr and std::cout
#include <vector>   // For std::vector
#include <string>   // For constructing test messages/paths if needed
#include <cstdio>   // For printf (used in debug prints)

// Define a preprocessor macro for debug prints
#ifdef _DEBUG
#define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#define DEBUG_COUT(x) std::cout << x
#else
#define DEBUG_PRINTF(...) do {} while (0)
#define DEBUG_COUT(x) do {} while (0)
#endif

// --- NtContinue Specifics ---
// Define NTSTATUS if not already available (usually from ntdef.h via windows.h, but good to be sure)
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

// Define the prototype for NtContinue
typedef NTSTATUS(NTAPI* NtContinue_t)(
    PCONTEXT ContextRecord,  // RCX in x64
    BOOLEAN TestAlert        // RDX in x64
    );

/**
 * @brief Parameters passed to the bootstrap thread that will call NtContinue.
 */
struct NtContinueBootstrapParams {
    CONTEXT* pTargetContext;    ///< Pointer to the CONTEXT structure to restore.
    NtContinue_t pNtContinue;   ///< Pointer to the NtContinue function in ntdll.dll.
};

// Forward declaration for PrepareStackForApiCall if needed, but it's defined before use here.

/**
 * @brief Prepares a new stack for a target API call according to the x64 calling convention.
 * (Implementation is identical to your previous working version)
 */
void* PrepareStackForApiCall(
    const std::vector<DWORD64>& stackArgs_in_order,
    FARPROC pRetAddressForApi,
    void** outStackAllocationBase
) {
    // ... (Full implementation from your previous working code) ...
    if (!pRetAddressForApi || !outStackAllocationBase) {
        std::cerr << "PrepareStackForApiCall: ERROR - Null pRetAddressForApi or outStackAllocationBase." << std::endl;
        return nullptr;
    }
    const size_t shadowSpaceSize = 32;
    const size_t retAddrSlotSize = 8;
    const size_t firstStackArgOffset = 0x28;
    size_t numStackArgs = stackArgs_in_order.size();
    size_t totalStackArgsSizeBytes = numStackArgs * sizeof(DWORD64);
    SIZE_T allocationSize = 65536;
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


/**
 * @brief Bootstrap thread function that prepares and calls NtContinue.
 *
 * This function is started as a new thread. It receives parameters to construct
 * a CONTEXT structure and then calls NtContinue to "warp" the thread to execute
 * the target API.
 * @param lpParameter Pointer to NtContinueBootstrapParams structure.
 * @return Does not return if NtContinue succeeds. Returns an error code otherwise.
 */
DWORD WINAPI BootstrapAndContinueThreadProc(LPVOID lpParameter) {
    NtContinueBootstrapParams* params = (NtContinueBootstrapParams*)lpParameter;

    if (!params || !params->pTargetContext || !params->pNtContinue) {
        DEBUG_COUT("BootstrapAndContinueThreadProc: ERROR - Invalid bootstrap parameters." << std::endl);
        // Cannot reliably call ExitThread if pNtContinue (from ntdll) is missing,
        // as ExitThread might also be in a different module we didn't resolve.
        // This thread will just exit.
        return 1;
    }

    DEBUG_COUT("BootstrapAndContinueThreadProc: Bootstrap started. Preparing to call NtContinue." << std::endl);
    DEBUG_PRINTF("  TargetContext->Rip = 0x%llX\n", params->pTargetContext->Rip);
    DEBUG_PRINTF("  TargetContext->Rsp = 0x%llX\n", params->pTargetContext->Rsp);
    DEBUG_PRINTF("  NtContinue address = %p\n", (void*)params->pNtContinue);

    // Call NtContinue.
    // RCX = PCONTEXT ContextRecord
    // RDX = BOOLEAN TestAlert (FALSE)
    // This function (BootstrapAndContinueThreadProc) will cease to exist in the call stack
    // if NtContinue is successful, as the thread's context is completely replaced.
    params->pNtContinue(params->pTargetContext, FALSE);

    // If NtContinue returns, it means it failed (highly unlikely for valid parameters).
    // Or, if TestAlert was TRUE and an alert was pending, it might return.
    DEBUG_COUT("BootstrapAndContinueThreadProc: ERROR - NtContinue returned, which is unexpected." << std::endl);
    return 2; // Should not be reached
}

/**
 * @brief Runs a test of hijacking a thread to call a specified API using NtContinue.
 */
void RunApiTestViaNtContinue(
    const std::string& testName,
    FARPROC apiToCall,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    const std::vector<DWORD64>& stackArgs,
    FARPROC pExitThreadAddress,
    NtContinue_t pNtContinueFunc, // Pass resolved NtContinue
    const std::string& postExecutionMessage = ""
) {
    std::cout << "\n--- TESTING " << testName << " (via NtContinue) ---" << std::endl;
    if (!apiToCall || !pExitThreadAddress || !pNtContinueFunc) {
        std::cerr << "RunApiTestViaNtContinue (" << testName << "): ERROR - NULL API, ExitThread, or NtContinue address." << std::endl;
        std::cout << "--- " << testName << " Test SKIPPED ---\n" << std::endl;
        return;
    }

    // 1. Prepare the new stack for the target API (same as before)
    void* stackAllocationBase = nullptr;
    void* pNewStackTopForApi = PrepareStackForApiCall(stackArgs, pExitThreadAddress, &stackAllocationBase);

    if (!pNewStackTopForApi) {
        std::cerr << "RunApiTestViaNtContinue (" << testName << "): ERROR - Failed to prepare stack." << std::endl;
        // stackAllocationBase might be NULL if VirtualAlloc failed, or valid if later step failed
        if (stackAllocationBase) VirtualFree(stackAllocationBase, 0, MEM_RELEASE);
        std::cout << "--- " << testName << " Test FAILED ---\n" << std::endl;
        return;
    }

    // 2. Prepare the CONTEXT structure for NtContinue
    // This CONTEXT structure will be restored by NtContinue.
    // It needs to be allocated somewhere the bootstrap thread can access it.
    // For simplicity, we allocate it on the main thread's stack, and the bootstrap
    // uses it before NtContinue overwrites the bootstrap's own stack.
    // For cross-process, this would need to be in shared/target memory.
    CONTEXT targetContext;
    ZeroMemory(&targetContext, sizeof(CONTEXT));
    targetContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; // Specify what's valid

    // Set registers for the target API call
    targetContext.Rip = (DWORD64)apiToCall;
    targetContext.Rcx = arg1;
    targetContext.Rdx = arg2;
    targetContext.R8 = arg3;
    targetContext.R9 = arg4;
    targetContext.Rsp = (DWORD64)pNewStackTopForApi;
    targetContext.Rbp = targetContext.Rsp; // Common practice

    // 3. Prepare parameters for the bootstrap thread
    NtContinueBootstrapParams bootstrapParams;
    bootstrapParams.pTargetContext = &targetContext; // Pointer to our CONTEXT structure
    bootstrapParams.pNtContinue = pNtContinueFunc;

    // 4. Create and run the bootstrap thread
    // The bootstrap thread is NOT created suspended. It runs immediately.
    HANDLE hThread = CreateThread(
        NULL,                           // Default security
        0,                              // Default stack size for bootstrap (it won't use much)
        BootstrapAndContinueThreadProc, // Start routine is our bootstrap
        &bootstrapParams,               // Pass params to bootstrap
        0,                              // Run immediately
        NULL                            // Don't need thread ID
    );

    if (!hThread) {
        std::cerr << "RunApiTestViaNtContinue (" << testName << "): ERROR - CreateThread for bootstrap failed: " << GetLastError() << std::endl;
        if (stackAllocationBase) VirtualFree(stackAllocationBase, 0, MEM_RELEASE);
        std::cout << "--- " << testName << " Test FAILED ---\n" << std::endl;
        return;
    }
    std::cout << "Created bootstrap thread for " << testName << ". Waiting for it to complete..." << std::endl;

    WaitForSingleObject(hThread, INFINITE); // Wait for the thread (which calls ExitThread) to terminate
    std::cout << testName << " (via NtContinue) thread exited." << std::endl;
    if (!postExecutionMessage.empty()) {
        std::cout << postExecutionMessage << std::endl;
    }

    CloseHandle(hThread);
    if (stackAllocationBase) {
        VirtualFree(stackAllocationBase, 0, MEM_RELEASE);
        DEBUG_COUT("Freed stack for " << testName << "." << std::endl);
    }
    std::cout << "--- " << testName << " Test Complete ---\n" << std::endl;
}


int main() {
    // --- Common Setup ---
    LoadLibraryA("user32.dll"); // For MessageBoxA
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cerr << "main: ERROR - Failed to get ntdll.dll handle." << std::endl;
        return 1;
    }

    FARPROC pExitThread = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    NtContinue_t pNtContinue = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");

    if (!pExitThread || !pNtContinue) {
        std::cerr << "main: ERROR - Failed to get ExitThread or NtContinue address. Cannot run tests." << std::endl;
        return 1;
    }
    DEBUG_PRINTF("main: NtContinue found at %p\n", (void*)pNtContinue);

    // --- Define and Run Tests using NtContinue ---

    // Test 1: MessageBoxA via NtContinue
    FARPROC pMessageBoxA = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    RunApiTestViaNtContinue(
        "MessageBoxA",
        pMessageBoxA,
        (DWORD64)NULL,
        (DWORD64)"Hello via NtContinue!",
        (DWORD64)"NtContinue Demo",
        (DWORD64)MB_OK | MB_ICONEXCLAMATION,
        {}, // No stack arguments
        pExitThread,
        pNtContinue
    );

    // Test 2: CreateFileA via NtContinue
    FARPROC pCreateFileA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
    const char* testFileNameNtCont = "C:\\temp\\hijack_ntcontinue_file.txt";
    std::vector<DWORD64> stackArgsCreateFileNtCont;
    stackArgsCreateFileNtCont.push_back((DWORD64)CREATE_ALWAYS);
    stackArgsCreateFileNtCont.push_back((DWORD64)FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE); // Different flags
    stackArgsCreateFileNtCont.push_back((DWORD64)NULL);

    RunApiTestViaNtContinue(
        "CreateFileA",
        pCreateFileA,
        (DWORD64)testFileNameNtCont,
        GENERIC_WRITE | GENERIC_READ,
        FILE_SHARE_READ,
        (DWORD64)NULL,
        stackArgsCreateFileNtCont,
        pExitThread,
        pNtContinue,
        "VERIFY: Check if '" + std::string(testFileNameNtCont) + "' was briefly created (it uses FILE_FLAG_DELETE_ON_CLOSE)."
    );

    // Test 3: GetTickCount via NtContinue
    FARPROC pGetTickCount = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount");
    RunApiTestViaNtContinue(
        "GetTickCount",
        pGetTickCount,
        0, 0, 0, 0,
        {},
        pExitThread,
        pNtContinue,
        "GetTickCount called via NtContinue (no output to verify)."
    );


    std::cout << "\nAll tests finished. Press any key to close..." << std::endl;
    std::cin.get();
    return 0;
}