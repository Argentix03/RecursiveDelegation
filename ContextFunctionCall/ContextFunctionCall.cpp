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

/**
 * @brief Context structure for preparing an API call via SetThreadContext.
 *
 * This structure holds all necessary information to set up the target thread's
 * context to call a specified WinAPI function with given arguments.
 */
struct HijackContext {
    FARPROC targetApiAddress;   ///< Address of the WinAPI function to be called.
    DWORD64 arg1_rcx;           ///< Value for the RCX register (1st integer/pointer argument).
    DWORD64 arg2_rdx;           ///< Value for the RDX register (2nd integer/pointer argument).
    DWORD64 arg3_r8;            ///< Value for the R8 register (3rd integer/pointer argument).
    DWORD64 arg4_r9;            ///< Value for the R9 register (4th integer/pointer argument).

    /**
     * @brief Pointer to the top of the prepared stack for the target API.
     * This address will become the new RSP (Stack Pointer) for the target thread.
     * It MUST be (16*N)+8 aligned as per x64 calling convention (RSP points to the return address,
     * and after a CALL, RSP is (16*N)+8; SetThreadContext bypasses CALL, so RSP itself must meet this).
     * The memory this RSP points to must contain the return address for the targetApiAddress.
     */
    void* pPreparedStackTop;
};

/**
 * @brief Modifies the context of a suspended thread to execute a target API call.
 *
 * @param hThread A handle to the suspended thread whose context will be modified.
 * @param context A HijackContext structure containing the API address, arguments, and prepared stack pointer.
 * @return true if the thread context was successfully set, false otherwise.
 *
 * The caller is responsible for resuming the thread and subsequent cleanup.
 */
bool ExecuteApiViaSetThreadContext(
    HANDLE hThread,
    const HijackContext& context)
{
    // ... (implementation remains the same as before) ...
    if (!hThread || !context.targetApiAddress || !context.pPreparedStackTop) {
        SetLastError(ERROR_INVALID_PARAMETER);
        std::cerr << "ExecuteApiViaSetThreadContext: ERROR - Invalid parameters." << std::endl;
        return false;
    }

    // x64 Calling Convention Requirement: RSP must be (16*N)+8 when a function is entered.
    // Here, context.pPreparedStackTop will become the new RSP and points to the return address.
    if (((DWORD64)context.pPreparedStackTop % 16) != 8) {
        SetLastError(ERROR_INVALID_PARAMETER);
        std::cerr << "ExecuteApiViaSetThreadContext: ERROR - pPreparedStackTop (new RSP) is not (16*N)+8 aligned. RSP: "
            << context.pPreparedStackTop << std::endl;
        return false;
    }
    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(hThread, &threadContext)) {
        std::cerr << "ExecuteApiViaSetThreadContext: ERROR - GetThreadContext failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Set Instruction Pointer to the target API function.
    threadContext.Rip = (DWORD64)context.targetApiAddress;

    // Set Register Arguments (first four integer/pointer arguments).
    threadContext.Rcx = context.arg1_rcx;
    threadContext.Rdx = context.arg2_rdx;
    threadContext.R8 = context.arg3_r8;
    threadContext.R9 = context.arg4_r9;

    // Set Stack Pointer to the top of the pre-prepared stack.
    threadContext.Rsp = (DWORD64)context.pPreparedStackTop;

    // Set Base Pointer (RBP).
    // For a hijacked call where the target API is entered directly, setting RBP to RSP
    // is a common and generally safe approach. The API will establish its own frame if needed.
    threadContext.Rbp = threadContext.Rsp;

    // Apply the modified context to the thread.
    // Ensure ContextFlags reflects all registers that were changed.
    if (!SetThreadContext(hThread, &threadContext)) {
        std::cerr << "ExecuteApiViaSetThreadContext: ERROR - SetThreadContext failed. Error: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

/**
 * @brief A dummy thread procedure.
 */
DWORD WINAPI DummyThreadProc(LPVOID lpParameter) {
    UNREFERENCED_PARAMETER(lpParameter);
    Sleep(INFINITE);
    return 0;
}

/**
 * @brief Prepares a new stack for a target API call according to the x64 calling convention.
 *
 * This function allocates memory for a new stack, calculates the correct RSP value (which will
 * point to the return address for the API), and places the API's stack-passed arguments
 * (5th argument onwards) at the correct offsets from this RSP.
 *
 * x64 Calling Convention Stack Layout (when API is entered, RSP points to Return Address):
 * [RSP+0x00]: Return Address (e.g., address of ExitThread)
 * [RSP+0x08]: Shadow space for RCX (callee can use)
 * [RSP+0x10]: Shadow space for RDX
 * [RSP+0x18]: Shadow space for R8
 * [RSP+0x20]: Shadow space for R9
 * [RSP+0x28]: 5th argument (if any)
 * [RSP+0x30]: 6th argument (if any)
 * ...
 * The RSP value itself must be (16*N)+8 aligned.
 *
 * @param stackArgs_in_order A vector of DWORD64 values representing the 5th, 6th, ... arguments
 *                           for the target API, in their natural call order.
 * @param pRetAddressForApi The address the target API should return to (e.g., ExitThread).
 * @param outStackAllocationBase Pointer to a void* that will receive the base address of the
 *                               VirtualAlloc'd stack region, so the caller can free it later.
 * @return A void* pointer to the calculated RSP value for the new stack, or nullptr on failure.
 *         This RSP value will point to pRetAddressForApi on the new stack.
 */
void* PrepareStackForApiCall(
    const std::vector<DWORD64>& stackArgs_in_order,
    FARPROC pRetAddressForApi,
    void** outStackAllocationBase
) {
    // ... (implementation remains the same as before) ...
    if (!pRetAddressForApi || !outStackAllocationBase) {
        std::cerr << "PrepareStackForApiCall: ERROR - Null pRetAddressForApi or outStackAllocationBase." << std::endl;
        return nullptr;
    }

    // Constants for x64 calling convention stack layout.
    const size_t shadowSpaceSize = 32; // 4 QWORDS for RCX, RDX, R8, R9 spill by callee
    const size_t retAddrSlotSize = 8;  // Size of the return address on stack
    const size_t firstStackArgOffset = 0x28; // Offset from RSP to the 5th argument

    size_t numStackArgs = stackArgs_in_order.size();
    size_t totalStackArgsSizeBytes = numStackArgs * sizeof(DWORD64);

    // Determine allocation size for the new stack.
    // Needs to be large enough for return address, shadow space, all stack arguments,
    // plus ample space for the target API's own local variables and any functions it might call.
    SIZE_T allocationSize = 65536; // Default 64KB, generally sufficient for many APIs.
    SIZE_T minRequiredForOurData = retAddrSlotSize + shadowSpaceSize + totalStackArgsSizeBytes + 16 /*alignment margin*/;
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

    // --- Calculate the finalRspVal (the RSP the target API will receive) ---
    // The goal is to determine an RSP that is (16*N)+8 aligned and correctly positions
    // the return address, shadow space, and stack arguments.
    // We calculate it based on a conceptual layout starting from the top of our allocated stack.

    char* pStackHighWatermark = (char*)stackBase + allocationSize; // Highest address + 1 in our block

    // Tentatively, where would the 5th argument be if all stack args were packed at the top?
    char* pTentative_Addr_5th_Arg_Slot = pStackHighWatermark - totalStackArgsSizeBytes;
    // This points to where the 5th argument would *start*.

    // pProspectiveRsp is the unaligned RSP if the return address slot were placed directly
    // below the shadow space, which itself is below the 5th argument slot.
    char* pProspectiveRsp = pTentative_Addr_5th_Arg_Slot - shadowSpaceSize - retAddrSlotSize;
    DEBUG_COUT("  DEBUG: pStackHighWatermark (initial top for calc) = " << (void*)pStackHighWatermark << std::endl);
    DEBUG_COUT("  DEBUG: pTentative_Addr_5th_Arg_Slot (if args pushed from top) = " << (void*)pTentative_Addr_5th_Arg_Slot << std::endl);
    DEBUG_COUT("  DEBUG: pProspectiveRsp (unaligned RSP target) = " << (void*)pProspectiveRsp << std::endl);

    // Align pProspectiveRsp downwards to be (16*N)+8. This is the final RSP.
    DWORD64 finalRspVal = ((DWORD64)pProspectiveRsp - 8ULL) & ~15ULL; // Aligns (value - 8) down to a multiple of 16
    finalRspVal += 8ULL;                                             // Add 8 back to get (16*N) + 8

    DEBUG_COUT("  DEBUG: finalRspVal (calculated and aligned RSP) = " << (void*)finalRspVal << std::endl);

    // Sanity check: finalRspVal must be within our allocated stack block.
    // It should point to where the return address will be.
    if (finalRspVal < (DWORD64)stackBase || (finalRspVal + retAddrSlotSize) >((DWORD64)stackBase + allocationSize)) {
        std::cerr << "PrepareStackForApiCall: ERROR - finalRspVal is outside allocated stack region after alignment." << std::endl;
        std::cerr << "  stackBase: " << stackBase << ", stackEnd: " << (void*)((char*)stackBase + allocationSize - 1) << std::endl;
        std::cerr << "  finalRspVal: " << (void*)finalRspVal << std::endl;
        VirtualFree(stackBase, 0, MEM_RELEASE); *outStackAllocationBase = nullptr; return nullptr;
    }

    // --- Place data onto the stack relative to the calculated finalRspVal ---

    // 1. Place the return address at finalRspVal.
    *(DWORD64*)finalRspVal = (DWORD64)pRetAddressForApi;
    DEBUG_PRINTF("  DEBUG: PLACED Return Address (value 0x%llX) to actual RSP %p\n",
        (unsigned long long)(DWORD64)pRetAddressForApi, (void*)finalRspVal);

    // 2. Place stack arguments (5th, 6th, etc.).
    //    The 5th argument goes to finalRspVal + firstStackArgOffset (RSP + 0x28).
    char* pArgWriter = (char*)finalRspVal + firstStackArgOffset;
    DEBUG_COUT("  DEBUG: Placing stack arguments relative to finalRspVal:" << std::endl);
    for (size_t i = 0; i < numStackArgs; ++i) {
        // Check if this write location is within the allocated stack.
        // pArgWriter points to the start of the current argument slot.
        if ((pArgWriter + sizeof(DWORD64)) > ((char*)stackBase + allocationSize)) {
            std::cerr << "PrepareStackForApiCall: ERROR - About to write stack argument #" << (i + 5)
                << " out of allocated stack bounds." << std::endl;
            std::cerr << "  pArgWriter: " << (void*)pArgWriter << ", stackEnd: "
                << (void*)((char*)stackBase + allocationSize - 1) << std::endl;
            VirtualFree(stackBase, 0, MEM_RELEASE); *outStackAllocationBase = nullptr; return nullptr;
        }

        *(DWORD64*)pArgWriter = stackArgs_in_order[i];
        DEBUG_PRINTF("  DEBUG: PLACED arg #%zu (value 0x%llX) to address %p (RSP+0x%X)\n",
            i + 5, // Argument number (5th, 6th, etc.)
            (unsigned long long)stackArgs_in_order[i],
            (void*)pArgWriter,
            (unsigned int)(firstStackArgOffset + i * sizeof(DWORD64))); // Offset from RSP
        pArgWriter += sizeof(DWORD64);
    }

    // Final summary print for the caller/debugger.
    std::cout << "Prepared stack. Final New RSP will be: " << (void*)finalRspVal
        << " (RSP % 16 = " << (finalRspVal % 16) << ")" << std::endl;
    std::cout << "  Return address for API set to: " << (void*)pRetAddressForApi << std::endl;
    if (!stackArgs_in_order.empty()) {
        DEBUG_PRINTF("  VERIFICATION: 5th arg (value 0x%llX) is at %p (RSP+0x%X)\n",
            (unsigned long long)stackArgs_in_order[0],
            (void*)(finalRspVal + firstStackArgOffset),
            (unsigned int)firstStackArgOffset);
        if (numStackArgs > 1) {
            DEBUG_PRINTF("  VERIFICATION: 6th arg (value 0x%llX) is at %p (RSP+0x%X)\n",
                (unsigned long long)stackArgs_in_order[1],
                (void*)(finalRspVal + firstStackArgOffset + sizeof(DWORD64)),
                (unsigned int)(firstStackArgOffset + sizeof(DWORD64)));
        }
        // Add more verification prints if desired.
    }
    else {
        std::cout << "  No stack arguments were provided for the API call." << std::endl;
    }
    return (void*)finalRspVal;
}

/**
 * @brief Runs a test of hijacking a thread to call a specified API.
 *
 * @param testName A descriptive name for the test.
 * @param apiToCall FARPROC address of the API function to call.
 * @param arg1 Value for RCX.
 * @param arg2 Value for RDX.
 * @param arg3 Value for R8.
 * @param arg4 Value for R9.
 * @param stackArgs Vector of DWORD64s for stack-passed arguments (5th onwards).
 * @param pExitThreadAddress FARPROC address of ExitThread (or similar cleanup function).
 * @param postExecutionMessage Optional message to print after successful execution.
 */
void RunApiTest(
    const std::string& testName,
    FARPROC apiToCall,
    DWORD64 arg1, DWORD64 arg2, DWORD64 arg3, DWORD64 arg4,
    const std::vector<DWORD64>& stackArgs,
    FARPROC pExitThreadAddress,
    const std::string& postExecutionMessage = ""
) {
    std::cout << "\n--- TESTING " << testName << " ---" << std::endl;
    if (!apiToCall) {
        std::cerr << "RunApiTest (" << testName << "): ERROR - apiToCall is NULL." << std::endl;
        std::cout << "--- " << testName << " Test SKIPPED ---\n" << std::endl;
        return;
    }
    if (!pExitThreadAddress) {
        std::cerr << "RunApiTest (" << testName << "): ERROR - pExitThreadAddress is NULL." << std::endl;
        std::cout << "--- " << testName << " Test SKIPPED ---\n" << std::endl;
        return;
    }

    HANDLE hThread = CreateThread(NULL, 0, DummyThreadProc, NULL, CREATE_SUSPENDED, NULL);
    if (!hThread) {
        std::cerr << "RunApiTest (" << testName << "): ERROR - CreateThread failed: " << GetLastError() << std::endl;
        std::cout << "--- " << testName << " Test FAILED ---\n" << std::endl;
        return;
    }
    std::cout << "Created suspended thread for " << testName << "." << std::endl;

    HijackContext ctx;
    ctx.targetApiAddress = apiToCall;
    ctx.arg1_rcx = arg1;
    ctx.arg2_rdx = arg2;
    ctx.arg3_r8 = arg3;
    ctx.arg4_r9 = arg4;

    void* stackAllocationBase = nullptr;
    ctx.pPreparedStackTop = PrepareStackForApiCall(stackArgs, pExitThreadAddress, &stackAllocationBase);

    if (!ctx.pPreparedStackTop) {
        std::cerr << "RunApiTest (" << testName << "): ERROR - Failed to prepare stack." << std::endl;
        ResumeThread(hThread); TerminateThread(hThread, 1); // Attempt cleanup
    }
    else {
        if (ExecuteApiViaSetThreadContext(hThread, ctx)) {
            std::cout << "SetThreadContext for " << testName << " successful. Resuming..." << std::endl;
            if (ResumeThread(hThread) == (DWORD)-1) {
                std::cerr << "RunApiTest (" << testName << "): ERROR - ResumeThread failed: " << GetLastError() << std::endl;
            }
            else {
                WaitForSingleObject(hThread, INFINITE); // Wait for ExitThread
                std::cout << testName << " thread exited." << std::endl;
                if (!postExecutionMessage.empty()) {
                    std::cout << postExecutionMessage << std::endl;
                }
            }
        }
        else {
            std::cerr << "RunApiTest (" << testName << "): ERROR - ExecuteApiViaSetThreadContext failed." << std::endl;
            ResumeThread(hThread); TerminateThread(hThread, 1); // Attempt cleanup
        }
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

    FARPROC pExitThread = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    if (!pExitThread) {
        std::cerr << "main: ERROR - Failed to get ExitThread address. Cannot run tests." << std::endl;
        return 1;
    }

    // --- Define and Run Tests ---

    // Test 1: MessageBoxA
    FARPROC pMessageBoxA = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    RunApiTest(
        "MessageBoxA",
        pMessageBoxA,
        (DWORD64)NULL,                                  // HWND hWnd
        (DWORD64)"Hello via Hijack (Test Main)!",      // LPCSTR lpText
        (DWORD64)"SetThreadContext Demo",              // LPCSTR lpCaption
        (DWORD64)MB_OK | MB_ICONINFORMATION,           // UINT uType
        {},                                             // No stack arguments
        pExitThread
    );

    // Test 2: CreateFileA
    FARPROC pCreateFileA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
    const char* testFileName = "C:\\temp\\hijack_test_file.txt"; // Ensure C:\temp is writable
    std::vector<DWORD64> stackArgsCreateFile;
    stackArgsCreateFile.push_back((DWORD64)CREATE_ALWAYS);          // 5th: dwCreationDisposition
    stackArgsCreateFile.push_back((DWORD64)FILE_ATTRIBUTE_NORMAL);  // 6th: dwFlagsAndAttributes
    stackArgsCreateFile.push_back((DWORD64)NULL);                   // 7th: hTemplateFile

    RunApiTest(
        "CreateFileA",
        pCreateFileA,
        (DWORD64)testFileName,                          // lpFileName
        GENERIC_WRITE | GENERIC_READ,                   // dwDesiredAccess
        FILE_SHARE_READ,                                // dwShareMode
        (DWORD64)NULL,                                  // lpSecurityAttributes
        stackArgsCreateFile,
        pExitThread,
        "VERIFY: Check if '" + std::string(testFileName) + "' was created."
    );

    // Add more tests here if needed...
    // Example: Test with another API, perhaps one that takes no arguments to test the simplest case.
    // FARPROC pGetTickCount = GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetTickCount");
    // RunApiTest("GetTickCount", pGetTickCount, 0,0,0,0, {}, pExitThread, "GetTickCount called (no output to verify).");


    std::cout << "\nAll tests finished. Press any key to close..." << std::endl;
    std::cin.get();
    return 0;
}