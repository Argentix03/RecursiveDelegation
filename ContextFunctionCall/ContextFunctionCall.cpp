#include <windows.h>
#include <iostream> // For std::cerr and std::cout
#include <vector>   // For std::vector
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
    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; // We'll modify control and integer registers.

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
 * @brief A dummy thread procedure to keep a thread alive until it's hijacked or terminated.
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
        allocationSize = minRequiredForOurData + 4096; // Add an extra page if minRequired is large
        DEBUG_COUT("  INFO: Increased allocationSize to " << allocationSize << " due to argument data size." << std::endl);
    }

    void* stackBase = VirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stackBase) {
        std::cerr << "PrepareStackForApiCall: ERROR - VirtualAlloc failed. Error: " << GetLastError() << std::endl;
        return nullptr;
    }
    *outStackAllocationBase = stackBase; // Return base for freeing

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

int main() {
    // --- Common Setup ---
    // Ensure necessary DLLs are loaded if functions are not from kernel32 by default.
    LoadLibraryA("user32.dll"); // For MessageBoxA

    FARPROC pExitThread = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    if (!pExitThread) {
        std::cerr << "main: ERROR - Failed to get ExitThread address." << std::endl;
        return 1;
    }

    // --- Test 1: MessageBoxA (4 register arguments, 0 stack arguments) ---
    std::cout << "\n--- TESTING MessageBoxA ---" << std::endl;
    FARPROC pMessageBoxA = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    if (!pMessageBoxA) {
        std::cerr << "main: ERROR - Failed to get MessageBoxA address." << std::endl;
    }
    else {
        HANDLE hThreadMsgBox = CreateThread(NULL, 0, DummyThreadProc, NULL, CREATE_SUSPENDED, NULL);
        if (!hThreadMsgBox) {
            std::cerr << "main: ERROR - CreateThread for MessageBoxA failed: " << GetLastError() << std::endl;
        }
        else {
            std::cout << "Created suspended thread for MessageBoxA." << std::endl;

            HijackContext ctxMsgBox;
            ctxMsgBox.targetApiAddress = pMessageBoxA;
            ctxMsgBox.arg1_rcx = (DWORD64)NULL;                           // HWND hWnd
            ctxMsgBox.arg2_rdx = (DWORD64)"Hello via Hijack (Test 1)!";   // LPCSTR lpText
            ctxMsgBox.arg3_r8 = (DWORD64)"SetThreadContext Demo";       // LPCSTR lpCaption
            ctxMsgBox.arg4_r9 = (DWORD64)MB_OK | MB_ICONINFORMATION;    // UINT uType

            void* stackAllocMsgBox = nullptr;
            std::vector<DWORD64> stackArgsMsgBox; // No stack arguments for MessageBoxA
            ctxMsgBox.pPreparedStackTop = PrepareStackForApiCall(stackArgsMsgBox, pExitThread, &stackAllocMsgBox);

            if (!ctxMsgBox.pPreparedStackTop) {
                std::cerr << "main: ERROR - Failed to prepare stack for MessageBoxA." << std::endl;
                ResumeThread(hThreadMsgBox); TerminateThread(hThreadMsgBox, 1);
            }
            else {
                if (ExecuteApiViaSetThreadContext(hThreadMsgBox, ctxMsgBox)) {
                    std::cout << "SetThreadContext for MessageBoxA successful. Resuming..." << std::endl;
                    ResumeThread(hThreadMsgBox);
                    WaitForSingleObject(hThreadMsgBox, INFINITE); // Wait for ExitThread
                    std::cout << "MessageBoxA thread exited." << std::endl;
                }
                else {
                    std::cerr << "main: ERROR - ExecuteApiViaSetThreadContext for MessageBoxA failed." << std::endl;
                    ResumeThread(hThreadMsgBox); TerminateThread(hThreadMsgBox, 1);
                }
            }
            CloseHandle(hThreadMsgBox);
            if (stackAllocMsgBox) {
                VirtualFree(stackAllocMsgBox, 0, MEM_RELEASE);
                DEBUG_COUT("Freed stack for MessageBoxA." << std::endl);
            }
        }
    }
    std::cout << "--- MessageBoxA Test Complete ---\n" << std::endl;


    // --- Test 2: CreateFileA (4 register arguments, 3 stack arguments) ---
    std::cout << "--- TESTING CreateFileA ---" << std::endl;
    FARPROC pCreateFileA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
    if (!pCreateFileA) {
        std::cerr << "main: ERROR - Failed to get CreateFileA address." << std::endl;
    }
    else {
        HANDLE hThreadCreateFile = CreateThread(NULL, 0, DummyThreadProc, NULL, CREATE_SUSPENDED, NULL);
        if (!hThreadCreateFile) {
            std::cerr << "main: ERROR - CreateThread for CreateFileA failed: " << GetLastError() << std::endl;
        }
        else {
            std::cout << "Created suspended thread for CreateFileA." << std::endl;

            HijackContext ctxCreateFile;
            ctxCreateFile.targetApiAddress = pCreateFileA;

            const char* testFileName = "C:\\temp\\hijack_test_file.txt"; // Ensure C:\temp is writable
            ctxCreateFile.arg1_rcx = (DWORD64)testFileName;                 // lpFileName
            ctxCreateFile.arg2_rdx = GENERIC_WRITE | GENERIC_READ;          // dwDesiredAccess
            ctxCreateFile.arg3_r8 = FILE_SHARE_READ;                       // dwShareMode
            ctxCreateFile.arg4_r9 = (DWORD64)NULL;                         // lpSecurityAttributes

            std::vector<DWORD64> stackArgsCreateFile;
            stackArgsCreateFile.push_back((DWORD64)CREATE_ALWAYS);          // 5th: dwCreationDisposition
            stackArgsCreateFile.push_back((DWORD64)FILE_ATTRIBUTE_NORMAL);  // 6th: dwFlagsAndAttributes
            stackArgsCreateFile.push_back((DWORD64)NULL);                   // 7th: hTemplateFile

            void* stackAllocCreateFile = nullptr;
            ctxCreateFile.pPreparedStackTop = PrepareStackForApiCall(stackArgsCreateFile, pExitThread, &stackAllocCreateFile);

            if (!ctxCreateFile.pPreparedStackTop) {
                std::cerr << "main: ERROR - Failed to prepare stack for CreateFileA." << std::endl;
                ResumeThread(hThreadCreateFile); TerminateThread(hThreadCreateFile, 1);
            }
            else {
                if (ExecuteApiViaSetThreadContext(hThreadCreateFile, ctxCreateFile)) {
                    std::cout << "SetThreadContext for CreateFileA successful. Resuming..." << std::endl;
                    ResumeThread(hThreadCreateFile);
                    WaitForSingleObject(hThreadCreateFile, INFINITE); // Wait for ExitThread
                    std::cout << "CreateFileA thread exited." << std::endl;
                    std::cout << "VERIFY: Check if '" << testFileName << "' was created." << std::endl;
                }
                else {
                    std::cerr << "main: ERROR - ExecuteApiViaSetThreadContext for CreateFileA failed." << std::endl;
                    ResumeThread(hThreadCreateFile); TerminateThread(hThreadCreateFile, 1);
                }
            }
            CloseHandle(hThreadCreateFile);
            if (stackAllocCreateFile) {
                VirtualFree(stackAllocCreateFile, 0, MEM_RELEASE);
                DEBUG_COUT("Freed stack for CreateFileA." << std::endl);
            }
        }
    }
    std::cout << "--- CreateFileA Test Complete ---" << std::endl;

    std::cout << "\nAll tests finished. Press any key to close..." << std::endl;
    std::cin.get(); // Keep console open
    return 0;
}