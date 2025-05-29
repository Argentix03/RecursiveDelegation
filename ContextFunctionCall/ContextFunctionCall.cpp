#include <windows.h>
#include <iostream> // For error messages
#include <vector>   // For HijackContext if it were to hold dynamic stack args

// Context provided by the caller
struct HijackContext {
    FARPROC targetApiAddress;
    DWORD64 arg1_rcx;
    DWORD64 arg2_rdx;
    DWORD64 arg3_r8;
    DWORD64 arg4_r9;
    void* pPreparedStackTop; // This is the RSP for the target API. Must be (16*N)+8 aligned.
    // It points to the "return address" for targetApiAddress.
};

bool ExecuteApiViaSetThreadContext(
    HANDLE hThread,
    const HijackContext& context)
{
    if (!hThread || !context.targetApiAddress || !context.pPreparedStackTop) {
        SetLastError(ERROR_INVALID_PARAMETER);
        std::cerr << "ExecuteApiViaSetThreadContext: Invalid parameters." << std::endl;
        return false;
    }

    // Validate pPreparedStackTop alignment (RSP must be (16*N)+8)
    if (((DWORD64)context.pPreparedStackTop % 16) != 8) {
        SetLastError(ERROR_INVALID_PARAMETER);
        std::cerr << "ExecuteApiViaSetThreadContext: pPreparedStackTop (new RSP) is not (16*N)+8 aligned. RSP: "
            << context.pPreparedStackTop << std::endl;
        return false;
    }

    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER; // We need control and integer registers

    if (!GetThreadContext(hThread, &threadContext)) {
        std::cerr << "ExecuteApiViaSetThreadContext: GetThreadContext failed. Error: " << GetLastError() << std::endl;
        // Note: Do not TerminateThread here, let the caller decide how to handle the suspended thread.
        return false;
    }

    // Set Instruction Pointer
    threadContext.Rip = (DWORD64)context.targetApiAddress;

    // Set Register Arguments
    threadContext.Rcx = context.arg1_rcx;
    threadContext.Rdx = context.arg2_rdx;
    threadContext.R8 = context.arg3_r8;
    threadContext.R9 = context.arg4_r9;

    // Set Stack Pointer
    threadContext.Rsp = (DWORD64)context.pPreparedStackTop;

    // Set Base Pointer (RBP)
    // Often RBP is set to RSP at the start of a function if it creates a new stack frame.
    // Or it can point to the base of the allocated stack region.
    // For simplicity and because the API will manage its own RBP if needed,
    // setting it to RSP is a common safe choice for this kind of hijack.
    threadContext.Rbp = threadContext.Rsp; // Or a more meaningful base if the API expects it (unlikely for standard WinAPIs this way)


    // Set the modified context
    // ContextFlags should only include bits for registers you actually changed and want to set.
    // We changed RIP, RCX, RDX, R8, R9, RSP, RBP.
    threadContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!SetThreadContext(hThread, &threadContext)) {
        std::cerr << "ExecuteApiViaSetThreadContext: SetThreadContext failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Resuming the thread is up to the caller, as is waiting and cleanup.
    // This function's job is just to set the context.

    return true;
}

// --- Example Usage (Illustrative - Caller's Responsibility) ---
DWORD WINAPI DummyThreadProc(LPVOID lpParameter) {
    Sleep(INFINITE); // Keep thread alive
    return 0;
}

#include <cstdio> // For printf

// Helper to allocate an aligned stack and prepare it
// Returns the RSP value to be used, or nullptr on failure.
// The caller is responsible for VirtualFree(stackAllocationBase, 0, MEM_RELEASE);
void* PrepareStackForApiCall(
    const std::vector<DWORD64>& stackArgs_in_order, // 5th, 6th... args in order
    FARPROC pRetAddressForApi,                      // e.g., ExitThread address
    void** outStackAllocationBase                   // To store the base for later freeing
) {
    if (!pRetAddressForApi || !outStackAllocationBase) {
        std::cerr << "PrepareStackForApiCall: Null pRetAddressForApi or outStackAllocationBase." << std::endl;
        return nullptr;
    }

    const size_t shadowSpaceSize = 32;
    const size_t retAddrSize = 8;
    size_t numStackArgs = stackArgs_in_order.size();
    size_t totalStackArgsSize = numStackArgs * 8;

    // Determine allocation size
    SIZE_T allocationSize = 65536; // Default 64KB
    SIZE_T minRequiredForData = totalStackArgsSize + shadowSpaceSize + retAddrSize + 16 /*alignment margin*/;
    if (allocationSize < minRequiredForData) {
        allocationSize = minRequiredForData + 1024; // Ensure enough space if minRequired is larger
        std::cout << "  INFO: Increased allocationSize to " << allocationSize << " due to argument data size." << std::endl;
    }

    void* stackBase = VirtualAlloc(NULL, allocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stackBase) {
        std::cerr << "PrepareStackForApiCall: VirtualAlloc failed. Error: " << GetLastError() << std::endl;
        return nullptr;
    }
    *outStackAllocationBase = stackBase;

    std::cout << "  DEBUG: stackBase = " << stackBase
        << ", allocationSize = " << allocationSize << std::endl;

    // --- Calculate finalRspVal ---
    // This logic determines where RSP will be. It needs to be (16*N)+8.
    // It's based on placing the arguments and return address starting from the *top* of the allocated stack.

    // Tentative top of stack where we start writing downwards
    char* pCurrentWriter_for_rsp_calc = (char*)stackBase + allocationSize;

    // Simulate pushing stack arguments to find the address of the 5th argument slot
    char* pTentative_Addr_5th_Arg = pCurrentWriter_for_rsp_calc - (numStackArgs * 8);
    // Note: If numStackArgs is 0, pTentative_Addr_5th_Arg is pCurrentWriter_for_rsp_calc.
    // The "5th arg slot" is still conceptually relevant for shadow space placement.

    // pProspectiveRsp is where the return address would notionally go, relative to the 5th arg slot
    char* pProspectiveRsp = pTentative_Addr_5th_Arg - shadowSpaceSize - retAddrSize;

    std::cout << "  DEBUG: pCurrentWriter_for_rsp_calc (initial top) = " << (void*)pCurrentWriter_for_rsp_calc << std::endl;
    if (numStackArgs > 0) {
        std::cout << "  DEBUG: pTentative_Addr_5th_Arg (if stack args were pushed from top) = " << (void*)pTentative_Addr_5th_Arg << std::endl;
    }
    else {
        std::cout << "  DEBUG: No stack args, pTentative_Addr_5th_Arg conceptually at " << (void*)pTentative_Addr_5th_Arg << std::endl;
    }
    std::cout << "  DEBUG: pProspectiveRsp (unaligned RSP target) = " << (void*)pProspectiveRsp << std::endl;


    // Align pProspectiveRsp downwards to (16*N)+8 to get finalRspVal
    DWORD64 step1_prospectiveRsp_val64 = (DWORD64)pProspectiveRsp;
    // std::cout << "  DEBUG: step1_prospectiveRsp_val64 = " << (void*)step1_prospectiveRsp_val64 << std::endl; // Redundant with above

    const DWORD64 eight_64 = 8ULL;
    DWORD64 step2_minus_8 = step1_prospectiveRsp_val64 - eight_64;
    // std::cout << "  DEBUG: step2_minus_8 = " << (void*)step2_minus_8 << std::endl;

    const DWORD64 fifteen_val_64 = 15ULL;
    const DWORD64 mask_complement_64 = ~fifteen_val_64;
    // printf("  DEBUG: mask_complement_64 (hex): %016llX\n", mask_complement_64);

    DWORD64 step3_anded_val = step2_minus_8 & mask_complement_64;
    // std::cout << "  DEBUG: step3_anded_val = " << (void*)step3_anded_val << std::endl;

    DWORD64 finalRspVal = step3_anded_val + eight_64;
    std::cout << "  DEBUG: finalRspVal (calculated and aligned RSP) = " << (void*)finalRspVal << std::endl;

    // Sanity check: finalRspVal must be within our allocated stack block
    if (finalRspVal < (DWORD64)stackBase || finalRspVal >= ((DWORD64)stackBase + allocationSize)) {
        std::cerr << "PrepareStackForApiCall: finalRspVal is outside allocated stack region after alignment." << std::endl;
        std::cerr << "  stackBase: " << stackBase << ", stackEnd: " << (void*)((char*)stackBase + allocationSize - 1) << std::endl;
        std::cerr << "  finalRspVal: " << (void*)finalRspVal << std::endl;
        VirtualFree(stackBase, 0, MEM_RELEASE); *outStackAllocationBase = nullptr; return nullptr;
    }

    // --- Place data onto the stack relative to finalRspVal ---

    // 1. Place the return address at finalRspVal
    *(DWORD64*)finalRspVal = (DWORD64)pRetAddressForApi;
    printf("  DEBUG: PLACED Return Address (value 0x%llX) to actual RSP %p\n",
        (unsigned long long)pRetAddressForApi, (void*)finalRspVal);

    // 2. Place stack arguments:
    //    5th arg goes to finalRspVal + 0x28
    //    6th arg goes to finalRspVal + 0x30
    //    etc.
    char* pArgWriter = (char*)finalRspVal + 0x28; // Start of 5th argument slot
    std::cout << "  DEBUG: Placing stack arguments relative to finalRspVal:" << std::endl;
    for (size_t i = 0; i < numStackArgs; ++i) {
        // Check if this write location is within the allocated stack
        if (((char*)pArgWriter + sizeof(DWORD64)) > ((char*)stackBase + allocationSize)) {
            std::cerr << "PrepareStackForApiCall: About to write stack argument #" << (i + 5)
                << " out of allocated stack bounds." << std::endl;
            std::cerr << "  pArgWriter: " << (void*)pArgWriter << ", stackEnd: "
                << (void*)((char*)stackBase + allocationSize - 1) << std::endl;
            VirtualFree(stackBase, 0, MEM_RELEASE); *outStackAllocationBase = nullptr; return nullptr;
        }

        *(DWORD64*)pArgWriter = stackArgs_in_order[i];
        printf("  DEBUG: PLACED arg #%zu (value 0x%llX) to address %p (RSP+0x%X)\n",
            i + 5, // Argument number (5th, 6th, etc.)
            (unsigned long long)stackArgs_in_order[i],
            (void*)pArgWriter,
            (unsigned int)(0x28 + i * 8)); // Offset from RSP
        pArgWriter += 8;
    }

    // Final summary print
    std::cout << "Prepared stack. Final New RSP will be: " << (void*)finalRspVal
        << " (RSP % 16 = " << (finalRspVal % 16) << ")" << std::endl;
    std::cout << "  Return address for API set to: " << (void*)pRetAddressForApi << std::endl;
    if (!stackArgs_in_order.empty()) {
        printf("  Verification: 5th arg (value 0x%llX) is at %p (RSP+0x28)\n",
            (unsigned long long)stackArgs_in_order[0], (void*)(finalRspVal + 0x28));
        if (numStackArgs > 1) {
            printf("  Verification: 6th arg (value 0x%llX) is at %p (RSP+0x30)\n",
                (unsigned long long)stackArgs_in_order[1], (void*)(finalRspVal + 0x30));
        }
        if (numStackArgs > 2) {
            printf("  Verification: 7th arg (value 0x%llX) is at %p (RSP+0x38)\n",
                (unsigned long long)stackArgs_in_order[2], (void*)(finalRspVal + 0x38));
        }
    }
    else {
        std::cout << "  No stack arguments were provided for the API call." << std::endl;
    }

    return (void*)finalRspVal;
}
#include <string> // For std::string
#include <algorithm> // For std::reverse, though not strictly needed for push_back

// ... (HijackContext, ExecuteApiViaSetThreadContext, DummyThreadProc, PrepareStackForApiCall remain the same) ...

int main() {
    // --- Common Setup ---
    LoadLibraryA("user32.dll"); // Still good to have for MessageBoxA if we switch back
    FARPROC pExitThread = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitThread");
    if (!pExitThread) {
        std::cerr << "Failed to get ExitThread address." << std::endl;
        return 1;
    }

    // --- Test 1: MessageBoxA (as before, to confirm baseline works) ---
    std::cout << "\n--- TESTING MessageBoxA ---" << std::endl;
    FARPROC pMessageBoxA = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA");
    if (!pMessageBoxA) {
        std::cerr << "Failed to get MessageBoxA address." << std::endl;
        return 1; // Or skip this test
    }

    HANDLE hThreadMsgBox = CreateThread(NULL, 0, DummyThreadProc, NULL, CREATE_SUSPENDED, NULL);
    if (!hThreadMsgBox) {
        std::cerr << "CreateThread for MessageBoxA failed: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "Created suspended thread for MessageBoxA." << std::endl;

    HijackContext ctxMsgBox;
    ctxMsgBox.targetApiAddress = pMessageBoxA;
    ctxMsgBox.arg1_rcx = (DWORD64)NULL;
    ctxMsgBox.arg2_rdx = (DWORD64)"Hello via Hijack (Test 1)!";
    ctxMsgBox.arg3_r8 = (DWORD64)"SetThreadContext Demo";
    ctxMsgBox.arg4_r9 = (DWORD64)MB_OK | MB_ICONINFORMATION;

    void* stackAllocMsgBox = nullptr;
    std::vector<DWORD64> stackArgsMsgBox; // Empty
    ctxMsgBox.pPreparedStackTop = PrepareStackForApiCall(stackArgsMsgBox, pExitThread, &stackAllocMsgBox);

    if (!ctxMsgBox.pPreparedStackTop) {
        std::cerr << "Failed to prepare stack for MessageBoxA." << std::endl;
        ResumeThread(hThreadMsgBox); TerminateThread(hThreadMsgBox, 1); CloseHandle(hThreadMsgBox);
    }
    else {
        if (ExecuteApiViaSetThreadContext(hThreadMsgBox, ctxMsgBox)) {
            std::cout << "SetThreadContext for MessageBoxA successful. Resuming..." << std::endl;
            ResumeThread(hThreadMsgBox);
            WaitForSingleObject(hThreadMsgBox, INFINITE);
            std::cout << "MessageBoxA thread exited." << std::endl;
        }
        else {
            std::cerr << "ExecuteApiViaSetThreadContext for MessageBoxA failed." << std::endl;
            ResumeThread(hThreadMsgBox); TerminateThread(hThreadMsgBox, 1);
        }
    }
    CloseHandle(hThreadMsgBox);
    if (stackAllocMsgBox) VirtualFree(stackAllocMsgBox, 0, MEM_RELEASE);
    std::cout << "--- MessageBoxA Test Complete ---\n" << std::endl;


    // --- Test 2: CreateFileA (7 parameters) ---
    std::cout << "--- TESTING CreateFileA ---" << std::endl;
    FARPROC pCreateFileA = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileA");
    if (!pCreateFileA) {
        std::cerr << "Failed to get CreateFileA address." << std::endl;
        return 1;
    }

    HANDLE hThreadCreateFile = CreateThread(NULL, 0, DummyThreadProc, NULL, CREATE_SUSPENDED, NULL);
    if (!hThreadCreateFile) {
        std::cerr << "CreateThread for CreateFileA failed: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "Created suspended thread for CreateFileA." << std::endl;

    HijackContext ctxCreateFile;
    ctxCreateFile.targetApiAddress = pCreateFileA;

    // Arguments for CreateFileA:
    const char* testFileName = "C:\\temp\\hijack_test_file.txt"; // Make sure this path is writable
    ctxCreateFile.arg1_rcx = (DWORD64)testFileName;          // lpFileName
    ctxCreateFile.arg2_rdx = GENERIC_WRITE | GENERIC_READ;   // dwDesiredAccess
    ctxCreateFile.arg3_r8 = FILE_SHARE_READ;                // dwShareMode
    ctxCreateFile.arg4_r9 = (DWORD64)NULL;                  // lpSecurityAttributes

    // Stack arguments (5th, 6th, 7th)
    std::vector<DWORD64> stackArgsCreateFile;
    stackArgsCreateFile.push_back((DWORD64)CREATE_ALWAYS);       // 5th: dwCreationDisposition
    stackArgsCreateFile.push_back((DWORD64)FILE_ATTRIBUTE_NORMAL); // 6th: dwFlagsAndAttributes
    stackArgsCreateFile.push_back((DWORD64)NULL);                // 7th: hTemplateFile

    void* stackAllocCreateFile = nullptr;
    // PrepareStackForApiCall expects arguments in order (5th, then 6th, then 7th).
    // It will reverse them internally for pushing onto the stack.
    ctxCreateFile.pPreparedStackTop = PrepareStackForApiCall(stackArgsCreateFile, pExitThread, &stackAllocCreateFile);

    if (!ctxCreateFile.pPreparedStackTop) {
        std::cerr << "Failed to prepare stack for CreateFileA." << std::endl;
        ResumeThread(hThreadCreateFile); TerminateThread(hThreadCreateFile, 1); CloseHandle(hThreadCreateFile);
    }
    else {
        if (ExecuteApiViaSetThreadContext(hThreadCreateFile, ctxCreateFile)) {
            std::cout << "SetThreadContext for CreateFileA successful. Resuming..." << std::endl;
            ResumeThread(hThreadCreateFile);
            WaitForSingleObject(hThreadCreateFile, INFINITE);
            std::cout << "CreateFileA thread exited." << std::endl;
            std::cout << "Check if '" << testFileName << "' was created (and then delete it manually)." << std::endl;
            // Note: If the file is created, it might be left open if the thread exits abruptly
            // before any internal cleanup by CreateFileA happens, or if ExitThread is too harsh.
            // However, since ExitThread is the 'return', the OS should handle resource cleanup for the thread.
        }
        else {
            std::cerr << "ExecuteApiViaSetThreadContext for CreateFileA failed." << std::endl;
            ResumeThread(hThreadCreateFile); TerminateThread(hThreadCreateFile, 1);
        }
    }
    CloseHandle(hThreadCreateFile);
    if (stackAllocCreateFile) VirtualFree(stackAllocCreateFile, 0, MEM_RELEASE);
    std::cout << "--- CreateFileA Test Complete ---" << std::endl;


    return 0;
}