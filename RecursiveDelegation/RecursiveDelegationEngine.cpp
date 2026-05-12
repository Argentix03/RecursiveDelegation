#include "RecursiveDelegationCore.h"

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

#ifdef _DEBUG
#define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#define DEBUG_COUT(x) std::cout << x
#else
#define DEBUG_PRINTF(...) do {} while (0)
#define DEBUG_COUT(x) do {} while (0)
#endif

HANDLE g_hPipeForChildResponse = INVALID_HANDLE_VALUE;
void* g_pSharedSection = nullptr;

NtContinue_t GetNtContinue() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return nullptr;
    return reinterpret_cast<NtContinue_t>(GetProcAddress(hNtdll, "NtContinue"));
}

bool IsChildModeArgs(int argc, char* argv[]) {
    if (argc < 4 || !argv || !argv[2]) return false;
    // Child cmdline shape: <exe> <level-int> <Module!Function> <pipeName> [exitFunc]
    return std::strchr(argv[2], '!') != nullptr;
}

extern "C" __declspec(noinline) void NTAPI ProcessResultAndExit(DWORD64 raxFromApi) {
    DEBUG_PRINTF("ProcessResultAndExit: Captured RAX from target API = 0x%llX\n", raxFromApi);

    ApiCallResultResponse response;
    response.wasApiCallConsideredSuccess = TRUE;
    response.apiReturnValue = raxFromApi;
    response.lastErrorValue = GetLastError();

    DEBUG_PRINTF("ProcessResultAndExit: LastError at time of helper execution: %lu\n", response.lastErrorValue);

    if (g_hPipeForChildResponse == INVALID_HANDLE_VALUE) {
        DEBUG_COUT("ProcessResultAndExit: g_hPipeForChildResponse is not initialized.");
        TerminateProcess(GetCurrentProcess(), 3);
    }

    DEBUG_COUT("Child (ProcessResultAndExit): Sending ApiCallResultResponse to parent." << std::endl);
    DWORD bytesWritten;
    if (!WriteFile(g_hPipeForChildResponse, &response, sizeof(ApiCallResultResponse), &bytesWritten, NULL) || bytesWritten != sizeof(ApiCallResultResponse)) {
        std::cerr << "Child (ProcessResultAndExit): Failed to write ApiCallResultResponse to pipe. Error: " << GetLastError() << std::endl;
    }
    else {
        DEBUG_COUT("Child (ProcessResultAndExit): Sent ApiCallResultResponse to parent." << std::endl);
    }

    TerminateProcess(GetCurrentProcess(), response.wasApiCallConsideredSuccess ? 0 : 1);
    ExitProcess(response.wasApiCallConsideredSuccess ? 0 : 2);
}

bool ExecuteApiCallAtLevelZero(
    const ApiCallParams* pCallParams,
    const std::vector<DWORD64>* pStackArgs,
    NtContinue_t pNtContinueFunc,
    FARPROC pExitFunc,
    std::string ExitFuncName
) {
    DEBUG_COUT("ExecuteApiCallAtLevelZero: Preparing to execute API: " << pCallParams->funcNameWithModule << std::endl);

    FARPROC targetApi = ResolveFunction(pCallParams->funcNameWithModule);
    if (!targetApi) {
        std::cerr << "ExecuteApiCallAtLevelZero: Failed to resolve target API." << std::endl;
        return false;
    }

    if (!pExitFunc) {
        if (ExitFuncName.empty() || ExitFuncName == "default" || ExitFuncName == "CaptureRAX_And_CallHelper") {
            pExitFunc = (FARPROC)CaptureRAX_And_CallHelper;
        }
        else {
            pExitFunc = ResolveFunction(ExitFuncName);
        }
    }

    if (!pExitFunc) {
        std::cerr << "ExecuteApiCallAtLevelZero: Failed to resolve exit function: " << ExitFuncName << std::endl;
        return false;
    }

    void* stackAllocationBase = nullptr;
    void* pNewStackTopForTargetApi = PrepareStackForApiCall(
        *pStackArgs,
        pExitFunc,
        &stackAllocationBase
    );

    if (!pNewStackTopForTargetApi) {
        std::cerr << "ExecuteApiCallAtLevelZero: ERROR - Failed to prepare stack for target API." << std::endl;
        if (stackAllocationBase) VirtualFree(stackAllocationBase, 0, MEM_RELEASE);
        return false;
    }

    CONTEXT targetContext;
    ZeroMemory(&targetContext, sizeof(CONTEXT));
    RtlCaptureContext(&targetContext);

    targetContext.Rip = (DWORD64)targetApi;
    targetContext.Rcx = pCallParams->rcx_val;
    targetContext.Rdx = pCallParams->rdx_val;
    targetContext.R8 = pCallParams->r8_val;
    targetContext.R9 = pCallParams->r9_val;
    targetContext.Rsp = (DWORD64)pNewStackTopForTargetApi;
    targetContext.Rbp = targetContext.Rsp;

    DWORD64 shadowSpace = 0x28;
    if (pCallParams->rcx_is_ptr_offset_from_stack) { targetContext.Rcx += targetContext.Rsp + shadowSpace;  }
    if (pCallParams->rdx_is_ptr_offset_from_stack) { targetContext.Rdx += targetContext.Rsp + shadowSpace; }
    if (pCallParams->r8_is_ptr_offset_from_stack)  { targetContext.R8  += targetContext.Rsp + shadowSpace; }
    if (pCallParams->r9_is_ptr_offset_from_stack)  { targetContext.R9  += targetContext.Rsp + shadowSpace; }

    NTSTATUS status = pNtContinueFunc(&targetContext, FALSE);

    std::cerr << "ExecuteApiCallAtLevelZero: ERROR - NtContinue returned with status 0x"
        << std::hex << status << std::dec << ". This is unexpected." << std::endl;
    if (stackAllocationBase) {
        VirtualFree(stackAllocationBase, 0, MEM_RELEASE);
    }
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

    if (level <= 0) {
        std::cout << "Executing function at level 0: " << pCallParams->funcNameWithModule << std::endl;
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
        DeleteFileA(clonePath.c_str());
        return false;
    }

    std::stringstream cmdLine;
    cmdLine << "\"" << clonePath << "\" " << (level - 1)
        << " \"" << pCallParams->funcNameWithModule << "\" "
        << pipeName << " "
        << ExitFunc;

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(NULL, const_cast<LPSTR>(cmdLine.str().c_str()), NULL, NULL,
        TRUE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "RecursiveDelegate: Failed to create child process. Error: " << GetLastError() << std::endl;
        CloseHandle(hPipe);
        DeleteFileA(clonePath.c_str());
        return false;
    }

    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        std::cerr << "RecursiveDelegate: Failed to connect to client on pipe. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hPipe);
        DeleteFileA(clonePath.c_str());
        return false;
    }

    DWORD bytesWritten;
    if (!WriteFile(hPipe, pCallParams, sizeof(ApiCallParams), &bytesWritten, NULL) || bytesWritten != sizeof(ApiCallParams)) {
        std::cerr << "RecursiveDelegate: Failed to write ApiCallParams to pipe. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hPipe); DeleteFileA(clonePath.c_str());
        return false;
    }

    SIZE_T numStackArgs = pStackArgs->size();
    if (!WriteFile(hPipe, &numStackArgs, sizeof(SIZE_T), &bytesWritten, NULL) || bytesWritten != sizeof(SIZE_T)) {
        std::cerr << "RecursiveDelegate: Failed to write numStackArgs to pipe. Error: " << GetLastError() << std::endl;
        TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hPipe); DeleteFileA(clonePath.c_str());
        return false;
    }

    if (numStackArgs > 0) {
        SIZE_T stackArgsDataSize = numStackArgs * sizeof(DWORD64);
        if (!WriteFile(hPipe, pStackArgs->data(), (DWORD)stackArgsDataSize, &bytesWritten, NULL) || bytesWritten != stackArgsDataSize) {
            std::cerr << "RecursiveDelegate: Failed to write stackArgs data to pipe. Error: " << GetLastError() << std::endl;
            TerminateProcess(pi.hProcess, 1); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); CloseHandle(hPipe); DeleteFileA(clonePath.c_str());
            return false;
        }
    }

    outApiResponse->wasApiCallConsideredSuccess = FALSE;
    outApiResponse->apiReturnValue = 0;
    outApiResponse->lastErrorValue = (DWORD)-1;

    DWORD bytesRead;
    if (!ReadFile(hPipe, outApiResponse, sizeof(ApiCallResultResponse), &bytesRead, NULL) || bytesRead != sizeof(ApiCallResultResponse)) {
        DWORD readError = GetLastError();
        std::cerr << "RecursiveDelegate (Parent of level " << level - 1 << "): Failed to read ApiCallResultResponse from child. Error: " << readError << std::endl;
        outApiResponse->lastErrorValue = readError;
        TerminateProcess(pi.hProcess, 1);
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD childExitCode;
    GetExitCodeProcess(pi.hProcess, &childExitCode);

    CloseHandle(hPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (!DeleteFileA(clonePath.c_str())) {
        if (GetLastError() != ERROR_FILE_NOT_FOUND) {
            std::cerr << "RecursiveDelegate: Warning - Failed to delete clone " << clonePath << ". Error: " << GetLastError() << std::endl;
        }
    }

    return outApiResponse->wasApiCallConsideredSuccess == TRUE;
}

bool ProcessChildMode(int argc, char* argv[], NtContinue_t pNtContinueFunc) {
    if (argc < 4) {
        std::cerr << "Child: Insufficient arguments." << std::endl;
        return false;
    }

    int level = atoi(argv[1]);
    std::string pipeName = argv[3];

    HANDLE hPipe = CreateIPCPipe(pipeName, false);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Child: Failed to connect to pipe '" << pipeName << "'. Error: " << GetLastError() << std::endl;
        return false;
    }
    g_hPipeForChildResponse = hPipe;

    ApiCallParams receivedApiParams;
    std::vector<DWORD64> receivedStackArgs;
    DWORD bytesRead;

    if (!ReadFile(hPipe, &receivedApiParams, sizeof(ApiCallParams), &bytesRead, NULL) || bytesRead != sizeof(ApiCallParams)) {
        std::cerr << "Child: Failed to read ApiCallParams. Error: " << GetLastError() << std::endl;
        CloseHandle(hPipe); return false;
    }

    SIZE_T numStackArgs;
    if (!ReadFile(hPipe, &numStackArgs, sizeof(SIZE_T), &bytesRead, NULL) || bytesRead != sizeof(SIZE_T)) {
        std::cerr << "Child: Failed to read numStackArgs. Error: " << GetLastError() << std::endl;
        CloseHandle(hPipe); return false;
    }

    if (numStackArgs > 0) {
        receivedStackArgs.resize(numStackArgs);
        SIZE_T stackArgsDataSize = numStackArgs * sizeof(DWORD64);
        if (!ReadFile(hPipe, receivedStackArgs.data(), (DWORD)stackArgsDataSize, &bytesRead, NULL) || bytesRead != stackArgsDataSize) {
            std::cerr << "Child: Failed to read stackArgs data. Error: " << GetLastError() << std::endl;
            CloseHandle(hPipe); return false;
        }
    }

    std::string ExitFunc = "default";
    FARPROC pExitFunc = NULL;
    if (argc >= 5) {
        std::string ExitFuncProvided = argv[4];
        if (ExitFuncProvided.empty() ||
            ExitFuncProvided == "default" ||
            ExitFuncProvided.find('!') != std::string::npos) {
            ExitFunc = ExitFuncProvided;
        }
        else {
            pExitFunc = (FARPROC)strtoull(ExitFuncProvided.c_str(), NULL, 16);
        }
    }

    ApiCallResultResponse responseToSendToMyParent;
    responseToSendToMyParent.wasApiCallConsideredSuccess = FALSE;
    responseToSendToMyParent.apiReturnValue = 0;
    responseToSendToMyParent.lastErrorValue = (DWORD)-1;

    if (level > 0) {
        RecursiveDelegate(level, &receivedApiParams, &receivedStackArgs, pNtContinueFunc, pExitFunc, ExitFunc, &responseToSendToMyParent);
    }
    else {
        if (!ExecuteApiCallAtLevelZero(&receivedApiParams, &receivedStackArgs, pNtContinueFunc, pExitFunc, ExitFunc)) {
            std::cerr << "Child (level 0): ExecuteApiCallAtLevelZero reported NtContinue launch failure." << std::endl;
            responseToSendToMyParent.wasApiCallConsideredSuccess = FALSE;
            responseToSendToMyParent.apiReturnValue = 0;
            responseToSendToMyParent.lastErrorValue = GetLastError();
        }
        else {
            if (g_hPipeForChildResponse != INVALID_HANDLE_VALUE) {
                CloseHandle(g_hPipeForChildResponse);
                g_hPipeForChildResponse = INVALID_HANDLE_VALUE;
            }
            return TRUE;
        }
    }

    if (g_hPipeForChildResponse != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        if (!WriteFile(g_hPipeForChildResponse, &responseToSendToMyParent, sizeof(ApiCallResultResponse), &bytesWritten, NULL) || bytesWritten != sizeof(ApiCallResultResponse)) {
            std::cerr << "Child (PID " << GetCurrentProcessId() << ", Level " << level
                << "): Failed to write ApiCallResultResponse to pipe. Error: " << GetLastError() << std::endl;
        }
        CloseHandle(g_hPipeForChildResponse);
        g_hPipeForChildResponse = INVALID_HANDLE_VALUE;
    }

    return responseToSendToMyParent.wasApiCallConsideredSuccess == TRUE;
}
