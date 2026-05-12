#pragma once

#include <windows.h>
#include <string>
#include <vector>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef NTSTATUS(NTAPI* NtContinue_t)(PCONTEXT ContextRecord, BOOLEAN TestAlert);

extern const std::vector<std::string> MS_BINARY_NAMES;

struct ApiCallParams {
    char funcNameWithModule[256];
    DWORD64 rcx_val;
    DWORD64 rdx_val;
    DWORD64 r8_val;
    DWORD64 r9_val;

    BOOL rcx_is_ptr_offset_from_stack;
    BOOL rdx_is_ptr_offset_from_stack;
    BOOL r8_is_ptr_offset_from_stack;
    BOOL r9_is_ptr_offset_from_stack;
};

struct ApiCallResultResponse {
    BOOL    wasApiCallConsideredSuccess;
    DWORD64 apiReturnValue;
    DWORD   lastErrorValue;
};

std::string GenerateRandomBinaryName();

FARPROC ResolveFunction(const std::string& funcNameWithModule);

HANDLE CreateIPCPipe(const std::string& pipeName, bool isServer);

std::string CreateCloneExecutable();

DWORD FindProcessPid(const wchar_t* ProcName);

void* PrepareStackForApiCall(
    const std::vector<DWORD64>& stackArgs_in_order,
    FARPROC pRetAddressForApi,
    void** outStackAllocationBase
);

// ---------- Delegation engine ----------

extern HANDLE g_hPipeForChildResponse;
extern void*  g_pSharedSection;

extern "C" void CaptureRAX_And_CallHelper();
extern "C" __declspec(noinline) void NTAPI ProcessResultAndExit(DWORD64 raxFromApi);

bool ExecuteApiCallAtLevelZero(
    const ApiCallParams* pCallParams,
    const std::vector<DWORD64>* pStackArgs,
    NtContinue_t pNtContinueFunc,
    FARPROC pExitFunc,
    std::string ExitFuncName
);

bool RecursiveDelegate(
    int level,
    const ApiCallParams* pCallParams,
    const std::vector<DWORD64>* pStackArgs,
    NtContinue_t pNtContinueFunc,
    FARPROC pExitFunc,
    std::string ExitFunc,
    ApiCallResultResponse* outApiResponse
);

bool ProcessChildMode(int argc, char* argv[], NtContinue_t pNtContinueFunc);

// Returns NtContinue from ntdll, or nullptr on failure.
NtContinue_t GetNtContinue();

// Child mode is signaled by: argc >= 4 and argv[2] looks like "Module!Function".
// Anything else (no args, or parent-mode CLI flags) returns false.
bool IsChildModeArgs(int argc, char* argv[]);
