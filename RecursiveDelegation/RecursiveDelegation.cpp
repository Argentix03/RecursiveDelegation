// RecursiveDelegation.cpp - Implementation of a recursive process tree function delegation system
#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>
#include <random>
#include <sstream>
#include <memory>
#include <TlHelp32.h>

#include <ntstatus.h>

// Add this definition if <ntstatus.h> is not available
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Structure to hold context data (CPU registers and state)
struct CtxData {
    CONTEXT Context;
    // Additional fields can be added as needed
};

// Structure to hold stack data
struct StackData {
    void* Buffer;
    SIZE_T Size;
};

// List of funny Microsoft binary names for random selection
const std::vector<std::string> MS_BINARY_NAMES = {
    "svchost", "wininit", "csrss", "lsass", "winlogon", "spoolsv", "dwm",
    "explorer", "taskmgr", "msiexec", "conhost", "rundll32", "services",
    "smss", "ntoskrnl", "regsvr32", "mmc", "dllhost", "wuauclt", "iexplore"
};

// Generate a random Microsoft-like binary name
std::string GenerateRandomBinaryName() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, MS_BINARY_NAMES.size() - 1);

    std::stringstream ss;
    ss << MS_BINARY_NAMES[distrib(gen)] << "_" << distrib(gen) << ".exe";
    return ss.str();
}

// Function to resolve a function pointer from a name (e.g., "Kernel32!VirtualAllocEx")
FARPROC ResolveFunction(const std::string& funcName) {
    size_t pos = funcName.find('!');
    if (pos == std::string::npos) {
        std::cerr << "Invalid function name format. Expected: 'Module!Function'" << std::endl;
        return nullptr;
    }

    std::string moduleName = funcName.substr(0, pos);
    std::string functionName = funcName.substr(pos + 1);

    HMODULE hModule = GetModuleHandleA(moduleName.c_str());
    if (!hModule) {
        hModule = LoadLibraryA(moduleName.c_str());
        if (!hModule) {
            std::cerr << "Failed to load module: " << moduleName << std::endl;
            return nullptr;
        }
    }

    FARPROC procAddr = GetProcAddress(hModule, functionName.c_str());
    if (!procAddr) {
        std::cerr << "Failed to resolve function: " << functionName << std::endl;
    }

    return procAddr;
}

// Create a named pipe for IPC
HANDLE CreateIPCPipe(const std::string& pipeName, bool isServer) {
    std::string fullPipeName = "\\\\.\\pipe\\" + pipeName;

    if (isServer) {
        return CreateNamedPipeA(
            fullPipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            NULL
        );
    }
    else {
        return CreateFileA(
            fullPipeName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
    }
}

// Execute the target function at recursion level 0
bool ExecuteFunction(const std::string& funcName, CtxData* ctxData, StackData* stackData) {
    FARPROC funcPtr = ResolveFunction(funcName);
    if (!funcPtr) {
        return false;
    }

    // Setup execution context
    ctxData->Context.Rip = reinterpret_cast<DWORD64>(funcPtr);

    ctxData->Context.ContextFlags = CONTEXT_FULL;

    // Create a trampoline that will safely exit after function execution
    void* trampolineCode = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!trampolineCode) {
        std::cerr << "Failed to allocate trampoline memory" << std::endl;
        return false;
    }

    // Fill with INT 3 for debugging purposes
    memset(trampolineCode, 0xCC, 16);

    // Write a RET instruction (0xC3) at the beginning
    *reinterpret_cast<BYTE*>(trampolineCode) = 0xC3;

    // Add some debug output to verify register values before execution
    std::cout << "Executing with registers:" << std::endl;
    std::cout << "RCX: 0x" << std::hex << ctxData->Context.Rcx << std::endl;
    std::cout << "RDX: 0x" << std::hex << ctxData->Context.Rdx << std::endl;
    std::cout << "R8: 0x" << std::hex << ctxData->Context.R8 << std::endl;
    std::cout << "R9: 0x" << std::hex << ctxData->Context.R9 << std::endl;
    std::cout << "RSP: 0x" << std::hex << ctxData->Context.Rsp << std::endl;
    std::cout << "RIP: 0x" << std::hex << ctxData->Context.Rip << std::endl;
    // Extract parameters from context
    HANDLE hProcess = reinterpret_cast<HANDLE>(ctxData->Context.Rcx);
    LPVOID lpAddress = reinterpret_cast<LPVOID>(ctxData->Context.Rdx);
    SIZE_T dwSize = static_cast<SIZE_T>(ctxData->Context.R8);
    DWORD flAllocationType = static_cast<DWORD>(ctxData->Context.R9);

    // Get the 5th parameter from stack
    DWORD64* stackPtr = reinterpret_cast<DWORD64*>(ctxData->Context.Rsp);
    DWORD flProtect = static_cast<DWORD>(stackPtr[4]);
        // Debug output
    std::cout << "Calling VirtualAllocEx with parameters:" << std::endl;
    std::cout << "  hProcess: 0x" << std::hex << reinterpret_cast<DWORD64>(hProcess) << std::endl;
    std::cout << "  lpAddress: 0x" << std::hex << reinterpret_cast<DWORD64>(lpAddress) << std::endl;
    std::cout << "  dwSize: 0x" << std::hex << dwSize << std::endl;
    std::cout << "  flAllocationType: 0x" << std::hex << flAllocationType << std::endl;
    std::cout << "  flProtect: 0x" << std::hex << flProtect << std::endl;

    // Execute the function using NtContinue
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        ntdll = LoadLibraryA("ntdll.dll");
        if (!ntdll) {
            std::cerr << "Failed to load ntdll.dll" << std::endl;
            return false;
        }
    }

    // Important: Set RBP properly (frame pointer)
    ctxData->Context.Rbp = ctxData->Context.Rsp + 48; // Usually above the stack frame

    // Initialize EFLAGS (typical value for normal execution)
    ctxData->Context.EFlags = 0x202; // Standard flags: IF=1,
    stackPtr[-1] = reinterpret_cast<DWORD64>(trampolineCode); // Return address one slot below RSP

    typedef NTSTATUS(NTAPI* pNtContinue)(PCONTEXT ContextRecord, BOOLEAN TestAlert);
    pNtContinue NtContinue = reinterpret_cast<pNtContinue>(GetProcAddress(ntdll, "NtContinue"));

    if (!NtContinue) {
        std::cerr << "Failed to resolve NtContinue" << std::endl;
        return false;
    }
    else {
		std::cout << "Resolved NtContinue successfully" << std::endl;
    }

    NTSTATUS status = NtContinue(&ctxData->Context, FALSE);
    return NT_SUCCESS(status);

}

// Copy the current executable to a new random binary name
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

    CopyFileA(currentPath, newPath.c_str(), FALSE);
    return newPath;
}

// Main recursive delegation function
bool RecursiveDelegate(int level, const std::string& funcName, CtxData* ctxData, StackData* stackData) {
    std::cout << "Process " << GetCurrentProcessId() << " at recursion level: " << level << std::endl;

    // If recursion level is 0 or less, execute the function
    if (level <= 0) {
        std::cout << "Executing function: " << funcName << std::endl;
        return ExecuteFunction(funcName, ctxData, stackData);
    }

    // Create a clone executable with a random name
    std::string clonePath = CreateCloneExecutable();

    // Create a unique pipe name for IPC
    std::stringstream pipeName;
    pipeName << "RecursiveDelegation_" << GetCurrentProcessId() << "_" << level;

    // Create a pipe server
    HANDLE hPipe = CreateIPCPipe(pipeName.str(), true);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create pipe server" << std::endl;
        return false;
    }

    // Prepare command line for child process
    std::stringstream cmdLine;
    cmdLine << "\"" << clonePath << "\" " << (level - 1) << " \"" << funcName << "\" " << pipeName.str();

    // Create child process
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessA(
        NULL,
        const_cast<LPSTR>(cmdLine.str().c_str()),
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        std::cerr << "Failed to create child process. Error: " << GetLastError() << std::endl;
        CloseHandle(hPipe);
        return false;
    }

    // Connect to the client
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        std::cerr << "Failed to connect to client" << std::endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hPipe);
        return false;
    }

    // Send the context and stack data
    DWORD bytesWritten;
    WriteFile(hPipe, ctxData, sizeof(CtxData), &bytesWritten, NULL);
    WriteFile(hPipe, &stackData->Size, sizeof(SIZE_T), &bytesWritten, NULL);
    WriteFile(hPipe, stackData->Buffer, stackData->Size, &bytesWritten, NULL);

    // Wait for the result
    BOOL result;
    DWORD bytesRead;
    ReadFile(hPipe, &result, sizeof(BOOL), &bytesRead, NULL);

    // Cleanup
    CloseHandle(hPipe);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return result == TRUE;
}

// Process the command line arguments when running as a spawned child
bool ProcessChildMode(int argc, char* argv[]) {
    if (argc < 4) {
        return false;
    }

    int level = atoi(argv[1]);
    std::string funcName = argv[2];
    std::string pipeName = argv[3];

    // Connect to the parent process pipe
    HANDLE hPipe = CreateIPCPipe(pipeName, false);
    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cerr << "Child: Failed to connect to pipe" << std::endl;
        return false;
    }

    // Receive context and stack data
    CtxData ctxData;
    SIZE_T stackSize;
    DWORD bytesRead;

    ReadFile(hPipe, &ctxData, sizeof(CtxData), &bytesRead, NULL);
    ReadFile(hPipe, &stackSize, sizeof(SIZE_T), &bytesRead, NULL);

    std::unique_ptr<char[]> stackBuffer(new char[stackSize]);
    StackData stackData = { stackBuffer.get(), stackSize };

    ReadFile(hPipe, stackData.Buffer, stackData.Size, &bytesRead, NULL);

    // Call RecursiveDelegate with the received data
    BOOL result = RecursiveDelegate(level, funcName, &ctxData, &stackData);

    // Send the result back to the parent
    DWORD bytesWritten;
    WriteFile(hPipe, &result, sizeof(BOOL), &bytesWritten, NULL);

    // Cleanup
    CloseHandle(hPipe);

    return true;
}

int main(int argc, char* argv[]) {
    // Check if running as a spawned child
    if (argc > 1) {
        if (ProcessChildMode(argc, argv)) {
            return 0;
        }
    }

    // Initialize context and stack data
    CtxData ctxData = {};
    ctxData.Context.ContextFlags = CONTEXT_FULL;

    // Allocate stack for the target function
    const SIZE_T STACK_SIZE = 1024 * 1024; // 1MB stack
    void* stackBuffer = VirtualAlloc(NULL, STACK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!stackBuffer) {
        std::cerr << "Failed to allocate stack" << std::endl;
        return 1;
    }

    StackData stackData = { stackBuffer, STACK_SIZE };

    // Example: VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
    HANDLE hProcess = GetCurrentProcess();
    LPVOID lpAddress = NULL;
    SIZE_T dwSize = 4096;
    DWORD flAllocationType = MEM_COMMIT;
    DWORD flProtect = PAGE_EXECUTE_READWRITE;

    // According to x64 calling convention:
    // 1. First 4 parameters go in registers
    ctxData.Context.Rcx = reinterpret_cast<DWORD64>(hProcess);        // 1st param: hProcess
    ctxData.Context.Rdx = reinterpret_cast<DWORD64>(lpAddress);       // 2nd param: lpAddress
    ctxData.Context.R8 = static_cast<DWORD64>(dwSize);                // 3rd param: dwSize
    ctxData.Context.R9 = static_cast<DWORD64>(flAllocationType);      // 4th param: flAllocationType

    // 2. Prepare the stack
    // The stack must be 16-byte aligned before the call
    char* stackTop = reinterpret_cast<char*>(stackBuffer) + STACK_SIZE;
    stackTop = reinterpret_cast<char*>((reinterpret_cast<DWORD64>(stackTop) & ~0xF) - 8);  // 16-byte align, 8-byte buffer

    // Allocate stack space for parameters and shadow space
    // - 32 bytes of shadow space for the first 4 parameters
    // - 8 bytes for the 5th parameter
    // - 8 bytes for the return address
    DWORD64* stackPtr = reinterpret_cast<DWORD64*>(stackTop - 48);

    // Shadow space (leave as is, used by callee if needed)
    stackPtr[0] = 0;  // Shadow space for RCX
    stackPtr[1] = 0;  // Shadow space for RDX
    stackPtr[2] = 0;  // Shadow space for R8
    stackPtr[3] = 0;  // Shadow space for R9

    // 5th parameter goes on the stack
    stackPtr[4] = static_cast<DWORD64>(flProtect);  // 5th param: flProtect

    // Return address (dummy, as we're using NtContinue)
    stackPtr[5] = 0;

    // Point RSP to our stack (just above the shadow space)
    ctxData.Context.Rsp = reinterpret_cast<DWORD64>(stackPtr);

    // Start the recursive delegation with 100 levels
    const int MAX_RECURSION = 0;
    bool result = RecursiveDelegate(MAX_RECURSION, "Kernel32!VirtualAllocEx", &ctxData, &stackData);

    std::cout << "Recursive delegation " << (result ? "succeeded" : "failed") << std::endl;

    // Cleanup
    VirtualFree(stackBuffer, 0, MEM_RELEASE);

    return result ? 0 : 1;
}
