#include <gtest/gtest.h>

#include "RecursiveDelegationCore.h"

#include <windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

namespace {

std::string OwnExeImageName() {
    char buf[MAX_PATH] = {};
    DWORD n = GetModuleFileNameA(NULL, buf, MAX_PATH);
    std::string path(buf, n);
    size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::wstring OwnExeImageNameW() {
    wchar_t buf[MAX_PATH] = {};
    DWORD n = GetModuleFileNameW(NULL, buf, MAX_PATH);
    std::wstring path(buf, n);
    size_t slash = path.find_last_of(L"\\/");
    return slash == std::wstring::npos ? path : path.substr(slash + 1);
}

bool EndsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool StartsWithAnyMsBinary(const std::string& s) {
    for (const auto& name : MS_BINARY_NAMES) {
        if (s.size() >= name.size() + 1 &&
            s.compare(0, name.size(), name) == 0 &&
            s[name.size()] == '_') {
            return true;
        }
    }
    return false;
}

}  // namespace

// ---------- GenerateRandomBinaryName ----------

TEST(GenerateRandomBinaryName, EndsWithDotExe) {
    EXPECT_TRUE(EndsWith(GenerateRandomBinaryName(), ".exe"));
}

TEST(GenerateRandomBinaryName, PrefixIsKnownMsBinary) {
    for (int i = 0; i < 20; ++i) {
        std::string name = GenerateRandomBinaryName();
        EXPECT_TRUE(StartsWithAnyMsBinary(name)) << "name was: " << name;
    }
}

TEST(GenerateRandomBinaryName, ContainsTickCountSeparator) {
    // Format: <msname>_<tickcount>.exe — must have exactly one underscore
    std::string name = GenerateRandomBinaryName();
    EXPECT_EQ(std::count(name.begin(), name.end(), '_'), 1) << name;
}

// ---------- ResolveFunction ----------

TEST(ResolveFunction, ResolvesKnownExportToSameAddrAsGetProcAddress) {
    FARPROC resolved = ResolveFunction("Kernel32!VirtualAlloc");
    ASSERT_NE(resolved, nullptr);
    FARPROC expected = GetProcAddress(GetModuleHandleA("Kernel32"), "VirtualAlloc");
    EXPECT_EQ(reinterpret_cast<void*>(resolved), reinterpret_cast<void*>(expected));
}

TEST(ResolveFunction, MissingBangDelimiterReturnsNull) {
    EXPECT_EQ(ResolveFunction("Kernel32VirtualAlloc"), nullptr);
    EXPECT_EQ(ResolveFunction(""), nullptr);
}

TEST(ResolveFunction, UnknownModuleReturnsNull) {
    EXPECT_EQ(ResolveFunction("definitely_not_a_real_module_xyz.dll!Foo"), nullptr);
}

TEST(ResolveFunction, UnknownFunctionInKnownModuleReturnsNull) {
    EXPECT_EQ(ResolveFunction("Kernel32!ThisExportDoesNotExist_xyz"), nullptr);
}

// ---------- PrepareStackForApiCall ----------

TEST(PrepareStackForApiCall, NullRetAddressReturnsNull) {
    void* base = nullptr;
    EXPECT_EQ(PrepareStackForApiCall({}, nullptr, &base), nullptr);
}

TEST(PrepareStackForApiCall, NullOutBaseReturnsNull) {
    FARPROC dummyRet = reinterpret_cast<FARPROC>(0x1234'5678'9abcULL);
    EXPECT_EQ(PrepareStackForApiCall({}, dummyRet, nullptr), nullptr);
}

TEST(PrepareStackForApiCall, RspIsAlignedSixteenPlusEight_NoStackArgs) {
    // Win64 ABI: at function entry RSP % 16 == 8 (the call pushed an 8-byte return address).
    void* base = nullptr;
    FARPROC dummyRet = reinterpret_cast<FARPROC>(0xDEAD'BEEF'CAFE'1234ULL);
    void* rsp = PrepareStackForApiCall({}, dummyRet, &base);
    ASSERT_NE(rsp, nullptr);
    ASSERT_NE(base, nullptr);
    EXPECT_EQ(reinterpret_cast<DWORD64>(rsp) % 16, 8u);
    EXPECT_EQ(*reinterpret_cast<DWORD64*>(rsp), reinterpret_cast<DWORD64>(dummyRet));
    VirtualFree(base, 0, MEM_RELEASE);
}

TEST(PrepareStackForApiCall, FifthAndSixthArgsAtCorrectOffsets) {
    void* base = nullptr;
    FARPROC dummyRet = reinterpret_cast<FARPROC>(0x1111'2222'3333'4444ULL);
    std::vector<DWORD64> args{0xAAAA'AAAA'AAAA'AAAAULL,
                              0xBBBB'BBBB'BBBB'BBBBULL,
                              0xCCCC'CCCC'CCCC'CCCCULL};
    void* rsp = PrepareStackForApiCall(args, dummyRet, &base);
    ASSERT_NE(rsp, nullptr);

    DWORD64 rspVal = reinterpret_cast<DWORD64>(rsp);
    EXPECT_EQ(rspVal % 16, 8u);
    EXPECT_EQ(*reinterpret_cast<DWORD64*>(rsp), reinterpret_cast<DWORD64>(dummyRet));

    // 5th arg at RSP+0x28, 6th at RSP+0x30, 7th at RSP+0x38.
    EXPECT_EQ(*reinterpret_cast<DWORD64*>(rspVal + 0x28), args[0]);
    EXPECT_EQ(*reinterpret_cast<DWORD64*>(rspVal + 0x30), args[1]);
    EXPECT_EQ(*reinterpret_cast<DWORD64*>(rspVal + 0x38), args[2]);

    VirtualFree(base, 0, MEM_RELEASE);
}

TEST(PrepareStackForApiCall, RspIsWithinAllocatedRegion) {
    void* base = nullptr;
    FARPROC dummyRet = reinterpret_cast<FARPROC>(0x4242'4242'4242'4242ULL);
    std::vector<DWORD64> args(8, 0xFEFEFEFEFEFEFEFEULL);
    void* rsp = PrepareStackForApiCall(args, dummyRet, &base);
    ASSERT_NE(rsp, nullptr);

    MEMORY_BASIC_INFORMATION mbi{};
    SIZE_T n = VirtualQuery(base, &mbi, sizeof(mbi));
    ASSERT_NE(n, 0u);
    EXPECT_EQ(mbi.State, static_cast<DWORD>(MEM_COMMIT));

    auto* start = static_cast<char*>(base);
    auto* end = start + mbi.RegionSize;
    EXPECT_GE(static_cast<char*>(rsp), start);
    // The last arg slot occupies bytes [rsp + 0x28 + (N-1)*8, rsp + 0x28 + N*8),
    // so the one-past-the-end pointer may equal `end` but must not exceed it.
    EXPECT_LE(static_cast<char*>(rsp) + 0x28 + args.size() * sizeof(DWORD64), end);

    VirtualFree(base, 0, MEM_RELEASE);
}

// ---------- CreateCloneExecutable ----------

TEST(CreateCloneExecutable, ProducesCopyWithTemporaryAttribute) {
    std::string clonePath = CreateCloneExecutable();
    ASSERT_FALSE(clonePath.empty());

    // Cleanup guard.
    struct Cleanup {
        std::string p;
        ~Cleanup() { if (!p.empty()) DeleteFileA(p.c_str()); }
    } cleanup{clonePath};

    DWORD attrs = GetFileAttributesA(clonePath.c_str());
    ASSERT_NE(attrs, INVALID_FILE_ATTRIBUTES);
    EXPECT_TRUE(attrs & FILE_ATTRIBUTE_TEMPORARY);

    // Sizes match the running module.
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    WIN32_FILE_ATTRIBUTE_DATA selfInfo{}, cloneInfo{};
    ASSERT_TRUE(GetFileAttributesExA(selfPath, GetFileExInfoStandard, &selfInfo));
    ASSERT_TRUE(GetFileAttributesExA(clonePath.c_str(), GetFileExInfoStandard, &cloneInfo));
    EXPECT_EQ(selfInfo.nFileSizeLow, cloneInfo.nFileSizeLow);
    EXPECT_EQ(selfInfo.nFileSizeHigh, cloneInfo.nFileSizeHigh);
}

TEST(CreateCloneExecutable, RepeatedCallsProduceDistinctPaths) {
    std::string a = CreateCloneExecutable();
    std::string b = CreateCloneExecutable();
    ASSERT_FALSE(a.empty());
    ASSERT_FALSE(b.empty());
    EXPECT_NE(a, b);
    DeleteFileA(a.c_str());
    DeleteFileA(b.c_str());
}

// ---------- FindProcessPid ----------

TEST(FindProcessPid, FindsOwnProcessByName) {
    std::wstring imageName = OwnExeImageNameW();
    DWORD pid = FindProcessPid(imageName.c_str());
    EXPECT_EQ(pid, GetCurrentProcessId());
}

TEST(FindProcessPid, ReturnsZeroForImpossibleName) {
    EXPECT_EQ(FindProcessPid(L"definitely_not_a_running_process_xyz_12345.exe"), 0u);
}

// ---------- CreateIPCPipe ----------

TEST(CreateIPCPipe, ServerClientRoundTrip) {
    // Unique pipe name per test run.
    std::string pipeName = "RecursiveDelegationTestPipe_" +
                           std::to_string(GetCurrentProcessId()) + "_" +
                           std::to_string(GetTickCount64());

    HANDLE hServer = CreateIPCPipe(pipeName, true);
    ASSERT_NE(hServer, INVALID_HANDLE_VALUE);

    std::atomic<bool> clientConnected{false};
    HANDLE hClientResult = INVALID_HANDLE_VALUE;

    std::thread clientThread([&] {
        // The server's ConnectNamedPipe blocks until we open the file end.
        hClientResult = CreateIPCPipe(pipeName, false);
        clientConnected.store(hClientResult != INVALID_HANDLE_VALUE);
    });

    BOOL connected = ConnectNamedPipe(hServer, NULL);
    if (!connected) {
        // ERROR_PIPE_CONNECTED means the client beat us — also a success.
        EXPECT_EQ(GetLastError(), static_cast<DWORD>(ERROR_PIPE_CONNECTED));
    }

    // Exchange one byte to prove the channel actually works.
    DWORD bytes = 0;
    const char ping = 0x42;
    clientThread.join();
    ASSERT_TRUE(clientConnected.load());
    ASSERT_NE(hClientResult, INVALID_HANDLE_VALUE);

    ASSERT_TRUE(WriteFile(hServer, &ping, 1, &bytes, NULL));
    EXPECT_EQ(bytes, 1u);

    char recv = 0;
    ASSERT_TRUE(ReadFile(hClientResult, &recv, 1, &bytes, NULL));
    EXPECT_EQ(bytes, 1u);
    EXPECT_EQ(recv, ping);

    CloseHandle(hServer);
    CloseHandle(hClientResult);
}

TEST(CreateIPCPipe, ClientGivesUpOnMissingPipe) {
    auto start = std::chrono::steady_clock::now();
    HANDLE h = CreateIPCPipe("nonexistent_pipe_" + std::to_string(GetTickCount64()), false);
    auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_EQ(h, INVALID_HANDLE_VALUE);
    // Function only sleeps when GetLastError == ERROR_PIPE_BUSY. Missing pipe returns
    // ERROR_FILE_NOT_FOUND on the first attempt, so this must return promptly.
    EXPECT_LT(std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count(), 500);
}

// ---------- ApiCall structs (wire format) ----------

TEST(ApiCallStructs, AreStandardLayoutAndTriviallyCopyable) {
    // These travel over named pipes as raw bytes — make sure they stay POD-ish.
    EXPECT_TRUE(std::is_standard_layout<ApiCallParams>::value);
    EXPECT_TRUE(std::is_trivially_copyable<ApiCallParams>::value);
    EXPECT_TRUE(std::is_standard_layout<ApiCallResultResponse>::value);
    EXPECT_TRUE(std::is_trivially_copyable<ApiCallResultResponse>::value);
}

// ---------- Layer 2: IPC wire format ----------
//
// These tests reproduce the exact byte sequence that flows between
// RecursiveDelegate (parent) and ProcessChildMode (child) in
// RecursiveDelegation.cpp:
//
//   parent -> child:  ApiCallParams                (sizeof struct, raw)
//                     SIZE_T numStackArgs
//                     numStackArgs * 8 bytes       (the stack args)
//   child  -> parent: ApiCallResultResponse        (sizeof struct, raw)

namespace {

struct Pipes {
    HANDLE server = INVALID_HANDLE_VALUE;
    HANDLE client = INVALID_HANDLE_VALUE;
    ~Pipes() {
        if (server != INVALID_HANDLE_VALUE) CloseHandle(server);
        if (client != INVALID_HANDLE_VALUE) CloseHandle(client);
    }
};

bool ConnectPipePair(Pipes& out) {
    std::string name = "RecursiveDelegationTestPipe_" +
                       std::to_string(GetCurrentProcessId()) + "_" +
                       std::to_string(GetTickCount64()) + "_" +
                       std::to_string(reinterpret_cast<DWORD64>(&out));
    out.server = CreateIPCPipe(name, true);
    if (out.server == INVALID_HANDLE_VALUE) return false;

    std::thread t([&] { out.client = CreateIPCPipe(name, false); });
    BOOL connected = ConnectNamedPipe(out.server, NULL);
    if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
        t.join();
        return false;
    }
    t.join();
    return out.client != INVALID_HANDLE_VALUE;
}

ApiCallParams MakeSampleParams() {
    ApiCallParams p{};
    strncpy_s(p.funcNameWithModule, "Kernel32!VirtualAllocEx", _TRUNCATE);
    p.rcx_val = 0x1111'1111'1111'1111ULL;
    p.rdx_val = 0x2222'2222'2222'2222ULL;
    p.r8_val  = 0x3333'3333'3333'3333ULL;
    p.r9_val  = 0x4444'4444'4444'4444ULL;
    p.rcx_is_ptr_offset_from_stack = FALSE;
    p.rdx_is_ptr_offset_from_stack = TRUE;
    p.r8_is_ptr_offset_from_stack  = FALSE;
    p.r9_is_ptr_offset_from_stack  = FALSE;
    return p;
}

}  // namespace

TEST(IpcWireFormat, RoundTripApiCallParams) {
    Pipes p;
    ASSERT_TRUE(ConnectPipePair(p));

    ApiCallParams sent = MakeSampleParams();
    DWORD written = 0;
    ASSERT_TRUE(WriteFile(p.server, &sent, sizeof(sent), &written, NULL));
    ASSERT_EQ(written, sizeof(sent));

    ApiCallParams received{};
    DWORD read = 0;
    ASSERT_TRUE(ReadFile(p.client, &received, sizeof(received), &read, NULL));
    ASSERT_EQ(read, sizeof(received));

    EXPECT_STREQ(received.funcNameWithModule, sent.funcNameWithModule);
    EXPECT_EQ(received.rcx_val, sent.rcx_val);
    EXPECT_EQ(received.rdx_val, sent.rdx_val);
    EXPECT_EQ(received.r8_val,  sent.r8_val);
    EXPECT_EQ(received.r9_val,  sent.r9_val);
    EXPECT_EQ(received.rdx_is_ptr_offset_from_stack, TRUE);
    EXPECT_EQ(received.rcx_is_ptr_offset_from_stack, FALSE);
}

TEST(IpcWireFormat, RoundTripFullDelegationRequest) {
    // Full parent->child request: params, count, then args.
    Pipes p;
    ASSERT_TRUE(ConnectPipePair(p));

    ApiCallParams sent = MakeSampleParams();
    std::vector<DWORD64> sentArgs{0xAAAA'AAAAULL, 0xBBBB'BBBBULL, 0xCCCC'CCCCULL};
    SIZE_T n = sentArgs.size();

    DWORD wrote = 0;
    ASSERT_TRUE(WriteFile(p.server, &sent, sizeof(sent), &wrote, NULL));
    ASSERT_EQ(wrote, sizeof(sent));
    ASSERT_TRUE(WriteFile(p.server, &n, sizeof(n), &wrote, NULL));
    ASSERT_EQ(wrote, sizeof(n));
    ASSERT_TRUE(WriteFile(p.server, sentArgs.data(), static_cast<DWORD>(n * sizeof(DWORD64)),
                          &wrote, NULL));
    ASSERT_EQ(wrote, n * sizeof(DWORD64));

    ApiCallParams rcvParams{};
    SIZE_T rcvN = 0;
    DWORD r = 0;
    ASSERT_TRUE(ReadFile(p.client, &rcvParams, sizeof(rcvParams), &r, NULL));
    ASSERT_EQ(r, sizeof(rcvParams));
    ASSERT_TRUE(ReadFile(p.client, &rcvN, sizeof(rcvN), &r, NULL));
    ASSERT_EQ(r, sizeof(rcvN));
    ASSERT_EQ(rcvN, n);

    std::vector<DWORD64> rcvArgs(rcvN);
    ASSERT_TRUE(ReadFile(p.client, rcvArgs.data(), static_cast<DWORD>(rcvN * sizeof(DWORD64)),
                         &r, NULL));
    ASSERT_EQ(r, rcvN * sizeof(DWORD64));
    EXPECT_STREQ(rcvParams.funcNameWithModule, sent.funcNameWithModule);
    EXPECT_EQ(rcvArgs, sentArgs);
}

TEST(IpcWireFormat, RoundTripApiCallResultResponse) {
    Pipes p;
    ASSERT_TRUE(ConnectPipePair(p));

    ApiCallResultResponse sent{};
    sent.wasApiCallConsideredSuccess = TRUE;
    sent.apiReturnValue = 0xDEAD'BEEF'CAFE'BABEULL;
    sent.lastErrorValue = 87;  // ERROR_INVALID_PARAMETER, for fun

    DWORD wrote = 0;
    // Child writes to its end (here, the "client" half) and parent reads on the server.
    ASSERT_TRUE(WriteFile(p.client, &sent, sizeof(sent), &wrote, NULL));
    ASSERT_EQ(wrote, sizeof(sent));

    ApiCallResultResponse received{};
    DWORD read = 0;
    ASSERT_TRUE(ReadFile(p.server, &received, sizeof(received), &read, NULL));
    ASSERT_EQ(read, sizeof(received));

    EXPECT_EQ(received.wasApiCallConsideredSuccess, sent.wasApiCallConsideredSuccess);
    EXPECT_EQ(received.apiReturnValue, sent.apiReturnValue);
    EXPECT_EQ(received.lastErrorValue, sent.lastErrorValue);
}

TEST(IpcWireFormat, ServerSeesFailureWhenClientClosesEarly) {
    // Mirrors the case in RecursiveDelegate where the child process is terminated
    // before sending its response. Parent's ReadFile must fail rather than hang.
    Pipes p;
    ASSERT_TRUE(ConnectPipePair(p));

    CloseHandle(p.client);
    p.client = INVALID_HANDLE_VALUE;

    ApiCallResultResponse resp{};
    DWORD read = 0;
    BOOL ok = ReadFile(p.server, &resp, sizeof(resp), &read, NULL);
    EXPECT_FALSE(ok);
    EXPECT_NE(GetLastError(), 0u);
    EXPECT_LT(read, sizeof(resp));
}

// ---------- Layer 3: End-to-end delegation ----------
//
// These tests actually spawn child processes via RecursiveDelegate. Because
// CreateCloneExecutable clones THIS test binary, the spawned children re-enter
// our main() and dispatch to ProcessChildMode (see custom main at bottom).

namespace {

ApiCallParams MakeApi(const char* name) {
    ApiCallParams p{};
    strncpy_s(p.funcNameWithModule, name, _TRUNCATE);
    return p;
}

}  // namespace

TEST(E2EDelegation, Level1_GetTickCount64_ReturnsReasonableValue) {
    NtContinue_t pNt = GetNtContinue();
    ASSERT_NE(pNt, nullptr);

    ApiCallParams params = MakeApi("Kernel32!GetTickCount64");
    std::vector<DWORD64> args;  // GetTickCount64 takes none
    ApiCallResultResponse resp{};

    DWORD64 hostBefore = GetTickCount64();
    bool ok = RecursiveDelegate(/*level=*/1, &params, &args, pNt,
                                /*pExitFunc=*/NULL, "default", &resp);
    DWORD64 hostAfter = GetTickCount64();

    ASSERT_TRUE(ok);
    EXPECT_TRUE(resp.wasApiCallConsideredSuccess);
    // The child's GetTickCount64() return must fall within the host window
    // (plus a generous fudge for child startup).
    EXPECT_GE(resp.apiReturnValue, hostBefore);
    EXPECT_LE(resp.apiReturnValue, hostAfter + 30000ULL);
}

TEST(E2EDelegation, Level1_VirtualAllocExSelf_ReturnsCommittedRegion) {
    NtContinue_t pNt = GetNtContinue();
    ASSERT_NE(pNt, nullptr);

    HANDLE hSelf = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                               /*bInherit=*/TRUE, GetCurrentProcessId());
    ASSERT_NE(hSelf, nullptr);

    ApiCallParams params = MakeApi("Kernel32!VirtualAllocEx");
    params.rcx_val = reinterpret_cast<DWORD64>(hSelf);
    params.rdx_val = 0;
    params.r8_val  = 4096;
    params.r9_val  = MEM_COMMIT | MEM_RESERVE;
    std::vector<DWORD64> args{PAGE_READWRITE};
    ApiCallResultResponse resp{};

    bool ok = RecursiveDelegate(/*level=*/1, &params, &args, pNt, NULL, "default", &resp);
    ASSERT_TRUE(ok);
    EXPECT_TRUE(resp.wasApiCallConsideredSuccess);
    ASSERT_NE(resp.apiReturnValue, 0u) << "VirtualAllocEx returned NULL; child LE=" << resp.lastErrorValue;

    // Confirm the returned address is actually mapped in our process.
    auto addr = reinterpret_cast<void*>(resp.apiReturnValue);
    MEMORY_BASIC_INFORMATION mbi{};
    ASSERT_NE(VirtualQuery(addr, &mbi, sizeof(mbi)), 0u);
    EXPECT_EQ(mbi.State, static_cast<DWORD>(MEM_COMMIT));
    EXPECT_EQ(mbi.Protect, static_cast<DWORD>(PAGE_READWRITE));

    VirtualFree(addr, 0, MEM_RELEASE);
    CloseHandle(hSelf);
}

TEST(E2EDelegation, Level2_VirtualAllocExSelf_ChainOfTwoProcesses) {
    NtContinue_t pNt = GetNtContinue();
    ASSERT_NE(pNt, nullptr);

    HANDLE hSelf = NULL;
    ASSERT_TRUE(DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
                                GetCurrentProcess(), &hSelf, 0, TRUE, DUPLICATE_SAME_ACCESS));

    ApiCallParams params = MakeApi("Kernel32!VirtualAllocEx");
    params.rcx_val = reinterpret_cast<DWORD64>(hSelf);
    params.rdx_val = 0;
    params.r8_val  = 8192;
    params.r9_val  = MEM_COMMIT | MEM_RESERVE;
    std::vector<DWORD64> args{PAGE_READWRITE};
    ApiCallResultResponse resp{};

    bool ok = RecursiveDelegate(/*level=*/2, &params, &args, pNt, NULL, "default", &resp);
    ASSERT_TRUE(ok);
    EXPECT_TRUE(resp.wasApiCallConsideredSuccess);
    ASSERT_NE(resp.apiReturnValue, 0u) << "VirtualAllocEx returned NULL; child LE=" << resp.lastErrorValue;

    VirtualFree(reinterpret_cast<void*>(resp.apiReturnValue), 0, MEM_RELEASE);
    CloseHandle(hSelf);
}

TEST(E2EDelegation, Level1_SetEvent_DelegateActuallySignals) {
    NtContinue_t pNt = GetNtContinue();
    ASSERT_NE(pNt, nullptr);

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE hEvent = CreateEventA(&sa, /*manualReset=*/TRUE, /*initial=*/FALSE, NULL);
    ASSERT_NE(hEvent, nullptr);

    ApiCallParams params = MakeApi("Kernel32!SetEvent");
    params.rcx_val = reinterpret_cast<DWORD64>(hEvent);
    std::vector<DWORD64> args;
    ApiCallResultResponse resp{};

    bool ok = RecursiveDelegate(/*level=*/1, &params, &args, pNt, NULL, "default", &resp);
    ASSERT_TRUE(ok);
    EXPECT_TRUE(resp.wasApiCallConsideredSuccess);

    DWORD wait = WaitForSingleObject(hEvent, 10000);
    EXPECT_EQ(wait, WAIT_OBJECT_0) << "Event was not signaled by the delegated child.";
    CloseHandle(hEvent);
}

// ---------- Custom main: dispatch child mode before initializing GoogleTest ----------

int main(int argc, char** argv) {
    NtContinue_t pNt = GetNtContinue();

    if (IsChildModeArgs(argc, argv)) {
        if (!pNt) return 2;
        return ProcessChildMode(argc, argv, pNt) ? 0 : 1;
    }

    if (!pNt) {
        std::cerr << "main(parent): failed to resolve NtContinue from ntdll." << std::endl;
        return 3;
    }

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
