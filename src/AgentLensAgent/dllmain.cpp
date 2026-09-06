#include <windows.h>

#include <string>
#include <vector>
#include <cstdint>
#include <bcrypt.h>
#include <wintrust.h>
#include <softpub.h>

#include "AgentLensProtocol/agl_control.h"

static volatile LONG g_started = 0;

static void UpdateKernelContext(ULONG64 processId, ULONG envCount, const std::wstring& cwd)
{
    HANDLE device = CreateFileW(
        AGL_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        return;
    }

    ULONG headerSize = sizeof(AGL_CONTROL_HEADER);
    ULONG cwdBytes = static_cast<ULONG>(cwd.size() * sizeof(wchar_t));
    std::vector<uint8_t> buffer(headerSize + sizeof(AGL_CONTEXT_UPDATE) + cwdBytes, 0);

    auto* header = reinterpret_cast<AGL_CONTROL_HEADER*>(buffer.data());
    header->StructSize = headerSize;
    header->Version = AGL_PROTOCOL_VERSION;
    header->OpCode = AGL_OP_UPDATE_CONTEXT;
    header->InputLength = sizeof(AGL_CONTEXT_UPDATE) + cwdBytes;

    auto* update = reinterpret_cast<AGL_CONTEXT_UPDATE*>(buffer.data() + headerSize);
    update->ProcessId = processId;
    update->EnvironmentHash = envCount;
    update->CurrentDirectoryLength = cwdBytes;
    if (cwdBytes)
    {
        memcpy(update->Data, cwd.c_str(), cwdBytes);
    }

    DWORD returned = 0;
    DeviceIoControl(
        device,
        AGL_CONTROL_IOCTL,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        nullptr,
        0,
        &returned,
        nullptr);

    CloseHandle(device);
}

static ULONG Fnv1a(const uint8_t* data, size_t length)
{
    ULONG hash = 2166136261u;
    for (size_t i = 0; i < length; i++)
    {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

static ULONG VerifyImageSignature(const wchar_t* path)
{
    WINTRUST_FILE_INFO fileInfo = {};
    WINTRUST_DATA trustData = {};
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG verifyResult;
    LONG closeResult;

    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path;
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    trustData.cbStruct = sizeof(trustData);
    trustData.pPolicyCallbackData = nullptr;
    trustData.pSIPClientData = nullptr;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = nullptr;
    trustData.pwszURLReference = nullptr;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    verifyResult = WinVerifyTrust(nullptr, &policy, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    closeResult = WinVerifyTrust(nullptr, &policy, &trustData);

    if (verifyResult == ERROR_SUCCESS)
    {
        return AGL_SIGNER_STATE_SIGNED;
    }

    if (verifyResult == TRUST_E_NOSIGNATURE ||
        verifyResult == TRUST_E_SUBJECT_FORM_UNKNOWN ||
        verifyResult == TRUST_E_PROVIDER_UNKNOWN)
    {
        return AGL_SIGNER_STATE_UNSIGNED;
    }

    return AGL_SIGNER_STATE_UNKNOWN;
}

static bool ComputeSha256(const wchar_t* path, unsigned char hash[32])
{
    HANDLE file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 &&
        BCryptCreateHash(alg, &hashHandle, nullptr, 0, nullptr, 0, 0) == 0)
    {
        uint8_t buffer[8192];
        DWORD read = 0;
        while (ReadFile(file, buffer, sizeof(buffer), &read, nullptr) && read > 0)
        {
            BCryptHashData(hashHandle, buffer, read, 0);
        }
        if (BCryptFinishHash(hashHandle, hash, 32, 0) == 0)
        {
            ok = true;
        }
    }

    if (hashHandle) BCryptDestroyHash(hashHandle);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    CloseHandle(file);
    return ok;
}

static void UpdateImageContext()
{
    wchar_t path[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    ULONG pathHash = Fnv1a((const uint8_t*)path, wcslen(path) * sizeof(wchar_t));
    unsigned char sha256[32] = { 0 };
    ComputeSha256(path, sha256);
    ULONG signerState = VerifyImageSignature(path);

    HANDLE device = CreateFileW(
        AGL_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    if (device == INVALID_HANDLE_VALUE)
    {
        return;
    }

    ULONG headerSize = sizeof(AGL_CONTROL_HEADER);
    std::vector<uint8_t> buffer(headerSize + sizeof(AGL_IMAGE_UPDATE), 0);
    auto* header = reinterpret_cast<AGL_CONTROL_HEADER*>(buffer.data());
    header->StructSize = headerSize;
    header->Version = AGL_PROTOCOL_VERSION;
    header->OpCode = AGL_OP_UPDATE_IMAGE_CONTEXT;
    header->InputLength = sizeof(AGL_IMAGE_UPDATE);

    auto* update = reinterpret_cast<AGL_IMAGE_UPDATE*>(buffer.data() + headerSize);
    update->ProcessId = GetCurrentProcessId();
    update->ImageBase = reinterpret_cast<ULONG64>(GetModuleHandleW(nullptr));
    update->PathHash = pathHash;
    memcpy(update->FileSha256, sha256, 32);
    update->SignerState = signerState;

    DWORD returned = 0;
    DeviceIoControl(
        device,
        AGL_CONTROL_IOCTL,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        nullptr,
        0,
        &returned,
        nullptr);
    CloseHandle(device);
}

static DWORD WINAPI AgentPipeThread(LPVOID)
{
    const wchar_t* pipeName = L"\\\\.\\pipe\\AgentLensAgent";
    HANDLE pipe = INVALID_HANDLE_VALUE;

    for (int attempt = 0; attempt < 10; attempt++)
    {
        pipe = CreateFileW(
            pipeName,
            GENERIC_WRITE | GENERIC_READ,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
        if (pipe != INVALID_HANDLE_VALUE)
        {
            break;
        }
        Sleep(100);
    }

    if (pipe == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    wchar_t path[MAX_PATH] = { 0 };
    wchar_t cwd[MAX_PATH] = { 0 };
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    GetCurrentDirectoryW(MAX_PATH, cwd);

    ULONG envCount = 0;
    LPWCH env = GetEnvironmentStringsW();
    if (env)
    {
        LPWCH p = env;
        while (*p)
        {
            envCount++;
            p += wcslen(p) + 1;
        }
        FreeEnvironmentStringsW(env);
    }

    void* stack[32] = { 0 };
    USHORT frames = CaptureStackBackTrace(0, 32, stack, nullptr);

    std::wstring callstack;
    for (USHORT i = 0; i < frames; i++)
    {
        wchar_t tmp[32];
        swprintf_s(tmp, L"%p", stack[i]);
        if (i) callstack += L";";
        callstack += tmp;
    }

    std::wstring json = L"{\"source\":\"AgentLensAgent\",";
    json += L"\"pid\":" + std::to_wstring(GetCurrentProcessId()) + L",";
    json += L"\"image\":\"" + std::wstring(path) + L"\",";
    json += L"\"command\":\"" + std::wstring(GetCommandLineW()) + L"\",";
    json += L"\"cwd\":\"" + std::wstring(cwd) + L"\",";
    json += L"\"env_count\":" + std::to_wstring(envCount) + L",";
    json += L"\"callstack\":\"" + callstack + L"\"}";

    UpdateKernelContext(GetCurrentProcessId(), envCount, cwd);
    UpdateImageContext();

    DWORD written = 0;
    WriteFile(pipe, json.c_str(), static_cast<DWORD>(json.size() * sizeof(wchar_t)), &written, nullptr);
    FlushFileBuffers(pipe);
    CloseHandle(pipe);
    return 0;
}

extern "C" __declspec(dllexport) void AglAgentStart()
{
    if (InterlockedExchange(&g_started, 1) == 0)
    {
        HANDLE thread = CreateThread(nullptr, 0, AgentPipeThread, nullptr, 0, nullptr);
        if (thread)
        {
            CloseHandle(thread);
        }
    }
}

extern "C" __declspec(dllexport) void AglAgentStop()
{
    InterlockedExchange(&g_started, 0);
}

extern "C" __declspec(dllexport) long AglAgentPing()
{
    return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(hModule);
    UNREFERENCED_PARAMETER(reserved);

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
