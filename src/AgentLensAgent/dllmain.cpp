#include <windows.h>

#include <string>

static volatile LONG g_started = 0;

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

    std::wstring json = L"{\"source\":\"AgentLensAgent\",";
    json += L"\"pid\":" + std::to_wstring(GetCurrentProcessId()) + L",";
    json += L"\"image\":\"" + std::wstring(path) + L"\",";
    json += L"\"command\":\"" + std::wstring(GetCommandLineW()) + L"\",";
    json += L"\"cwd\":\"" + std::wstring(cwd) + L"\"}";

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
