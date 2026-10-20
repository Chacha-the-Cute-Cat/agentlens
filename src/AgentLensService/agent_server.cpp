#include "agent_server.h"

#include <windows.h>
#include <string>
#include <vector>
#include <cwchar>

namespace
{
    HANDLE g_agentThread = nullptr;
    volatile LONG g_agentStop = 0;

    DWORD WINAPI AgentServerThread(LPVOID)
    {
        const wchar_t* pipeName = L"\\\\.\\pipe\\AgentLensAgent";

        for (;;)
        {
            if (g_agentStop != 0)
            {
                break;
            }

            HANDLE pipe = CreateNamedPipeW(
                pipeName,
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                64 * 1024,
                64 * 1024,
                0,
                nullptr);

            if (pipe == INVALID_HANDLE_VALUE)
            {
                Sleep(1000);
                continue;
            }

            if (!ConnectNamedPipe(pipe, nullptr))
            {
                CloseHandle(pipe);
                if (g_agentStop != 0)
                {
                    break;
                }
                Sleep(500);
                continue;
            }

            std::vector<wchar_t> buffer(64 * 1024, 0);
            DWORD read = 0;
            if (ReadFile(pipe, buffer.data(), static_cast<DWORD>((buffer.size() - 1) * sizeof(wchar_t)), &read, nullptr) && read > 0)
            {
                wprintf(L"[agent] %s\n", buffer.data());
            }

            FlushFileBuffers(pipe);
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
        return 0;
    }
}

bool StartAgentServer()
{
    if (g_agentThread)
    {
        return true;
    }

    InterlockedExchange(&g_agentStop, 0);
    g_agentThread = CreateThread(nullptr, 0, AgentServerThread, nullptr, 0, nullptr);
    return g_agentThread != nullptr;
}

void StopAgentServer()
{
    InterlockedExchange(&g_agentStop, 1);

    if (g_agentThread)
    {
        CancelSynchronousIo(g_agentThread);
        WaitForSingleObject(g_agentThread, 3000);
        CloseHandle(g_agentThread);
        g_agentThread = nullptr;
    }
}
