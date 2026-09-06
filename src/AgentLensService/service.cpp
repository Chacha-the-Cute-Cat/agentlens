#include "service.h"
#include "control_client.h"
#include "event_reader.h"
#include "policy_loader.h"
#include "config.h"
#include "logger.h"
#include "agent_server.h"

#include <windows.h>
#include <vector>

static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS g_status{};

static void UpdateStatus(DWORD state, DWORD exitCode, DWORD waitHint)
{
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted = 0;
    if (state == SERVICE_START_PENDING)
    {
        g_status.dwControlsAccepted = 0;
    }
    if (state == SERVICE_RUNNING)
    {
        g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }
    if (g_statusHandle)
    {
        SetServiceStatus(g_statusHandle, &g_status);
    }
}

static DWORD WINAPI ServiceCtrl(DWORD control, DWORD eventType, LPVOID eventData, LPVOID context)
{
    UNREFERENCED_PARAMETER(eventType);
    UNREFERENCED_PARAMETER(eventData);
    UNREFERENCED_PARAMETER(context);

    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN)
    {
        UpdateStatus(SERVICE_STOPPED, NO_ERROR, 0);
    }
    return NO_ERROR;
}

static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    g_statusHandle = RegisterServiceCtrlHandlerExW(L"AgentLensService", ServiceCtrl, nullptr);
    if (!g_statusHandle)
    {
        return;
    }

    UpdateStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
    Logger logger;
    logger.Info(L"Starting AgentLensService.");
    StartAgentServer();

    ControlClient client;
    if (!client.Open())
    {
        logger.Error(L"Failed to open AgentLens control device.");
        UpdateStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    AGL_VERSION_INFO version{};
    if (client.GetVersion(version))
    {
        logger.Info(L"Connected to AgentLensKernel.");
    }

    client.Subscribe(0, 0);
    EventReader reader(client);
    std::vector<BYTE> buffer;

    UpdateStatus(SERVICE_RUNNING, NO_ERROR, 0);

    for (;;)
    {
        if (!reader.ReadOnce(buffer))
        {
            Sleep(100);
            continue;
        }
        if (!buffer.empty())
        {
            reader.PrintJsonEvents(buffer);
        }
    }
}

int RunService()
{
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(L"AgentLensService"), ServiceMain },
        { nullptr, nullptr }
    };

    if (!StartServiceCtrlDispatcherW(table))
    {
        return static_cast<int>(GetLastError());
    }
    return 0;
}

int RunConsole()
{
    Logger logger;
    logger.Info(L"Running AgentLensService in console mode.");
    StartAgentServer();

    ControlClient client;
    if (!client.Open())
    {
        logger.Error(L"Failed to open AgentLens control device. Is AgentLensKernel loaded?");
        return 1;
    }

    client.Subscribe(0, 0);
    EventReader reader(client);
    std::vector<BYTE> buffer;

    while (true)
    {
        if (!reader.ReadOnce(buffer))
        {
            Sleep(100);
            continue;
        }
        if (!buffer.empty())
        {
            reader.PrintJsonEvents(buffer);
        }
    }
}
