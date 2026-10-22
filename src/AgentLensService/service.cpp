#include "service.h"
#include "control_client.h"
#include "event_reader.h"
#include "dns_associator.h"
#include "policy_loader.h"
#include "config.h"
#include "logger.h"
#include "agent_server.h"

#include <windows.h>
#include <string>
#include <vector>

static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static SERVICE_STATUS g_status{};
static FILE* g_eventOutput = nullptr;
static unsigned long long g_filterPid = 0;
static unsigned long g_filterType = 0;
static bool g_mirrorEventsToConsole = false;
static HANDLE g_stopEvent = nullptr;
static std::wstring g_policyPath;
static bool g_policyPathExplicit = false;

void SetEventOptions(
    FILE* output,
    unsigned long long filterPid,
    unsigned long filterType,
    bool mirrorToConsole)
{
    g_eventOutput = output;
    g_filterPid = filterPid;
    g_filterType = filterType;
    g_mirrorEventsToConsole = mirrorToConsole;
}

void SetPolicyPath(const wchar_t* path)
{
    g_policyPath = path ? path : L"";
    g_policyPathExplicit = !g_policyPath.empty();
}

static void UpdateStatus(DWORD state, DWORD exitCode, DWORD waitHint)
{
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exitCode;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwWaitHint = waitHint;
    g_status.dwControlsAccepted = 0;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
    {
        g_status.dwCheckPoint++;
    }
    else
    {
        g_status.dwCheckPoint = 0;
    }
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
        UpdateStatus(SERVICE_STOP_PENDING, NO_ERROR, 10000);
        if (g_stopEvent)
        {
            SetEvent(g_stopEvent);
        }
    }
    return NO_ERROR;
}

static BOOL WINAPI ConsoleCtrlHandler(DWORD control)
{
    if (control == CTRL_C_EVENT ||
        control == CTRL_BREAK_EVENT ||
        control == CTRL_CLOSE_EVENT)
    {
        if (g_stopEvent)
        {
            SetEvent(g_stopEvent);
        }
        return TRUE;
    }
    return FALSE;
}

static bool CreateStopEvent()
{
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    return g_stopEvent != nullptr;
}

static void RunEventLoop(
    ControlClient& client,
    EventReader& reader,
    DnsAssociator& dns,
    Logger& logger)
{
    std::vector<BYTE> buffer;
    ULONGLONG nextReconnect = 0;
    bool reconnectLogged = false;

    while (WaitForSingleObject(g_stopEvent, 0) != WAIT_OBJECT_0)
    {
        if (!reader.ReadOnce(buffer))
        {
            DWORD error = client.LastError();
            if (error != ERROR_NO_MORE_ITEMS && error != ERROR_SUCCESS)
            {
                if (!reconnectLogged)
                {
                    logger.Error(
                        L"Event read failed with error " +
                        std::to_wstring(error) +
                        L"; waiting for AgentLensKernel.");
                    reconnectLogged = true;
                }

                ULONGLONG now = GetTickCount64();
                if (now >= nextReconnect)
                {
                    client.Close();
                    if (client.Open())
                    {
                        AGL_VERSION_INFO version{};
                        if (client.GetVersion(version) && client.Subscribe(0, 0))
                        {
                            logger.Info(L"Reconnected to AgentLensKernel.");
                            reconnectLogged = false;
                        }
                        else
                        {
                            client.Close();
                        }
                    }
                    nextReconnect = now + 1000;
                }
            }
            WaitForSingleObject(g_stopEvent, 100);
            continue;
        }
        reconnectLogged = false;
        if (!buffer.empty())
        {
            reader.PrintJsonEvents(
                buffer,
                g_eventOutput,
                g_filterPid,
                g_filterType,
                &dns,
                g_mirrorEventsToConsole);
        }
    }

    client.Unsubscribe();
    dns.Stop();
    StopAgentServer();
}

static bool ApplyPolicy(ControlClient& client, Logger& logger)
{
    AgentLensConfig config = LoadConfig();
    std::wstring policyPath = g_policyPath.empty() ? config.PolicyPath : g_policyPath;
    std::vector<uint8_t> policy;

    if (policyPath.empty())
    {
        return true;
    }

    if (!LoadPolicyFile(policyPath.c_str(), policy))
    {
        if (!g_policyPathExplicit)
        {
            return true;
        }
        logger.Error(L"Failed to read policy file: " + policyPath);
        return false;
    }

    if (!client.LoadPolicy(policy.data(), static_cast<ULONG>(policy.size())))
    {
        logger.Error(L"Failed to apply policy: " + policyPath);
        return false;
    }

    logger.Info(L"Loaded policy: " + policyPath);
    return true;
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
    Logger logger(GetDefaultServiceLogPath());
    logger.Info(L"Starting AgentLensService.");

    if (!CreateStopEvent())
    {
        logger.Error(L"Failed to create the service stop event.");
        UpdateStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }
    if (!StartAgentServer())
    {
        logger.Error(L"Failed to start the AgentLensAgent named-pipe server.");
    }

    ControlClient client;
    if (!client.Open())
    {
        logger.Error(L"Failed to open AgentLens control device.");
        StopAgentServer();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        UpdateStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    AGL_VERSION_INFO version{};
    if (!client.GetVersion(version))
    {
        logger.Error(
            L"Failed to query AgentLensKernel version. Win32 error: " +
            std::to_wstring(client.LastError()));
        StopAgentServer();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        UpdateStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }
    logger.Info(L"Connected to AgentLensKernel.");

    if (!ApplyPolicy(client, logger))
    {
        StopAgentServer();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        UpdateStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }

    if (!client.Subscribe(0, 0))
    {
        logger.Error(
            L"Failed to subscribe to AgentLensKernel events. Win32 error: " +
            std::to_wstring(client.LastError()));
        StopAgentServer();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        UpdateStatus(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 0);
        return;
    }
    EventReader reader(client);
    DnsAssociator dns;
    if (!dns.Start())
    {
        logger.Error(L"Failed to start DNS event association; network IP events remain available.");
    }

    UpdateStatus(SERVICE_RUNNING, NO_ERROR, 0);

    RunEventLoop(client, reader, dns, logger);

    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    UpdateStatus(SERVICE_STOPPED, NO_ERROR, 0);
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
    Logger logger(GetDefaultServiceLogPath(), true);
    logger.Info(L"Running AgentLensService in console mode.");

    if (!CreateStopEvent())
    {
        logger.Error(L"Failed to create the console stop event.");
        return 1;
    }
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    if (!StartAgentServer())
    {
        logger.Error(L"Failed to start the AgentLensAgent named-pipe server.");
    }

    ControlClient client;
    if (!client.Open())
    {
        logger.Error(L"Failed to open AgentLens control device. Is AgentLensKernel loaded?");
        StopAgentServer();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return 1;
    }

    if (!ApplyPolicy(client, logger))
    {
        StopAgentServer();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
        return 1;
    }

    AGL_VERSION_INFO version{};
    if (!client.GetVersion(version))
    {
        logger.Error(
            L"Failed to query AgentLensKernel version. Win32 error: " +
            std::to_wstring(client.LastError()));
        StopAgentServer();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return 1;
    }
    if (!client.Subscribe(0, 0))
    {
        logger.Error(
            L"Failed to subscribe to AgentLensKernel events. Win32 error: " +
            std::to_wstring(client.LastError()));
        StopAgentServer();
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return 1;
    }
    EventReader reader(client);
    DnsAssociator dns;
    if (!dns.Start())
    {
        logger.Error(L"Failed to start DNS event association; network IP events remain available.");
    }

    RunEventLoop(client, reader, dns, logger);

    SetConsoleCtrlHandler(ConsoleCtrlHandler, FALSE);
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    return 0;
}
