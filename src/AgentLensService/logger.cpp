#include "logger.h"

#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <share.h>

Logger::Logger(const std::wstring& path, bool mirrorToConsole)
    : m_mirrorToConsole(mirrorToConsole)
{
    if (!path.empty())
    {
        m_file = _wfsopen(path.c_str(), L"a, ccs=UTF-8", _SH_DENYNO);
    }
}

Logger::~Logger()
{
    if (m_file)
    {
        fclose(m_file);
        m_file = nullptr;
    }
}

void Logger::Write(const wchar_t* level, const std::wstring& message)
{
    FILE* console = wcscmp(level, L"[ERROR]") == 0 ? stderr : stdout;

    if (m_file)
    {
        fwprintf(m_file, L"[AgentLensService]%s %s\n", level, message.c_str());
        fflush(m_file);
    }

    if (!m_file || m_mirrorToConsole)
    {
        fwprintf(console, L"[AgentLensService]%s %s\n", level, message.c_str());
        fflush(console);
    }

    std::wstring debug = L"AgentLensService" + std::wstring(level) + L" " + message + L"\n";
    OutputDebugStringW(debug.c_str());
}

void Logger::Info(const std::wstring& message)
{
    Write(L"[INFO]", message);
}

void Logger::Error(const std::wstring& message)
{
    Write(L"[ERROR]", message);
}
