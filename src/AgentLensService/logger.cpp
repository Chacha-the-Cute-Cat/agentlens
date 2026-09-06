#include "logger.h"

#include <windows.h>
#include <cwchar>

void Logger::Info(const std::wstring& message)
{
    wprintf(L"[AgentLensService] %s\n", message.c_str());
}

void Logger::Error(const std::wstring& message)
{
    fwprintf(stderr, L"[AgentLensService][ERROR] %s\n", message.c_str());
}
