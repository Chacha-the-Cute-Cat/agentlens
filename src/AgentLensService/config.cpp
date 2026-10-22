#include "config.h"

#include <windows.h>
#include <filesystem>

AgentLensConfig LoadConfig()
{
    return AgentLensConfig{};
}

std::wstring GetAgentLensDataDirectory()
{
    wchar_t programData[MAX_PATH] = {};
    DWORD length = GetEnvironmentVariableW(
        L"ProgramData",
        programData,
        ARRAYSIZE(programData));
    std::filesystem::path directory =
        length > 0 && length < ARRAYSIZE(programData)
            ? std::filesystem::path(programData)
            : std::filesystem::path(L"C:\\ProgramData");
    directory /= L"AgentLens";

    std::error_code error;
    std::filesystem::create_directories(directory, error);
    return directory.wstring();
}

std::wstring GetDefaultEventLogPath()
{
    return (std::filesystem::path(GetAgentLensDataDirectory()) / L"events.jsonl").wstring();
}

std::wstring GetDefaultServiceLogPath()
{
    return (std::filesystem::path(GetAgentLensDataDirectory()) / L"service.log").wstring();
}
