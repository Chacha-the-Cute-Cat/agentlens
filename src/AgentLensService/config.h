#pragma once

#include <string>

struct AgentLensConfig
{
    std::wstring ServiceName = L"AgentLensService";
    std::wstring DisplayName = L"AgentLens Kernel Service";
    std::wstring PolicyPath = L"AgentLens.policy";
};

AgentLensConfig LoadConfig();
