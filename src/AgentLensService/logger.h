#pragma once

#include <string>

class Logger
{
public:
    void Info(const std::wstring& message);
    void Error(const std::wstring& message);
};
