#pragma once

#include <cstdio>
#include <string>

class Logger
{
public:
    Logger() = default;
    explicit Logger(const std::wstring& path, bool mirrorToConsole = false);
    ~Logger();

    void Info(const std::wstring& message);
    void Error(const std::wstring& message);

private:
    void Write(const wchar_t* level, const std::wstring& message);

    FILE* m_file = nullptr;
    bool m_mirrorToConsole = false;
};
