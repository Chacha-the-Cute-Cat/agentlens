#include "service.h"

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

static int ReplayEvents(const wchar_t* path, FILE* output)
{
    std::wifstream file(path);
    if (!file)
    {
        fwprintf(stderr, L"Failed to open replay file: %s\n", path);
        return 1;
    }

    std::wstring line;
    while (std::getline(file, line))
    {
        if (output)
        {
            fwprintf(output, L"%s\n", line.c_str());
        }
        else
        {
            wprintf(L"%s\n", line.c_str());
        }
    }
    return 0;
}

int wmain(int argc, wchar_t* argv[])
{
    bool console = false;
    FILE* output = nullptr;
    unsigned long long filterPid = 0;
    unsigned long filterType = 0;
    const wchar_t* replayPath = nullptr;

    for (int i = 1; i < argc; i++)
    {
        if (lstrcmpiW(argv[i], L"--console") == 0)
        {
            console = true;
        }
        else if (lstrcmpiW(argv[i], L"--output") == 0 && i + 1 < argc)
        {
            _wfopen_s(&output, argv[++i], L"w, ccs=UTF-8");
        }
        else if (lstrcmpiW(argv[i], L"--filter-pid") == 0 && i + 1 < argc)
        {
            filterPid = _wcstoui64(argv[++i], nullptr, 0);
        }
        else if (lstrcmpiW(argv[i], L"--filter-type") == 0 && i + 1 < argc)
        {
            filterType = _wtoi(argv[++i]);
        }
        else if (lstrcmpiW(argv[i], L"--replay") == 0 && i + 1 < argc)
        {
            replayPath = argv[++i];
        }
        else if (lstrcmpiW(argv[i], L"--policy") == 0 && i + 1 < argc)
        {
            SetPolicyPath(argv[++i]);
        }
    }

    if (replayPath)
    {
        int rc = ReplayEvents(replayPath, output);
        if (output) fclose(output);
        return rc;
    }

    SetEventOptions(output, filterPid, filterType);
    int rc = console ? RunConsole() : RunService();
    if (output)
    {
        fclose(output);
    }
    return rc;
}
