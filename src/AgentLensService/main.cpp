#include "service.h"

#include <windows.h>

int wmain(int argc, wchar_t* argv[])
{
    bool console = false;
    for (int i = 1; i < argc; i++)
    {
        if (lstrcmpiW(argv[i], L"--console") == 0)
        {
            console = true;
        }
    }

    return console ? RunConsole() : RunService();
}
