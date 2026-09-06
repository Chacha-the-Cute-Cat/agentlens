#include "policy_loader.h"
#include "AgentLensProtocol/agl_policy.h"

#include <windows.h>
#include <cstdio>
#include <cstring>

bool LoadPolicyFile(const wchar_t* path, std::vector<uint8_t>& policy)
{
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f)
    {
        return false;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0)
    {
        fclose(f);
        return false;
    }

    policy.resize(size);
    size_t read = fread(policy.data(), 1, size, f);
    fclose(f);
    policy.resize(read);
    return read > 0;
}
