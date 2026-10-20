#include "policy_compiler.h"

#include "AgentLensProtocol/agl_policy.h"
#include "AgentLensProtocol/agl_event.h"

#include <windows.h>
#include <fstream>
#include <sstream>
#include <cwctype>
#include <algorithm>

namespace
{
    std::wstring Trim(const std::wstring& s)
    {
        size_t first = 0;
        while (first < s.size() && std::iswspace(s[first]))
        {
            first++;
        }
        size_t last = s.size();
        while (last > first && std::iswspace(s[last - 1]))
        {
            last--;
        }
        return s.substr(first, last - first);
    }

    bool ParseEventType(const std::wstring& text, ULONG& eventType)
    {
        struct Entry
        {
            const wchar_t* name;
            ULONG value;
        };

        static const Entry entries[] = {
            { L"file.open", AGL_EVENT_FILE_OPEN },
            { L"file.create", AGL_EVENT_FILE_OPEN },
            { L"file.rename", AGL_EVENT_FILE_RENAME },
            { L"file.read", AGL_EVENT_FILE_READ },
            { L"file.write", AGL_EVENT_FILE_WRITE },
            { L"file.delete", AGL_EVENT_FILE_DELETE },
            { L"file.close", AGL_EVENT_FILE_CLOSE },
            { L"registry.open", AGL_EVENT_REGISTRY_OPEN },
            { L"registry.set", AGL_EVENT_REGISTRY_SET_VALUE },
            { L"registry.delete_key", AGL_EVENT_REGISTRY_DELETE_KEY },
            { L"registry.delete_value", AGL_EVENT_REGISTRY_DELETE_VALUE },
            { L"process.create", AGL_EVENT_PROCESS_CREATE },
            { L"process.exit", AGL_EVENT_PROCESS_EXIT },
            { L"thread.create", AGL_EVENT_THREAD_CREATE },
            { L"thread.exit", AGL_EVENT_THREAD_EXIT },
            { L"image.load", AGL_EVENT_IMAGE_LOAD },
            { L"object.handle", AGL_EVENT_OBJECT_HANDLE },
            { L"network.connect", AGL_EVENT_NETWORK_CONNECT },
        };

        for (const auto& entry : entries)
        {
            if (_wcsicmp(text.c_str(), entry.name) == 0)
            {
                eventType = entry.value;
                return true;
            }
        }
        return false;
    }

    bool NormalizeKernelPath(std::wstring& value, std::wstring& error, int lineNumber)
    {
        if (value.size() < 3 ||
            !std::iswalpha(value[0]) ||
            value[1] != L':' ||
            (value[2] != L'\\' && value[2] != L'/'))
        {
            return true;
        }

        wchar_t drive[3] = { value[0], L':', L'\0' };
        wchar_t device[1024] = { 0 };
        if (QueryDosDeviceW(drive, device, ARRAYSIZE(device)) == 0)
        {
            error = L"Line " + std::to_wstring(lineNumber) +
                L": cannot resolve drive " + std::wstring(drive) + L".";
            return false;
        }

        value = std::wstring(device) + L"\\" + value.substr(3);
        for (wchar_t& ch : value)
        {
            if (ch == L'/')
            {
                ch = L'\\';
            }
        }
        return true;
    }
}

bool CompileTextPolicy(const wchar_t* path, std::vector<uint8_t>& binaryPolicy, std::wstring& error)
{
    std::wifstream file(path);
    if (!file)
    {
        error = L"Failed to open policy file.";
        return false;
    }

    std::wstring modeText = L"observe";
    struct Rule
    {
        ULONG eventType = 0;
        ULONG action = 0;
        ULONG ruleSet = 0;
        ULONG priority = 0;
        ULONG accessMask = 0;
        ULONG imageHash = 0;
        ULONG userSidHash = 0;
        ULONG rootProcessHash = 0;
        std::wstring path;
        std::wstring process;
        std::wstring commandLine;
    };

    std::vector<Rule> rules;
    Rule* current = nullptr;
    int lineNumber = 0;
    std::wstring line;

    while (std::getline(file, line))
    {
        lineNumber++;
        std::wstring trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == L'#')
        {
            continue;
        }

        if (trimmed.find(L"mode") == 0)
        {
            size_t eq = trimmed.find(L'=');
            if (eq == std::wstring::npos)
            {
                error = L"Line " + std::to_wstring(lineNumber) + L": expected '='.";
                return false;
            }
            modeText = Trim(trimmed.substr(eq + 1));
            continue;
        }

        if (trimmed.find(L"deny ") == 0)
        {
            Rule rule;
            rule.action = 1;
            if (!ParseEventType(Trim(trimmed.substr(5)), rule.eventType))
            {
                error = L"Line " + std::to_wstring(lineNumber) + L": unknown event type.";
                return false;
            }
            rules.push_back(rule);
            current = &rules.back();
            continue;
        }

        if (trimmed.find(L"log ") == 0)
        {
            Rule rule;
            rule.action = 2;
            if (!ParseEventType(Trim(trimmed.substr(4)), rule.eventType))
            {
                error = L"Line " + std::to_wstring(lineNumber) + L": unknown event type.";
                return false;
            }
            rules.push_back(rule);
            current = &rules.back();
            continue;
        }

        if (trimmed.find(L"allow ") == 0)
        {
            Rule rule;
            rule.action = 0;
            if (!ParseEventType(Trim(trimmed.substr(6)), rule.eventType))
            {
                error = L"Line " + std::to_wstring(lineNumber) + L": unknown event type.";
                return false;
            }
            rules.push_back(rule);
            current = &rules.back();
            continue;
        }

        if (current)
        {
            size_t eq = trimmed.find(L'=');
            if (eq != std::wstring::npos)
            {
                std::wstring key = Trim(trimmed.substr(0, eq));
                std::wstring value = Trim(trimmed.substr(eq + 1));
                if ((key == L"path" || key == L"process" || key == L"command") &&
                    value.find_first_of(L"*?") != std::wstring::npos)
                {
                    error = L"Line " + std::to_wstring(lineNumber) +
                        L": wildcards are not supported; use a literal prefix.";
                    return false;
                }
                if ((key == L"path" || key == L"process") &&
                    !NormalizeKernelPath(value, error, lineNumber))
                {
                    return false;
                }
                if (key == L"path")
                {
                    current->path = value;
                }
                else if (key == L"process")
                {
                    current->process = value;
                }
                else if (key == L"priority")
                {
                    current->priority = static_cast<ULONG>(_wtoi(value.c_str()));
                }
                else if (key == L"ruleset")
                {
                    current->ruleSet = static_cast<ULONG>(_wtoi(value.c_str()));
                }
                else if (key == L"access")
                {
                    current->accessMask = static_cast<ULONG>(wcstoul(value.c_str(), nullptr, 0));
                }
                else if (key == L"imagehash")
                {
                    current->imageHash = static_cast<ULONG>(wcstoul(value.c_str(), nullptr, 0));
                }
                else if (key == L"sidhash")
                {
                    current->userSidHash = static_cast<ULONG>(wcstoul(value.c_str(), nullptr, 0));
                }
                else if (key == L"roothash")
                {
                    current->rootProcessHash = static_cast<ULONG>(wcstoul(value.c_str(), nullptr, 0));
                }
                else if (key == L"command")
                {
                    current->commandLine = value;
                }
                else
                {
                    error = L"Line " + std::to_wstring(lineNumber) + L": unknown attribute '" + key + L"'.";
                    return false;
                }
                continue;
            }
        }

        error = L"Line " + std::to_wstring(lineNumber) + L": invalid syntax.";
        return false;
    }

    ULONG payloadLength = 0;
    for (const auto& rule : rules)
    {
        payloadLength += static_cast<ULONG>(
            sizeof(AGL_POLICY_RULE) +
            rule.path.size() * sizeof(wchar_t) +
            rule.process.size() * sizeof(wchar_t) +
            rule.commandLine.size() * sizeof(wchar_t));
    }

    binaryPolicy.resize(sizeof(AGL_POLICY_HEADER) + payloadLength);
    auto* header = reinterpret_cast<AGL_POLICY_HEADER*>(binaryPolicy.data());
    header->StructSize = sizeof(AGL_POLICY_HEADER);
    header->Version = AGL_PROTOCOL_VERSION;
    header->Mode = (modeText == L"control") ? AGL_POLICY_MODE_CONTROL : AGL_POLICY_MODE_OBSERVE;
    header->RuleCount = static_cast<ULONG>(rules.size());
    header->PayloadLength = payloadLength;

    uint8_t* cursor = binaryPolicy.data() + sizeof(AGL_POLICY_HEADER);
    for (const auto& rule : rules)
    {
        ULONG pathBytes = static_cast<ULONG>(rule.path.size() * sizeof(wchar_t));
        ULONG processBytes = static_cast<ULONG>(rule.process.size() * sizeof(wchar_t));
        ULONG commandBytes = static_cast<ULONG>(rule.commandLine.size() * sizeof(wchar_t));
        auto* out = reinterpret_cast<AGL_POLICY_RULE*>(cursor);
        out->EventType = rule.eventType;
        out->Action = rule.action;
        out->RuleSet = rule.ruleSet;
        out->Priority = rule.priority;
        out->AccessMask = rule.accessMask;
        out->ImageHash = rule.imageHash;
        out->UserSidHash = rule.userSidHash;
        out->RootProcessHash = rule.rootProcessHash;
        out->PathLength = pathBytes;
        out->ProcessLength = processBytes;
        out->CommandLineLength = commandBytes;
        if (pathBytes)
        {
            memcpy(out->Data, rule.path.c_str(), pathBytes);
        }
        if (processBytes)
        {
            memcpy(out->Data + pathBytes / sizeof(wchar_t), rule.process.c_str(), processBytes);
        }
        if (commandBytes)
        {
            memcpy(out->Data + (pathBytes + processBytes) / sizeof(wchar_t), rule.commandLine.c_str(), commandBytes);
        }
        cursor += sizeof(AGL_POLICY_RULE) + pathBytes + processBytes + commandBytes;
    }

    return true;
}
