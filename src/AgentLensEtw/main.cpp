#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <evntrace.h>
#include <evntprov.h>
#include <evntcons.h>
#include <tdh.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "AgentLensProtocol/agl_event.h"

namespace {

struct DnsBinding
{
    unsigned long ProcessId;
    std::wstring QueryName;
    std::vector<std::wstring> Addresses;
    unsigned long long Timestamp;
};

std::map<std::pair<unsigned long, std::wstring>, DnsBinding> g_dnsBindings;

bool FindProperty(
    PTRACE_EVENT_INFO info,
    const wchar_t* name,
    unsigned short* outIndex,
    PEVENT_PROPERTY_INFO* outProperty)
{
    if (!info || !name)
    {
        return false;
    }

    for (ULONG i = 0; i < info->TopLevelPropertyCount; i++)
    {
        const EVENT_PROPERTY_INFO& property = info->EventPropertyInfoArray[i];
        const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const BYTE*>(info) + property.NameOffset);

        if (propertyName && _wcsicmp(propertyName, name) == 0)
        {
            if (outIndex)
            {
                *outIndex = static_cast<unsigned short>(i);
            }
            if (outProperty)
            {
                *outProperty = const_cast<PEVENT_PROPERTY_INFO>(&info->EventPropertyInfoArray[i]);
            }
            return true;
        }
    }

    return false;
}

bool GetPropertyRaw(
    PEVENT_RECORD eventRecord,
    const wchar_t* name,
    std::vector<BYTE>& raw,
    PEVENT_PROPERTY_INFO* outProperty)
{
    ULONG bufferSize = 0;
    PTRACE_EVENT_INFO info = nullptr;
    ULONG status = TdhGetEventInformation(eventRecord, 0, nullptr, nullptr, &bufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0)
    {
        return false;
    }

    info = static_cast<PTRACE_EVENT_INFO>(malloc(bufferSize));
    if (!info)
    {
        return false;
    }

    status = TdhGetEventInformation(eventRecord, 0, nullptr, info, &bufferSize);
    if (status != ERROR_SUCCESS)
    {
        free(info);
        return false;
    }

    PEVENT_PROPERTY_INFO property = nullptr;
    if (!FindProperty(info, name, nullptr, &property))
    {
        free(info);
        return false;
    }

    const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(
        reinterpret_cast<const BYTE*>(info) + property->NameOffset);
    PROPERTY_DATA_DESCRIPTOR descriptor = {};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
    descriptor.ArrayIndex = 0;

    ULONG propertySize = 0;
    status = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &descriptor, &propertySize);
    if (status != ERROR_SUCCESS || propertySize == 0)
    {
        free(info);
        return false;
    }

    raw.resize(propertySize);
    status = TdhGetProperty(eventRecord, 0, nullptr, 1, &descriptor, propertySize, raw.data());
    if (status != ERROR_SUCCESS)
    {
        raw.clear();
        free(info);
        return false;
    }

    if (outProperty)
    {
        *outProperty = property;
    }

    // The property descriptor and returned buffer are self-contained. The
    // TRACE_EVENT_INFO allocation is only needed while extracting property
    // data, so it can be released before returning.
    free(info);
    return true;
}

bool GetPropertyString(
    PEVENT_RECORD eventRecord,
    const wchar_t* name,
    std::wstring& value)
{
    std::vector<BYTE> raw;
    if (!GetPropertyRaw(eventRecord, name, raw, nullptr) || raw.empty())
    {
        return false;
    }

    value.assign(reinterpret_cast<const wchar_t*>(raw.data()),
                 raw.size() / sizeof(wchar_t));
    while (!value.empty() && value.back() == L'\0')
    {
        value.pop_back();
    }
    return !value.empty();
}

bool FormatPropertyText(
    PEVENT_RECORD eventRecord,
    const wchar_t* name,
    std::wstring& value)
{
    ULONG infoSize = 0;
    ULONG status = TdhGetEventInformation(eventRecord, 0, nullptr, nullptr, &infoSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || infoSize == 0)
    {
        return false;
    }

    PTRACE_EVENT_INFO info = static_cast<PTRACE_EVENT_INFO>(malloc(infoSize));
    if (!info)
    {
        return false;
    }

    status = TdhGetEventInformation(eventRecord, 0, nullptr, info, &infoSize);
    if (status != ERROR_SUCCESS)
    {
        free(info);
        return false;
    }

    PEVENT_PROPERTY_INFO property = nullptr;
    if (!FindProperty(info, name, nullptr, &property))
    {
        free(info);
        return false;
    }

    const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(
        reinterpret_cast<const BYTE*>(info) + property->NameOffset);
    PROPERTY_DATA_DESCRIPTOR descriptor = {};
    descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
    descriptor.ArrayIndex = 0;

    ULONG propertySize = 0;
    status = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &descriptor, &propertySize);
    if (status != ERROR_SUCCESS || propertySize == 0)
    {
        free(info);
        return false;
    }

    std::vector<BYTE> raw(propertySize);
    status = TdhGetProperty(eventRecord, 0, nullptr, 1, &descriptor, propertySize, raw.data());
    if (status != ERROR_SUCCESS)
    {
        free(info);
        return false;
    }

    if (!(property->Flags & PropertyStruct))
    {
        value.assign(reinterpret_cast<const wchar_t*>(raw.data()),
                     raw.size() / sizeof(wchar_t));
        while (!value.empty() && value.back() == L'\0')
        {
            value.pop_back();
        }
        free(info);
        return !value.empty();
    }

    ULONG bufferSize = 0;
    USHORT consumed = 0;
    USHORT propertyLength = property->length;
    if (propertyLength == 0)
    {
        propertyLength = static_cast<USHORT>(raw.size());
    }

    ULONG formatStatus = TdhFormatProperty(
        info,
        nullptr,
        sizeof(void*),
        property->nonStructType.InType,
        property->nonStructType.OutType,
        propertyLength,
        static_cast<USHORT>(raw.size()),
        raw.data(),
        &bufferSize,
        nullptr,
        &consumed);

    if (formatStatus != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0)
    {
        free(info);
        return false;
    }

    value.resize(bufferSize / sizeof(wchar_t) + 1);
    formatStatus = TdhFormatProperty(
        info,
        nullptr,
        sizeof(void*),
        property->nonStructType.InType,
        property->nonStructType.OutType,
        propertyLength,
        static_cast<USHORT>(raw.size()),
        raw.data(),
        &bufferSize,
        &value[0],
        &consumed);

    if (formatStatus != ERROR_SUCCESS)
    {
        value.clear();
        free(info);
        return false;
    }

    while (!value.empty() && value.back() == L'\0')
    {
        value.pop_back();
    }
    free(info);
    return !value.empty();
}

bool IsIPv4Token(const std::wstring& token, std::wstring& canonical)
{
    IN_ADDR addr = {};
    if (InetPtonW(AF_INET, token.c_str(), &addr) == 1)
    {
        wchar_t buffer[INET_ADDRSTRLEN] = {};
        if (InetNtopW(AF_INET, &addr, buffer, ARRAYSIZE(buffer)))
        {
            canonical = buffer;
            return true;
        }
    }
    return false;
}

std::vector<std::wstring> SplitDnsResults(const std::wstring& text)
{
    std::vector<std::wstring> result;
    std::wstring current;
    std::wstring canonical;

    for (wchar_t ch : text)
    {
        if (ch == L';' || ch == L',' || ch == L' ')
        {
            if (!current.empty() && IsIPv4Token(current, canonical))
            {
                result.push_back(canonical);
            }
            current.clear();
        }
        else
        {
            current.push_back(ch);
        }
    }

    if (!current.empty() && IsIPv4Token(current, canonical))
    {
        result.push_back(canonical);
    }

    return result;
}

void HandleDnsClientEvent(PEVENT_RECORD eventRecord)
{
    const unsigned short eventId = eventRecord->EventHeader.EventDescriptor.Id;
    const unsigned long processId = eventRecord->EventHeader.ProcessId;
    std::wstring queryName;

    if (eventId == 3006 || eventId == 3008 || eventId == 3009 || eventId == 3020)
    {
        if (!GetPropertyString(eventRecord, L"QueryName", queryName))
        {
            return;
        }
    }

    if (eventId == 3008 || eventId == 3020)
    {
        std::wstring queryResults;
        if (!FormatPropertyText(eventRecord, L"QueryResults", queryResults))
        {
            queryResults.clear();
        }

        std::vector<std::wstring> addresses = SplitDnsResults(queryResults);
        if (!addresses.empty())
        {
            DnsBinding binding;
            binding.ProcessId = processId;
            binding.QueryName = queryName;
            binding.Addresses = std::move(addresses);
            binding.Timestamp = eventRecord->EventHeader.TimeStamp.QuadPart;
            g_dnsBindings[std::make_pair(processId, queryName)] = std::move(binding);

            for (const auto& address : g_dnsBindings[std::make_pair(processId, queryName)].Addresses)
            {
                wprintf(L"DNS-MAP pid=%lu query=%ls ip=%ls\n",
                    processId, queryName.c_str(), address.c_str());
            }
        }
    }
    else
    {
        wprintf(L"DNS-QUERY pid=%lu query=%ls\n", processId, queryName.c_str());
    }
}

std::wstring IPv4FromMappedAddress(const unsigned char address[16])
{
    IN_ADDR addr = {};
    addr.S_un.S_un_b.s_b1 = address[12];
    addr.S_un.S_un_b.s_b2 = address[13];
    addr.S_un.S_un_b.s_b3 = address[14];
    addr.S_un.S_un_b.s_b4 = address[15];

    wchar_t buffer[INET_ADDRSTRLEN] = {};
    if (!InetNtopW(AF_INET, &addr, buffer, ARRAYSIZE(buffer)))
    {
        return L"";
    }
    return buffer;
}

std::wstring FindDnsName(unsigned long processId, const std::wstring& ip)
{
    auto findByPid = [&]() -> std::wstring {
        for (const auto& item : g_dnsBindings)
        {
            if (item.first.first != processId)
            {
                continue;
            }
            for (const auto& address : item.second.Addresses)
            {
                if (address == ip)
                {
                    return item.second.QueryName;
                }
            }
        }
        return L"";
    };

    std::wstring name = findByPid();
    if (!name.empty())
    {
        return name;
    }

    for (const auto& item : g_dnsBindings)
    {
        for (const auto& address : item.second.Addresses)
        {
            if (address == ip)
            {
                return item.second.QueryName;
            }
        }
    }

    return L"";
}

void HandleAgentLensEvent(PEVENT_RECORD eventRecord)
{
    if (eventRecord->UserDataLength < sizeof(AGL_EVENT_HEADER))
    {
        return;
    }

    const AGL_EVENT_HEADER* header =
        reinterpret_cast<const AGL_EVENT_HEADER*>(eventRecord->UserData);
    if (header->StructSize < sizeof(*header))
    {
        return;
    }

    if (header->EventType == AGL_EVENT_NETWORK_CONNECT &&
        eventRecord->UserDataLength >= sizeof(AGL_NETWORK_EVENT))
    {
        const AGL_NETWORK_EVENT* network =
            reinterpret_cast<const AGL_NETWORK_EVENT*>(eventRecord->UserData);
        std::wstring ip = IPv4FromMappedAddress(network->RemoteAddress);
        std::wstring dnsName = FindDnsName(
            static_cast<unsigned long>(header->ProcessId), ip);

        wprintf(
            L"NET-CONNECT pid=%llu remote=%ls:%lu dns=%ls\n",
            static_cast<unsigned long long>(header->ProcessId),
            ip.c_str(),
            network->RemotePort,
            dnsName.c_str());
        return;
    }

    wprintf(
        L"ETW type=%u seq=%llu pid=%llu tid=%llu flags=%u payload=%u\n",
        header->EventType,
        static_cast<unsigned long long>(header->Sequence),
        static_cast<unsigned long long>(header->ProcessId),
        static_cast<unsigned long long>(header->ThreadId),
        header->Flags,
        header->PayloadLength);
}

} // namespace

static const GUID AgentLensProviderGuid = {
    0x8b2d1c3e, 0x1234, 0x4a2b,
    { 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50 }
};

static const GUID DnsClientProviderGuid = {
    0x1c95126e, 0x7eea, 0x49a9,
    { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d }
};

static void WINAPI EventRecordCallback(PEVENT_RECORD EventRecord)
{
    if (IsEqualGUID(EventRecord->EventHeader.ProviderId, DnsClientProviderGuid))
    {
        HandleDnsClientEvent(EventRecord);
        return;
    }

    if (IsEqualGUID(EventRecord->EventHeader.ProviderId, AgentLensProviderGuid))
    {
        HandleAgentLensEvent(EventRecord);
        return;
    }

    wprintf(L"ETW event provider=%08x event=%u pid=%u tid=%u\n",
        EventRecord->EventHeader.ProviderId.Data1,
        EventRecord->EventHeader.EventDescriptor.Id,
        EventRecord->EventHeader.ProcessId,
        EventRecord->EventHeader.ThreadId);
}

int wmain()
{
    const wchar_t* sessionName = L"AgentLensEtwSession";
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) +
        (ULONG)(wcslen(sessionName) + 1) * sizeof(wchar_t);
    EVENT_TRACE_PROPERTIES* props = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (!props)
    {
        return 1;
    }

    ZeroMemory(props, bufferSize);
    props->Wnode.BufferSize = bufferSize;
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s((wchar_t*)((BYTE*)props + props->LoggerNameOffset), wcslen(sessionName) + 1, sessionName);

    TRACEHANDLE sessionHandle = 0;
    ULONG status = StartTraceW(&sessionHandle, sessionName, props);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS)
    {
        wprintf(L"StartTrace failed: %u\n", status);
        free(props);
        return 1;
    }

    status = EnableTraceEx2(
        sessionHandle,
        &AgentLensProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        nullptr);
    if (status != ERROR_SUCCESS)
    {
        wprintf(L"EnableTraceEx2 failed: %u\n", status);
        ControlTraceW(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP);
        free(props);
        return 1;
    }

    EnableTraceEx2(
        sessionHandle,
        &DnsClientProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        nullptr);

    EVENT_TRACE_LOGFILEW logFile = { 0 };
    logFile.LoggerName = (LPWSTR)sessionName;
    logFile.ProcessTraceMode = EVENT_TRACE_REAL_TIME_MODE;
    logFile.EventRecordCallback = EventRecordCallback;

    TRACEHANDLE traceHandle = OpenTraceW(&logFile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        wprintf(L"OpenTrace failed\n");
        ControlTraceW(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP);
        free(props);
        return 1;
    }

    wprintf(L"AgentLens ETW consumer running. Press Ctrl+C to stop.\n");
    status = ProcessTrace(&traceHandle, 1, nullptr, nullptr);

    CloseTrace(traceHandle);
    ControlTraceW(sessionHandle, sessionName, props, EVENT_TRACE_CONTROL_STOP);
    free(props);
    return 0;
}
