#include "dns_associator.h"

#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <algorithm>
#include <cwctype>
#include <cstdlib>

namespace
{
    const GUID DnsClientProviderGuid = {
        0x1c95126e, 0x7eea, 0x49a9,
        { 0xa3, 0xfe, 0xa3, 0x78, 0xb0, 0x3d, 0xdb, 0x4d }
    };

    DnsAssociator* g_associator = nullptr;

    bool FindProperty(PTRACE_EVENT_INFO info, const wchar_t* name, PEVENT_PROPERTY_INFO* outProperty)
    {
        if (!info || !name)
        {
            return false;
        }

        for (ULONG i = 0; i < info->TopLevelPropertyCount; i++)
        {
            const auto& property = info->EventPropertyInfoArray[i];
            const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(
                reinterpret_cast<const BYTE*>(info) + property.NameOffset);
            if (propertyName && _wcsicmp(propertyName, name) == 0)
            {
                if (outProperty)
                {
                    *outProperty = const_cast<PEVENT_PROPERTY_INFO>(&info->EventPropertyInfoArray[i]);
                }
                return true;
            }
        }
        return false;
    }

    bool GetPropertyString(PEVENT_RECORD eventRecord, const wchar_t* name, std::wstring& value)
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
        if (!FindProperty(info, name, &property))
        {
            free(info);
            return false;
        }

        const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const BYTE*>(info) + property->NameOffset);
        PROPERTY_DATA_DESCRIPTOR descriptor = {};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);

        ULONG propertySize = 0;
        status = TdhGetPropertySize(eventRecord, 0, nullptr, 1, &descriptor, &propertySize);
        if (status != ERROR_SUCCESS || propertySize == 0)
        {
            free(info);
            return false;
        }

        std::vector<BYTE> raw(propertySize);
        status = TdhGetProperty(eventRecord, 0, nullptr, 1, &descriptor, propertySize, raw.data());
        free(info);
        if (status != ERROR_SUCCESS)
        {
            return false;
        }

        value.assign(reinterpret_cast<const wchar_t*>(raw.data()), raw.size() / sizeof(wchar_t));
        while (!value.empty() && value.back() == L'\0')
        {
            value.pop_back();
        }
        return !value.empty();
    }

    bool FormatPropertyText(PEVENT_RECORD eventRecord, const wchar_t* name, std::wstring& value)
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
        if (!FindProperty(info, name, &property))
        {
            free(info);
            return false;
        }

        const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const BYTE*>(info) + property->NameOffset);
        PROPERTY_DATA_DESCRIPTOR descriptor = {};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);

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
            value.assign(reinterpret_cast<const wchar_t*>(raw.data()), raw.size() / sizeof(wchar_t));
            while (!value.empty() && value.back() == L'\0')
            {
                value.pop_back();
            }
            free(info);
            return !value.empty();
        }

        ULONG bufferSize = 0;
        USHORT consumed = 0;
        USHORT propertyLength = property->length ? property->length : static_cast<USHORT>(raw.size());
        status = TdhFormatProperty(
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

        if (status != ERROR_INSUFFICIENT_BUFFER || bufferSize == 0)
        {
            free(info);
            return false;
        }

        value.resize(bufferSize / sizeof(wchar_t) + 1);
        status = TdhFormatProperty(
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

        free(info);
        if (status != ERROR_SUCCESS)
        {
            value.clear();
            return false;
        }

        while (!value.empty() && value.back() == L'\0')
        {
            value.pop_back();
        }
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
}

DnsAssociator::DnsAssociator()
    : m_sessionName(L"AgentLensServiceDns")
{
}

DnsAssociator::~DnsAssociator()
{
    Stop();
}

bool DnsAssociator::Start()
{
    if (InterlockedCompareExchange(&m_running, 1, 0) != 0)
    {
        return true;
    }

    if (!OpenTraceSession())
    {
        InterlockedExchange(&m_running, 0);
        return false;
    }

    g_associator = this;
    m_thread = CreateThread(nullptr, 0, TraceThreadProc, this, 0, nullptr);
    if (!m_thread)
    {
        CloseTrace(m_traceHandle);
        m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
        ControlTraceW(m_sessionHandle, m_sessionName.c_str(), nullptr, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = 0;
        g_associator = nullptr;
        InterlockedExchange(&m_running, 0);
        return false;
    }

    return true;
}

void DnsAssociator::Stop()
{
    if (InterlockedCompareExchange(&m_running, 0, 1) != 1)
    {
        return;
    }

    if (m_sessionHandle)
    {
        ControlTraceW(m_sessionHandle, m_sessionName.c_str(), nullptr, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = 0;
    }

    if (m_thread)
    {
        WaitForSingleObject(m_thread, 3000);
        CloseHandle(m_thread);
        m_thread = nullptr;
    }

    if (m_traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        CloseTrace(m_traceHandle);
        m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    g_associator = nullptr;
}

bool DnsAssociator::Running() const
{
    return m_running != 0;
}

bool DnsAssociator::OpenTraceSession()
{
    const size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) +
        (m_sessionName.size() + 1) * sizeof(wchar_t);
    EVENT_TRACE_PROPERTIES* props = static_cast<EVENT_TRACE_PROPERTIES*>(malloc(bufferSize));
    if (!props)
    {
        return false;
    }

    ZeroMemory(props, bufferSize);
    props->Wnode.BufferSize = static_cast<ULONG>(bufferSize);
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy_s(
        reinterpret_cast<wchar_t*>(reinterpret_cast<BYTE*>(props) + props->LoggerNameOffset),
        m_sessionName.size() + 1,
        m_sessionName.c_str());

    ULONG status = StartTraceW(&m_sessionHandle, m_sessionName.c_str(), props);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS)
    {
        free(props);
        return false;
    }

    status = EnableTraceEx2(
        m_sessionHandle,
        &DnsClientProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        nullptr);
    if (status != ERROR_SUCCESS)
    {
        ControlTraceW(m_sessionHandle, m_sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = 0;
        free(props);
        return false;
    }

    EVENT_TRACE_LOGFILEW logFile = {};
    logFile.LoggerName = const_cast<LPWSTR>(m_sessionName.c_str());
    logFile.ProcessTraceMode = EVENT_TRACE_REAL_TIME_MODE;
    logFile.EventRecordCallback = EventRecordCallback;

    m_traceHandle = OpenTraceW(&logFile);
    if (m_traceHandle == INVALID_PROCESSTRACE_HANDLE)
    {
        ControlTraceW(m_sessionHandle, m_sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
        m_sessionHandle = 0;
        free(props);
        return false;
    }

    free(props);
    return true;
}

void WINAPI DnsAssociator::EventRecordCallback(PEVENT_RECORD eventRecord)
{
    if (g_associator &&
        IsEqualGUID(eventRecord->EventHeader.ProviderId, DnsClientProviderGuid))
    {
        g_associator->ParseDnsEvent(eventRecord);
    }
}

DWORD WINAPI DnsAssociator::TraceThreadProc(LPVOID parameter)
{
    auto* associator = static_cast<DnsAssociator*>(parameter);
    if (associator && associator->m_traceHandle != INVALID_PROCESSTRACE_HANDLE)
    {
        ProcessTrace(&associator->m_traceHandle, 1, nullptr, nullptr);
    }
    return 0;
}

bool DnsAssociator::ParseDnsEvent(PEVENT_RECORD eventRecord)
{
    const unsigned short eventId = eventRecord->EventHeader.EventDescriptor.Id;
    if (eventId != 3006 && eventId != 3008 && eventId != 3009 && eventId != 3020)
    {
        return false;
    }

    std::wstring queryName;
    if (!GetPropertyString(eventRecord, L"QueryName", queryName))
    {
        return false;
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
            AddBinding(
                eventRecord->EventHeader.ProcessId,
                queryName,
                std::move(addresses),
                eventRecord->EventHeader.TimeStamp.QuadPart);
        }
    }

    return true;
}

void DnsAssociator::AddBinding(
    unsigned long processId,
    const std::wstring& queryName,
    std::vector<std::wstring> addresses,
    unsigned long long timestamp)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    Binding binding;
    binding.ProcessId = processId;
    binding.QueryName = queryName;
    binding.Addresses = std::move(addresses);
    binding.Timestamp = timestamp;
    m_bindings[std::make_pair(processId, queryName)] = std::move(binding);
}

std::wstring DnsAssociator::Resolve(unsigned long processId, const std::wstring& ip) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto& item : m_bindings)
    {
        if (item.second.ProcessId != processId)
        {
            continue;
        }
        if (std::find(item.second.Addresses.begin(), item.second.Addresses.end(), ip) !=
            item.second.Addresses.end())
        {
            return item.second.QueryName;
        }
    }

    for (const auto& item : m_bindings)
    {
        if (std::find(item.second.Addresses.begin(), item.second.Addresses.end(), ip) !=
            item.second.Addresses.end())
        {
            return item.second.QueryName;
        }
    }

    return L"";
}

std::wstring DnsAssociator::FormatIPv4(const unsigned char address[16])
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
