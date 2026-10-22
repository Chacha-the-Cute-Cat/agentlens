#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include <map>
#include <mutex>
#include <string>
#include <vector>

class DnsAssociator
{
public:
    DnsAssociator();
    ~DnsAssociator();

    DnsAssociator(const DnsAssociator&) = delete;
    DnsAssociator& operator=(const DnsAssociator&) = delete;

    bool Start();
    void Stop();
    bool Running() const;

    std::wstring Resolve(unsigned long processId, const std::wstring& ip) const;
    static std::wstring FormatIPv4(const unsigned char address[16]);

private:
    struct Binding
    {
        unsigned long ProcessId = 0;
        std::wstring QueryName;
        std::vector<std::wstring> Addresses;
        unsigned long long Timestamp = 0;
    };

    using Key = std::pair<unsigned long, std::wstring>;

    static void WINAPI EventRecordCallback(PEVENT_RECORD eventRecord);
    static DWORD WINAPI TraceThreadProc(LPVOID parameter);

    bool OpenTraceSession();
    bool ParseDnsEvent(PEVENT_RECORD eventRecord);
    void AddBinding(unsigned long processId, const std::wstring& queryName, std::vector<std::wstring> addresses, unsigned long long timestamp);
    void PruneBindingsLocked(unsigned long long timestamp) const;

    mutable std::mutex m_mutex;
    mutable std::map<Key, Binding> m_bindings;

    std::wstring m_sessionName;
    TRACEHANDLE m_sessionHandle = 0;
    TRACEHANDLE m_traceHandle = INVALID_PROCESSTRACE_HANDLE;
    HANDLE m_thread = nullptr;
    volatile LONG m_running = 0;
};
