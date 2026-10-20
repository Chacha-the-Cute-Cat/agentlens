#pragma once

#include <vector>
#include <cstdint>
#include <windows.h>
#include "AgentLensProtocol/agl_event.h"

class DnsAssociator;

class EventReader
{
public:
    explicit EventReader(class ControlClient& client);
    ~EventReader();

    bool ReadOnce(std::vector<uint8_t>& buffer);
    void PrintRawEvents(const std::vector<uint8_t>& buffer) const;
    void PrintJsonEvents(
        const std::vector<uint8_t>& buffer,
        FILE* output = nullptr,
        unsigned long long filterPid = 0,
        unsigned long filterType = 0,
        const DnsAssociator* dns = nullptr) const;

private:
    ControlClient& m_client;
};
