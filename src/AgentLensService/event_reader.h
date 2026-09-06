#pragma once

#include <vector>
#include <cstdint>
#include <windows.h>
#include "AgentLensProtocol/agl_event.h"

class EventReader
{
public:
    explicit EventReader(class ControlClient& client);
    ~EventReader();

    bool ReadOnce(std::vector<uint8_t>& buffer);
    void PrintRawEvents(const std::vector<uint8_t>& buffer) const;
    void PrintJsonEvents(const std::vector<uint8_t>& buffer) const;

private:
    bool OpenSharedRing();
    bool ReadShared(std::vector<uint8_t>& buffer);

    ControlClient& m_client;
    HANDLE m_event = nullptr;
    HANDLE m_mapping = nullptr;
    AGL_EVENT_RING_SHARED_HEADER* m_header = nullptr;
    uint8_t* m_data = nullptr;
};
