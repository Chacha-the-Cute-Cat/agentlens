#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include "AgentLensProtocol/agl_control.h"
#include "AgentLensProtocol/agl_event.h"
#include "AgentLensProtocol/agl_policy.h"

class ControlClient
{
public:
    ControlClient() = default;
    ~ControlClient();

    bool Open();
    void Close();
    bool IsOpen() const;

    bool GetVersion(AGL_VERSION_INFO& info);
    bool Subscribe(ULONG64 processId, ULONG interestMask);
    bool Unsubscribe();
    bool ReadEvents(std::vector<uint8_t>& events);
    bool GetStats(AGL_STATS& stats);
    bool QueryProcess(ULONG64 processId, AGL_PROCESS_QUERY& query);
    bool LoadPolicy(const void* policy, ULONG length);
    bool ClearPolicy();
    DWORD LastError() const;

private:
    bool Call(
        AGL_OPCODE op,
        const void* input,
        ULONG inputLength,
        void* output,
        ULONG outputLength,
        ULONG& bytesReturned);

    HANDLE m_handle = INVALID_HANDLE_VALUE;
    DWORD m_lastError = ERROR_SUCCESS;
};
