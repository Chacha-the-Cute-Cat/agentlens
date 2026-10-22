#include "control_client.h"

#include <stdexcept>

ControlClient::~ControlClient()
{
    Close();
}

bool ControlClient::Open()
{
    if (m_handle != INVALID_HANDLE_VALUE)
    {
        return true;
    }

    m_handle = CreateFileW(
        AGL_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (m_handle == INVALID_HANDLE_VALUE)
    {
        m_lastError = GetLastError();
        return false;
    }

    m_lastError = ERROR_SUCCESS;
    return true;
}

void ControlClient::Close()
{
    if (m_handle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }
    m_lastError = ERROR_SUCCESS;
}

bool ControlClient::IsOpen() const
{
    return m_handle != INVALID_HANDLE_VALUE;
}

bool ControlClient::Call(
    AGL_OPCODE op,
    const void* input,
    ULONG inputLength,
    void* output,
    ULONG outputLength,
    ULONG& bytesReturned)
{
    m_lastError = ERROR_SUCCESS;
    if (m_handle == INVALID_HANDLE_VALUE)
    {
        m_lastError = ERROR_INVALID_HANDLE;
        return false;
    }

    const ULONG headerSize = sizeof(AGL_CONTROL_HEADER);
    ULONG inSize = headerSize + inputLength;
    ULONG outSize = headerSize + outputLength;
    std::vector<BYTE> inBuffer(inSize, 0);
    std::vector<BYTE> outBuffer(outSize, 0);

    AGL_CONTROL_HEADER* header = reinterpret_cast<AGL_CONTROL_HEADER*>(inBuffer.data());
    header->StructSize = headerSize;
    header->Version = AGL_PROTOCOL_VERSION;
    header->OpCode = static_cast<ULONG>(op);
    header->InputLength = inputLength;
    header->OutputLength = outputLength;

    if (input && inputLength)
    {
        memcpy(inBuffer.data() + headerSize, input, inputLength);
    }

    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        m_handle,
        AGL_CONTROL_IOCTL,
        inBuffer.data(),
        static_cast<DWORD>(inBuffer.size()),
        outBuffer.data(),
        static_cast<DWORD>(outBuffer.size()),
        &returned,
        nullptr);

    if (!ok)
    {
        m_lastError = GetLastError();
        return false;
    }

    if (output && outputLength && returned > headerSize)
    {
        ULONG copy = (returned - headerSize) < outputLength ? (returned - headerSize) : outputLength;
        memcpy(output, outBuffer.data() + headerSize, copy);
        bytesReturned = copy;
    }
    else
    {
        bytesReturned = 0;
    }

    return true;
}

DWORD ControlClient::LastError() const
{
    return m_lastError;
}

bool ControlClient::GetVersion(AGL_VERSION_INFO& info)
{
    ULONG returned = 0;
    return Call(AGL_OP_GET_VERSION, nullptr, 0, &info, sizeof(info), returned);
}

bool ControlClient::Subscribe(ULONG64 processId, ULONG interestMask)
{
    AGL_SUBSCRIBE sub{};
    sub.ProcessId = processId;
    sub.InterestMask = interestMask;
    ULONG returned = 0;
    return Call(AGL_OP_SUBSCRIBE_EVENTS, &sub, sizeof(sub), nullptr, 0, returned);
}

bool ControlClient::Unsubscribe()
{
    ULONG returned = 0;
    return Call(AGL_OP_UNSUBSCRIBE_EVENTS, nullptr, 0, nullptr, 0, returned);
}

bool ControlClient::ReadEvents(std::vector<uint8_t>& events)
{
    events.resize(256 * 1024);
    ULONG returned = 0;
    if (!Call(AGL_OP_READ_EVENTS, nullptr, 0, events.data(), static_cast<ULONG>(events.size()), returned))
    {
        events.clear();
        return false;
    }
    events.resize(returned);
    return true;
}

bool ControlClient::GetStats(AGL_STATS& stats)
{
    ULONG returned = 0;
    return Call(AGL_OP_GET_STATS, nullptr, 0, &stats, sizeof(stats), returned);
}

bool ControlClient::QueryProcess(ULONG64 processId, AGL_PROCESS_QUERY& query)
{
    query.ProcessId = processId;
    ULONG returned = 0;
    return Call(AGL_OP_QUERY_PROCESS, &query, sizeof(query), &query, sizeof(query), returned);
}

bool ControlClient::LoadPolicy(const void* policy, ULONG length)
{
    ULONG returned = 0;
    return Call(AGL_OP_LOAD_POLICY, policy, length, nullptr, 0, returned);
}

bool ControlClient::ClearPolicy()
{
    ULONG returned = 0;
    return Call(AGL_OP_CLEAR_POLICY, nullptr, 0, nullptr, 0, returned);
}
