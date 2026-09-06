#include "event_reader.h"
#include "control_client.h"
#include "AgentLensProtocol/agl_event.h"
#include "dns_associator.h"

#include <cstdio>
#include <cwchar>
#include <string>

namespace
{
    std::wstring EventTypeName(ULONG type)
    {
        switch (type)
        {
        case AGL_EVENT_PROCESS_CREATE: return L"process.create";
        case AGL_EVENT_PROCESS_EXIT: return L"process.exit";
        case AGL_EVENT_THREAD_CREATE: return L"thread.create";
        case AGL_EVENT_THREAD_EXIT: return L"thread.exit";
        case AGL_EVENT_IMAGE_LOAD: return L"image.load";
        case AGL_EVENT_FILE_OPEN: return L"file.open";
        case AGL_EVENT_FILE_RENAME: return L"file.rename";
        case AGL_EVENT_FILE_READ: return L"file.read";
        case AGL_EVENT_FILE_WRITE: return L"file.write";
        case AGL_EVENT_FILE_DELETE: return L"file.delete";
        case AGL_EVENT_FILE_CLOSE: return L"file.close";
        case AGL_EVENT_FILE_QUERY: return L"file.query";
        case AGL_EVENT_FILE_SECURITY: return L"file.security";
        case AGL_EVENT_FILE_DIRECTORY: return L"file.directory";
        case AGL_EVENT_REGISTRY_OPEN: return L"registry.open";
        case AGL_EVENT_REGISTRY_QUERY: return L"registry.query";
        case AGL_EVENT_REGISTRY_SET_VALUE: return L"registry.set";
        case AGL_EVENT_REGISTRY_ENUM_KEY: return L"registry.enum_key";
        case AGL_EVENT_REGISTRY_ENUM_VALUE: return L"registry.enum_value";
        case AGL_EVENT_REGISTRY_DELETE_KEY: return L"registry.delete_key";
        case AGL_EVENT_REGISTRY_DELETE_VALUE: return L"registry.delete_value";
        case AGL_EVENT_OBJECT_HANDLE: return L"object.handle";
        case AGL_EVENT_NETWORK_CONNECT: return L"network.connect";
        case AGL_EVENT_NETWORK_FLOW_ESTABLISHED: return L"network.flow_established";
        case AGL_EVENT_NETWORK_FLOW_CLOSED: return L"network.flow_closed";
        default: return L"unknown";
        }
    }

    std::wstring JsonEscape(const wchar_t* text, size_t length)
    {
        std::wstring out;
        out.reserve(length + 8);
        for (size_t i = 0; i < length; i++)
        {
            wchar_t ch = text[i];
            switch (ch)
            {
            case L'\\': out += L"\\\\"; break;
            case L'"': out += L"\\\""; break;
            case L'\r': out += L"\\r"; break;
            case L'\n': out += L"\\n"; break;
            case L'\t': out += L"\\t"; break;
            default:
                if (ch < 0x20)
                {
                    wchar_t buf[16];
                    swprintf_s(buf, L"\\u%04X", ch);
                    out += buf;
                }
                else
                {
                    out += ch;
                }
                break;
            }
        }
        return out;
    }
}

EventReader::EventReader(ControlClient& client)
    : m_client(client)
{
    OpenSharedRing();
}

EventReader::~EventReader()
{
    if (m_header)
    {
        UnmapViewOfFile(m_header);
        m_header = nullptr;
    }
    if (m_mapping)
    {
        CloseHandle(m_mapping);
        m_mapping = nullptr;
    }
    if (m_event)
    {
        CloseHandle(m_event);
        m_event = nullptr;
    }
}

bool EventReader::OpenSharedRing()
{
    m_event = OpenEventW(SYNCHRONIZE, FALSE, L"AgentLensEventReady");
    if (!m_event)
    {
        return false;
    }

    m_mapping = OpenFileMappingW(FILE_MAP_READ, FALSE, L"AgentLensEventRing");
    if (!m_mapping)
    {
        return false;
    }

    void* view = MapViewOfFile(m_mapping, FILE_MAP_READ, 0, 0, 0);
    if (!view)
    {
        return false;
    }

    m_header = static_cast<AGL_EVENT_RING_SHARED_HEADER*>(view);
    m_data = reinterpret_cast<uint8_t*>(view) + sizeof(AGL_EVENT_RING_SHARED_HEADER);
    return m_header->Magic == AGL_EVENT_RING_MAGIC;
}

bool EventReader::ReadOnce(std::vector<uint8_t>& buffer)
{
    if (m_header)
    {
        if (ReadShared(buffer))
        {
            return true;
        }
    }
    return m_client.ReadEvents(buffer);
}

bool EventReader::ReadShared(std::vector<uint8_t>& buffer)
{
    if (!m_header)
    {
        return false;
    }

    unsigned long long head = m_header->Head;
    unsigned long long tail = m_header->Tail;
    unsigned long long size = m_header->Size;
    if (size == 0 || size > (1 << 24))
    {
        return false;
    }

    unsigned long long available;
    if (head >= tail)
    {
        available = head - tail;
    }
    else
    {
        available = size - tail + head;
    }

    if (available == 0)
    {
        return false;
    }

    if (available > buffer.max_size())
    {
        available = buffer.max_size();
    }

    buffer.resize(static_cast<size_t>(available));
    for (size_t i = 0; i < buffer.size(); i++)
    {
        unsigned long long pos = (tail + i) % size;
        buffer[i] = m_data[pos];
    }

    m_header->Tail = (tail + available) % size;
    return true;
}

void EventReader::PrintRawEvents(const std::vector<uint8_t>& buffer) const
{
    const uint8_t* p = buffer.data();
    size_t remaining = buffer.size();

    while (remaining >= sizeof(AGL_RING_RECORD_HEADER) + sizeof(AGL_EVENT_HEADER))
    {
        const auto* recordHeader = reinterpret_cast<const AGL_RING_RECORD_HEADER*>(p);
        if (recordHeader->RecordLength < sizeof(AGL_RING_RECORD_HEADER) + sizeof(AGL_EVENT_HEADER) ||
            recordHeader->RecordLength > remaining)
        {
            break;
        }

        const auto* header = reinterpret_cast<const AGL_EVENT_HEADER*>(
            p + sizeof(AGL_RING_RECORD_HEADER));
        if (header->StructSize < sizeof(AGL_EVENT_HEADER) ||
            header->PayloadLength > recordHeader->RecordLength - sizeof(AGL_RING_RECORD_HEADER) - sizeof(AGL_EVENT_HEADER))
        {
            break;
        }

        wprintf(
            L"[evt] type=%u seq=%llu pid=%llu tid=%llu status=0x%08X payload=%u\n",
            header->EventType,
            static_cast<unsigned long long>(header->Sequence),
            static_cast<unsigned long long>(header->ProcessId),
            static_cast<unsigned long long>(header->ThreadId),
            header->ResultStatus,
            header->PayloadLength);

        p += recordHeader->RecordLength;
        remaining -= recordHeader->RecordLength;
    }
}

void EventReader::PrintJsonEvents(
    const std::vector<uint8_t>& buffer,
    FILE* output,
    unsigned long long filterPid,
    unsigned long filterType,
    const DnsAssociator* dns) const
{
    const uint8_t* p = buffer.data();
    size_t remaining = buffer.size();

    while (remaining >= sizeof(AGL_RING_RECORD_HEADER) + sizeof(AGL_EVENT_HEADER))
    {
        const auto* recordHeader = reinterpret_cast<const AGL_RING_RECORD_HEADER*>(p);
        if (recordHeader->RecordLength < sizeof(AGL_RING_RECORD_HEADER) + sizeof(AGL_EVENT_HEADER) ||
            recordHeader->RecordLength > remaining)
        {
            break;
        }

        const auto* header = reinterpret_cast<const AGL_EVENT_HEADER*>(
            p + sizeof(AGL_RING_RECORD_HEADER));
        if (header->StructSize < sizeof(AGL_EVENT_HEADER))
        {
            break;
        }

        if (filterPid && header->ProcessId != filterPid)
        {
            p += recordHeader->RecordLength;
            remaining -= recordHeader->RecordLength;
            continue;
        }

        if (filterType && header->EventType != filterType)
        {
            p += recordHeader->RecordLength;
            remaining -= recordHeader->RecordLength;
            continue;
        }

        const uint8_t* payload = p + sizeof(AGL_RING_RECORD_HEADER) + sizeof(AGL_EVENT_HEADER);
        ULONG payloadLength = header->PayloadLength;
        (void)payload;

        std::wstring json = L"{";
        json += L"\"schema\":" + std::to_wstring(AGL_EVENT_SCHEMA_VERSION) + L",";
        json += L"\"type\":\"" + EventTypeName(header->EventType) + L"\",";
        json += L"\"sequence\":" + std::to_wstring(header->Sequence) + L",";
        json += L"\"timestamp\":" + std::to_wstring(header->Timestamp) + L",";
        json += L"\"pid\":" + std::to_wstring(header->ProcessId) + L",";
        json += L"\"tid\":" + std::to_wstring(header->ThreadId) + L",";
        json += L"\"parent_pid\":" + std::to_wstring(header->ParentProcessId) + L",";
        json += L"\"correlation\":" + std::to_wstring(header->CorrelationId) + L",";
        json += L"\"agent_session\":" + std::to_wstring(header->AgentSessionId) + L",";
        json += L"\"conversation_id\":" + std::to_wstring(header->ConversationId) + L",";
        json += L"\"tool_call_id\":" + std::to_wstring(header->ToolCallId) + L",";
        json += L"\"status\":\"" + std::to_wstring(header->ResultStatus) + L"\",";
        json += L"\"flags\":" + std::to_wstring(header->Flags) + L",";
        json += L"\"payload_bytes\":" + std::to_wstring(payloadLength);

        switch (header->EventType)
        {
        case AGL_EVENT_FILE_OPEN:
        case AGL_EVENT_FILE_RENAME:
        case AGL_EVENT_FILE_READ:
        case AGL_EVENT_FILE_WRITE:
        case AGL_EVENT_FILE_DELETE:
        case AGL_EVENT_FILE_CLOSE:
        case AGL_EVENT_FILE_QUERY:
        case AGL_EVENT_FILE_SECURITY:
        case AGL_EVENT_FILE_DIRECTORY:
            if (payloadLength >= sizeof(AGL_FILE_EVENT) - sizeof(AGL_EVENT_HEADER))
            {
                const auto* file = reinterpret_cast<const AGL_FILE_EVENT*>(
                    p + sizeof(AGL_RING_RECORD_HEADER));
                json += L",\"desired_access\":" + std::to_wstring(file->DesiredAccess);
                json += L",\"create_options\":" + std::to_wstring(file->CreateOptions);
                json += L",\"create_disposition\":" + std::to_wstring(file->CreateDisposition);
                json += L",\"offset\":" + std::to_wstring(file->Offset);
                json += L",\"length\":" + std::to_wstring(file->Length);
                json += L",\"security_information\":" + std::to_wstring(file->SecurityInformation);
                json += L",\"info_class\":" + std::to_wstring(file->InfoClass);
                json += L",\"name_length\":" + std::to_wstring(file->NameLength);
                json += L",\"path\":\"" + JsonEscape(file->Data, file->PathLength / sizeof(wchar_t)) + L"\"";
            }
            break;

        case AGL_EVENT_REGISTRY_OPEN:
        case AGL_EVENT_REGISTRY_QUERY:
        case AGL_EVENT_REGISTRY_SET_VALUE:
        case AGL_EVENT_REGISTRY_ENUM_KEY:
        case AGL_EVENT_REGISTRY_ENUM_VALUE:
        case AGL_EVENT_REGISTRY_DELETE_KEY:
        case AGL_EVENT_REGISTRY_DELETE_VALUE:
            if (payloadLength >= sizeof(AGL_REGISTRY_EVENT) - sizeof(AGL_EVENT_HEADER))
            {
                const auto* reg = reinterpret_cast<const AGL_REGISTRY_EVENT*>(
                    p + sizeof(AGL_RING_RECORD_HEADER));
                json += L",\"desired_access\":" + std::to_wstring(reg->DesiredAccess);
                json += L",\"value_type\":" + std::to_wstring(reg->ValueType);
                json += L",\"value_length\":" + std::to_wstring(reg->ValueLength);
                json += L",\"value_hash\":" + std::to_wstring(reg->ValueHash);
                json += L",\"flags\":" + std::to_wstring(reg->Flags);
                json += L",\"index\":" + std::to_wstring(reg->Index);
                json += L",\"info_class\":" + std::to_wstring(reg->InfoClass);
                json += L",\"path\":\"" + JsonEscape(reg->Data, reg->PathLength / sizeof(wchar_t)) + L"\"";
            }
            break;

        case AGL_EVENT_NETWORK_CONNECT:
        case AGL_EVENT_NETWORK_FLOW_ESTABLISHED:
        case AGL_EVENT_NETWORK_FLOW_CLOSED:
            if (payloadLength >= sizeof(AGL_NETWORK_EVENT) - sizeof(AGL_EVENT_HEADER))
            {
                const auto* net = reinterpret_cast<const AGL_NETWORK_EVENT*>(
                    p + sizeof(AGL_RING_RECORD_HEADER));
                json += L",\"protocol\":" + std::to_wstring(net->Protocol);
                json += L",\"remote_port\":" + std::to_wstring(net->RemotePort);
                json += L",\"local_port\":" + std::to_wstring(net->LocalPort);
                json += L",\"bytes_sent\":" + std::to_wstring(net->BytesSent);
                json += L",\"bytes_received\":" + std::to_wstring(net->BytesReceived);
                json += L",\"packets_sent\":" + std::to_wstring(net->PacketsSent);
                json += L",\"packets_received\":" + std::to_wstring(net->PacketsReceived);

                std::wstring remoteIp = DnsAssociator::FormatIPv4(net->RemoteAddress);
                if (!remoteIp.empty())
                {
                    json += L",\"remote_ip\":\"" + JsonEscape(remoteIp.c_str(), remoteIp.size()) + L"\"";
                    if (dns)
                    {
                        std::wstring dnsName = dns->Resolve(
                            static_cast<unsigned long>(header->ProcessId),
                            remoteIp);
                        if (!dnsName.empty())
                        {
                            json += L",\"dns_name\":\"" + JsonEscape(dnsName.c_str(), dnsName.size()) + L"\"";
                        }
                    }
                }
            }
            break;
        }
        json += L"}";

        if (output)
        {
            fwprintf(output, L"%s\n", json.c_str());
        }
        else
        {
            wprintf(L"%s\n", json.c_str());
        }

        p += recordHeader->RecordLength;
        remaining -= recordHeader->RecordLength;
    }
}
