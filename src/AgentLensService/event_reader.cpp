#include "event_reader.h"
#include "control_client.h"
#include "AgentLensProtocol/agl_event.h"
#include "dns_associator.h"

#include <cstdio>
#include <cstring>
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
        case AGL_EVENT_NETWORK_DOMAIN: return L"network.domain";
        case AGL_EVENT_NETWORK_FLOW_ESTABLISHED: return L"network.flow_established";
        case AGL_EVENT_NETWORK_FLOW_CLOSED: return L"network.flow_closed";
        case AGL_EVENT_TOKEN_ANOMALY: return L"token.anomaly";
        case AGL_EVENT_POLICY_DENY: return L"policy.deny";
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

    bool ReadPayloadString(
        const uint8_t*& cursor,
        size_t& remaining,
        unsigned long bytes,
        std::wstring& value)
    {
        if ((bytes & 1) != 0 || bytes > remaining)
        {
            return false;
        }

        value.assign(bytes / sizeof(wchar_t), L'\0');
        if (bytes != 0)
        {
            memcpy(&value[0], cursor, bytes);
        }
        cursor += bytes;
        remaining -= bytes;

        if (remaining >= sizeof(wchar_t))
        {
            cursor += sizeof(wchar_t);
            remaining -= sizeof(wchar_t);
        }
        return true;
    }
}

EventReader::EventReader(ControlClient& client)
    : m_client(client)
{
}

EventReader::~EventReader()
{
}

bool EventReader::ReadOnce(std::vector<uint8_t>& buffer)
{
    // The kernel is the only writer of the ring's consumer index. Reading
    // through the control device keeps Head/Tail accounting in one place and
    // avoids mapping shared memory writable in a privileged service.
    return m_client.ReadEvents(buffer);
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
    const DnsAssociator* dns,
    bool mirrorToConsole) const
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
            header->StructSize >
                recordHeader->RecordLength - sizeof(AGL_RING_RECORD_HEADER) ||
            header->PayloadLength >
                recordHeader->RecordLength - sizeof(AGL_RING_RECORD_HEADER) -
                    header->StructSize)
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

        ULONG payloadLength = header->PayloadLength;

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
        case AGL_EVENT_PROCESS_CREATE:
        case AGL_EVENT_PROCESS_EXIT:
        {
            const ULONG fixedLength =
                sizeof(AGL_PROCESS_EVENT) - sizeof(AGL_EVENT_HEADER);
            if (payloadLength >= fixedLength)
            {
                const auto* process = reinterpret_cast<const AGL_PROCESS_EVENT*>(
                    p + sizeof(AGL_RING_RECORD_HEADER));
                json += L",\"create_time\":" + std::to_wstring(process->CreateTime);
                json += L",\"image_path_length\":" + std::to_wstring(process->ImagePathLength);
                json += L",\"image_name_length\":" + std::to_wstring(process->ImageNameLength);
                json += L",\"command_line_length\":" + std::to_wstring(process->CommandLineLength);

                const uint8_t* cursor = reinterpret_cast<const uint8_t*>(process->Data);
                size_t payloadRemaining = payloadLength - fixedLength;
                std::wstring imagePath;
                std::wstring imageName;
                std::wstring commandLine;
                if (ReadPayloadString(cursor, payloadRemaining, process->ImagePathLength, imagePath))
                {
                    json += L",\"path\":\"" + JsonEscape(imagePath.data(), imagePath.size()) + L"\"";
                }
                if (ReadPayloadString(cursor, payloadRemaining, process->ImageNameLength, imageName))
                {
                    json += L",\"name\":\"" + JsonEscape(imageName.data(), imageName.size()) + L"\"";
                }
                if (ReadPayloadString(cursor, payloadRemaining, process->CommandLineLength, commandLine))
                {
                    json += L",\"command_line\":\"" +
                        JsonEscape(commandLine.data(), commandLine.size()) + L"\"";
                }
            }
            break;
        }

        case AGL_EVENT_THREAD_CREATE:
        case AGL_EVENT_THREAD_EXIT:
            if (payloadLength >= sizeof(unsigned long long))
            {
                unsigned long long createTime = 0;
                memcpy(&createTime, p + sizeof(AGL_RING_RECORD_HEADER) + sizeof(AGL_EVENT_HEADER), sizeof(createTime));
                json += L",\"thread_create_time\":" + std::to_wstring(createTime);
            }
            break;

        case AGL_EVENT_IMAGE_LOAD:
        {
            const ULONG fixedLength =
                sizeof(AGL_IMAGE_EVENT) - sizeof(AGL_EVENT_HEADER);
            if (payloadLength >= fixedLength)
            {
                const auto* image = reinterpret_cast<const AGL_IMAGE_EVENT*>(
                    p + sizeof(AGL_RING_RECORD_HEADER));
                json += L",\"image_base\":" + std::to_wstring(image->ImageBase);
                json += L",\"image_size\":" + std::to_wstring(image->ImageSize);
                json += L",\"path_length\":" + std::to_wstring(image->PathLength);
                if ((image->PathLength & 1) == 0 &&
                    image->PathLength <= payloadLength - fixedLength)
                {
                    std::wstring path(image->PathLength / sizeof(wchar_t), L'\0');
                    if (!path.empty())
                    {
                        memcpy(&path[0], image->Data, image->PathLength);
                    }
                    json += L",\"path\":\"" + JsonEscape(path.data(), path.size()) + L"\"";
                }
            }
            break;
        }

        case AGL_EVENT_OBJECT_HANDLE:
            if (payloadLength >= sizeof(AGL_OBJECT_EVENT) - sizeof(AGL_EVENT_HEADER))
            {
                const auto* object = reinterpret_cast<const AGL_OBJECT_EVENT*>(
                    p + sizeof(AGL_RING_RECORD_HEADER));
                json += L",\"object_type\":" + std::to_wstring(object->ObjectType);
                json += L",\"desired_access\":" + std::to_wstring(object->DesiredAccess);
                json += L",\"granted_access\":" + std::to_wstring(object->GrantedAccess);
                json += L",\"target_pid\":" + std::to_wstring(object->TargetProcessId);
            }
            break;

        case AGL_EVENT_FILE_OPEN:
        case AGL_EVENT_FILE_RENAME:
        case AGL_EVENT_FILE_READ:
        case AGL_EVENT_FILE_WRITE:
        case AGL_EVENT_FILE_DELETE:
        case AGL_EVENT_FILE_CLOSE:
        case AGL_EVENT_FILE_QUERY:
        case AGL_EVENT_FILE_SECURITY:
        case AGL_EVENT_FILE_DIRECTORY:
        {
            const ULONG fixedLength =
                sizeof(AGL_FILE_EVENT) - sizeof(AGL_EVENT_HEADER);
            if (payloadLength >= fixedLength)
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
                if (file->PathLength <= payloadLength - fixedLength)
                {
                    json += L",\"path\":\"" +
                        JsonEscape(file->Data, file->PathLength / sizeof(wchar_t)) +
                        L"\"";
                }
            }
            break;
        }

        case AGL_EVENT_REGISTRY_OPEN:
        case AGL_EVENT_REGISTRY_QUERY:
        case AGL_EVENT_REGISTRY_SET_VALUE:
        case AGL_EVENT_REGISTRY_ENUM_KEY:
        case AGL_EVENT_REGISTRY_ENUM_VALUE:
        case AGL_EVENT_REGISTRY_DELETE_KEY:
        case AGL_EVENT_REGISTRY_DELETE_VALUE:
        {
            const ULONG fixedLength =
                sizeof(AGL_REGISTRY_EVENT) - sizeof(AGL_EVENT_HEADER);
            if (payloadLength >= fixedLength)
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
                if (reg->PathLength <= payloadLength - fixedLength)
                {
                    json += L",\"path\":\"" +
                        JsonEscape(reg->Data, reg->PathLength / sizeof(wchar_t)) +
                        L"\"";
                }
            }
            break;
        }

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

        case AGL_EVENT_NETWORK_DOMAIN:
        {
            const ULONG fixedLength =
                sizeof(AGL_DOMAIN_EVENT) - sizeof(AGL_EVENT_HEADER);
            if (payloadLength >= fixedLength)
            {
                const auto* domain = reinterpret_cast<const AGL_DOMAIN_EVENT*>(
                    p + sizeof(AGL_RING_RECORD_HEADER));
                json += L",\"flow_id\":" + std::to_wstring(domain->FlowId);
                json += L",\"protocol\":" + std::to_wstring(domain->Protocol);
                json += L",\"remote_port\":" + std::to_wstring(domain->RemotePort);
                json += L",\"local_port\":" + std::to_wstring(domain->LocalPort);
                if (domain->SniLength <= payloadLength - fixedLength)
                {
                    json += L",\"sni\":\"" +
                        JsonEscape(domain->Data, domain->SniLength / sizeof(wchar_t)) +
                        L"\"";
                }
            }
            break;
        }

        case AGL_EVENT_TOKEN_ANOMALY:
            if (payloadLength >= sizeof(AGL_TOKEN_EVENT) - sizeof(AGL_EVENT_HEADER))
            {
                const auto* token = reinterpret_cast<const AGL_TOKEN_EVENT*>(
                    p + sizeof(AGL_RING_RECORD_HEADER));
                json += L",\"parent_sid_hash\":" + std::to_wstring(token->ParentSidHash);
                json += L",\"parent_integrity\":" + std::to_wstring(token->ParentIntegrityLevel);
                json += L",\"parent_privilege_hash\":" + std::to_wstring(token->ParentPrivilegeHash);
                json += L",\"current_sid_hash\":" + std::to_wstring(token->CurrentSidHash);
                json += L",\"current_integrity\":" + std::to_wstring(token->CurrentIntegrityLevel);
                json += L",\"current_privilege_hash\":" + std::to_wstring(token->CurrentPrivilegeHash);
            }
            break;
        }
        json += L"}";

        if (output)
        {
            fwprintf(output, L"%s\n", json.c_str());
            fflush(output);
        }
        if (!output || mirrorToConsole)
        {
            wprintf(L"%s\n", json.c_str());
            fflush(stdout);
        }

        p += recordHeader->RecordLength;
        remaining -= recordHeader->RecordLength;
    }
}
