#include "agl_event.h"
#include "agl_event_ring.h"
#include "agl_context.h"
#include "agl_util.h"
#include "agl_etw.h"

static ULONG AglEventFlags(ULONG EventType)
{
    if (EventType == AGL_EVENT_PROCESS_CREATE ||
        EventType == AGL_EVENT_PROCESS_EXIT ||
        EventType == AGL_EVENT_REGISTRY_SET_VALUE ||
        EventType == AGL_EVENT_REGISTRY_DELETE_KEY ||
        EventType == AGL_EVENT_REGISTRY_DELETE_VALUE ||
        EventType == AGL_EVENT_TOKEN_ANOMALY ||
        EventType == AGL_EVENT_NETWORK_CONNECT ||
        EventType == AGL_EVENT_NETWORK_DOMAIN)
    {
        return AGL_EVENT_FLAG_CRITICAL;
    }
    return 0;
}

static ULONG64 AglNow(void)
{
    LARGE_INTEGER time;
    KeQuerySystemTime(&time);
    return (ULONG64)time.QuadPart;
}

NTSTATUS AglEventEmit(
    ULONG EventType,
    ULONG ResultStatus,
    ULONG64 ProcessId,
    ULONG64 ThreadId,
    ULONG64 ParentProcessId,
    ULONG64 CorrelationId,
    ULONG SessionId,
    PVOID Payload,
    ULONG PayloadLength)
{
    ULONG total = sizeof(AGL_EVENT_HEADER) + PayloadLength;
    ULONG recordLength = sizeof(AGL_RING_RECORD_HEADER) + total;
    PUCHAR buffer;
    AGL_RING_RECORD_HEADER* recordHeader;
    AGL_EVENT_HEADER* header;
    NTSTATUS status;

    if (total > AGL_MAX_EVENT_PAYLOAD + sizeof(AGL_EVENT_HEADER))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    buffer = AglAllocNonPaged(recordLength);
    if (!buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    recordHeader = (AGL_RING_RECORD_HEADER*)buffer;
    recordHeader->RecordLength = recordLength;
    recordHeader->Flags = 0;
    recordHeader->Reserved = 0;

    header = (AGL_EVENT_HEADER*)(buffer + sizeof(AGL_RING_RECORD_HEADER));
    RtlZeroMemory(header, sizeof(*header));

    if (CorrelationId == 0 && ProcessId != 0)
    {
        CorrelationId = AglContextGetCorrelationId(ProcessId);
    }

    header->AgentSessionId = ProcessId
        ? AglContextGetAgentSessionId(ProcessId)
        : 0;
    {
        ULONG64 conversationId = 0;
        ULONG64 toolCallId = 0;
        if (ProcessId)
        {
            AglContextGetAgentTag(
                ProcessId,
                &conversationId,
                &toolCallId);
        }
        header->ConversationId = conversationId;
        header->ToolCallId = toolCallId;
    }

    header->StructSize = sizeof(*header);
    header->Version = AGL_PROTOCOL_VERSION;
    header->EventType = EventType;
    header->ResultStatus = ResultStatus;
    header->Sequence = AglContextNextCorrelationId();
    header->Timestamp = AglNow();
    header->ProcessId = ProcessId;
    header->ThreadId = ThreadId;
    header->ParentProcessId = ParentProcessId;
    header->CorrelationId = CorrelationId ? CorrelationId : header->Sequence;
    header->SessionId = SessionId;
    header->Flags = AglEventFlags(EventType);
    header->PayloadLength = PayloadLength;
    recordHeader->Flags = header->Flags;

    if (Payload && PayloadLength)
    {
        RtlCopyMemory(
            buffer + sizeof(AGL_RING_RECORD_HEADER) + sizeof(*header),
            Payload,
            PayloadLength);
    }

    status = AglEventRingWrite(buffer, recordLength);
    if (NT_SUCCESS(status))
    {
        AglEtwWriteEvent(header, Payload, PayloadLength);
    }
    AglFree(buffer);
    return status;
}

NTSTATUS AglEventEmitProcess(
    ULONG EventType,
    ULONG64 ProcessId,
    ULONG64 ParentProcessId,
    ULONG64 CreateTime,
    ULONG64 CorrelationId,
    PCUNICODE_STRING ImagePath,
    PCUNICODE_STRING ImageName,
    PCUNICODE_STRING CommandLine)
{
    ULONG pathLen = ImagePath ? ImagePath->Length : 0;
    ULONG cmdLen = CommandLine ? CommandLine->Length : 0;
    ULONG nameLen = ImageName ? ImageName->Length : 0;
    ULONG fixedPayload = sizeof(AGL_PROCESS_EVENT) - sizeof(AGL_EVENT_HEADER);
    ULONG budget = 0;
    ULONG total;
    PUCHAR buffer;
    AGL_PROCESS_EVENT* event;
    PWCHAR data;
    NTSTATUS status;

    if (AGL_MAX_EVENT_PAYLOAD >= fixedPayload + sizeof(WCHAR) * 3)
    {
        budget = AGL_MAX_EVENT_PAYLOAD - fixedPayload - sizeof(WCHAR) * 3;
    }
    budget &= ~((ULONG)sizeof(WCHAR) - 1);

    if (pathLen > budget)
    {
        pathLen = budget;
    }
    budget -= pathLen;

    if (nameLen > budget)
    {
        nameLen = budget;
    }
    budget -= nameLen;

    if (cmdLen > budget)
    {
        cmdLen = budget;
    }

    total = pathLen + nameLen + cmdLen + sizeof(WCHAR) * 3;

    buffer = AglAllocNonPaged(sizeof(AGL_PROCESS_EVENT) + total);
    if (!buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    event = (AGL_PROCESS_EVENT*)buffer;
    RtlZeroMemory(event, sizeof(AGL_PROCESS_EVENT) + total);
    event->CreateTime = CreateTime;
    event->ImagePathLength = pathLen;
    event->CommandLineLength = cmdLen;
    event->ImageNameLength = (USHORT)nameLen;
    data = event->Data;

    if (ImagePath && ImagePath->Buffer)
    {
        RtlCopyMemory(data, ImagePath->Buffer, pathLen);
        data += pathLen / sizeof(WCHAR);
    }
    *data++ = L'\0';

    if (ImageName && ImageName->Buffer)
    {
        RtlCopyMemory(data, ImageName->Buffer, nameLen);
        data += nameLen / sizeof(WCHAR);
    }
    *data++ = L'\0';

    if (CommandLine && CommandLine->Buffer)
    {
        RtlCopyMemory(data, CommandLine->Buffer, cmdLen);
    }

    status = AglEventEmit(
        EventType,
        STATUS_SUCCESS,
        ProcessId,
        (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
        ParentProcessId,
        CorrelationId,
        0,
        buffer + sizeof(AGL_EVENT_HEADER),
        sizeof(AGL_PROCESS_EVENT) - sizeof(AGL_EVENT_HEADER) + total);

    AglFree(buffer);
    return status;
}

NTSTATUS AglEventEmitThread(
    ULONG EventType,
    ULONG64 ProcessId,
    ULONG64 ThreadId,
    ULONG64 ParentProcessId)
{
    AGL_THREAD_EVENT event;
    RtlZeroMemory(&event, sizeof(event));
    event.ThreadCreateTime = AglNow();
    return AglEventEmit(
        EventType,
        STATUS_SUCCESS,
        ProcessId,
        ThreadId,
        ParentProcessId,
        0,
        0,
        &event.ThreadCreateTime,
        sizeof(event.ThreadCreateTime));
}

NTSTATUS AglEventEmitTokenAnomaly(
    ULONG64 ProcessId,
    ULONG64 ParentProcessId,
    ULONG ParentSidHash,
    ULONG ParentIntegrityLevel,
    ULONG ParentPrivilegeHash,
    ULONG CurrentSidHash,
    ULONG CurrentIntegrityLevel,
    ULONG CurrentPrivilegeHash)
{
    AGL_TOKEN_EVENT event;
    RtlZeroMemory(&event, sizeof(event));
    event.ParentSidHash = ParentSidHash;
    event.ParentIntegrityLevel = ParentIntegrityLevel;
    event.ParentPrivilegeHash = ParentPrivilegeHash;
    event.CurrentSidHash = CurrentSidHash;
    event.CurrentIntegrityLevel = CurrentIntegrityLevel;
    event.CurrentPrivilegeHash = CurrentPrivilegeHash;
    return AglEventEmit(
        AGL_EVENT_TOKEN_ANOMALY,
        STATUS_SUCCESS,
        ProcessId,
        (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
        ParentProcessId,
        0,
        0,
        (PUCHAR)&event + sizeof(AGL_EVENT_HEADER),
        sizeof(event) - sizeof(AGL_EVENT_HEADER));
}

NTSTATUS AglEventEmitNetworkDomain(
    ULONG64 ProcessId,
    ULONG64 FlowId,
    ULONG Protocol,
    USHORT RemotePort,
    USHORT LocalPort,
    const UCHAR* RemoteAddress,
    PCUNICODE_STRING Sni)
{
    ULONG sniLength = Sni ? Sni->Length : 0;
    ULONG payloadLength = sizeof(AGL_DOMAIN_EVENT) - sizeof(AGL_EVENT_HEADER) + sniLength;
    PUCHAR buffer;
    AGL_DOMAIN_EVENT* event;
    NTSTATUS status;

    if (sniLength > AGL_MAX_EVENT_PAYLOAD)
    {
        sniLength = AGL_MAX_EVENT_PAYLOAD;
    }

    buffer = AglAllocNonPaged(sizeof(AGL_EVENT_HEADER) + payloadLength);
    if (!buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    event = (AGL_DOMAIN_EVENT*)buffer;
    RtlZeroMemory(event, sizeof(AGL_EVENT_HEADER) + payloadLength);
    event->FlowId = FlowId;
    event->Protocol = Protocol;
    event->RemotePort = RemotePort;
    event->LocalPort = LocalPort;
    if (RemoteAddress)
    {
        RtlCopyMemory(event->RemoteAddress, RemoteAddress, 16);
    }
    event->SniLength = sniLength;
    if (Sni && Sni->Buffer && sniLength)
    {
        RtlCopyMemory(event->Data, Sni->Buffer, sniLength);
    }

    status = AglEventEmit(
        AGL_EVENT_NETWORK_DOMAIN,
        STATUS_SUCCESS,
        ProcessId,
        (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
        0,
        0,
        0,
        buffer + sizeof(AGL_EVENT_HEADER),
        payloadLength);
    AglFree(buffer);
    return status;
}

NTSTATUS AglEventEmitImage(
    ULONG EventType,
    ULONG64 ProcessId,
    ULONG64 ImageBase,
    ULONG ImageSize,
    PCUNICODE_STRING Path)
{
    ULONG pathLen = Path ? Path->Length : 0;
    PUCHAR buffer;
    AGL_IMAGE_EVENT* event;
    NTSTATUS status;

    if (pathLen > AGL_MAX_EVENT_PAYLOAD - 16)
    {
        pathLen = AGL_MAX_EVENT_PAYLOAD - 16;
    }

    buffer = AglAllocNonPaged(sizeof(AGL_IMAGE_EVENT) + pathLen);
    if (!buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    event = (AGL_IMAGE_EVENT*)buffer;
    RtlZeroMemory(event, sizeof(AGL_IMAGE_EVENT) + pathLen);
    event->ImageBase = ImageBase;
    event->ImageSize = ImageSize;
    event->PathLength = pathLen;
    if (Path && Path->Buffer && pathLen)
    {
        RtlCopyMemory(event->Data, Path->Buffer, pathLen);
    }

    status = AglEventEmit(
        EventType,
        STATUS_SUCCESS,
        ProcessId,
        (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
        0,
        0,
        0,
        buffer + sizeof(AGL_EVENT_HEADER),
        sizeof(AGL_IMAGE_EVENT) - sizeof(AGL_EVENT_HEADER) + pathLen);

    AglFree(buffer);
    return status;
}
