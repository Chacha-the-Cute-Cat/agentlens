#include "agl_event.h"
#include "agl_event_ring.h"
#include "agl_context.h"
#include "agl_util.h"
#include "agl_etw.h"

static volatile LONG AglSampleCounter = 0;

static BOOLEAN AglShouldSampleEvent(ULONG EventType)
{
    if (EventType == AGL_EVENT_FILE_READ || EventType == AGL_EVENT_FILE_WRITE)
    {
        return (InterlockedIncrement(&AglSampleCounter) % 10) != 0;
    }
    return FALSE;
}

static ULONG AglEventFlags(ULONG EventType)
{
    if (EventType == AGL_EVENT_PROCESS_CREATE ||
        EventType == AGL_EVENT_PROCESS_EXIT ||
        EventType == AGL_EVENT_REGISTRY_SET_VALUE ||
        EventType == AGL_EVENT_REGISTRY_DELETE_KEY ||
        EventType == AGL_EVENT_REGISTRY_DELETE_VALUE ||
        EventType == AGL_EVENT_NETWORK_CONNECT)
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

    if (AglShouldSampleEvent(EventType))
    {
        return STATUS_SUCCESS;
    }

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

    if (CorrelationId == 0 && ProcessId != 0)
    {
        CorrelationId = AglContextGetCorrelationId(ProcessId);
    }

    header = (AGL_EVENT_HEADER*)(buffer + sizeof(AGL_RING_RECORD_HEADER));
    RtlZeroMemory(header, sizeof(*header));
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
    ULONG total = pathLen + cmdLen + nameLen + sizeof(WCHAR) * 3;
    PUCHAR buffer;
    AGL_PROCESS_EVENT* event;
    PWCHAR data;
    NTSTATUS status;

    if (total > AGL_MAX_EVENT_PAYLOAD)
    {
        total = AGL_MAX_EVENT_PAYLOAD;
    }

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
