#include "agl_event_ring.h"
#include "agl_util.h"
#include "agl_control.h"
#include "AgentLensProtocol/agl_control.h"

AGL_EVENT_RING AglEventRing = { 0 };

#define AGL_EVENT_RING_SECTION_NAME L"\\BaseNamedObjects\\AgentLensEventRing"
#define AGL_EVENT_READY_EVENT_NAME L"\\BaseNamedObjects\\AgentLensEventReady"

static AGL_EVENT_RING_SHARED_HEADER* AglSharedHeader(void)
{
    if (!AglEventRing.Base)
    {
        return NULL;
    }
    return (AGL_EVENT_RING_SHARED_HEADER*)((PUCHAR)AglEventRing.Base - AglEventRing.DataOffset);
}

NTSTATUS AglEventRingInitialize(SIZE_T Size)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING sectionName;
    UNICODE_STRING eventName;
    LARGE_INTEGER maximumSize;
    PVOID sectionObject = NULL;
    PVOID mappedBase = NULL;
    SIZE_T viewSize = 0;
    HANDLE sectionHandle = NULL;
    HANDLE readyEvent = NULL;
    PKEVENT readyEventObject = NULL;

    if (Size < PAGE_SIZE)
    {
        Size = PAGE_SIZE;
    }

    maximumSize.QuadPart = (LONGLONG)(sizeof(AGL_EVENT_RING_SHARED_HEADER) + Size);
    RtlInitUnicodeString(&sectionName, AGL_EVENT_RING_SECTION_NAME);
    InitializeObjectAttributes(
        &objectAttributes,
        &sectionName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    status = ZwCreateSection(
        &sectionHandle,
        SECTION_MAP_READ | SECTION_MAP_WRITE,
        &objectAttributes,
        &maximumSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ObReferenceObjectByHandle(
        sectionHandle,
        SECTION_MAP_READ | SECTION_MAP_WRITE,
        NULL,
        KernelMode,
        &sectionObject,
        NULL);
    if (!NT_SUCCESS(status))
    {
        ZwClose(sectionHandle);
        return status;
    }

    status = MmMapViewInSystemSpace(sectionObject, &mappedBase, &viewSize);
    if (!NT_SUCCESS(status) || viewSize < (SIZE_T)maximumSize.QuadPart)
    {
        ObDereferenceObject(sectionObject);
        ZwClose(sectionHandle);
        return status;
    }

    RtlInitUnicodeString(&eventName, AGL_EVENT_READY_EVENT_NAME);
    InitializeObjectAttributes(
        &objectAttributes,
        &eventName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    readyEventObject = IoCreateSynchronizationEvent(&eventName, &readyEvent);
    if (!readyEventObject)
    {
        MmUnmapViewInSystemSpace(mappedBase);
        ObDereferenceObject(sectionObject);
        ZwClose(sectionHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ZwClose(readyEvent);

    AglEventRing.SectionObject = sectionObject;
    AglEventRing.SectionHandle = sectionHandle;
    AglEventRing.ReadyEventObject = readyEventObject;
    AglEventRing.DataOffset = sizeof(AGL_EVENT_RING_SHARED_HEADER);
    AglEventRing.Base = (PUCHAR)mappedBase + AglEventRing.DataOffset;
    AglEventRing.Size = Size;
    AglEventRing.Head = 0;
    AglEventRing.Tail = 0;
    AglEventRing.Written = 0;
    AglEventRing.Read = 0;
    AglEventRing.Dropped = 0;
    AglEventRing.ActiveSubscribers = 0;
    KeInitializeSpinLock(&AglEventRing.Lock);

    {
        AGL_EVENT_RING_SHARED_HEADER* header = AglSharedHeader();
        if (header)
        {
            header->Magic = AGL_EVENT_RING_MAGIC;
            header->Version = AGL_PROTOCOL_VERSION;
            header->Size = (ULONG64)Size;
            header->Head = 0;
            header->Tail = 0;
            header->Written = 0;
            header->Dropped = 0;
        }
    }

    return STATUS_SUCCESS;
}

void AglEventRingDestroy(void)
{
    PVOID mappedBase = (PUCHAR)AglEventRing.Base - AglEventRing.DataOffset;

    if (AglEventRing.ReadyEventObject)
    {
        ObDereferenceObject(AglEventRing.ReadyEventObject);
        AglEventRing.ReadyEventObject = NULL;
    }

    if (AglEventRing.Base)
    {
        MmUnmapViewInSystemSpace(mappedBase);
        AglEventRing.Base = NULL;
    }

    if (AglEventRing.SectionObject)
    {
        ObDereferenceObject(AglEventRing.SectionObject);
        AglEventRing.SectionObject = NULL;
    }

    if (AglEventRing.SectionHandle)
    {
        ZwClose(AglEventRing.SectionHandle);
        AglEventRing.SectionHandle = NULL;
    }
}

ULONG AglEventRingSubscribe(void)
{
    return InterlockedIncrement((LONG*)&AglEventRing.ActiveSubscribers);
}

void AglEventRingUnsubscribe(void)
{
    LONG value = InterlockedDecrement((LONG*)&AglEventRing.ActiveSubscribers);
    if (value < 0)
    {
        InterlockedExchange((LONG*)&AglEventRing.ActiveSubscribers, 0);
    }
}

NTSTATUS AglEventRingWrite(PVOID Data, ULONG Length)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PUCHAR base;
    SIZE_T head;

    if (!Data || Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    base = (PUCHAR)AglEventRing.Base;
    KeAcquireInStackQueuedSpinLock(&AglEventRing.Lock, &lockHandle);
    head = AglEventRing.Head;

    if (Length > AglEventRing.Size)
    {
        AglEventRing.Dropped++;
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return STATUS_BUFFER_TOO_SMALL;
    }

    if ((head + Length) <= AglEventRing.Size)
    {
        RtlCopyMemory(base + head, Data, Length);
    }
    else
    {
        SIZE_T first = AglEventRing.Size - head;
        RtlCopyMemory(base + head, Data, first);
        RtlCopyMemory(base, (PUCHAR)Data + first, Length - first);
    }

    AglEventRing.Head = (head + Length) % AglEventRing.Size;
    AglEventRing.Written++;
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    {
        AGL_EVENT_RING_SHARED_HEADER* header = AglSharedHeader();
        if (header)
        {
            header->Head = (ULONG64)AglEventRing.Head;
            header->Written = AglEventRing.Written;
            header->Dropped = AglEventRing.Dropped;
        }
    }

    if (AglEventRing.ReadyEventObject)
    {
        KeSetEvent(AglEventRing.ReadyEventObject, IO_NO_INCREMENT, FALSE);
    }
    return STATUS_SUCCESS;
}

NTSTATUS AglEventRingRead(PVOID Buffer, ULONG BufferLength, PULONG BytesReturned)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    SIZE_T tail;
    SIZE_T available;
    SIZE_T first;
    PUCHAR base;

    if (!Buffer || BufferLength == 0 || !BytesReturned)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *BytesReturned = 0;
    base = (PUCHAR)AglEventRing.Base;

    KeAcquireInStackQueuedSpinLock(&AglEventRing.Lock, &lockHandle);
    tail = AglEventRing.Tail;
    if (AglEventRing.Head >= tail)
    {
        available = AglEventRing.Head - tail;
    }
    else
    {
        available = AglEventRing.Size - tail + AglEventRing.Head;
    }

    if (available == 0)
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return STATUS_NO_MORE_ENTRIES;
    }

    if ((ULONG)available > BufferLength)
    {
        available = BufferLength;
    }

    first = AglEventRing.Size - tail;
    if (first > available)
    {
        first = available;
    }

    RtlCopyMemory(Buffer, base + tail, first);
    if (available > first)
    {
        RtlCopyMemory((PUCHAR)Buffer + first, base, available - first);
    }

    AglEventRing.Tail = (tail + available) % AglEventRing.Size;
    AglEventRing.Read++;
    *BytesReturned = (ULONG)available;
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    {
        AGL_EVENT_RING_SHARED_HEADER* header = AglSharedHeader();
        if (header)
        {
            header->Tail = (ULONG64)AglEventRing.Tail;
        }
    }
    return STATUS_SUCCESS;
}

void AglEventRingGetStats(PVOID Stats, ULONG StatsLength)
{
    AGL_STATS local;

    RtlZeroMemory(&local, sizeof(local));
    local.EventsWritten = AglEventRing.Written;
    local.EventsRead = AglEventRing.Read;
    local.EventsDropped = AglEventRing.Dropped;
    local.RingBytesTotal = (ULONG64)AglEventRing.Size;
    local.RingBytesUsed = (AglEventRing.Head >= AglEventRing.Tail)
        ? (ULONG64)(AglEventRing.Head - AglEventRing.Tail)
        : (ULONG64)(AglEventRing.Size - AglEventRing.Tail + AglEventRing.Head);
    local.ActiveSubscribers = AglEventRing.ActiveSubscribers;

    if (StatsLength > sizeof(local))
    {
        StatsLength = sizeof(local);
    }
    RtlCopyMemory(Stats, &local, StatsLength);
}
