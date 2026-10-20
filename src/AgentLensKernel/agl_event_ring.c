#include <ntifs.h>
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

static NTSTATUS AglCreateReadyEvent(
    PUNICODE_STRING EventName,
    PKEVENT* EventObject)
{
    SECURITY_DESCRIPTOR securityDescriptor;
    PACL dacl = NULL;
    ULONG daclSize;
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE eventHandle = NULL;
    PKEVENT eventObject = NULL;
    NTSTATUS status;

    daclSize = sizeof(ACL) +
        (sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG)) * 2 +
        RtlLengthSid(SeExports->SeLocalSystemSid) +
        RtlLengthSid(SeExports->SeAliasAdminsSid);

    dacl = (PACL)AglAllocNonPaged(daclSize);
    if (!dacl)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RtlCreateAcl(dacl, daclSize, ACL_REVISION);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    status = RtlAddAccessAllowedAce(
        dacl,
        ACL_REVISION,
        EVENT_ALL_ACCESS,
        SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    status = RtlAddAccessAllowedAce(
        dacl,
        ACL_REVISION,
        EVENT_ALL_ACCESS,
        SeExports->SeAliasAdminsSid);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = RtlCreateSecurityDescriptor(
        &securityDescriptor,
        SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    status = RtlSetDaclSecurityDescriptor(
        &securityDescriptor,
        TRUE,
        dacl,
        FALSE);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        EventName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        &securityDescriptor);

    status = ZwCreateEvent(
        &eventHandle,
        EVENT_ALL_ACCESS,
        &objectAttributes,
        SynchronizationEvent,
        FALSE);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    status = ObReferenceObjectByHandle(
        eventHandle,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        (PVOID*)&eventObject,
        NULL);
    if (NT_SUCCESS(status))
    {
        *EventObject = eventObject;
    }

Exit:
    if (eventHandle)
    {
        ZwClose(eventHandle);
    }
    AglFree(dacl);
    return status;
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
    PKEVENT readyEventObject = NULL;
    SECURITY_DESCRIPTOR securityDescriptor;
    PACL emptyDacl = NULL;

    if (Size < PAGE_SIZE)
    {
        Size = PAGE_SIZE;
    }

    // The shared section is an internal kernel buffer. User mode has no reason
    // to map it (the service consumes events through the control device), so
    // give it an empty DACL and fail closed if the descriptor cannot be built.
    emptyDacl = (PACL)AglAllocNonPaged(sizeof(ACL));
    if (!emptyDacl)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    status = RtlCreateAcl(emptyDacl, sizeof(ACL), ACL_REVISION);
    if (!NT_SUCCESS(status))
    {
        AglFree(emptyDacl);
        return status;
    }
    status = RtlCreateSecurityDescriptor(
        &securityDescriptor,
        SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status))
    {
        AglFree(emptyDacl);
        return status;
    }
    status = RtlSetDaclSecurityDescriptor(
        &securityDescriptor,
        TRUE,
        emptyDacl,
        FALSE);
    if (!NT_SUCCESS(status))
    {
        AglFree(emptyDacl);
        return status;
    }

    maximumSize.QuadPart = (LONGLONG)(sizeof(AGL_EVENT_RING_SHARED_HEADER) + Size);
    RtlInitUnicodeString(&sectionName, AGL_EVENT_RING_SECTION_NAME);
    InitializeObjectAttributes(
        &objectAttributes,
        &sectionName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        &securityDescriptor);

    status = ZwCreateSection(
        &sectionHandle,
        SECTION_MAP_READ | SECTION_MAP_WRITE,
        &objectAttributes,
        &maximumSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);
    AglFree(emptyDacl);
    emptyDacl = NULL;
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
        if (NT_SUCCESS(status))
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        ObDereferenceObject(sectionObject);
        ZwClose(sectionHandle);
        return status;
    }

    RtlInitUnicodeString(&eventName, AGL_EVENT_READY_EVENT_NAME);
    status = AglCreateReadyEvent(&eventName, &readyEventObject);
    if (!NT_SUCCESS(status))
    {
        MmUnmapViewInSystemSpace(mappedBase);
        ObDereferenceObject(sectionObject);
        ZwClose(sectionHandle);
        return status;
    }

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
    AglEventRing.CriticalDropped = 0;
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
    SIZE_T tail;
    SIZE_T used;
    SIZE_T freeSpace;
    AGL_RING_RECORD_HEADER* recordHeader = (AGL_RING_RECORD_HEADER*)Data;

    if (!Data || Length == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    base = (PUCHAR)AglEventRing.Base;
    KeAcquireInStackQueuedSpinLock(&AglEventRing.Lock, &lockHandle);
    head = AglEventRing.Head;
    tail = AglEventRing.Tail;

    if (Length > AglEventRing.Size)
    {
        AglEventRing.Dropped++;
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return STATUS_BUFFER_TOO_SMALL;
    }

    used = (head >= tail) ? (head - tail) : (AglEventRing.Size - tail + head);
    // Keep one byte unused so a completely full ring is distinguishable from an
    // empty one (Head == Tail must always mean empty).
    freeSpace = (used < AglEventRing.Size) ? (AglEventRing.Size - used - 1) : 0;

    if (Length > freeSpace)
    {
        AglEventRing.Dropped++;
        if ((recordHeader->Flags & AGL_EVENT_FLAG_CRITICAL) != 0)
        {
            AglEventRing.CriticalDropped++;
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        {
            AGL_EVENT_RING_SHARED_HEADER* sharedHeader = AglSharedHeader();
            if (sharedHeader)
            {
                sharedHeader->Dropped = AglEventRing.Dropped;
            }
        }
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
    SIZE_T head;
    SIZE_T available;
    SIZE_T copied = 0;
    PUCHAR base;
    BOOLEAN tooLarge = FALSE;

    if (!Buffer || !BytesReturned)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (BufferLength < sizeof(AGL_RING_RECORD_HEADER))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    *BytesReturned = 0;
    base = (PUCHAR)AglEventRing.Base;

    KeAcquireInStackQueuedSpinLock(&AglEventRing.Lock, &lockHandle);
    tail = AglEventRing.Tail;
    head = AglEventRing.Head;
    if (head >= tail)
    {
        available = head - tail;
    }
    else
    {
        available = AglEventRing.Size - tail + head;
    }

    if (available == 0)
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return STATUS_NO_MORE_ENTRIES;
    }

    // Consumers only ever receive complete records. A record that does not fit
    // into the caller's buffer is left in the ring for the next read.
    while (copied < available &&
           copied + sizeof(AGL_RING_RECORD_HEADER) <= BufferLength)
    {
        SIZE_T position = (tail + copied) % AglEventRing.Size;
        SIZE_T firstPart = AglEventRing.Size - position;
        SIZE_T remaining = available - copied;
        AGL_RING_RECORD_HEADER recordHeader;

        if (firstPart >= sizeof(recordHeader))
        {
            RtlCopyMemory(&recordHeader, base + position, sizeof(recordHeader));
        }
        else
        {
            RtlCopyMemory(&recordHeader, base + position, firstPart);
            RtlCopyMemory(
                (PUCHAR)&recordHeader + firstPart,
                base,
                sizeof(recordHeader) - firstPart);
        }

        if (recordHeader.RecordLength <
                sizeof(AGL_RING_RECORD_HEADER) + sizeof(AGL_EVENT_HEADER) ||
            recordHeader.RecordLength > AglEventRing.Size ||
            recordHeader.RecordLength > remaining)
        {
            break;
        }

        if (recordHeader.RecordLength > BufferLength - copied)
        {
            tooLarge = TRUE;
            break;
        }

        position = (tail + copied) % AglEventRing.Size;
        firstPart = AglEventRing.Size - position;
        if (firstPart > recordHeader.RecordLength)
        {
            firstPart = recordHeader.RecordLength;
        }
        RtlCopyMemory((PUCHAR)Buffer + copied, base + position, firstPart);
        if (recordHeader.RecordLength > firstPart)
        {
            RtlCopyMemory(
                (PUCHAR)Buffer + copied + firstPart,
                base,
                recordHeader.RecordLength - firstPart);
        }
        copied += recordHeader.RecordLength;
    }

    if (copied == 0)
    {
        if (tooLarge)
        {
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            return STATUS_BUFFER_TOO_SMALL;
        }

        // Corrupt framing can never be recovered by re-reading the same bytes;
        // discard the unread remainder so the reader cannot stall forever.
        AglEventRing.Tail = head;
        AglEventRing.Read++;
        AglEventRing.Dropped++;
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        {
            AGL_EVENT_RING_SHARED_HEADER* sharedHeader = AglSharedHeader();
            if (sharedHeader)
            {
                sharedHeader->Tail = (ULONG64)AglEventRing.Tail;
                sharedHeader->Dropped = AglEventRing.Dropped;
            }
        }
        return STATUS_NO_MORE_ENTRIES;
    }

    AglEventRing.Tail = (tail + copied) % AglEventRing.Size;
    AglEventRing.Read++;
    *BytesReturned = (ULONG)copied;
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    {
        AGL_EVENT_RING_SHARED_HEADER* sharedHeader = AglSharedHeader();
        if (sharedHeader)
        {
            sharedHeader->Tail = (ULONG64)AglEventRing.Tail;
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
    local.CriticalDropped = AglEventRing.CriticalDropped;
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
