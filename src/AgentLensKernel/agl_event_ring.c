#include <ntifs.h>
#include "agl_event_ring.h"
#include "agl_util.h"
#include "agl_control.h"
#include "AgentLensProtocol/agl_control.h"

AGL_EVENT_RING AglEventRing = { 0 };

#define AGL_EVENT_READY_EVENT_NAME L"\\BaseNamedObjects\\AgentLensEventReady"

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
    UNICODE_STRING eventName;
    PVOID base;
    PKEVENT readyEventObject = NULL;

    if (Size < PAGE_SIZE)
    {
        Size = PAGE_SIZE;
    }

    /*
     * Event callbacks can run at DISPATCH_LEVEL while the ring lock is held.
     * Keep the backing buffer in nonpaged pool so those copies cannot fault.
     */
    base = AglAllocNonPaged(Size);
    if (!base)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&eventName, AGL_EVENT_READY_EVENT_NAME);
    status = AglCreateReadyEvent(&eventName, &readyEventObject);
    if (!NT_SUCCESS(status))
    {
        AglFree(base);
        return status;
    }
    KeClearEvent(readyEventObject);

    RtlZeroMemory(&AglEventRing, sizeof(AglEventRing));
    KeInitializeSpinLock(&AglEventRing.Lock);
    AglEventRing.ReadyEventObject = readyEventObject;
    AglEventRing.Base = base;
    AglEventRing.Size = Size;
    AglEventRing.Head = 0;
    AglEventRing.Tail = 0;
    AglEventRing.Written = 0;
    AglEventRing.Read = 0;
    AglEventRing.Dropped = 0;
    AglEventRing.CriticalDropped = 0;
    AglEventRing.ActiveSubscribers = 0;

    return STATUS_SUCCESS;
}

void AglEventRingDestroy(void)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PVOID base;
    PKEVENT readyEvent;

    KeAcquireInStackQueuedSpinLock(&AglEventRing.Lock, &lockHandle);
    base = AglEventRing.Base;
    AglEventRing.Base = NULL;
    AglEventRing.Size = 0;
    readyEvent = AglEventRing.ReadyEventObject;
    AglEventRing.ReadyEventObject = NULL;
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (readyEvent)
    {
        ObDereferenceObject(readyEvent);
    }

    AglFree(base);
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
    AGL_RING_RECORD_HEADER* recordHeader;

    if (!Data ||
        Length < sizeof(AGL_RING_RECORD_HEADER) + sizeof(AGL_EVENT_HEADER))
    {
        return STATUS_INVALID_PARAMETER;
    }
    recordHeader = (AGL_RING_RECORD_HEADER*)Data;
    if (recordHeader->RecordLength != Length)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireInStackQueuedSpinLock(&AglEventRing.Lock, &lockHandle);
    base = (PUCHAR)AglEventRing.Base;
    if (!base || AglEventRing.Size == 0)
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return STATUS_DEVICE_NOT_READY;
    }
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

    if (AglEventRing.ReadyEventObject)
    {
        KeSetEvent(AglEventRing.ReadyEventObject, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
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
    KeAcquireInStackQueuedSpinLock(&AglEventRing.Lock, &lockHandle);
    base = (PUCHAR)AglEventRing.Base;
    if (!base || AglEventRing.Size == 0)
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return STATUS_DEVICE_NOT_READY;
    }
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
        return STATUS_NO_MORE_ENTRIES;
    }

    AglEventRing.Tail = (tail + copied) % AglEventRing.Size;
    AglEventRing.Read++;
    *BytesReturned = (ULONG)copied;
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return STATUS_SUCCESS;
}

void AglEventRingGetStats(PVOID Stats, ULONG StatsLength)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    AGL_STATS local;

    if (!Stats || StatsLength == 0)
    {
        return;
    }

    RtlZeroMemory(&local, sizeof(local));
    KeAcquireInStackQueuedSpinLock(&AglEventRing.Lock, &lockHandle);
    local.EventsWritten = AglEventRing.Written;
    local.EventsRead = AglEventRing.Read;
    local.EventsDropped = AglEventRing.Dropped;
    local.CriticalDropped = AglEventRing.CriticalDropped;
    local.RingBytesTotal = (ULONG64)AglEventRing.Size;
    if (AglEventRing.Base && AglEventRing.Size != 0)
    {
        local.RingBytesUsed = (AglEventRing.Head >= AglEventRing.Tail)
            ? (ULONG64)(AglEventRing.Head - AglEventRing.Tail)
            : (ULONG64)(AglEventRing.Size - AglEventRing.Tail + AglEventRing.Head);
    }
    local.ActiveSubscribers = AglEventRing.ActiveSubscribers;
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (StatsLength > sizeof(local))
    {
        StatsLength = sizeof(local);
    }
    RtlCopyMemory(Stats, &local, StatsLength);
}
