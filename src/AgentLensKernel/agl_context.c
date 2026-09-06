#include <ntifs.h>
#include "agl_context.h"
#include "agl_control.h"
#include "agl_util.h"
#include "agl_trace.h"

AGL_CONTEXT_MANAGER AglContext = { 0 };

void AglContextInitialize(void)
{
    KeInitializeSpinLock(&AglContext.Lock);
    InitializeListHead(&AglContext.ProcessList);
    InitializeListHead(&AglContext.ThreadList);
    InitializeListHead(&AglContext.ImageList);
    InitializeListHead(&AglContext.FlowList);
    AglContext.NextCorrelationId = 1;
}

void AglContextDestroy(void)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    PLIST_ENTRY next;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    entry = AglContext.ProcessList.Flink;
    while (entry != &AglContext.ProcessList)
    {
        next = entry->Flink;
        RemoveEntryList(entry);
        entry = next;
    }
    AglContext.ProcessCount = 0;

    entry = AglContext.ThreadList.Flink;
    while (entry != &AglContext.ThreadList)
    {
        next = entry->Flink;
        RemoveEntryList(entry);
        AglFree(CONTAINING_RECORD(entry, AGL_THREAD_CTX, ListEntry));
        entry = next;
    }
    AglContext.ThreadCount = 0;

    entry = AglContext.ImageList.Flink;
    while (entry != &AglContext.ImageList)
    {
        next = entry->Flink;
        RemoveEntryList(entry);
        AglFree(CONTAINING_RECORD(entry, AGL_IMAGE_CTX, ListEntry));
        entry = next;
    }
    AglContext.ImageCount = 0;

    entry = AglContext.FlowList.Flink;
    while (entry != &AglContext.FlowList)
    {
        next = entry->Flink;
        RemoveEntryList(entry);
        AglFree(CONTAINING_RECORD(entry, AGL_NET_FLOW_CTX, ListEntry));
        entry = next;
    }
    AglContext.FlowCount = 0;
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

void AglContextFlushTombstones(void)
{
    LARGE_INTEGER delay;
    ULONG i;

    delay.QuadPart = -10 * 1000; // 10 ms
    for (i = 0; i < 1000 && AglContext.PendingTombstones != 0; i++)
    {
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
}

static void AglFreeProcessCtx(AGL_PROCESS_CTX* Ctx)
{
    if (!Ctx)
    {
        return;
    }

    AglFreeUnicodeString(&Ctx->ImagePath);
    AglFreeUnicodeString(&Ctx->ImageName);
    AglFreeUnicodeString(&Ctx->CommandLine);
    AglFreeUnicodeString(&Ctx->CurrentDirectory);
    AglFree(Ctx);
}

static VOID AglTombstoneWorker(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    AGL_PROCESS_CTX* ctx = (AGL_PROCESS_CTX*)Context;
    LARGE_INTEGER delay;

    UNREFERENCED_PARAMETER(DeviceObject);

    delay.QuadPart = -5 * 1000 * 1000 * 10; // 5 seconds
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    if (ctx->WorkItem)
    {
        IoFreeWorkItem(ctx->WorkItem);
        ctx->WorkItem = NULL;
    }
    AglFreeProcessCtx(ctx);
    InterlockedDecrement(&AglContext.PendingTombstones);
}

static VOID AglQueueTombstone(AGL_PROCESS_CTX* Ctx)
{
    PIO_WORKITEM workItem;

    if (InterlockedCompareExchange(&Ctx->TombstoneQueued, 1, 0) != 0)
    {
        return;
    }

    workItem = IoAllocateWorkItem(AglControlGetDevice());
    if (!workItem)
    {
        InterlockedExchange(&Ctx->TombstoneQueued, 0);
        AglFreeProcessCtx(Ctx);
        return;
    }

    Ctx->WorkItem = workItem;
    InterlockedIncrement(&AglContext.PendingTombstones);
    IoQueueWorkItem(workItem, AglTombstoneWorker, DelayedWorkQueue, Ctx);
}

AGL_PROCESS_CTX* AglContextAcquireProcess(ULONG64 ProcessId)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    AGL_PROCESS_CTX* ctx = NULL;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.ProcessList.Flink;
         entry != &AglContext.ProcessList;
         entry = entry->Flink)
    {
        AGL_PROCESS_CTX* item = CONTAINING_RECORD(entry, AGL_PROCESS_CTX, ListEntry);
        if (item->ProcessId == ProcessId)
        {
            item->RefCount++;
            ctx = item;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return ctx;
}

AGL_PROCESS_CTX* AglContextAcquireProcessValidated(ULONG64 ProcessId)
{
    PEPROCESS processObject = NULL;
    ULONG64 createTime = 0;
    AGL_PROCESS_CTX* ctx;
    NTSTATUS status;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &processObject);
    if (!NT_SUCCESS(status))
    {
        return NULL;
    }

    createTime = (ULONG64)PsGetProcessCreateTimeQuadPart(processObject);
    ObDereferenceObject(processObject);

    ctx = AglContextAcquireProcess(ProcessId);
    if (ctx && ctx->CreateTime != createTime)
    {
        AglContextReleaseProcess(ctx);
        return NULL;
    }

    return ctx;
}

void AglContextReleaseProcess(AGL_PROCESS_CTX* Ctx)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    LONG refs;

    if (!Ctx)
    {
        return;
    }

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    refs = InterlockedDecrement(&Ctx->RefCount);
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (refs == 0)
    {
        if (Ctx->Tombstoned)
        {
            AglQueueTombstone(Ctx);
        }
        else
        {
            AglFreeProcessCtx(Ctx);
        }
    }
}

AGL_PROCESS_CTX* AglContextGetOrCreateProcess(
    ULONG64 ProcessId,
    ULONG64 ParentProcessId,
    ULONG64 CreateTime,
    ULONG64 CorrelationId,
    ULONG64 ParentCorrelationId,
    ULONG SessionId,
    PCUNICODE_STRING ImagePath,
    PCUNICODE_STRING ImageName,
    PCUNICODE_STRING CommandLine)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    AGL_PROCESS_CTX* ctx = NULL;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);

    for (entry = AglContext.ProcessList.Flink;
         entry != &AglContext.ProcessList;
         entry = entry->Flink)
    {
        AGL_PROCESS_CTX* item = CONTAINING_RECORD(entry, AGL_PROCESS_CTX, ListEntry);
        if (item->ProcessId == ProcessId)
        {
            item->RefCount++;
            ctx = item;
            break;
        }
    }

    if (!ctx)
    {
        ctx = AglAllocNonPaged(sizeof(*ctx));
        if (ctx)
        {
            RtlZeroMemory(ctx, sizeof(*ctx));
            ctx->ProcessId = ProcessId;
            ctx->ParentProcessId = ParentProcessId;
            ctx->CreateTime = CreateTime;
            ctx->CorrelationId = CorrelationId;
            ctx->ParentCorrelationId = ParentCorrelationId;
            ctx->AgentSessionId = CorrelationId;
            ctx->SessionId = SessionId;
            ctx->RefCount = 1;
            ctx->Version = 1;

            AglCopyUnicodeString(ImagePath, &ctx->ImagePath, PagedPool);
            AglCopyUnicodeString(ImageName, &ctx->ImageName, PagedPool);
            AglCopyUnicodeString(CommandLine, &ctx->CommandLine, PagedPool);

            InsertTailList(&AglContext.ProcessList, &ctx->ListEntry);
            AglContext.ProcessCount++;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return ctx;
}

void AglContextRemoveProcess(ULONG64 ProcessId)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    AGL_PROCESS_CTX* itemToQueue = NULL;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.ProcessList.Flink;
         entry != &AglContext.ProcessList;
         entry = entry->Flink)
    {
        AGL_PROCESS_CTX* item = CONTAINING_RECORD(entry, AGL_PROCESS_CTX, ListEntry);
        if (item->ProcessId == ProcessId)
        {
            RemoveEntryList(entry);
            AglContext.ProcessCount--;
            item->Tombstoned = TRUE;
            {
                LARGE_INTEGER systemTime;
                KeQuerySystemTime(&systemTime);
                item->ExitTime = (ULONG64)systemTime.QuadPart;
            }
            if (InterlockedDecrement(&item->RefCount) == 0)
            {
                itemToQueue = item;
            }
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (itemToQueue)
    {
        AglQueueTombstone(itemToQueue);
    }
}

void AglContextUpdateProcess(ULONG64 ProcessId, ULONG EnvironmentHash, PCUNICODE_STRING CurrentDirectory)
{
    AGL_PROCESS_CTX* ctx = AglContextAcquireProcess(ProcessId);

    if (ctx)
    {
        ctx->EnvironmentHash = EnvironmentHash;
        AglFreeUnicodeString(&ctx->CurrentDirectory);
        AglCopyUnicodeString(CurrentDirectory, &ctx->CurrentDirectory, NonPagedPool);
        AglContextReleaseProcess(ctx);
    }
}

ULONG64 AglContextNextCorrelationId(void)
{
    return InterlockedIncrement64((LONG64*)&AglContext.NextCorrelationId);
}

ULONG64 AglContextGetCorrelationId(ULONG64 ProcessId)
{
    AGL_PROCESS_CTX* ctx = AglContextAcquireProcess(ProcessId);
    ULONG64 correlationId = 0;

    if (ctx)
    {
        correlationId = ctx->CorrelationId;
        AglContextReleaseProcess(ctx);
    }

    return correlationId;
}

AGL_THREAD_CTX* AglContextGetOrCreateThread(ULONG64 ProcessId, ULONG64 ThreadId)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    AGL_THREAD_CTX* ctx = NULL;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.ThreadList.Flink;
         entry != &AglContext.ThreadList;
         entry = entry->Flink)
    {
        AGL_THREAD_CTX* item = CONTAINING_RECORD(entry, AGL_THREAD_CTX, ListEntry);
        if (item->ThreadId == ThreadId)
        {
            ctx = item;
            break;
        }
    }

    if (!ctx)
    {
        ctx = AglAllocNonPaged(sizeof(*ctx));
        if (ctx)
        {
            RtlZeroMemory(ctx, sizeof(*ctx));
            ctx->ThreadId = ThreadId;
            ctx->ProcessId = ProcessId;
            ctx->CreateTime = (ULONG64)KeQueryInterruptTime();
            InsertTailList(&AglContext.ThreadList, &ctx->ListEntry);
            AglContext.ThreadCount++;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return ctx;
}

void AglContextRemoveThread(ULONG64 ThreadId)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.ThreadList.Flink;
         entry != &AglContext.ThreadList;
         entry = entry->Flink)
    {
        AGL_THREAD_CTX* item = CONTAINING_RECORD(entry, AGL_THREAD_CTX, ListEntry);
        if (item->ThreadId == ThreadId)
        {
            RemoveEntryList(entry);
            AglContext.ThreadCount--;
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            AglFree(item);
            return;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

AGL_IMAGE_CTX* AglContextGetOrCreateImage(
    ULONG64 ProcessId,
    ULONG64 ImageBase,
    ULONG ImageSize,
    ULONG PathHash)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    AGL_IMAGE_CTX* ctx = NULL;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.ImageList.Flink;
         entry != &AglContext.ImageList;
         entry = entry->Flink)
    {
        AGL_IMAGE_CTX* item = CONTAINING_RECORD(entry, AGL_IMAGE_CTX, ListEntry);
        if (item->ProcessId == ProcessId && item->ImageBase == ImageBase)
        {
            ctx = item;
            break;
        }
    }

    if (!ctx)
    {
        ctx = AglAllocNonPaged(sizeof(*ctx));
        if (ctx)
        {
            RtlZeroMemory(ctx, sizeof(*ctx));
            ctx->ProcessId = ProcessId;
            ctx->ImageBase = ImageBase;
            ctx->ImageSize = ImageSize;
            ctx->FileSize = ImageSize;
            ctx->PathHash = PathHash;
            InsertTailList(&AglContext.ImageList, &ctx->ListEntry);
            AglContext.ImageCount++;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return ctx;
}

void AglContextUpdateImage(
    ULONG64 ProcessId,
    ULONG64 ImageBase,
    ULONG PathHash,
    PUCHAR FileSha256,
    ULONG SignerState)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.ImageList.Flink;
         entry != &AglContext.ImageList;
         entry = entry->Flink)
    {
        AGL_IMAGE_CTX* item = CONTAINING_RECORD(entry, AGL_IMAGE_CTX, ListEntry);
        if (item->ProcessId == ProcessId && item->ImageBase == ImageBase)
        {
            item->PathHash = PathHash;
            item->SignerState = SignerState;
            if (FileSha256)
            {
                RtlCopyMemory(item->FileSha256, FileSha256, 32);
                item->FileHashValid = TRUE;
            }
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

AGL_NET_FLOW_CTX* AglContextGetOrCreateFlow(
    ULONG64 FlowId,
    ULONG64 ProcessId,
    ULONG Protocol,
    USHORT RemotePort,
    USHORT LocalPort,
    const UCHAR* RemoteAddress)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    AGL_NET_FLOW_CTX* ctx = NULL;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.FlowList.Flink;
         entry != &AglContext.FlowList;
         entry = entry->Flink)
    {
        AGL_NET_FLOW_CTX* item = CONTAINING_RECORD(entry, AGL_NET_FLOW_CTX, ListEntry);
        if (item->FlowId == FlowId)
        {
            ctx = item;
            break;
        }
    }

    if (!ctx)
    {
        ctx = AglAllocNonPaged(sizeof(*ctx));
        if (ctx)
        {
            RtlZeroMemory(ctx, sizeof(*ctx));
            ctx->FlowId = FlowId;
            ctx->ProcessId = ProcessId;
            ctx->Protocol = Protocol;
            ctx->RemotePort = RemotePort;
            ctx->LocalPort = LocalPort;
            if (RemoteAddress)
            {
                RtlCopyMemory(ctx->RemoteAddress, RemoteAddress, 16);
            }
            InsertTailList(&AglContext.FlowList, &ctx->ListEntry);
            AglContext.FlowCount++;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return ctx;
}

void AglContextRemoveFlow(ULONG64 FlowId)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.FlowList.Flink;
         entry != &AglContext.FlowList;
         entry = entry->Flink)
    {
        AGL_NET_FLOW_CTX* item = CONTAINING_RECORD(entry, AGL_NET_FLOW_CTX, ListEntry);
        if (item->FlowId == FlowId)
        {
            RemoveEntryList(entry);
            AglContext.FlowCount--;
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            AglFree(item);
            return;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

void AglContextAddFlowStats(ULONG64 FlowId, ULONG64 Bytes, ULONG64 Packets)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.FlowList.Flink;
         entry != &AglContext.FlowList;
         entry = entry->Flink)
    {
        AGL_NET_FLOW_CTX* item = CONTAINING_RECORD(entry, AGL_NET_FLOW_CTX, ListEntry);
        if (item->FlowId == FlowId)
        {
            item->Bytes += Bytes;
            item->Packets += Packets;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

void AglContextAddFlowDirectionStats(
    ULONG64 FlowId,
    BOOLEAN Send,
    ULONG64 Bytes,
    ULONG64 Packets)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.FlowList.Flink;
         entry != &AglContext.FlowList;
         entry = entry->Flink)
    {
        AGL_NET_FLOW_CTX* item = CONTAINING_RECORD(entry, AGL_NET_FLOW_CTX, ListEntry);
        if (item->FlowId == FlowId)
        {
            item->Bytes += Bytes;
            item->Packets += Packets;
            if (Send)
            {
                item->SendBytes += Bytes;
                item->SendPackets += Packets;
            }
            else
            {
                item->RecvBytes += Bytes;
                item->RecvPackets += Packets;
            }
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

BOOLEAN AglContextGetFlowSnapshot(ULONG64 FlowId, AGL_NET_FLOW_CTX* Out)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    BOOLEAN found = FALSE;

    KeAcquireInStackQueuedSpinLock(&AglContext.Lock, &lockHandle);
    for (entry = AglContext.FlowList.Flink;
         entry != &AglContext.FlowList;
         entry = entry->Flink)
    {
        AGL_NET_FLOW_CTX* item = CONTAINING_RECORD(entry, AGL_NET_FLOW_CTX, ListEntry);
        if (item->FlowId == FlowId)
        {
            RtlCopyMemory(Out, item, sizeof(*Out));
            found = TRUE;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return found;
}
