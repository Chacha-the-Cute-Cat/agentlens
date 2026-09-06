#include "agl_context.h"
#include "agl_util.h"
#include "agl_trace.h"

AGL_CONTEXT_MANAGER AglContext = { 0 };

void AglContextInitialize(void)
{
    KeInitializeSpinLock(&AglContext.Lock);
    InitializeListHead(&AglContext.ProcessList);
    InitializeListHead(&AglContext.ThreadList);
    InitializeListHead(&AglContext.ImageList);
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
    KeReleaseInStackQueuedSpinLock(&lockHandle);
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
    AglFree(Ctx);
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
        AglFreeProcessCtx(Ctx);
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
            if (InterlockedDecrement(&item->RefCount) == 0)
            {
                KeReleaseInStackQueuedSpinLock(&lockHandle);
                AglFreeProcessCtx(item);
                return;
            }
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
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
            ctx->PathHash = PathHash;
            InsertTailList(&AglContext.ImageList, &ctx->ListEntry);
            AglContext.ImageCount++;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return ctx;
}
