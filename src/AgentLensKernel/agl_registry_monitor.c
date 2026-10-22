#include <ntifs.h>
#include "agl_monitors.h"
#include "agl_event.h"
#include "agl_policy.h"
#include "agl_policy.h"
#include "agl_util.h"
#include "agl_trace.h"

static LARGE_INTEGER AglRegistryCookie = { 0 };
static BOOLEAN AglRegistryInstalled = FALSE;
static UNICODE_STRING AglRegistryAltitude = RTL_CONSTANT_STRING(L"365000");

#define AGL_MAX_REG_VALUE_HASH_BYTES 4096

typedef struct _AGL_REGISTRY_CTX {
    LIST_ENTRY ListEntry;
    PVOID Object;
    ULONG RefCount;
    UNICODE_STRING Path;
} AGL_REGISTRY_CTX;

static KSPIN_LOCK AglRegistryCtxLock;
static LIST_ENTRY AglRegistryCtxList;

static AGL_REGISTRY_CTX* AglRegistryFindCtxLocked(PVOID Object)
{
    PLIST_ENTRY entry;
    for (entry = AglRegistryCtxList.Flink;
         entry != &AglRegistryCtxList;
         entry = entry->Flink)
    {
        AGL_REGISTRY_CTX* ctx = CONTAINING_RECORD(entry, AGL_REGISTRY_CTX, ListEntry);
        if (ctx->Object == Object)
        {
            return ctx;
        }
    }
    return NULL;
}

static void AglRegistryAddCtx(PVOID Object, PCUNICODE_STRING Path)
{
    AGL_REGISTRY_CTX* ctx;
    KLOCK_QUEUE_HANDLE lockHandle;

    if (!Object)
    {
        return;
    }

    KeAcquireInStackQueuedSpinLock(&AglRegistryCtxLock, &lockHandle);
    ctx = AglRegistryFindCtxLocked(Object);
    if (ctx)
    {
        ctx->RefCount++;
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return;
    }

    ctx = (AGL_REGISTRY_CTX*)AglAllocNonPaged(sizeof(*ctx));
    if (!ctx)
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return;
    }

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Object = Object;
    ctx->RefCount = 1;
    ObReferenceObject(Object);
    AglCopyUnicodeString(Path, &ctx->Path, NonPagedPool);
    InsertTailList(&AglRegistryCtxList, &ctx->ListEntry);
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

static void AglRegistryReleaseCtx(PVOID Object)
{
    AGL_REGISTRY_CTX* ctx;
    AGL_REGISTRY_CTX* toFree = NULL;
    KLOCK_QUEUE_HANDLE lockHandle;

    if (!Object)
    {
        return;
    }

    KeAcquireInStackQueuedSpinLock(&AglRegistryCtxLock, &lockHandle);
    ctx = AglRegistryFindCtxLocked(Object);
    if (ctx)
    {
        if (ctx->RefCount > 1)
        {
            ctx->RefCount--;
        }
        else
        {
            RemoveEntryList(&ctx->ListEntry);
            toFree = ctx;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    if (toFree)
    {
        AglFreeUnicodeString(&toFree->Path);
        ObDereferenceObject(toFree->Object);
        AglFree(toFree);
    }
}

static void AglRegistryCleanupCtxList(void)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    AGL_REGISTRY_CTX* ctx = NULL;

    for (;;)
    {
        KeAcquireInStackQueuedSpinLock(&AglRegistryCtxLock, &lockHandle);
        if (!IsListEmpty(&AglRegistryCtxList))
        {
            ctx = CONTAINING_RECORD(AglRegistryCtxList.Flink, AGL_REGISTRY_CTX, ListEntry);
            RemoveEntryList(&ctx->ListEntry);
        }
        else
        {
            ctx = NULL;
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        if (!ctx)
        {
            break;
        }

        AglFreeUnicodeString(&ctx->Path);
        ObDereferenceObject(ctx->Object);
        AglFree(ctx);
    }
}

static NTSTATUS AglRegistryGetObjectPath(
    PVOID Object,
    PWCHAR Buffer,
    ULONG BufferLength,
    PUNICODE_STRING OutPath)
{
    ULONG returned = 0;
    NTSTATUS status;

    RtlZeroMemory(OutPath, sizeof(*OutPath));
    if (!Object)
    {
        return STATUS_INVALID_PARAMETER;
    }

    status = ObQueryNameString(Object, (POBJECT_NAME_INFORMATION)Buffer, BufferLength, &returned);
    if (NT_SUCCESS(status) && returned > sizeof(UNICODE_STRING))
    {
        POBJECT_NAME_INFORMATION nameInfo = (POBJECT_NAME_INFORMATION)Buffer;
        OutPath->Buffer = nameInfo->Name.Buffer;
        OutPath->Length = nameInfo->Name.Length;
        OutPath->MaximumLength = nameInfo->Name.MaximumLength;

    }

    return status;
}

static ULONG AglHashBuffer(PVOID Data, ULONG Length)
{
    ULONG hash = 5381;
    PUCHAR bytes = (PUCHAR)Data;
    for (ULONG i = 0; i < Length; i++)
    {
        hash = hash * 33 + bytes[i];
    }
    return hash;
}

static ULONG AglHashBufferSafe(PVOID Data, ULONG Length)
{
    UCHAR stackBuffer[256];
    ULONG hash = 5381;
    ULONG offset = 0;

    if (!Data || Length == 0)
    {
        return 0;
    }

    if ((ULONG_PTR)Data >= (ULONG_PTR)MmUserProbeAddress)
    {
        return AglHashBuffer(Data, Length);
    }

    while (offset < Length)
    {
        ULONG chunk = min((ULONG)sizeof(stackBuffer), Length - offset);
        __try
        {
            ProbeForRead((PUCHAR)Data + offset, chunk, sizeof(UCHAR));
            RtlCopyMemory(stackBuffer, (PUCHAR)Data + offset, chunk);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            break;
        }

        for (ULONG i = 0; i < chunk; i++)
        {
            hash = hash * 33 + stackBuffer[i];
        }
        offset += chunk;
    }

    return hash;
}

static BOOLEAN AglSafeReadUlong32(PVOID Address, PULONG Value)
{
    if (!Address || !Value)
    {
        return FALSE;
    }

    if ((ULONG_PTR)Address < (ULONG_PTR)MmUserProbeAddress)
    {
        __try
        {
            ProbeForRead(Address, sizeof(ULONG), sizeof(ULONG));
            *Value = *(PULONG)Address;
            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return FALSE;
        }
    }

    *Value = *(PULONG)Address;
    return TRUE;
}

static ULONG AglHashPartialValueData(
    PREG_QUERY_VALUE_KEY_INFORMATION Info,
    PULONG ValueType,
    PULONG ValueLength)
{
    ULONG type = 0;
    ULONG dataLength = 0;
    ULONG headerSize;
    PUCHAR data;
    ULONG hashLength;

    *ValueType = 0;
    *ValueLength = 0;

    if (!Info ||
        Info->KeyValueInformationClass != KeyValuePartialInformation ||
        !Info->KeyValueInformation)
    {
        return 0;
    }

    if (!AglSafeReadUlong32(
            (PUCHAR)Info->KeyValueInformation + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Type),
            &type))
    {
        return 0;
    }

    if (!AglSafeReadUlong32(
            (PUCHAR)Info->KeyValueInformation + FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, DataLength),
            &dataLength))
    {
        return 0;
    }

    headerSize = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data);
    if (dataLength == 0)
    {
        *ValueType = type;
        *ValueLength = 0;
        return 0;
    }

    data = (PUCHAR)Info->KeyValueInformation + headerSize;
    hashLength = min(dataLength, AGL_MAX_REG_VALUE_HASH_BYTES);
    hashLength = min(hashLength, Info->Length > headerSize ? Info->Length - headerSize : 0);

    *ValueType = type;
    *ValueLength = dataLength;

    if (hashLength == 0)
    {
        return 0;
    }

    if ((ULONG_PTR)data < (ULONG_PTR)MmUserProbeAddress)
    {
        UCHAR stackBuffer[256];
        ULONG hash = 5381;
        ULONG offset = 0;

        while (offset < hashLength)
        {
            ULONG chunk = min((ULONG)sizeof(stackBuffer), hashLength - offset);
            __try
            {
                ProbeForRead(data + offset, chunk, sizeof(UCHAR));
                RtlCopyMemory(stackBuffer, data + offset, chunk);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                break;
            }

            for (ULONG i = 0; i < chunk; i++)
            {
                hash = hash * 33 + stackBuffer[i];
            }
            offset += chunk;
        }

        return hash;
    }

    return AglHashBuffer(data, hashLength);
}

static BOOLEAN AglIsPersistencePath(PCUNICODE_STRING Path);

static NTSTATUS AglRegistryEmitEvent(
    ULONG EventType,
    PCUNICODE_STRING Path,
    ULONG DesiredAccess,
    ULONG ValueType,
    ULONG ValueLength,
    ULONG ValueHash,
    ULONG Flags,
    ULONG Index,
    ULONG InfoClass)
{
    AGL_REGISTRY_EVENT* event = NULL;
    PUCHAR buffer = NULL;
    ULONG fixedPayload = sizeof(AGL_REGISTRY_EVENT) - sizeof(AGL_EVENT_HEADER);
    ULONG pathLength = Path ? Path->Length : 0;
    ULONG payloadLength;
    NTSTATUS status;

    if (pathLength > AGL_MAX_EVENT_PAYLOAD - fixedPayload)
    {
        pathLength = AGL_MAX_EVENT_PAYLOAD - fixedPayload;
    }
    payloadLength = fixedPayload + pathLength;

    buffer = AglAllocNonPaged(sizeof(AGL_EVENT_HEADER) + payloadLength);
    if (!buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    event = (AGL_REGISTRY_EVENT*)buffer;
    RtlZeroMemory(event, sizeof(AGL_EVENT_HEADER) + payloadLength);
    event->DesiredAccess = DesiredAccess;
    event->ValueType = ValueType;
    event->ValueLength = ValueLength;
    event->ValueHash = ValueHash;
    event->Flags = Flags;
    event->Index = Index;
    event->InfoClass = InfoClass;
    event->PathLength = pathLength;
    if (Path && AglIsPersistencePath(Path))
    {
        event->Flags |= 1;
    }
    if (Path && Path->Buffer && pathLength)
    {
        RtlCopyMemory(event->Data, Path->Buffer, pathLength);
    }

    status = AglEventEmit(
        EventType,
        STATUS_SUCCESS,
        (ULONG64)(ULONG_PTR)PsGetCurrentProcessId(),
        (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
        0,
        0,
        0,
        buffer + sizeof(AGL_EVENT_HEADER),
        payloadLength);

    AglFree(buffer);
    return status;
}

static BOOLEAN AglIsPersistencePath(PCUNICODE_STRING Path)
{
    static const WCHAR* keywords[] = {
        L"\\Run\\",
        L"\\RunOnce\\",
        L"\\Services\\",
        L"\\Windows\\CurrentVersion\\Run",
        L"\\Windows\\CurrentVersion\\RunOnce",
        L"\\COM\\",
        L"\\WMI\\",
    };

    WCHAR local[AGL_MAX_PATH_CHARS];

    if (!Path || !Path->Buffer || Path->Length >= sizeof(local))
    {
        return FALSE;
    }

    RtlZeroMemory(local, sizeof(local));
    RtlCopyMemory(local, Path->Buffer, Path->Length);

    for (ULONG i = 0; i < ARRAYSIZE(keywords); i++)
    {
        if (wcsstr(local, keywords[i]) != NULL)
        {
            return TRUE;
        }
    }
    return FALSE;
}

static NTSTATUS AglRegistryCallback(PVOID Context, PVOID Arg1, PVOID Arg2)
{
    ULONG eventType = AGL_EVENT_NONE;
    PCUNICODE_STRING path = NULL;
    ULONG desiredAccess = 0;
    ULONG valueType = 0;
    ULONG valueLength = 0;
    ULONG valueHash = 0;
    ULONG flags = 0;
    ULONG index = 0;
    ULONG infoClass = 0;
    ULONG notifyClass = (ULONG)(ULONG_PTR)Arg1;
    BOOLEAN suppressEmit = FALSE;
    WCHAR objPathBuffer[AGL_MAX_PATH_CHARS];
    UNICODE_STRING objPath = { 0 };

    UNREFERENCED_PARAMETER(Context);

    if (notifyClass == (ULONG)RegNtPostCreateKeyEx ||
        notifyClass == (ULONG)RegNtPostOpenKeyEx)
    {
        REG_POST_CREATE_KEY_INFORMATION* info = (REG_POST_CREATE_KEY_INFORMATION*)Arg2;
        if (info->Status == STATUS_SUCCESS)
        {
            AglRegistryAddCtx(info->Object, info->CompleteName);
        }
        return STATUS_SUCCESS;
    }

    if (notifyClass == (ULONG)RegNtPreKeyHandleClose)
    {
        REG_KEY_HANDLE_CLOSE_INFORMATION* info =
            (REG_KEY_HANDLE_CLOSE_INFORMATION*)Arg2;
        AglRegistryReleaseCtx(info->Object);
        return STATUS_SUCCESS;
    }

    if (notifyClass == (ULONG)RegNtPostQueryValueKey)
    {
        REG_POST_OPERATION_INFORMATION* post = (REG_POST_OPERATION_INFORMATION*)Arg2;
        PREG_QUERY_VALUE_KEY_INFORMATION preInfo =
            (PREG_QUERY_VALUE_KEY_INFORMATION)post->PreInformation;

        if (NT_SUCCESS(post->Status) &&
            preInfo &&
            NT_SUCCESS(AglRegistryGetObjectPath(
                preInfo->Object,
                objPathBuffer,
                sizeof(objPathBuffer),
                &objPath)))
        {
            ULONG postValueType = 0;
            ULONG postValueLength = 0;
            ULONG postValueHash = AglHashPartialValueData(
                preInfo,
                &postValueType,
                &postValueLength);

            (void)AglRegistryEmitEvent(
                AGL_EVENT_REGISTRY_QUERY,
                &objPath,
                KEY_QUERY_VALUE,
                postValueType,
                postValueLength,
                postValueHash,
                0,
                0,
                0);
            return STATUS_SUCCESS;
        }

        return STATUS_SUCCESS;
    }

    if (notifyClass == (ULONG)RegNtPreCreateKeyEx || notifyClass == (ULONG)RegNtPreOpenKeyEx)
    {
        REG_CREATE_KEY_INFORMATION* info = (REG_CREATE_KEY_INFORMATION*)Arg2;
        eventType = AGL_EVENT_REGISTRY_OPEN;
        path = info->CompleteName;
        desiredAccess = info->DesiredAccess;
    }
    else if (notifyClass == (ULONG)RegNtPreSetValueKey)
    {
        REG_SET_VALUE_KEY_INFORMATION* info = (REG_SET_VALUE_KEY_INFORMATION*)Arg2;
        eventType = AGL_EVENT_REGISTRY_SET_VALUE;
        desiredAccess = KEY_SET_VALUE;
        valueType = info->Type;
        valueLength = info->DataSize;
        valueHash = AglHashBufferSafe(info->Data, info->DataSize);
        if (NT_SUCCESS(AglRegistryGetObjectPath(
                info->Object,
                objPathBuffer,
                sizeof(objPathBuffer),
                &objPath)))
        {
            path = &objPath;
        }
    }
    else if (notifyClass == (ULONG)RegNtPreEnumerateKey)
    {
        eventType = AGL_EVENT_REGISTRY_ENUM_KEY;
        desiredAccess = KEY_ENUMERATE_SUB_KEYS;
        REG_ENUMERATE_KEY_INFORMATION* info = (REG_ENUMERATE_KEY_INFORMATION*)Arg2;
        index = info->Index;
        infoClass = info->KeyInformationClass;
        if (NT_SUCCESS(AglRegistryGetObjectPath(
                info->Object,
                objPathBuffer,
                sizeof(objPathBuffer),
                &objPath)))
        {
            path = &objPath;
        }
    }
    else if (notifyClass == (ULONG)RegNtPreEnumerateValueKey)
    {
        eventType = AGL_EVENT_REGISTRY_ENUM_VALUE;
        desiredAccess = KEY_QUERY_VALUE;
        REG_ENUMERATE_VALUE_KEY_INFORMATION* info = (REG_ENUMERATE_VALUE_KEY_INFORMATION*)Arg2;
        index = info->Index;
        infoClass = info->KeyValueInformationClass;
        if (NT_SUCCESS(AglRegistryGetObjectPath(
                info->Object,
                objPathBuffer,
                sizeof(objPathBuffer),
                &objPath)))
        {
            path = &objPath;
        }
    }
    else if (notifyClass == (ULONG)RegNtPreQueryValueKey)
    {
        REG_QUERY_VALUE_KEY_INFORMATION* info = (REG_QUERY_VALUE_KEY_INFORMATION*)Arg2;
        eventType = AGL_EVENT_REGISTRY_QUERY;
        desiredAccess = KEY_QUERY_VALUE;
        suppressEmit = TRUE;
        if (NT_SUCCESS(AglRegistryGetObjectPath(
                info->Object,
                objPathBuffer,
                sizeof(objPathBuffer),
                &objPath)))
        {
            path = &objPath;
        }
    }
    else if (notifyClass == (ULONG)RegNtPreDeleteKey)
    {
        eventType = AGL_EVENT_REGISTRY_DELETE_KEY;
        desiredAccess = DELETE;
        REG_DELETE_KEY_INFORMATION* info = (REG_DELETE_KEY_INFORMATION*)Arg2;
        if (NT_SUCCESS(AglRegistryGetObjectPath(
                info->Object,
                objPathBuffer,
                sizeof(objPathBuffer),
                &objPath)))
        {
            path = &objPath;
        }
    }
    else if (notifyClass == (ULONG)RegNtPreDeleteValueKey)
    {
        eventType = AGL_EVENT_REGISTRY_DELETE_VALUE;
        desiredAccess = KEY_SET_VALUE;
        REG_DELETE_VALUE_KEY_INFORMATION* info = (REG_DELETE_VALUE_KEY_INFORMATION*)Arg2;
        if (NT_SUCCESS(AglRegistryGetObjectPath(
                info->Object,
                objPathBuffer,
                sizeof(objPathBuffer),
                &objPath)))
        {
            path = &objPath;
        }
    }

    if (eventType == AGL_EVENT_NONE)
    {
        return STATUS_SUCCESS;
    }

    if (path)
    {
        ULONG accessMask = 0;
        if (eventType == AGL_EVENT_REGISTRY_QUERY) accessMask = KEY_QUERY_VALUE;
        else if (eventType == AGL_EVENT_REGISTRY_SET_VALUE) accessMask = KEY_SET_VALUE;
        else if (eventType == AGL_EVENT_REGISTRY_DELETE_KEY) accessMask = DELETE;
        else if (eventType == AGL_EVENT_REGISTRY_DELETE_VALUE) accessMask = KEY_SET_VALUE;
        else accessMask = KEY_READ;

        if (AglPolicyShouldDenyEx(eventType, path, accessMask))
        {
            return STATUS_ACCESS_DENIED;
        }
    }

    if (suppressEmit)
    {
        return STATUS_SUCCESS;
    }

    (void)AglRegistryEmitEvent(
        eventType,
        path,
        desiredAccess,
        valueType,
        valueLength,
        valueHash,
        flags,
        index,
        infoClass);
    return STATUS_SUCCESS;
}

NTSTATUS AglRegistryMonitorInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;

    KeInitializeSpinLock(&AglRegistryCtxLock);
    InitializeListHead(&AglRegistryCtxList);

    status = CmRegisterCallbackEx(
        AglRegistryCallback,
        &AglRegistryAltitude,
        DriverObject,
        NULL,
        &AglRegistryCookie,
        NULL);

    if (!NT_SUCCESS(status))
    {
        AglTraceError("CmRegisterCallbackEx failed: 0x%08X\n", status);
        return status;
    }

    AglRegistryInstalled = TRUE;
    return STATUS_SUCCESS;
}

void AglRegistryMonitorUninitialize(void)
{
    if (AglRegistryInstalled)
    {
        CmUnRegisterCallback(AglRegistryCookie);
        AglRegistryCleanupCtxList();
        AglRegistryInstalled = FALSE;
    }
}
