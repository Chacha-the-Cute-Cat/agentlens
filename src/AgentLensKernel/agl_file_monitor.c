#include <fltKernel.h>
#include "agl_monitors.h"
#include "agl_event.h"
#include "agl_policy.h"
#include "agl_util.h"
#include "agl_trace.h"

static PFLT_FILTER AglFileFilter = NULL;
static BOOLEAN AglFileMonitorInstalled = FALSE;

static FLT_PREOP_CALLBACK_STATUS AglFilePreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext);

static FLT_PREOP_CALLBACK_STATUS AglFilePreWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext);

static FLT_PREOP_CALLBACK_STATUS AglFilePreSetInfo(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS AglFilePostRead(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags);

static FLT_POSTOP_CALLBACK_STATUS AglFilePostWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags);

static FLT_POSTOP_CALLBACK_STATUS AglFilePostClose(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags);

static const FLT_OPERATION_REGISTRATION AglFileOperations[] = {
    { IRP_MJ_CREATE, 0, AglFilePreCreate, NULL, NULL },
    { IRP_MJ_SET_INFORMATION, 0, AglFilePreSetInfo, NULL, NULL },
    { IRP_MJ_READ, 0, NULL, AglFilePostRead, NULL },
    { IRP_MJ_WRITE, 0, AglFilePreWrite, AglFilePostWrite, NULL },
    { IRP_MJ_CLOSE, 0, NULL, AglFilePostClose, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION AglFileRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    (FLT_OPERATION_REGISTRATION*)AglFileOperations,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

static void AglEmitFileEvent(
    ULONG EventType,
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    ULONG64 Offset,
    ULONG Length)
{
    UNREFERENCED_PARAMETER(FltObjects);
    FLT_FILE_NAME_INFORMATION* nameInfo = NULL;
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;
    ULONG pathLength = 0;
    ULONG payloadLength = 0;
    PUCHAR buffer = NULL;
    AGL_FILE_EVENT* event = NULL;
    NTSTATUS status;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo)
    {
        return;
    }

    pathLength = nameInfo->Name.Length;
    if (pathLength > AGL_MAX_EVENT_PAYLOAD - 32)
    {
        pathLength = AGL_MAX_EVENT_PAYLOAD - 32;
    }

    payloadLength = sizeof(AGL_FILE_EVENT) - sizeof(AGL_EVENT_HEADER) + pathLength;
    buffer = AglAllocNonPaged(sizeof(AGL_EVENT_HEADER) + payloadLength);
    if (!buffer)
    {
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    event = (AGL_FILE_EVENT*)buffer;
    RtlZeroMemory(event, sizeof(AGL_EVENT_HEADER) + payloadLength);
    event->Offset = Offset;
    event->Length = Length;
    event->PathLength = pathLength;
    RtlCopyMemory(event->Data, nameInfo->Name.Buffer, pathLength);

    if (EventType == AGL_EVENT_FILE_OPEN)
    {
        event->DesiredAccess = iopb->Parameters.Create.SecurityContext->DesiredAccess;
        event->CreateOptions = iopb->Parameters.Create.Options;
        event->CreateDisposition = (iopb->Parameters.Create.Options >> 24) & 0xFF;
    }

    AglEventEmit(
        EventType,
        STATUS_SUCCESS,
        (ULONG64)(ULONG_PTR)PsGetCurrentProcessId(),
        (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
        0,
        0,
        0,
        buffer + sizeof(AGL_EVENT_HEADER),
        payloadLength);

    FltReleaseFileNameInformation(nameInfo);
    AglFree(buffer);
}

static BOOLEAN AglFileShouldDenyCreate(PFLT_CALLBACK_DATA Data)
{
    FLT_FILE_NAME_INFORMATION* nameInfo = NULL;
    BOOLEAN deny = FALSE;
    NTSTATUS status;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (NT_SUCCESS(status) && nameInfo)
    {
        deny = AglPolicyShouldDeny(AGL_EVENT_FILE_OPEN, &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
    }

    return deny;
}

static BOOLEAN AglFileShouldDenyWrite(PFLT_CALLBACK_DATA Data)
{
    FLT_FILE_NAME_INFORMATION* nameInfo = NULL;
    BOOLEAN deny = FALSE;
    NTSTATUS status;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (NT_SUCCESS(status) && nameInfo)
    {
        deny = AglPolicyShouldDeny(AGL_EVENT_FILE_WRITE, &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
    }

    return deny;
}

static BOOLEAN AglFileShouldDenyRename(PFLT_CALLBACK_DATA Data)
{
    FLT_FILE_NAME_INFORMATION* nameInfo = NULL;
    BOOLEAN deny = FALSE;
    NTSTATUS status;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (NT_SUCCESS(status) && nameInfo)
    {
        deny = AglPolicyShouldDeny(AGL_EVENT_FILE_RENAME, &nameInfo->Name);
        FltReleaseFileNameInformation(nameInfo);
    }

    return deny;
}

static FLT_PREOP_CALLBACK_STATUS AglFilePreCreate(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (AglFileShouldDenyCreate(Data))
    {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }

    AglEmitFileEvent(AGL_EVENT_FILE_OPEN, Data, FltObjects, 0, 0);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS AglFilePreWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (AglFileShouldDenyWrite(Data))
    {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        return FLT_PREOP_COMPLETE;
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS AglFilePreSetInfo(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID* CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformation ||
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileRenameInformationEx ||
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileLinkInformation ||
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileLinkInformationEx)
    {
        if (AglFileShouldDenyRename(Data))
        {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            return FLT_PREOP_COMPLETE;
        }
        AglEmitFileEvent(AGL_EVENT_FILE_RENAME, Data, FltObjects, 0, 0);
    }
    else if (Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformation ||
             Data->Iopb->Parameters.SetFileInformation.FileInformationClass == FileDispositionInformationEx)
    {
        FLT_FILE_NAME_INFORMATION* nameInfo = NULL;
        if (NT_SUCCESS(FltGetFileNameInformation(
                Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
                &nameInfo)))
        {
            if (nameInfo && AglPolicyShouldDeny(AGL_EVENT_FILE_DELETE, &nameInfo->Name))
            {
                FltReleaseFileNameInformation(nameInfo);
                Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                return FLT_PREOP_COMPLETE;
            }
            if (nameInfo)
            {
                FltReleaseFileNameInformation(nameInfo);
            }
        }
        AglEmitFileEvent(AGL_EVENT_FILE_DELETE, Data, FltObjects, 0, 0);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS AglFilePostRead(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (NT_SUCCESS(Data->IoStatus.Status))
    {
        AglEmitFileEvent(
            AGL_EVENT_FILE_READ,
            Data,
            FltObjects,
            Data->Iopb->Parameters.Read.ByteOffset.QuadPart,
            (ULONG)Data->IoStatus.Information);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS AglFilePostWrite(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);

    if (NT_SUCCESS(Data->IoStatus.Status))
    {
        AglEmitFileEvent(
            AGL_EVENT_FILE_WRITE,
            Data,
            FltObjects,
            Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
            (ULONG)Data->IoStatus.Information);
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

static FLT_POSTOP_CALLBACK_STATUS AglFilePostClose(
    PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects,
    PVOID CompletionContext,
    FLT_POST_OPERATION_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(Flags);
    AglEmitFileEvent(AGL_EVENT_FILE_CLOSE, Data, FltObjects, 0, 0);
    return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS AglFileMonitorInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = FltRegisterFilter(DriverObject, &AglFileRegistration, &AglFileFilter);
    if (!NT_SUCCESS(status))
    {
        AglTraceError("FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    status = FltStartFiltering(AglFileFilter);
    if (!NT_SUCCESS(status))
    {
        FltUnregisterFilter(AglFileFilter);
        AglFileFilter = NULL;
        return status;
    }

    AglFileMonitorInstalled = TRUE;
    return STATUS_SUCCESS;
}

void AglFileMonitorUninitialize(void)
{
    if (AglFileMonitorInstalled)
    {
        FltUnregisterFilter(AglFileFilter);
        AglFileFilter = NULL;
        AglFileMonitorInstalled = FALSE;
    }
}
