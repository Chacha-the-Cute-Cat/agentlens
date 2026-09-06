#include "agl_monitors.h"
#include "agl_context.h"
#include "agl_event.h"
#include "agl_policy.h"
#include "agl_util.h"
#include "agl_trace.h"

static BOOLEAN AglProcessMonitorInstalled = FALSE;

static PWCHAR AglFindLastBackslash(PCWSTR Str)
{
    PCWSTR last = NULL;
    if (!Str)
    {
        return NULL;
    }
    while (*Str)
    {
        if (*Str == L'\\')
        {
            last = Str;
        }
        Str++;
    }
    return (PWCHAR)last;
}

static void AglProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo)
    {
        if (AglPolicyShouldDeny(
                AGL_EVENT_PROCESS_CREATE,
                CreateInfo->ImageFileName))
        {
            CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            return;
        }

        AGL_PROCESS_CTX* ctx;
        ULONG64 createTime = 0;
        ULONG64 correlationId = AglContextNextCorrelationId();
        ULONG64 parentCorrelationId = AglContextGetCorrelationId(
            (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId);
        UNICODE_STRING imageName = { 0 };

        if (Process)
        {
            createTime = (ULONG64)PsGetProcessCreateTimeQuadPart(Process);
        }

        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer)
        {
            PWCHAR last = AglFindLastBackslash(CreateInfo->ImageFileName->Buffer);
            if (last)
            {
                RtlInitUnicodeString(&imageName, last + 1);
            }
        }

        ctx = AglContextGetOrCreateProcess(
            (ULONG64)(ULONG_PTR)ProcessId,
            (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
            createTime,
            correlationId,
            parentCorrelationId,
            0,
            CreateInfo->ImageFileName,
            imageName.Length ? &imageName : NULL,
            CreateInfo->CommandLine);

        AglEventEmitProcess(
            AGL_EVENT_PROCESS_CREATE,
            (ULONG64)(ULONG_PTR)ProcessId,
            (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
            createTime,
            correlationId,
            CreateInfo->ImageFileName,
            imageName.Length ? &imageName : NULL,
            CreateInfo->CommandLine);

        if (ctx)
        {
            AglContextReleaseProcess(ctx);
        }
    }
    else
    {
        AglContextRemoveProcess((ULONG64)(ULONG_PTR)ProcessId);
        AglEventEmit(
            AGL_EVENT_PROCESS_EXIT,
            STATUS_SUCCESS,
            (ULONG64)(ULONG_PTR)ProcessId,
            (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
            0,
            0,
            0,
            NULL,
            0);
    }
}

NTSTATUS AglProcessMonitorInitialize(void)
{
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(AglProcessNotify, FALSE);
    if (!NT_SUCCESS(status))
    {
        AglTraceError("PsSetCreateProcessNotifyRoutineEx failed: 0x%08X\n", status);
        return status;
    }

    AglProcessMonitorInstalled = TRUE;
    return STATUS_SUCCESS;
}

void AglProcessMonitorUninitialize(void)
{
    if (AglProcessMonitorInstalled)
    {
        PsSetCreateProcessNotifyRoutineEx(AglProcessNotify, TRUE);
        AglProcessMonitorInstalled = FALSE;
    }
}
