#include <ntifs.h>
#include "agl_monitors.h"
#include "agl_context.h"
#include "agl_event.h"
#include "agl_policy.h"
#include "agl_util.h"
#include "agl_trace.h"

static BOOLEAN AglProcessMonitorInstalled = FALSE;

static void AglCaptureTokenFields(
    PEPROCESS Process,
    PULONG SidHash,
    PULONG IntegrityLevel,
    PULONG PrivilegeHash)
{
    PACCESS_TOKEN token = NULL;
    PVOID info = NULL;
    NTSTATUS status;

    *SidHash = 0;
    *IntegrityLevel = 0;
    *PrivilegeHash = 0;

    token = PsReferencePrimaryToken(Process);
    if (!token)
    {
        return;
    }

    status = SeQueryInformationToken(token, TokenUser, &info);
    if (NT_SUCCESS(status) && info)
    {
        PTOKEN_USER user = (PTOKEN_USER)info;
        if (user->User.Sid)
        {
            PUCHAR sid = (PUCHAR)user->User.Sid;
            ULONG len = RtlLengthSid(user->User.Sid);
            for (ULONG i = 0; i < len; i++)
            {
                *SidHash = *SidHash * 33 + sid[i];
            }
        }
        ExFreePool(info);
        info = NULL;
    }

    status = SeQueryInformationToken(token, TokenIntegrityLevel, &info);
    if (NT_SUCCESS(status) && info)
    {
        PTOKEN_MANDATORY_LABEL label = (PTOKEN_MANDATORY_LABEL)info;
        if (label->Label.Sid)
        {
            *IntegrityLevel = *RtlSubAuthoritySid(
                label->Label.Sid,
                (ULONG)(*RtlSubAuthorityCountSid(label->Label.Sid) - 1));
        }
        ExFreePool(info);
        info = NULL;
    }

    status = SeQueryInformationToken(token, TokenPrivileges, &info);
    if (NT_SUCCESS(status) && info)
    {
        PTOKEN_PRIVILEGES privileges = (PTOKEN_PRIVILEGES)info;
        for (ULONG i = 0; i < privileges->PrivilegeCount; i++)
        {
            ULONG64 luid = (ULONG64)privileges->Privileges[i].Luid.LowPart |
                ((ULONG64)privileges->Privileges[i].Luid.HighPart << 32);
            *PrivilegeHash = *PrivilegeHash * 33 + (ULONG)luid;
        }
        ExFreePool(info);
    }

    PsDereferencePrimaryToken(token);
}

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
            AglCaptureTokenFields(
                Process,
                &ctx->TokenSidHash,
                &ctx->TokenIntegrityLevel,
                &ctx->TokenPrivilegeHash);
            ctx->TokenSnapshotValid =
                ctx->TokenSidHash != 0 ||
                ctx->TokenIntegrityLevel != 0 ||
                ctx->TokenPrivilegeHash != 0;

            {
                AGL_PROCESS_CTX* parentCtx = AglContextAcquireProcess(
                    (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId);
                if (parentCtx)
                {
                    if (parentCtx->TokenSnapshotValid && ctx->TokenSnapshotValid)
                    {
                        if (ctx->TokenIntegrityLevel > parentCtx->TokenIntegrityLevel ||
                            ctx->TokenSidHash != parentCtx->TokenSidHash ||
                            ctx->TokenPrivilegeHash != parentCtx->TokenPrivilegeHash)
                        {
                            AglEventEmitTokenAnomaly(
                                (ULONG64)(ULONG_PTR)ProcessId,
                                (ULONG64)(ULONG_PTR)CreateInfo->ParentProcessId,
                                parentCtx->TokenSidHash,
                                parentCtx->TokenIntegrityLevel,
                                parentCtx->TokenPrivilegeHash,
                                ctx->TokenSidHash,
                                ctx->TokenIntegrityLevel,
                                ctx->TokenPrivilegeHash);
                        }
                    }
                    AglContextReleaseProcess(parentCtx);
                }
            }
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
