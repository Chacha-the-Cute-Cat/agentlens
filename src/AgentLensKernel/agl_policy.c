#include "agl_policy.h"
#include "agl_context.h"
#include "agl_util.h"
#include "AgentLensProtocol/agl_policy.h"

#define AGL_MAX_POLICY_RULES 128

typedef struct _AGL_POLICY_ENTRY {
    ULONG EventType;
    ULONG Action;
    ULONG Priority;
    ULONG AccessMask;
    ULONG PathLength;
    ULONG ProcessLength;
    WCHAR Path[AGL_MAX_PATH_CHARS];
    WCHAR Process[AGL_MAX_PATH_CHARS];
} AGL_POLICY_ENTRY;

static KSPIN_LOCK AglPolicyLock;
static AGL_POLICY_ENTRY AglPolicyRules[AGL_MAX_POLICY_RULES];
static ULONG AglPolicyCount;
static ULONG AglPolicyMode;

static BOOLEAN AglMatchString(
    PCWSTR Pattern,
    ULONG PatternLength,
    PCUNICODE_STRING Value)
{
    UNICODE_STRING pattern;

    if (!PatternLength || !Value || !Value->Buffer || Value->Length == 0)
    {
        return FALSE;
    }

    pattern.Buffer = (PWCH)Pattern;
    pattern.Length = (USHORT)(PatternLength * sizeof(WCHAR));
    pattern.MaximumLength = pattern.Length;
    return RtlPrefixUnicodeString(&pattern, Value, TRUE);
}

NTSTATUS AglPolicyInitialize(void)
{
    KeInitializeSpinLock(&AglPolicyLock);
    AglPolicyCount = 0;
    AglPolicyMode = AGL_POLICY_MODE_OBSERVE;
    return STATUS_SUCCESS;
}

void AglPolicyUninitialize(void)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&AglPolicyLock, &lockHandle);
    AglPolicyCount = 0;
    AglPolicyMode = AGL_POLICY_MODE_OBSERVE;
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

NTSTATUS AglPolicyLoad(PVOID Policy, ULONG PolicyLength)
{
    AGL_POLICY_HEADER* header;
    PUCHAR cursor;
    ULONG remaining;
    ULONG i;
    KLOCK_QUEUE_HANDLE lockHandle;

    if (!Policy || PolicyLength < sizeof(AGL_POLICY_HEADER))
    {
        return STATUS_INVALID_PARAMETER;
    }

    header = (AGL_POLICY_HEADER*)Policy;
    if (header->StructSize < sizeof(*header) || header->Version != AGL_PROTOCOL_VERSION)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (header->RuleCount > AGL_MAX_POLICY_RULES)
    {
        return STATUS_BUFFER_OVERFLOW;
    }

    cursor = (PUCHAR)Policy + header->StructSize;
    remaining = PolicyLength - header->StructSize;

    for (i = 0; i < header->RuleCount; i++)
    {
        AGL_POLICY_RULE* rule;
        AGL_POLICY_ENTRY* entry;
        ULONG pathBytes;
        ULONG processBytes;

        if (remaining < sizeof(AGL_POLICY_RULE))
        {
            return STATUS_INVALID_PARAMETER;
        }

        rule = (AGL_POLICY_RULE*)cursor;
        pathBytes = rule->PathLength;
        processBytes = rule->ProcessLength;

        if (pathBytes > (AGL_MAX_PATH_CHARS - 1) * sizeof(WCHAR) ||
            processBytes > (AGL_MAX_PATH_CHARS - 1) * sizeof(WCHAR))
        {
            return STATUS_INVALID_PARAMETER;
        }

        if (remaining < sizeof(AGL_POLICY_RULE) + pathBytes + processBytes)
        {
            return STATUS_INVALID_PARAMETER;
        }

        entry = &AglPolicyRules[i];
        RtlZeroMemory(entry, sizeof(*entry));
        entry->EventType = rule->EventType;
        entry->Action = rule->Action;
        entry->Priority = rule->Priority;
        entry->AccessMask = rule->AccessMask;
        entry->PathLength = pathBytes / sizeof(WCHAR);
        entry->ProcessLength = processBytes / sizeof(WCHAR);

        if (pathBytes)
        {
            RtlCopyMemory(entry->Path, rule->Data, pathBytes);
        }
        if (processBytes)
        {
            RtlCopyMemory(
                entry->Process,
                (PUCHAR)rule->Data + pathBytes,
                processBytes);
        }

        cursor += sizeof(AGL_POLICY_RULE) + pathBytes + processBytes;
        remaining -= sizeof(AGL_POLICY_RULE) + pathBytes + processBytes;
    }

    KeAcquireInStackQueuedSpinLock(&AglPolicyLock, &lockHandle);
    AglPolicyCount = header->RuleCount;
    AglPolicyMode = header->Mode;
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return STATUS_SUCCESS;
}

void AglPolicyClear(void)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&AglPolicyLock, &lockHandle);
    AglPolicyCount = 0;
    AglPolicyMode = AGL_POLICY_MODE_OBSERVE;
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

BOOLEAN AglPolicyShouldDeny(ULONG EventType, PCUNICODE_STRING Path)
{
    ULONG i;
    BOOLEAN deny = FALSE;
    AGL_PROCESS_CTX* processCtx = NULL;
    UNICODE_STRING processPath = { 0 };
    KLOCK_QUEUE_HANDLE lockHandle;

    processCtx = AglContextAcquireProcess((ULONG64)(ULONG_PTR)PsGetCurrentProcessId());
    if (processCtx)
    {
        processPath = processCtx->ImagePath;
    }

    KeAcquireInStackQueuedSpinLock(&AglPolicyLock, &lockHandle);
    if (AglPolicyMode != AGL_POLICY_MODE_CONTROL)
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        if (processCtx) AglContextReleaseProcess(processCtx);
        return FALSE;
    }

    for (i = 0; i < AglPolicyCount; i++)
    {
        AGL_POLICY_ENTRY* entry = &AglPolicyRules[i];
        if (entry->EventType != EventType)
        {
            continue;
        }

        if (entry->ProcessLength &&
            !AglMatchString(entry->Process, entry->ProcessLength, &processPath))
        {
            continue;
        }

        if (entry->PathLength &&
            !AglMatchString(entry->Path, entry->PathLength, Path))
        {
            continue;
        }

        if (entry->Action == 1)
        {
            deny = TRUE;
        }
        break;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    if (processCtx)
    {
        AglContextReleaseProcess(processCtx);
    }
    return deny;
}
