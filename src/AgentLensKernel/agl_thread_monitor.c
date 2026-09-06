#include "agl_monitors.h"
#include "agl_context.h"
#include "agl_event.h"
#include "agl_trace.h"

static BOOLEAN AglThreadMonitorInstalled = FALSE;

static void AglThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    if (Create)
    {
        AglContextGetOrCreateThread(
            (ULONG64)(ULONG_PTR)ProcessId,
            (ULONG64)(ULONG_PTR)ThreadId);
    }
    else
    {
        AglContextRemoveThread((ULONG64)(ULONG_PTR)ThreadId);
    }

    AglEventEmitThread(
        Create ? AGL_EVENT_THREAD_CREATE : AGL_EVENT_THREAD_EXIT,
        (ULONG64)(ULONG_PTR)ProcessId,
        (ULONG64)(ULONG_PTR)ThreadId,
        0);
}

NTSTATUS AglThreadMonitorInitialize(void)
{
    NTSTATUS status = PsSetCreateThreadNotifyRoutine(AglThreadNotify);
    if (!NT_SUCCESS(status))
    {
        AglTraceError("PsSetCreateThreadNotifyRoutine failed: 0x%08X\n", status);
        return status;
    }

    AglThreadMonitorInstalled = TRUE;
    return STATUS_SUCCESS;
}

void AglThreadMonitorUninitialize(void)
{
    if (AglThreadMonitorInstalled)
    {
        PsRemoveCreateThreadNotifyRoutine(AglThreadNotify);
        AglThreadMonitorInstalled = FALSE;
    }
}
