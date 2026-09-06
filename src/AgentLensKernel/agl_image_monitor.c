#include "agl_monitors.h"
#include "agl_context.h"
#include "agl_event.h"
#include "agl_trace.h"

static BOOLEAN AglImageMonitorInstalled = FALSE;

static void AglImageNotify(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    if (!FullImageName || !ImageInfo || ImageInfo->SystemModeImage)
    {
        return;
    }

    ULONG hash = 5381;
    for (USHORT i = 0; i < FullImageName->Length / sizeof(WCHAR); i++)
    {
        hash = hash * 33 + FullImageName->Buffer[i];
    }

    AglContextGetOrCreateImage(
        (ULONG64)(ULONG_PTR)ProcessId,
        (ULONG64)(ULONG_PTR)ImageInfo->ImageBase,
        (ULONG)ImageInfo->ImageSize,
        hash);

    AglEventEmitImage(
        AGL_EVENT_IMAGE_LOAD,
        (ULONG64)(ULONG_PTR)ProcessId,
        (ULONG64)(ULONG_PTR)ImageInfo->ImageBase,
        (ULONG)ImageInfo->ImageSize,
        FullImageName);
}

NTSTATUS AglImageMonitorInitialize(void)
{
    NTSTATUS status = PsSetLoadImageNotifyRoutine(AglImageNotify);
    if (!NT_SUCCESS(status))
    {
        AglTraceError("PsSetLoadImageNotifyRoutine failed: 0x%08X\n", status);
        return status;
    }

    AglImageMonitorInstalled = TRUE;
    return STATUS_SUCCESS;
}

void AglImageMonitorUninitialize(void)
{
    if (AglImageMonitorInstalled)
    {
        PsRemoveLoadImageNotifyRoutine(AglImageNotify);
        AglImageMonitorInstalled = FALSE;
    }
}
