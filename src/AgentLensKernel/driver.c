#include "driver.h"
#include "agl_trace.h"
#include "agl_util.h"
#include "agl_context.h"
#include "agl_event.h"
#include "agl_event_ring.h"
#include "agl_etw.h"
#include "agl_policy.h"
#include "agl_control.h"
#include "agl_monitors.h"

PDRIVER_OBJECT AglDriverObject = NULL;
UNICODE_STRING AglRegistryPath = { 0 };
BOOLEAN AglReady = FALSE;

static BOOLEAN AglControlInit = FALSE;
static BOOLEAN AglEventInit = FALSE;
static BOOLEAN AglProcessInit = FALSE;
static BOOLEAN AglThreadInit = FALSE;
static BOOLEAN AglImageInit = FALSE;
static BOOLEAN AglRegistryInit = FALSE;
static BOOLEAN AglObjectInit = FALSE;
static BOOLEAN AglFileInit = FALSE;
static BOOLEAN AglNetworkInit = FALSE;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    AglDriverObject = DriverObject;
    DriverObject->DriverUnload = AglDriverUnload;
    AglRegistryPath = *RegistryPath;

    AglTraceInfo("AgentLensKernel starting.\n");

    AglContextInitialize();
    AglPolicyInitialize();
    AglEtwInitialize();

    status = AglEventRingInitialize(1024 * 1024);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    AglEventInit = TRUE;

    status = AglControlInitialize(DriverObject);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    AglControlInit = TRUE;

    status = AglProcessMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    AglProcessInit = TRUE;

    status = AglThreadMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    AglThreadInit = TRUE;

    status = AglImageMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    AglImageInit = TRUE;

    status = AglRegistryMonitorInitialize(DriverObject);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    AglRegistryInit = TRUE;

    status = AglObjectMonitorInitialize();
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    AglObjectInit = TRUE;

    status = AglFileMonitorInitialize(DriverObject);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    AglFileInit = TRUE;

    status = AglNetworkMonitorInitialize(DriverObject);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }
    AglNetworkInit = TRUE;

    AglReady = TRUE;
    AglTraceInfo("AgentLensKernel ready.\n");
    return STATUS_SUCCESS;

Exit:
    AglTraceError("AgentLensKernel init failed: 0x%08X\n", status);
    if (AglNetworkInit) AglNetworkMonitorUninitialize();
    if (AglFileInit) AglFileMonitorUninitialize();
    if (AglObjectInit) AglObjectMonitorUninitialize();
    if (AglRegistryInit) AglRegistryMonitorUninitialize();
    if (AglImageInit) AglImageMonitorUninitialize();
    if (AglThreadInit) AglThreadMonitorUninitialize();
    if (AglProcessInit) AglProcessMonitorUninitialize();
    if (AglControlInit) AglControlUninitialize(DriverObject);
    if (AglEventInit) AglEventRingDestroy();
    AglPolicyUninitialize();
    AglEtwUninitialize();
    AglContextDestroy();
    return status;
}

void AglDriverUnload(PDRIVER_OBJECT DriverObject)
{
    AglReady = FALSE;

    if (AglNetworkInit)
    {
        AglNetworkMonitorUninitialize();
        AglNetworkInit = FALSE;
    }
    if (AglFileInit)
    {
        AglFileMonitorUninitialize();
        AglFileInit = FALSE;
    }
    if (AglObjectInit)
    {
        AglObjectMonitorUninitialize();
        AglObjectInit = FALSE;
    }
    if (AglRegistryInit)
    {
        AglRegistryMonitorUninitialize();
        AglRegistryInit = FALSE;
    }
    if (AglImageInit)
    {
        AglImageMonitorUninitialize();
        AglImageInit = FALSE;
    }
    if (AglThreadInit)
    {
        AglThreadMonitorUninitialize();
        AglThreadInit = FALSE;
    }
    if (AglProcessInit)
    {
        AglProcessMonitorUninitialize();
        AglProcessInit = FALSE;
    }
    if (AglControlInit)
    {
        AglControlUninitialize(DriverObject);
        AglControlInit = FALSE;
    }
    if (AglEventInit)
    {
        AglEventRingDestroy();
        AglEventInit = FALSE;
    }

    AglEtwUninitialize();
    AglPolicyUninitialize();
    AglContextDestroy();
    AglTraceInfo("AgentLensKernel unloaded.\n");
}
