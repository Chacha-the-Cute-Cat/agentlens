#include "agl_monitors.h"
#include "agl_event.h"
#include "agl_trace.h"

static PVOID AglObjectRegistration = NULL;
static OB_OPERATION_REGISTRATION AglObjectOps[2] = { { 0 } };
static OB_CALLBACK_REGISTRATION AglObjectCallbacks = { 0 };
static UNICODE_STRING AglObjectAltitude = RTL_CONSTANT_STRING(L"365000");
static BOOLEAN AglObjectInstalled = FALSE;

static OB_PREOP_CALLBACK_STATUS AglObjectPre(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle)
    {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType == *PsProcessType)
    {
        PEPROCESS target = (PEPROCESS)OperationInformation->Object;
        AGL_OBJECT_EVENT event;
        RtlZeroMemory(&event, sizeof(event));
        event.ObjectType = 1;
        event.DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        event.GrantedAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
        event.TargetProcessId = (ULONG)(ULONG_PTR)PsGetProcessId(target);
        AglEventEmit(
            AGL_EVENT_OBJECT_HANDLE,
            STATUS_SUCCESS,
            (ULONG64)(ULONG_PTR)PsGetCurrentProcessId(),
            (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
            0,
            0,
            0,
            &event,
            sizeof(event));
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS AglObjectMonitorInitialize(void)
{
    NTSTATUS status;

    AglObjectOps[0].ObjectType = PsProcessType;
    AglObjectOps[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    AglObjectOps[0].PreOperation = AglObjectPre;
    AglObjectOps[0].PostOperation = NULL;

    AglObjectOps[1].ObjectType = PsThreadType;
    AglObjectOps[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    AglObjectOps[1].PreOperation = AglObjectPre;
    AglObjectOps[1].PostOperation = NULL;

    AglObjectCallbacks.Version = OB_FLT_REGISTRATION_VERSION;
    AglObjectCallbacks.OperationRegistrationCount = 2;
    AglObjectCallbacks.Altitude = AglObjectAltitude;
    AglObjectCallbacks.RegistrationContext = NULL;
    AglObjectCallbacks.OperationRegistration = AglObjectOps;

    status = ObRegisterCallbacks(&AglObjectCallbacks, &AglObjectRegistration);
    if (!NT_SUCCESS(status))
    {
        AglTraceError("ObRegisterCallbacks failed: 0x%08X\n", status);
        return status;
    }

    AglObjectInstalled = TRUE;
    return STATUS_SUCCESS;
}

void AglObjectMonitorUninitialize(void)
{
    if (AglObjectInstalled)
    {
        ObUnRegisterCallbacks(AglObjectRegistration);
        AglObjectRegistration = NULL;
        AglObjectInstalled = FALSE;
    }
}
