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

static NTSTATUS AglRegistryCallback(PVOID Context, PVOID Arg1, PVOID Arg2)
{
    ULONG eventType = AGL_EVENT_NONE;
    PCUNICODE_STRING path = NULL;
    ULONG desiredAccess = 0;
    ULONG valueType = 0;
    ULONG valueLength = 0;
    ULONG notifyClass = (ULONG)(ULONG_PTR)Arg1;
    PUCHAR buffer = NULL;
    AGL_REGISTRY_EVENT* event = NULL;
    WCHAR objPathBuffer[AGL_MAX_PATH_CHARS];
    UNICODE_STRING objPath = { 0 };
    ULONG pathLength = 0;
    ULONG payloadLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Context);

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

    if (path && AglPolicyShouldDeny(eventType, path))
    {
        return STATUS_ACCESS_DENIED;
    }

    if (path)
    {
        pathLength = path->Length;
    }

    payloadLength = sizeof(AGL_REGISTRY_EVENT) - sizeof(AGL_EVENT_HEADER) + pathLength;
    buffer = AglAllocNonPaged(sizeof(AGL_EVENT_HEADER) + payloadLength);
    if (!buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    event = (AGL_REGISTRY_EVENT*)buffer;
    RtlZeroMemory(event, sizeof(AGL_EVENT_HEADER) + payloadLength);
    event->DesiredAccess = desiredAccess;
    event->ValueType = valueType;
    event->ValueLength = valueLength;
    event->PathLength = pathLength;
    if (path && path->Buffer && pathLength)
    {
        RtlCopyMemory(event->Data, path->Buffer, pathLength);
    }

    AglEventEmit(
        eventType,
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

NTSTATUS AglRegistryMonitorInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = CmRegisterCallbackEx(
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
        AglRegistryInstalled = FALSE;
    }
}
