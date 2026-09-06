#include "agl_control.h"
#include "agl_event_ring.h"
#include "agl_context.h"
#include "agl_policy.h"
#include "agl_monitors.h"
#include "agl_util.h"
#include "agl_trace.h"
#include "AgentLensProtocol/agl_control.h"
#include "AgentLensProtocol/agl_event.h"
#include "AgentLensProtocol/agl_policy.h"
#include <wdmsec.h>

static PDEVICE_OBJECT AglControlDevice = NULL;
static UNICODE_STRING AglSymbolicLink = { 0 };

typedef NTSTATUS (*AGL_CONTROL_HANDLER)(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information);

typedef struct _AGL_CONTROL_OPERATION {
    ULONG OpCode;
    ULONG RequiredInput;
    ULONG RequiredOutput;
    AGL_CONTROL_HANDLER Handler;
} AGL_CONTROL_OPERATION;

static NTSTATUS AglHandleDeviceControl(
    PIRP Irp,
    PIO_STACK_LOCATION IrpSp,
    PULONG_PTR Information);

PDEVICE_OBJECT AglControlGetDevice(void)
{
    return AglControlDevice;
}

NTSTATUS AglControlInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING sddl;

    RtlInitUnicodeString(&deviceName, AGL_DEVICE_NAME);
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        NULL,
        &AglControlDevice);

    if (!NT_SUCCESS(status))
    {
        AglTraceError("IoCreateDeviceSecure failed: 0x%08X\n", status);
        return status;
    }

    RtlInitUnicodeString(&AglSymbolicLink, AGL_DOS_DEVICE_NAME);
    status = IoCreateSymbolicLink(&AglSymbolicLink, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(AglControlDevice);
        AglControlDevice = NULL;
        return status;
    }

    AglControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = AglControlDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = AglControlDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = AglControlDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AglControlDispatch;
    return STATUS_SUCCESS;
}

void AglControlUninitialize(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    if (AglSymbolicLink.Buffer)
    {
        IoDeleteSymbolicLink(&AglSymbolicLink);
    }
    if (AglControlDevice)
    {
        IoDeleteDevice(AglControlDevice);
        AglControlDevice = NULL;
    }
}

static NTSTATUS AglFinishIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS AglControlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (irpSp->MajorFunction)
    {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLEANUP:
    case IRP_MJ_CLOSE:
        status = STATUS_SUCCESS;
        break;

    case IRP_MJ_DEVICE_CONTROL:
        status = AglHandleDeviceControl(Irp, irpSp, &info);
        break;
    }

    return AglFinishIrp(Irp, status, info);
}

static NTSTATUS AglControlGetVersion(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    AGL_VERSION_INFO info;

    UNREFERENCED_PARAMETER(InputLength);
    UNREFERENCED_PARAMETER(Header);

    if (OutputLength < sizeof(info))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(&info, sizeof(info));
    info.ProtocolVersion = AGL_PROTOCOL_VERSION;
    info.KernelMajor = 0;
    info.KernelMinor = 1;
    info.KernelBuild = 0;
    RtlCopyMemory(SystemBuffer, &info, sizeof(info));
    *Information = sizeof(info);
    return STATUS_SUCCESS;
}

static NTSTATUS AglControlSubscribe(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    UNREFERENCED_PARAMETER(SystemBuffer);
    UNREFERENCED_PARAMETER(InputLength);
    UNREFERENCED_PARAMETER(OutputLength);
    UNREFERENCED_PARAMETER(Header);
    UNREFERENCED_PARAMETER(Information);
    AglEventRingSubscribe();
    return STATUS_SUCCESS;
}

static NTSTATUS AglControlUnsubscribe(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    UNREFERENCED_PARAMETER(SystemBuffer);
    UNREFERENCED_PARAMETER(InputLength);
    UNREFERENCED_PARAMETER(OutputLength);
    UNREFERENCED_PARAMETER(Header);
    UNREFERENCED_PARAMETER(Information);
    AglEventRingUnsubscribe();
    return STATUS_SUCCESS;
}

static NTSTATUS AglControlReadEvents(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    ULONG bytes = 0;
    ULONG offset = Header->StructSize;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(InputLength);

    if (OutputLength <= offset)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    status = AglEventRingRead(
        (PUCHAR)SystemBuffer + offset,
        OutputLength - offset,
        &bytes);
    if (status == STATUS_NO_MORE_ENTRIES)
    {
        return status;
    }
    *Information = offset + bytes;
    return status;
}

static NTSTATUS AglControlGetStats(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    AGL_STATS stats;

    UNREFERENCED_PARAMETER(InputLength);
    UNREFERENCED_PARAMETER(Header);

    if (OutputLength < sizeof(stats))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    AglEventRingGetStats(&stats, sizeof(stats));
    RtlCopyMemory(SystemBuffer, &stats, sizeof(stats));
    *Information = sizeof(stats);
    return STATUS_SUCCESS;
}

static NTSTATUS AglControlQueryProcess(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    AGL_PROCESS_QUERY* query = (AGL_PROCESS_QUERY*)((PUCHAR)SystemBuffer + Header->StructSize);
    AGL_PROCESS_CTX* ctx;
    ULONG fixedSize = sizeof(AGL_PROCESS_QUERY);
    ULONG totalSize;

    if (InputLength < Header->StructSize + fixedSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ctx = AglContextAcquireProcessValidated(query->ProcessId);
    if (!ctx)
    {
        return STATUS_NOT_FOUND;
    }

    totalSize = fixedSize + ctx->ImagePath.Length + ctx->ImageName.Length;
    if (OutputLength < Header->StructSize + totalSize)
    {
        AglContextReleaseProcess(ctx);
        return STATUS_BUFFER_TOO_SMALL;
    }

    query->CreateTime = ctx->CreateTime;
    query->ParentProcessId = ctx->ParentProcessId;
    query->SessionId = ctx->SessionId;
    query->ImagePathLength = ctx->ImagePath.Length;
    query->ImageNameLength = ctx->ImageName.Length;
    query->ImagePathOffset = fixedSize;
    query->ImageNameOffset = fixedSize + ctx->ImagePath.Length;
    if (ctx->ImagePath.Length)
    {
        RtlCopyMemory(
            (PUCHAR)query + query->ImagePathOffset,
            ctx->ImagePath.Buffer,
            ctx->ImagePath.Length);
    }
    if (ctx->ImageName.Length)
    {
        RtlCopyMemory(
            (PUCHAR)query + query->ImageNameOffset,
            ctx->ImageName.Buffer,
            ctx->ImageName.Length);
    }

    AglContextReleaseProcess(ctx);
    *Information = Header->StructSize + totalSize;
    return STATUS_SUCCESS;
}

static NTSTATUS AglControlLoadPolicy(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    ULONG policyLength;

    UNREFERENCED_PARAMETER(OutputLength);
    UNREFERENCED_PARAMETER(Information);

    policyLength = InputLength > Header->StructSize
        ? InputLength - Header->StructSize
        : 0;
    if (policyLength == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }
    return AglPolicyLoad(
        (PUCHAR)SystemBuffer + Header->StructSize,
        policyLength);
}

static NTSTATUS AglControlClearPolicy(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    UNREFERENCED_PARAMETER(SystemBuffer);
    UNREFERENCED_PARAMETER(InputLength);
    UNREFERENCED_PARAMETER(OutputLength);
    UNREFERENCED_PARAMETER(Header);
    UNREFERENCED_PARAMETER(Information);
    AglPolicyClear();
    return STATUS_SUCCESS;
}

static NTSTATUS AglControlUpdateContext(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    AGL_CONTEXT_UPDATE* update = (AGL_CONTEXT_UPDATE*)((PUCHAR)SystemBuffer + Header->StructSize);
    UNICODE_STRING cwd;

    UNREFERENCED_PARAMETER(OutputLength);
    UNREFERENCED_PARAMETER(Information);

    if (InputLength < Header->StructSize + sizeof(AGL_CONTEXT_UPDATE) ||
        update->CurrentDirectoryLength > AGL_MAX_PATH_CHARS * sizeof(WCHAR) ||
        InputLength < Header->StructSize + sizeof(AGL_CONTEXT_UPDATE) + update->CurrentDirectoryLength)
    {
        return STATUS_INVALID_PARAMETER;
    }

    cwd.Buffer = update->Data;
    cwd.Length = (USHORT)update->CurrentDirectoryLength;
    cwd.MaximumLength = cwd.Length + sizeof(WCHAR);
    AglContextUpdateProcess(update->ProcessId, update->EnvironmentHash, &cwd);
    return STATUS_SUCCESS;
}

static NTSTATUS AglControlGetStreamStats(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    AGL_STREAM_STATS stats;

    UNREFERENCED_PARAMETER(InputLength);
    UNREFERENCED_PARAMETER(Header);

    if (OutputLength < sizeof(stats))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }
    AglNetworkGetStreamStats(&stats.Bytes, &stats.Packets);
    RtlCopyMemory(SystemBuffer, &stats, sizeof(stats));
    *Information = sizeof(stats);
    return STATUS_SUCCESS;
}

static NTSTATUS AglControlUpdateImageContext(
    PVOID SystemBuffer,
    ULONG InputLength,
    ULONG OutputLength,
    AGL_CONTROL_HEADER* Header,
    PULONG_PTR Information)
{
    AGL_IMAGE_UPDATE* update = (AGL_IMAGE_UPDATE*)((PUCHAR)SystemBuffer + Header->StructSize);

    UNREFERENCED_PARAMETER(OutputLength);
    UNREFERENCED_PARAMETER(Information);

    if (InputLength < Header->StructSize + sizeof(AGL_IMAGE_UPDATE))
    {
        return STATUS_INVALID_PARAMETER;
    }

    AglContextUpdateImage(
        update->ProcessId,
        update->ImageBase,
        update->PathHash,
        update->FileSha256,
        update->SignerState);
    return STATUS_SUCCESS;
}

static const AGL_CONTROL_OPERATION AglControlOperations[] = {
    { AGL_OP_GET_VERSION, 0, sizeof(AGL_VERSION_INFO), AglControlGetVersion },
    { AGL_OP_SUBSCRIBE_EVENTS, 0, 0, AglControlSubscribe },
    { AGL_OP_UNSUBSCRIBE_EVENTS, 0, 0, AglControlUnsubscribe },
    { AGL_OP_READ_EVENTS, 0, 0, AglControlReadEvents },
    { AGL_OP_GET_STATS, 0, sizeof(AGL_STATS), AglControlGetStats },
    { AGL_OP_QUERY_PROCESS, sizeof(AGL_PROCESS_QUERY), sizeof(AGL_PROCESS_QUERY), AglControlQueryProcess },
    { AGL_OP_LOAD_POLICY, 0, 0, AglControlLoadPolicy },
    { AGL_OP_CLEAR_POLICY, 0, 0, AglControlClearPolicy },
    { AGL_OP_UPDATE_CONTEXT, sizeof(AGL_CONTEXT_UPDATE), 0, AglControlUpdateContext },
    { AGL_OP_GET_STREAM_STATS, 0, sizeof(AGL_STREAM_STATS), AglControlGetStreamStats },
    { AGL_OP_UPDATE_IMAGE_CONTEXT, sizeof(AGL_IMAGE_UPDATE), 0, AglControlUpdateImageContext },
};

static NTSTATUS AglHandleDeviceControl(
    PIRP Irp,
    PIO_STACK_LOCATION IrpSp,
    PULONG_PTR Information)
{
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    AGL_CONTROL_HEADER* header;
    const AGL_CONTROL_OPERATION* operation = NULL;

    if (Irp->RequestorMode != UserMode)
    {
        return STATUS_ACCESS_DENIED;
    }

    if (IrpSp->Parameters.DeviceIoControl.IoControlCode != AGL_CONTROL_IOCTL)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (!systemBuffer || inputLength < sizeof(AGL_CONTROL_HEADER))
    {
        return STATUS_INVALID_PARAMETER;
    }

    header = (AGL_CONTROL_HEADER*)systemBuffer;
    if (header->StructSize != sizeof(*header) ||
        header->Version != AGL_PROTOCOL_VERSION)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (header->OpCode >= AGL_OP_MAX)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    for (ULONG i = 0; i < ARRAYSIZE(AglControlOperations); i++)
    {
        if (AglControlOperations[i].OpCode == header->OpCode)
        {
            operation = &AglControlOperations[i];
            break;
        }
    }

    if (!operation)
    {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (inputLength < header->StructSize + operation->RequiredInput ||
        outputLength < operation->RequiredOutput)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return operation->Handler(
        systemBuffer,
        inputLength,
        outputLength,
        header,
        Information);
}
