#include "agl_etw.h"

static const GUID AglEtwProviderGuid = {
    0x8b2d1c3e, 0x1234, 0x4a2b,
    { 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50 }
};

static REGHANDLE AglEtwHandle = 0;
static BOOLEAN AglEtwEnabled = FALSE;

static EVENT_DESCRIPTOR AglEtwDescriptor = {
    1000, 0, 0, 0, 0, 0, 0
};

NTSTATUS AglEtwInitialize(void)
{
    NTSTATUS status = EtwRegister(&AglEtwProviderGuid, NULL, NULL, &AglEtwHandle);
    if (NT_SUCCESS(status))
    {
        AglEtwEnabled = TRUE;
    }
    return status;
}

void AglEtwUninitialize(void)
{
    if (AglEtwEnabled)
    {
        EtwUnregister(AglEtwHandle);
        AglEtwHandle = 0;
        AglEtwEnabled = FALSE;
    }
}

void AglEtwWriteEvent(const AGL_EVENT_HEADER* Header, PVOID Payload, ULONG PayloadLength)
{
    ULONG total = sizeof(*Header) + PayloadLength;
    PUCHAR buffer;
    EVENT_DATA_DESCRIPTOR dataDescriptor;

    if (!AglEtwEnabled || !Header)
    {
        return;
    }

    buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, total, AGL_TAG);
    if (!buffer)
    {
        return;
    }

    RtlCopyMemory(buffer, Header, sizeof(*Header));
    if (Payload && PayloadLength)
    {
        RtlCopyMemory(buffer + sizeof(*Header), Payload, PayloadLength);
    }

    EventDataDescCreate(&dataDescriptor, buffer, total);

    EtwWriteTransfer(
        AglEtwHandle,
        &AglEtwDescriptor,
        NULL,
        NULL,
        1,
        &dataDescriptor);

    ExFreePoolWithTag(buffer, AGL_TAG);
}
