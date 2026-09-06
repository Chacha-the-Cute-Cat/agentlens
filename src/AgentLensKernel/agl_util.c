#include "agl_util.h"

PVOID AglAllocNonPaged(SIZE_T Size)
{
    return ExAllocatePoolWithTag(NonPagedPoolNx, Size, AGL_TAG);
}

PVOID AglAllocPaged(SIZE_T Size)
{
    return ExAllocatePoolWithTag(PagedPool, Size, AGL_TAG);
}

void AglFree(PVOID Ptr)
{
    if (Ptr)
    {
        ExFreePoolWithTag(Ptr, AGL_TAG);
    }
}

NTSTATUS AglCopyUnicodeString(
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Dest,
    _In_ POOL_TYPE PoolType)
{
    USHORT bytes = 0;

    RtlZeroMemory(Dest, sizeof(*Dest));
    if (!Source || !Source->Buffer || Source->Length == 0)
    {
        return STATUS_SUCCESS;
    }

    bytes = Source->Length;
    Dest->Buffer = (PoolType == PagedPool)
        ? AglAllocPaged(bytes + sizeof(WCHAR))
        : AglAllocNonPaged(bytes + sizeof(WCHAR));
    if (!Dest->Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Dest->Buffer, Source->Buffer, bytes);
    Dest->Buffer[bytes / sizeof(WCHAR)] = L'\0';
    Dest->Length = bytes;
    Dest->MaximumLength = bytes + sizeof(WCHAR);
    return STATUS_SUCCESS;
}

NTSTATUS AglCaptureString(
    _In_opt_ PCWSTR Source,
    _In_ USHORT MaxChars,
    _Out_ PUNICODE_STRING Dest,
    _In_ POOL_TYPE PoolType)
{
    SIZE_T len = 0;
    SIZE_T bytes = 0;

    RtlZeroMemory(Dest, sizeof(*Dest));
    if (!Source)
    {
        return STATUS_SUCCESS;
    }

    len = 0;
    while (len < MaxChars && Source[len] != L'\0')
    {
        len++;
    }
    if (len == 0)
    {
        return STATUS_SUCCESS;
    }

    bytes = (len + 1) * sizeof(WCHAR);
    Dest->Buffer = (PoolType == PagedPool)
        ? AglAllocPaged(bytes)
        : AglAllocNonPaged(bytes);
    if (!Dest->Buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(Dest->Buffer, Source, len * sizeof(WCHAR));
    Dest->Buffer[len] = L'\0';
    Dest->Length = (USHORT)(len * sizeof(WCHAR));
    Dest->MaximumLength = (USHORT)bytes;
    return STATUS_SUCCESS;
}

void AglFreeUnicodeString(_In_ PUNICODE_STRING Str)
{
    if (Str && Str->Buffer)
    {
        AglFree(Str->Buffer);
        RtlZeroMemory(Str, sizeof(*Str));
    }
}
