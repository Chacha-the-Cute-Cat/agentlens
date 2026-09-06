#pragma once

#include <ntddk.h>
#include <ntstrsafe.h>
#include "AgentLensProtocol/agl_types.h"

PVOID AglAllocNonPaged(SIZE_T Size);
PVOID AglAllocPaged(SIZE_T Size);
void  AglFree(PVOID Ptr);

NTSTATUS AglCopyUnicodeString(
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Dest,
    _In_ POOL_TYPE PoolType);

NTSTATUS AglCaptureString(
    _In_opt_ PCWSTR Source,
    _In_ USHORT MaxChars,
    _Out_ PUNICODE_STRING Dest,
    _In_ POOL_TYPE PoolType);

void AglFreeUnicodeString(_In_ PUNICODE_STRING Str);
