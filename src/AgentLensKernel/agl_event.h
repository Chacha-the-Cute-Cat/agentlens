#pragma once

#include <ntddk.h>
#include "AgentLensProtocol/agl_event.h"

NTSTATUS AglEventEmit(
    ULONG EventType,
    ULONG ResultStatus,
    ULONG64 ProcessId,
    ULONG64 ThreadId,
    ULONG64 ParentProcessId,
    ULONG64 CorrelationId,
    ULONG SessionId,
    PVOID Payload,
    ULONG PayloadLength);

NTSTATUS AglEventEmitProcess(
    ULONG EventType,
    ULONG64 ProcessId,
    ULONG64 ParentProcessId,
    ULONG64 CreateTime,
    ULONG64 CorrelationId,
    PCUNICODE_STRING ImagePath,
    PCUNICODE_STRING ImageName,
    PCUNICODE_STRING CommandLine);

NTSTATUS AglEventEmitThread(
    ULONG EventType,
    ULONG64 ProcessId,
    ULONG64 ThreadId,
    ULONG64 ParentProcessId);

NTSTATUS AglEventEmitImage(
    ULONG EventType,
    ULONG64 ProcessId,
    ULONG64 ImageBase,
    ULONG ImageSize,
    PCUNICODE_STRING Path);
