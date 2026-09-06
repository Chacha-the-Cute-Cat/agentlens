#pragma once

#include <ntddk.h>
#include "AgentLensProtocol/agl_types.h"

typedef struct _AGL_PROCESS_CTX {
    LIST_ENTRY ListEntry;
    ULONG64 ProcessId;
    ULONG64 ParentProcessId;
    ULONG64 CreateTime;
    ULONG64 CorrelationId;
    ULONG64 ParentCorrelationId;
    ULONG64 AgentSessionId;
    ULONG64 ExitTime;
    PVOID   TokenSnapshot;
    BOOLEAN Tombstoned;
    ULONG   SessionId;
    ULONG   Flags;
    LONG    RefCount;
    ULONG   Version;
    UNICODE_STRING ImagePath;
    UNICODE_STRING ImageName;
    UNICODE_STRING CommandLine;
} AGL_PROCESS_CTX;

typedef struct _AGL_THREAD_CTX {
    LIST_ENTRY ListEntry;
    ULONG64 ThreadId;
    ULONG64 ProcessId;
    ULONG64 CreateTime;
    ULONG   Flags;
} AGL_THREAD_CTX;

typedef struct _AGL_IMAGE_CTX {
    LIST_ENTRY ListEntry;
    ULONG64 ProcessId;
    ULONG64 ImageBase;
    ULONG   ImageSize;
    ULONG   PathHash;
    ULONG   SignerState;
} AGL_IMAGE_CTX;

typedef struct _AGL_CONTEXT_MANAGER {
    KSPIN_LOCK Lock;
    LIST_ENTRY ProcessList;
    ULONG      ProcessCount;
    LIST_ENTRY ThreadList;
    ULONG      ThreadCount;
    LIST_ENTRY ImageList;
    ULONG      ImageCount;
    ULONG64    NextCorrelationId;
} AGL_CONTEXT_MANAGER;

extern AGL_CONTEXT_MANAGER AglContext;

void AglContextInitialize(void);
void AglContextDestroy(void);

AGL_PROCESS_CTX* AglContextAcquireProcess(ULONG64 ProcessId);
void AglContextReleaseProcess(AGL_PROCESS_CTX* Ctx);

AGL_PROCESS_CTX* AglContextGetOrCreateProcess(
    ULONG64 ProcessId,
    ULONG64 ParentProcessId,
    ULONG64 CreateTime,
    ULONG64 CorrelationId,
    ULONG64 ParentCorrelationId,
    ULONG SessionId,
    PCUNICODE_STRING ImagePath,
    PCUNICODE_STRING ImageName,
    PCUNICODE_STRING CommandLine);

void AglContextRemoveProcess(ULONG64 ProcessId);
ULONG64 AglContextNextCorrelationId(void);
ULONG64 AglContextGetCorrelationId(ULONG64 ProcessId);

AGL_THREAD_CTX* AglContextGetOrCreateThread(ULONG64 ProcessId, ULONG64 ThreadId);
void AglContextRemoveThread(ULONG64 ThreadId);

AGL_IMAGE_CTX* AglContextGetOrCreateImage(
    ULONG64 ProcessId,
    ULONG64 ImageBase,
    ULONG ImageSize,
    ULONG PathHash);
