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
    ULONG64 ConversationId;
    ULONG64 ToolCallId;
    ULONG64 ExitTime;
    PVOID   TokenSnapshot;
    ULONG   TokenSidHash;
    ULONG   TokenIntegrityLevel;
    ULONG   TokenPrivilegeHash;
    BOOLEAN TokenSnapshotValid;
    BOOLEAN Tombstoned;
    volatile LONG TombstoneQueued;
    PIO_WORKITEM WorkItem;
    ULONG   SessionId;
    ULONG   Flags;
    LONG    RefCount;
    ULONG   Version;
    UNICODE_STRING ImagePath;
    UNICODE_STRING ImageName;
    UNICODE_STRING CommandLine;
    UNICODE_STRING CurrentDirectory;
    ULONG EnvironmentHash;
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
    ULONG64 FileSize;
    ULONG   PathHash;
    ULONG   SignerState;
    UCHAR   FileSha256[32];
    BOOLEAN FileHashValid;
} AGL_IMAGE_CTX;

typedef struct _AGL_NET_FLOW_CTX {
    LIST_ENTRY ListEntry;
    ULONG64 FlowId;
    ULONG64 ProcessId;
    ULONG   Protocol;
    USHORT  RemotePort;
    USHORT  LocalPort;
    UCHAR   RemoteAddress[16];
    ULONG64 Bytes;
    ULONG64 Packets;
    ULONG64 SendBytes;
    ULONG64 RecvBytes;
    ULONG64 SendPackets;
    ULONG64 RecvPackets;
} AGL_NET_FLOW_CTX;

typedef struct _AGL_CONTEXT_MANAGER {
    KSPIN_LOCK Lock;
    LIST_ENTRY ProcessList;
    ULONG      ProcessCount;
    LIST_ENTRY ThreadList;
    ULONG      ThreadCount;
    LIST_ENTRY ImageList;
    ULONG      ImageCount;
    LIST_ENTRY FlowList;
    ULONG      FlowCount;
    ULONG64    NextCorrelationId;
    volatile LONG PendingTombstones;
} AGL_CONTEXT_MANAGER;

extern AGL_CONTEXT_MANAGER AglContext;

void AglContextInitialize(void);
void AglContextDestroy(void);
void AglContextFlushTombstones(void);

AGL_PROCESS_CTX* AglContextAcquireProcess(ULONG64 ProcessId);
AGL_PROCESS_CTX* AglContextAcquireProcessValidated(ULONG64 ProcessId);
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
void AglContextUpdateProcess(ULONG64 ProcessId, ULONG EnvironmentHash, PCUNICODE_STRING CurrentDirectory);
void AglContextUpdateAgentTag(ULONG64 ProcessId, ULONG64 ConversationId, ULONG64 ToolCallId);
ULONG64 AglContextNextCorrelationId(void);
ULONG64 AglContextGetCorrelationId(ULONG64 ProcessId);
ULONG64 AglContextGetAgentSessionId(ULONG64 ProcessId);
void AglContextGetAgentTag(ULONG64 ProcessId, PULONG64 ConversationId, PULONG64 ToolCallId);
AGL_PROCESS_CTX* AglContextAcquireRootByAgentSessionId(ULONG64 AgentSessionId);

AGL_THREAD_CTX* AglContextGetOrCreateThread(ULONG64 ProcessId, ULONG64 ThreadId);
void AglContextRemoveThread(ULONG64 ThreadId);

AGL_IMAGE_CTX* AglContextGetOrCreateImage(
    ULONG64 ProcessId,
    ULONG64 ImageBase,
    ULONG ImageSize,
    ULONG PathHash);
void AglContextUpdateImage(
    ULONG64 ProcessId,
    ULONG64 ImageBase,
    ULONG PathHash,
    PUCHAR FileSha256,
    ULONG SignerState);

AGL_NET_FLOW_CTX* AglContextGetOrCreateFlow(
    ULONG64 FlowId,
    ULONG64 ProcessId,
    ULONG Protocol,
    USHORT RemotePort,
    USHORT LocalPort,
    const UCHAR* RemoteAddress);
void AglContextRemoveFlow(ULONG64 FlowId);
void AglContextAddFlowStats(ULONG64 FlowId, ULONG64 Bytes, ULONG64 Packets);
void AglContextAddFlowDirectionStats(
    ULONG64 FlowId,
    BOOLEAN Send,
    ULONG64 Bytes,
    ULONG64 Packets);
BOOLEAN AglContextGetFlowSnapshot(ULONG64 FlowId, AGL_NET_FLOW_CTX* Out);
