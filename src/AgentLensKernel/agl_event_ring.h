#pragma once

#include <ntddk.h>
#include "AgentLensProtocol/agl_types.h"
#include "AgentLensProtocol/agl_event.h"

typedef struct _AGL_EVENT_RING {
    KSPIN_LOCK Lock;
    PVOID      Base;
    PVOID      SectionObject;
    HANDLE     SectionHandle;
    PKEVENT    ReadyEventObject;
    SIZE_T     Size;
    SIZE_T     DataOffset;
    SIZE_T     Head;      // write offset
    SIZE_T     Tail;      // read offset
    ULONG64    Written;
    ULONG64    Read;
    ULONG64    Dropped;
    ULONG64    CriticalDropped;
    ULONG      ActiveSubscribers;
} AGL_EVENT_RING;

extern AGL_EVENT_RING AglEventRing;

NTSTATUS AglEventRingInitialize(SIZE_T Size);
void     AglEventRingDestroy(void);

ULONG AglEventRingSubscribe(void);
void  AglEventRingUnsubscribe(void);

NTSTATUS AglEventRingWrite(PVOID Data, ULONG Length);
NTSTATUS AglEventRingRead(PVOID Buffer, ULONG BufferLength, PULONG BytesReturned);
void     AglEventRingGetStats(PVOID Stats, ULONG StatsLength);
