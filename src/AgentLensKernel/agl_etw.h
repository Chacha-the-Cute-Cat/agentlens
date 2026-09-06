#pragma once

#include <ntddk.h>
#include "AgentLensProtocol/agl_event.h"

NTSTATUS AglEtwInitialize(void);
void     AglEtwUninitialize(void);
void     AglEtwWriteEvent(const AGL_EVENT_HEADER* Header, PVOID Payload, ULONG PayloadLength);
