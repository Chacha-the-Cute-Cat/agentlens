#pragma once

#include <ntddk.h>
#include "AgentLensProtocol/agl_types.h"

extern PDRIVER_OBJECT AglDriverObject;
extern UNICODE_STRING AglRegistryPath;
extern BOOLEAN AglReady;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD AglDriverUnload;
