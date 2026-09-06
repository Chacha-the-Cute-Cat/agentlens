#pragma once

#include <ntddk.h>

void AglTraceInfo(const char* Format, ...);
void AglTraceError(const char* Format, ...);
