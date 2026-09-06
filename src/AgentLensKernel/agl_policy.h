#pragma once

#include <ntddk.h>

NTSTATUS AglPolicyInitialize(void);
void     AglPolicyUninitialize(void);

NTSTATUS AglPolicyLoad(PVOID Policy, ULONG PolicyLength);
void     AglPolicyClear(void);

BOOLEAN AglPolicyShouldDeny(ULONG EventType, PCUNICODE_STRING Path);
