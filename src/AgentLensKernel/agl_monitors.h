#pragma once

#include <ntddk.h>

NTSTATUS AglProcessMonitorInitialize(void);
void     AglProcessMonitorUninitialize(void);

NTSTATUS AglThreadMonitorInitialize(void);
void     AglThreadMonitorUninitialize(void);

NTSTATUS AglImageMonitorInitialize(void);
void     AglImageMonitorUninitialize(void);

NTSTATUS AglRegistryMonitorInitialize(PDRIVER_OBJECT DriverObject);
void     AglRegistryMonitorUninitialize(void);

NTSTATUS AglObjectMonitorInitialize(void);
void     AglObjectMonitorUninitialize(void);

NTSTATUS AglFileMonitorInitialize(PDRIVER_OBJECT DriverObject);
void     AglFileMonitorUninitialize(void);

NTSTATUS AglNetworkMonitorInitialize(PDRIVER_OBJECT DriverObject);
void     AglNetworkMonitorUninitialize(void);
