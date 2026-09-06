#pragma once

#include <ntddk.h>

NTSTATUS AglControlInitialize(PDRIVER_OBJECT DriverObject);
void     AglControlUninitialize(PDRIVER_OBJECT DriverObject);
PDEVICE_OBJECT AglControlGetDevice(void);

DRIVER_DISPATCH AglControlDispatch;
