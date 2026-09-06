#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <basetsd.h>

#define AGL_PROTOCOL_VERSION 1

#define AGL_TAG 'sglA'

#define AGL_DEVICE_NAME       L"\\Device\\AgentLensControl"
#define AGL_DOS_DEVICE_NAME   L"\\DosDevices\\AgentLensControl"
#define AGL_WIN32_DEVICE_NAME L"\\\\.\\AgentLensControl"

#define AGL_MAX_PATH_CHARS      1024
#define AGL_MAX_COMMAND_CHARS   2048
#define AGL_MAX_EVENT_PAYLOAD   4096

typedef unsigned long      AGL_STATUS;
typedef unsigned long long AGL_SEQUENCE;
typedef unsigned long long AGL_TIMESTAMP;

#define AGL_STATUS_SUCCESS            0L
#define AGL_STATUS_INVALID_PARAMETER  0xC000000DL
#define AGL_STATUS_BUFFER_TOO_SMALL   0xC0000023L
#define AGL_STATUS_NOT_FOUND          0xC0000225L
#define AGL_STATUS_ACCESS_DENIED      0xC0000022L
#define AGL_STATUS_NOT_SUPPORTED      0xC00000BBL

#ifdef __cplusplus
}
#endif
