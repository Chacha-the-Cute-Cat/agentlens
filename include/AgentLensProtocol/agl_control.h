#pragma once

#include "agl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#define AGL_CONTROL_IOCTL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define AGL_STREAM_DEVICE_NAME L"\\Device\\AgentLensStream"
#define AGL_STREAM_WIN32_DEVICE_NAME L"\\\\.\\AgentLensStream"
#define AGL_STREAM_IOCTL \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _AGL_STREAM_STATS {
    unsigned long long Bytes;
    unsigned long long Packets;
} AGL_STREAM_STATS;

typedef enum _AGL_OPCODE {
    AGL_OP_NONE = 0,
    AGL_OP_GET_VERSION,
    AGL_OP_SUBSCRIBE_EVENTS,
    AGL_OP_UNSUBSCRIBE_EVENTS,
    AGL_OP_READ_EVENTS,
    AGL_OP_GET_STATS,
    AGL_OP_QUERY_PROCESS,
    AGL_OP_LOAD_POLICY,
    AGL_OP_CLEAR_POLICY,
    AGL_OP_UPDATE_CONTEXT,
    AGL_OP_UPDATE_IMAGE_CONTEXT,
    AGL_OP_GET_STREAM_STATS,
    AGL_OP_MAX
} AGL_OPCODE;

typedef struct _AGL_CONTROL_HEADER {
    unsigned long  StructSize;
    unsigned long  Version;
    unsigned long  MessageId;
    unsigned long  OpCode;
    unsigned long  InputLength;
    unsigned long  OutputLength;
    unsigned long long CorrelationId;
    unsigned long long ProcessId;
    unsigned long long Reserved;
} AGL_CONTROL_HEADER;

typedef struct _AGL_SUBSCRIBE {
    unsigned long long ProcessId;
    unsigned long      InterestMask;
    unsigned long      Reserved;
} AGL_SUBSCRIBE;

typedef struct _AGL_VERSION_INFO {
    unsigned long ProtocolVersion;
    unsigned long KernelMajor;
    unsigned long KernelMinor;
    unsigned long KernelBuild;
} AGL_VERSION_INFO;

typedef struct _AGL_STATS {
    unsigned long long EventsWritten;
    unsigned long long EventsRead;
    unsigned long long EventsDropped;
    unsigned long long CriticalDropped;
    unsigned long long RingBytesUsed;
    unsigned long long RingBytesTotal;
    unsigned long      ActiveSubscribers;
    unsigned long      Reserved;
} AGL_STATS;

typedef struct _AGL_PROCESS_QUERY {
    unsigned long long ProcessId;
    unsigned long long CreateTime;
    unsigned long long ParentProcessId;
    unsigned long      SessionId;
    unsigned short     ImagePathLength;
    unsigned short     ImageNameLength;
    unsigned long      ImagePathOffset;
    unsigned long      ImageNameOffset;
} AGL_PROCESS_QUERY;

typedef struct _AGL_CONTEXT_UPDATE {
    unsigned long long ProcessId;
    unsigned long      EnvironmentHash;
    unsigned long      CurrentDirectoryLength;
    wchar_t            Data[1];
} AGL_CONTEXT_UPDATE;

typedef struct _AGL_IMAGE_UPDATE {
    unsigned long long ProcessId;
    unsigned long long ImageBase;
    unsigned long      PathHash;
    unsigned char      FileSha256[32];
    unsigned long      SignerState;
} AGL_IMAGE_UPDATE;

#define AGL_SIGNER_STATE_UNKNOWN  0
#define AGL_SIGNER_STATE_UNSIGNED 1
#define AGL_SIGNER_STATE_SIGNED   2

#ifdef __cplusplus
}
#endif
