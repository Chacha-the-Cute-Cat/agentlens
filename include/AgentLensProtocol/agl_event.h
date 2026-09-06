#pragma once

#include "agl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _AGL_EVENT_TYPE {
    AGL_EVENT_NONE = 0,
    AGL_EVENT_PROCESS_CREATE,
    AGL_EVENT_PROCESS_EXIT,
    AGL_EVENT_THREAD_CREATE,
    AGL_EVENT_THREAD_EXIT,
    AGL_EVENT_IMAGE_LOAD,
    AGL_EVENT_FILE_OPEN,
    AGL_EVENT_FILE_RENAME,
    AGL_EVENT_FILE_READ,
    AGL_EVENT_FILE_WRITE,
    AGL_EVENT_FILE_DELETE,
    AGL_EVENT_FILE_CLOSE,
    AGL_EVENT_FILE_QUERY,
    AGL_EVENT_FILE_SECURITY,
    AGL_EVENT_FILE_DIRECTORY,
    AGL_EVENT_REGISTRY_OPEN,
    AGL_EVENT_REGISTRY_QUERY,
    AGL_EVENT_REGISTRY_SET_VALUE,
    AGL_EVENT_REGISTRY_ENUM_KEY,
    AGL_EVENT_REGISTRY_ENUM_VALUE,
    AGL_EVENT_REGISTRY_DELETE_KEY,
    AGL_EVENT_REGISTRY_DELETE_VALUE,
    AGL_EVENT_OBJECT_HANDLE,
    AGL_EVENT_NETWORK_CONNECT,
    AGL_EVENT_NETWORK_FLOW_ESTABLISHED,
    AGL_EVENT_NETWORK_FLOW_CLOSED,
    AGL_EVENT_POLICY_DENY,
    AGL_EVENT_MAX
} AGL_EVENT_TYPE;

#define AGL_EVENT_RING_MAGIC 0x676C4145 // 'EAgL' little-endian
#define AGL_EVENT_SCHEMA_VERSION 2

typedef struct _AGL_RING_RECORD_HEADER {
    unsigned long RecordLength; // total bytes, including this header
    unsigned long Flags;
    unsigned long Reserved;
} AGL_RING_RECORD_HEADER;

typedef struct _AGL_EVENT_RING_SHARED_HEADER {
    unsigned long  Magic;
    unsigned long  Version;
    unsigned long long Size;
    volatile unsigned long long Head;
    volatile unsigned long long Tail;
    volatile unsigned long long Written;
    volatile unsigned long long Dropped;
    unsigned long  Reserved[8];
} AGL_EVENT_RING_SHARED_HEADER;

typedef struct _AGL_EVENT_HEADER {
    unsigned long      StructSize;
    unsigned long      Version;
    unsigned long      EventType;
    unsigned long      ResultStatus;
    unsigned long long Sequence;
    unsigned long long Timestamp;
    unsigned long long ProcessId;
    unsigned long long ThreadId;
    unsigned long long ParentProcessId;
    unsigned long long CorrelationId;
    unsigned long      SessionId;
    unsigned long      Flags;
    unsigned long      PayloadLength;
} AGL_EVENT_HEADER;

#define AGL_EVENT_FLAG_CRITICAL 0x00000001

typedef struct _AGL_PROCESS_EVENT {
    AGL_EVENT_HEADER Header;
    unsigned long long CreateTime;
    unsigned long      ImagePathLength;
    unsigned long      CommandLineLength;
    unsigned short     ImageNameLength;
    unsigned short     Reserved;
    wchar_t            Data[1];
} AGL_PROCESS_EVENT;

typedef struct _AGL_THREAD_EVENT {
    AGL_EVENT_HEADER Header;
    unsigned long long ThreadCreateTime;
} AGL_THREAD_EVENT;

typedef struct _AGL_IMAGE_EVENT {
    AGL_EVENT_HEADER Header;
    unsigned long long ImageBase;
    unsigned long      ImageSize;
    unsigned long      PathLength;
    wchar_t            Data[1];
} AGL_IMAGE_EVENT;

typedef struct _AGL_FILE_EVENT {
    AGL_EVENT_HEADER Header;
    unsigned long DesiredAccess;
    unsigned long CreateOptions;
    unsigned long CreateDisposition;
    unsigned long long Offset;
    unsigned long Length;
    unsigned long SecurityInformation;
    unsigned long InfoClass;
    unsigned long NameLength;
    unsigned long PathLength;
    wchar_t       Data[1];
} AGL_FILE_EVENT;

typedef struct _AGL_REGISTRY_EVENT {
    AGL_EVENT_HEADER Header;
    unsigned long DesiredAccess;
    unsigned long ValueType;
    unsigned long ValueLength;
    unsigned long ValueHash;
    unsigned long Flags;
    unsigned long Index;
    unsigned long InfoClass;
    unsigned long PathLength;
    wchar_t       Data[1];
} AGL_REGISTRY_EVENT;

typedef struct _AGL_OBJECT_EVENT {
    AGL_EVENT_HEADER Header;
    unsigned long ObjectType;
    unsigned long DesiredAccess;
    unsigned long GrantedAccess;
    unsigned long TargetProcessId;
} AGL_OBJECT_EVENT;

typedef struct _AGL_NETWORK_EVENT {
    AGL_EVENT_HEADER Header;
    unsigned long Protocol;
    unsigned long RemotePort;
    unsigned long LocalPort;
    unsigned long long BytesSent;
    unsigned long long BytesReceived;
    unsigned long long PacketsSent;
    unsigned long long PacketsReceived;
    unsigned char  RemoteAddress[16];
    unsigned char  LocalAddress[16];
} AGL_NETWORK_EVENT;

#ifdef __cplusplus
}
#endif
