#pragma once

#include "agl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AGL_POLICY_MODE_OBSERVE 0
#define AGL_POLICY_MODE_CONTROL 1

typedef struct _AGL_POLICY_HEADER {
    unsigned long StructSize;
    unsigned long Version;
    unsigned long Mode;
    unsigned long RuleCount;
    unsigned long PayloadLength;
    unsigned long Reserved;
} AGL_POLICY_HEADER;

typedef struct _AGL_POLICY_RULE {
    unsigned long EventType;
    unsigned long Action;      // 0 = allow/log, 1 = deny
    unsigned long RuleSet;
    unsigned long Priority;
    unsigned long AccessMask;
    unsigned long ImageHash;
    unsigned long UserSidHash;
    unsigned long RootProcessHash;
    unsigned long PathLength;
    unsigned long ProcessLength;
    unsigned long CommandLineLength;
    wchar_t       Data[1];     // Path, followed by Process
} AGL_POLICY_RULE;

#ifdef __cplusplus
}
#endif
