#include "agl_trace.h"
#include <stdarg.h>

void AglTraceInfo(const char* Format, ...)
{
    va_list args;
    va_start(args, Format);
    vDbgPrintExWithPrefix("[AgentLens] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, args);
    va_end(args);
}

void AglTraceError(const char* Format, ...)
{
    va_list args;
    va_start(args, Format);
    vDbgPrintExWithPrefix("[AgentLens][ERROR] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Format, args);
    va_end(args);
}
