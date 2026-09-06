#define NDIS61 1

#include <ntifs.h>
#include <ntddk.h>

#pragma warning(push)
#pragma warning(disable: 4201)
#include <fwpsk.h>
#pragma warning(pop)

#include <guiddef.h>
#include <initguid.h>
#include <fwpmk.h>
#include <fwpvi.h>

#include "agl_monitors.h"
#include "agl_control.h"
#include "agl_context.h"
#include "agl_event.h"
#include "agl_policy.h"
#include "agl_trace.h"

DRIVER_INITIALIZE DriverEntry;

static HANDLE AglWfpEngine = NULL;
static UINT32 AglCalloutConnectV4 = 0;
static UINT32 AglCalloutConnectV6 = 0;
static UINT32 AglCalloutRecvV4 = 0;
static UINT32 AglCalloutRecvV6 = 0;
static UINT32 AglCalloutFlowV4 = 0;
static UINT32 AglCalloutFlowV6 = 0;
static UINT32 AglCalloutCloseV4 = 0;
static UINT32 AglCalloutCloseV6 = 0;
static UINT64 AglFilterConnectV4 = 0;
static UINT64 AglFilterConnectV6 = 0;
static UINT64 AglFilterRecvV4 = 0;
static UINT64 AglFilterRecvV6 = 0;
static UINT64 AglFilterFlowV4 = 0;
static UINT64 AglFilterFlowV6 = 0;
static UINT64 AglFilterCloseV4 = 0;
static UINT64 AglFilterCloseV6 = 0;
static UINT32 AglCalloutStreamV4 = 0;
static UINT32 AglCalloutStreamV6 = 0;
static UINT64 AglFilterStreamV4 = 0;
static UINT64 AglFilterStreamV6 = 0;
static volatile ULONG64 AglStreamBytes = 0;
static volatile ULONG64 AglStreamPackets = 0;

void AglNetworkGetStreamStats(ULONG64* Bytes, ULONG64* Packets)
{
    if (Bytes) *Bytes = AglStreamBytes;
    if (Packets) *Packets = AglStreamPackets;
}

DEFINE_GUID(AGL_CALLOUT_CONNECT_V4,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21);
DEFINE_GUID(AGL_CALLOUT_CONNECT_V6,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22);
DEFINE_GUID(AGL_CALLOUT_RECV_V4,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23);
DEFINE_GUID(AGL_CALLOUT_RECV_V6,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24);
DEFINE_GUID(AGL_CALLOUT_FLOW_V4,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25);
DEFINE_GUID(AGL_CALLOUT_FLOW_V6,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26);
DEFINE_GUID(AGL_CALLOUT_CLOSE_V4,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x27);
DEFINE_GUID(AGL_CALLOUT_CLOSE_V6,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28);
DEFINE_GUID(AGL_CALLOUT_STREAM_V4,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x29);
DEFINE_GUID(AGL_CALLOUT_STREAM_V6,
    0x8b2d1c3e, 0x1234, 0x4a2b, 0x9c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A);

static void AglFormatIPv4(UINT32 address, PWCHAR Buffer, USHORT BufferChars)
{
    static const WCHAR prefix[] = L"IPv4:";
    WCHAR digits[16];
    UCHAR bytes[4];
    ULONG i;
    ULONG pos = 0;

    bytes[0] = (UCHAR)(address & 0xFF);
    bytes[1] = (UCHAR)((address >> 8) & 0xFF);
    bytes[2] = (UCHAR)((address >> 16) & 0xFF);
    bytes[3] = (UCHAR)((address >> 24) & 0xFF);

    if (BufferChars < ARRAYSIZE(prefix))
    {
        return;
    }
    for (i = 0; i < ARRAYSIZE(prefix) - 1; i++)
    {
        Buffer[pos++] = prefix[i];
    }

    for (i = 0; i < 4; i++)
    {
        ULONG value = bytes[i];
        ULONG len = 0;
        if (value >= 100)
        {
            digits[len++] = (WCHAR)(L'0' + value / 100);
            value %= 100;
        }
        if (value >= 10 || len > 0)
        {
            digits[len++] = (WCHAR)(L'0' + value / 10);
            value %= 10;
        }
        digits[len++] = (WCHAR)(L'0' + value);
        digits[len] = L'\0';

        if (pos + len >= (ULONG)(BufferChars - 1))
        {
            break;
        }
        RtlCopyMemory(&Buffer[pos], digits, len * sizeof(WCHAR));
        pos += len;
        if (i != 3 && pos + 1 < BufferChars)
        {
            Buffer[pos++] = L'.';
        }
    }
    Buffer[pos] = L'\0';
}

static void AglNetworkClassify(
    const FWPS_INCOMING_VALUES* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
    void* layerData,
    const void* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT* classifyOut)
{
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(filter);
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0)
    {
        classifyOut->actionType = FWP_ACTION_PERMIT;
    }

    if (inFixedValues &&
        (inFixedValues->layerId == FWPS_LAYER_STREAM_V4 ||
         inFixedValues->layerId == FWPS_LAYER_STREAM_V6))
    {
        FWPS_STREAM_CALLOUT_IO_PACKET0* packet = (FWPS_STREAM_CALLOUT_IO_PACKET0*)layerData;
        if (packet && packet->streamData)
        {
            InterlockedAdd64((LONG64*)&AglStreamBytes, (LONG64)packet->streamData->dataLength);
            InterlockedIncrement64((LONG64*)&AglStreamPackets);
            if (flowContext)
            {
                BOOLEAN send = (packet->streamData->flags & FWPS_STREAM_FLAG_SEND) != 0;
                AglContextAddFlowDirectionStats(
                    flowContext,
                    send,
                    (ULONG64)packet->streamData->dataLength,
                    1);
            }
        }
    }

    if (FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID))
    {
        AGL_NETWORK_EVENT event;
        ULONG eventType = AGL_EVENT_NETWORK_CONNECT;
        UNICODE_STRING remotePath = { 0 };
        WCHAR remotePathBuffer[64];
        RtlZeroMemory(&event, sizeof(event));

        if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4)
        {
            event.Protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
            event.RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
            event.LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
            UINT32 remote = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
            event.RemoteAddress[12] = (remote >> 0) & 0xFF;
            event.RemoteAddress[13] = (remote >> 8) & 0xFF;
            event.RemoteAddress[14] = (remote >> 16) & 0xFF;
            event.RemoteAddress[15] = (remote >> 24) & 0xFF;
            remotePath.Buffer = remotePathBuffer;
            remotePath.MaximumLength = sizeof(remotePathBuffer);
            AglFormatIPv4(remote, remotePathBuffer, 64);
            remotePath.Length = (USHORT)(wcslen(remotePathBuffer) * sizeof(WCHAR));
        }
        else if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6)
        {
            event.Protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
            event.RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
            event.LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
            const FWP_BYTE_ARRAY16* remote = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
            if (remote)
            {
                RtlCopyMemory(event.RemoteAddress, remote->byteArray16, 16);
            }
        }
        else if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4)
        {
            event.Protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
            event.RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
            event.LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
        }
        else if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6)
        {
            event.Protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8;
            event.RemotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16;
            event.LocalPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
        }
        else if (inFixedValues->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 ||
                 inFixedValues->layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6)
        {
            eventType = AGL_EVENT_NETWORK_FLOW_ESTABLISHED;
        }
        else if (inFixedValues->layerId == FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V4 ||
                 inFixedValues->layerId == FWPS_LAYER_ALE_ENDPOINT_CLOSURE_V6)
        {
            eventType = AGL_EVENT_NETWORK_FLOW_CLOSED;
        }

        if ((eventType == AGL_EVENT_NETWORK_CONNECT) &&
            AglPolicyShouldDeny(
                AGL_EVENT_NETWORK_CONNECT,
                remotePath.Length ? &remotePath : NULL))
        {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            return;
        }

        AglEventEmit(
            eventType,
            STATUS_SUCCESS,
            (ULONG64)(ULONG_PTR)inMetaValues->processId,
            (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
            0,
            0,
            0,
            &event,
            sizeof(event));

        if (flowContext)
        {
            AglContextGetOrCreateFlow(
                flowContext,
                (ULONG64)(ULONG_PTR)inMetaValues->processId,
                event.Protocol,
                (USHORT)event.RemotePort,
                (USHORT)event.LocalPort,
                event.RemoteAddress);
        }
    }
}

static NTSTATUS AglNetworkNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    const FWPS_FILTER1* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static NTSTATUS AglNetworkFlowDelete(
    UINT16 layerId,
    UINT32 calloutId,
    UINT64 flowContext)
{
    AGL_NET_FLOW_CTX snapshot = { 0 };
    if (AglContextGetFlowSnapshot(flowContext, &snapshot))
    {
        AGL_NETWORK_EVENT event;
        RtlZeroMemory(&event, sizeof(event));
        event.Protocol = snapshot.Protocol;
        event.RemotePort = snapshot.RemotePort;
        event.LocalPort = snapshot.LocalPort;
        event.BytesSent = snapshot.SendBytes;
        event.BytesReceived = snapshot.RecvBytes;
        event.PacketsSent = snapshot.SendPackets;
        event.PacketsReceived = snapshot.RecvPackets;
        RtlCopyMemory(event.RemoteAddress, snapshot.RemoteAddress, 16);

        AglEventEmit(
            AGL_EVENT_NETWORK_FLOW_CLOSED,
            STATUS_SUCCESS,
            snapshot.ProcessId,
            (ULONG64)(ULONG_PTR)PsGetCurrentThreadId(),
            0,
            0,
            0,
            &event,
            sizeof(event));
    }

    AglContextRemoveFlow(flowContext);
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    return STATUS_SUCCESS;
}

static NTSTATUS AglRegisterCallout(
    const GUID* calloutKey,
    const GUID* layerKey,
    UINT32* calloutId,
    UINT64* filterId)
{
    NTSTATUS status;
    FWPS_CALLOUT1 callout = { 0 };
    FWPM_CALLOUT0 fwpmCallout = { 0 };
    FWPM_FILTER0 filter = { 0 };

    callout.calloutKey = *calloutKey;
    callout.classifyFn = AglNetworkClassify;
    callout.notifyFn = AglNetworkNotify;
    callout.flowDeleteFn = AglNetworkFlowDelete;

    status = FwpsCalloutRegister1(AglControlGetDevice(), &callout, calloutId);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    fwpmCallout.calloutKey = *calloutKey;
    fwpmCallout.displayData.name = (wchar_t*)L"AgentLens WFP Callout";
    fwpmCallout.displayData.description = (wchar_t*)L"AgentLens network monitor";
    fwpmCallout.applicableLayer = *layerKey;

    status = FwpmCalloutAdd0(AglWfpEngine, &fwpmCallout, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        FwpsCalloutUnregisterById(*calloutId);
        *calloutId = 0;
        return status;
    }

    filter.displayData.name = (wchar_t*)L"AgentLens WFP Filter";
    filter.displayData.description = (wchar_t*)L"AgentLens network observation";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = *calloutKey;
    filter.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 15;
    filter.numFilterConditions = 0;
    filter.layerKey = *layerKey;

    status = FwpmFilterAdd0(AglWfpEngine, &filter, NULL, filterId);
    if (!NT_SUCCESS(status))
    {
        FwpsCalloutUnregisterById(*calloutId);
        *calloutId = 0;
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS AglNetworkMonitorInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    FWPM_SESSION0 session = { 0 };
    BOOLEAN inTransaction = FALSE;

    UNREFERENCED_PARAMETER(DriverObject);

    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &AglWfpEngine);
    if (!NT_SUCCESS(status))
    {
        AglTraceError("FwpmEngineOpen0 failed: 0x%08X\n", status);
        return status;
    }

    status = FwpmTransactionBegin0(AglWfpEngine, 0);
    if (!NT_SUCCESS(status))
    {
        FwpmEngineClose0(AglWfpEngine);
        AglWfpEngine = NULL;
        return status;
    }
    inTransaction = TRUE;

    status = AglRegisterCallout(&AGL_CALLOUT_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &AglCalloutConnectV4, &AglFilterConnectV4);
    if (NT_SUCCESS(status))
    {
        status = AglRegisterCallout(&AGL_CALLOUT_CONNECT_V6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &AglCalloutConnectV6, &AglFilterConnectV6);
    }
    if (NT_SUCCESS(status))
    {
        status = AglRegisterCallout(&AGL_CALLOUT_RECV_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, &AglCalloutRecvV4, &AglFilterRecvV4);
    }
    if (NT_SUCCESS(status))
    {
        status = AglRegisterCallout(&AGL_CALLOUT_RECV_V6, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, &AglCalloutRecvV6, &AglFilterRecvV6);
    }
    if (NT_SUCCESS(status))
    {
        status = AglRegisterCallout(&AGL_CALLOUT_FLOW_V4, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, &AglCalloutFlowV4, &AglFilterFlowV4);
    }
    if (NT_SUCCESS(status))
    {
        status = AglRegisterCallout(&AGL_CALLOUT_FLOW_V6, &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6, &AglCalloutFlowV6, &AglFilterFlowV6);
    }
    if (NT_SUCCESS(status))
    {
        status = AglRegisterCallout(&AGL_CALLOUT_CLOSE_V4, &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4, &AglCalloutCloseV4, &AglFilterCloseV4);
    }
    if (NT_SUCCESS(status))
    {
        status = AglRegisterCallout(&AGL_CALLOUT_CLOSE_V6, &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6, &AglCalloutCloseV6, &AglFilterCloseV6);
    }
    if (NT_SUCCESS(status))
    {
        status = AglRegisterCallout(&AGL_CALLOUT_STREAM_V4, &FWPM_LAYER_STREAM_V4, &AglCalloutStreamV4, &AglFilterStreamV4);
    }
    if (NT_SUCCESS(status))
    {
        status = AglRegisterCallout(&AGL_CALLOUT_STREAM_V6, &FWPM_LAYER_STREAM_V6, &AglCalloutStreamV6, &AglFilterStreamV6);
    }

    if (NT_SUCCESS(status))
    {
        status = FwpmTransactionCommit0(AglWfpEngine);
        inTransaction = FALSE;
    }

    if (!NT_SUCCESS(status))
    {
        if (inTransaction)
        {
            FwpmTransactionAbort0(AglWfpEngine);
        }
        if (AglCalloutConnectV4) FwpsCalloutUnregisterById(AglCalloutConnectV4);
        if (AglCalloutConnectV6) FwpsCalloutUnregisterById(AglCalloutConnectV6);
        if (AglCalloutRecvV4) FwpsCalloutUnregisterById(AglCalloutRecvV4);
        if (AglCalloutRecvV6) FwpsCalloutUnregisterById(AglCalloutRecvV6);
        if (AglCalloutFlowV4) FwpsCalloutUnregisterById(AglCalloutFlowV4);
        if (AglCalloutFlowV6) FwpsCalloutUnregisterById(AglCalloutFlowV6);
        if (AglCalloutCloseV4) FwpsCalloutUnregisterById(AglCalloutCloseV4);
        if (AglCalloutCloseV6) FwpsCalloutUnregisterById(AglCalloutCloseV6);
        if (AglCalloutStreamV4) FwpsCalloutUnregisterById(AglCalloutStreamV4);
        if (AglCalloutStreamV6) FwpsCalloutUnregisterById(AglCalloutStreamV6);
        FwpmEngineClose0(AglWfpEngine);
        AglWfpEngine = NULL;
        return status;
    }

    AglTraceInfo("AgentLens WFP ALE callouts registered.\n");
    return STATUS_SUCCESS;
}

void AglNetworkMonitorUninitialize(void)
{
    if (AglCalloutConnectV4) FwpsCalloutUnregisterById(AglCalloutConnectV4);
    if (AglCalloutConnectV6) FwpsCalloutUnregisterById(AglCalloutConnectV6);
    if (AglCalloutRecvV4) FwpsCalloutUnregisterById(AglCalloutRecvV4);
    if (AglCalloutRecvV6) FwpsCalloutUnregisterById(AglCalloutRecvV6);
    if (AglCalloutFlowV4) FwpsCalloutUnregisterById(AglCalloutFlowV4);
    if (AglCalloutFlowV6) FwpsCalloutUnregisterById(AglCalloutFlowV6);
    if (AglCalloutCloseV4) FwpsCalloutUnregisterById(AglCalloutCloseV4);
    if (AglCalloutCloseV6) FwpsCalloutUnregisterById(AglCalloutCloseV6);
    if (AglCalloutStreamV4) FwpsCalloutUnregisterById(AglCalloutStreamV4);
    if (AglCalloutStreamV6) FwpsCalloutUnregisterById(AglCalloutStreamV6);
    AglCalloutConnectV4 = 0;
    AglCalloutConnectV6 = 0;
    AglCalloutRecvV4 = 0;
    AglCalloutRecvV6 = 0;
    AglCalloutFlowV4 = 0;
    AglCalloutFlowV6 = 0;
    AglCalloutCloseV4 = 0;
    AglCalloutCloseV6 = 0;
    AglCalloutStreamV4 = 0;
    AglCalloutStreamV6 = 0;

    if (AglWfpEngine)
    {
        FwpmEngineClose0(AglWfpEngine);
        AglWfpEngine = NULL;
    }
}
