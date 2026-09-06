#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdint>
#include <fstream>
#include <cstdlib>

#include "AgentLensProtocol/agl_control.h"
#include "AgentLensProtocol/agl_policy.h"
#include "policy_compiler.h"

static void PrintUsage()
{
    wprintf(L"AgentLensCtl usage:\n");
    wprintf(L"  --version\n");
    wprintf(L"  --stats\n");
    wprintf(L"  --subscribe\n");
    wprintf(L"  --unsubscribe\n");
    wprintf(L"  --policy <file>\n");
    wprintf(L"  --text-policy <file>\n");
    wprintf(L"  --clear-policy\n");
    wprintf(L"  --driver-stop\n");
    wprintf(L"  --driver-start\n");
    wprintf(L"  --driver-restart\n");
    wprintf(L"  --selftest\n");
    wprintf(L"  --fuzz-ioctl <count>\n");
    wprintf(L"  --fuzz-policy <count>\n");
    wprintf(L"  --stream-stats\n");
}

static bool SendControl(
    HANDLE device,
    AGL_OPCODE op,
    const void* input,
    ULONG inputLength,
    void* output,
    ULONG outputLength,
    ULONG& returned);

static void RunSelftest(HANDLE device)
{
    ULONG returned = 0;
    int passed = 0;
    int failed = 0;

    AGL_VERSION_INFO version{};
    if (SendControl(device, AGL_OP_GET_VERSION, nullptr, 0, &version, sizeof(version), returned))
    {
        wprintf(L"[PASS] get_version protocol=%u\n", version.ProtocolVersion);
        passed++;
    }
    else
    {
        wprintf(L"[FAIL] get_version\n");
        failed++;
    }

    AGL_SUBSCRIBE subscribe{};
    if (SendControl(device, AGL_OP_SUBSCRIBE_EVENTS, &subscribe, sizeof(subscribe), nullptr, 0, returned))
    {
        wprintf(L"[PASS] subscribe\n");
        passed++;
    }
    else
    {
        wprintf(L"[FAIL] subscribe\n");
        failed++;
    }

    if (SendControl(device, AGL_OP_UNSUBSCRIBE_EVENTS, nullptr, 0, nullptr, 0, returned))
    {
        wprintf(L"[PASS] unsubscribe\n");
        passed++;
    }
    else
    {
        wprintf(L"[FAIL] unsubscribe\n");
        failed++;
    }

    AGL_STATS stats{};
    if (SendControl(device, AGL_OP_GET_STATS, nullptr, 0, &stats, sizeof(stats), returned))
    {
        wprintf(L"[PASS] get_stats written=%llu dropped=%llu\n",
            static_cast<unsigned long long>(stats.EventsWritten),
            static_cast<unsigned long long>(stats.EventsDropped));
        passed++;
    }
    else
    {
        wprintf(L"[FAIL] get_stats\n");
        failed++;
    }

    // Invalid version must be rejected.
    AGL_CONTROL_HEADER bad{};
    bad.StructSize = sizeof(bad);
    bad.Version = 0;
    bad.OpCode = AGL_OP_GET_VERSION;
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(
        device,
        AGL_CONTROL_IOCTL,
        &bad,
        sizeof(bad),
        nullptr,
        0,
        &bytes,
        nullptr);
    if (!ok)
    {
        wprintf(L"[PASS] invalid_version_rejected error=%u\n", GetLastError());
        passed++;
    }
    else
    {
        wprintf(L"[FAIL] invalid_version_rejected\n");
        failed++;
    }

    wprintf(L"selftest passed=%d failed=%d\n", passed, failed);
    if (failed != 0)
    {
        ExitProcess(1);
    }
}

static void RunFuzzIoctl(HANDLE device, ULONG count)
{
    std::vector<uint8_t> buffer(512);
    DWORD bytes = 0;
    ULONG rejected = 0;

    srand(GetTickCount());
    for (ULONG i = 0; i < count; i++)
    {
        ULONG len = rand() % buffer.size();
        for (ULONG j = 0; j < len; j++)
        {
            buffer[j] = static_cast<uint8_t>(rand());
        }
        BOOL ok = DeviceIoControl(
            device,
            AGL_CONTROL_IOCTL,
            buffer.data(),
            len,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytes,
            nullptr);
        if (!ok)
        {
            rejected++;
        }
    }

    ULONG structured = 0;
    for (ULONG op = 0; op < AGL_OP_MAX; op++)
    {
        for (ULONG variant = 0; variant < 8; variant++)
        {
            std::vector<uint8_t> in(256, 0);
            std::vector<uint8_t> out(512, 0);
            auto* header = reinterpret_cast<AGL_CONTROL_HEADER*>(in.data());
            header->StructSize = sizeof(*header);
            header->Version = AGL_PROTOCOL_VERSION;
            header->OpCode = op;
            header->InputLength = 0;

            switch (variant)
            {
            case 0:
                header->StructSize = sizeof(*header) - 1;
                break;
            case 1:
                header->StructSize = sizeof(*header) + 1;
                break;
            case 2:
                header->StructSize = 0xFFFFFFFF;
                break;
            case 3:
                header->Version = 0;
                break;
            case 4:
                header->Version = 0xFFFFFFFF;
                break;
            case 5:
                header->OpCode = AGL_OP_MAX + 0x10;
                break;
            case 6:
                header->InputLength = 0xFFFFFFFF;
                break;
            case 7:
                header->InputLength = 0;
                break;
            }

            BOOL ok = DeviceIoControl(
                device,
                AGL_CONTROL_IOCTL,
                in.data(),
                static_cast<DWORD>(in.size()),
                out.data(),
                static_cast<DWORD>(out.size()),
                &bytes,
                nullptr);
            if (!ok)
            {
                rejected++;
            }
            structured++;
        }
    }

    wprintf(L"fuzz_ioctl random=%u structured=%u rejected=%u\n",
        count, structured, rejected);
}

static void RunFuzzPolicy(HANDLE device, ULONG count)
{
    ULONG rejected = 0;
    ULONG returned = 0;

    srand(GetTickCount());
    for (ULONG i = 0; i < count; i++)
    {
        ULONG length = (rand() % 2048) + 1;
        std::vector<uint8_t> policy(length);
        for (ULONG j = 0; j < length; j++)
        {
            policy[j] = static_cast<uint8_t>(rand());
        }

        if (length >= sizeof(AGL_POLICY_HEADER))
        {
            auto* header = reinterpret_cast<AGL_POLICY_HEADER*>(policy.data());
            header->StructSize = rand() % 256;
            header->Version = rand() % 4;
            header->Mode = rand() % 2;
            header->RuleCount = rand() % 256;
            header->PayloadLength = length - sizeof(*header);
        }

        if (!SendControl(
                device,
                AGL_OP_LOAD_POLICY,
                policy.data(),
                length,
                nullptr,
                0,
                returned))
        {
            rejected++;
        }
    }

    wprintf(L"fuzz_policy total=%u rejected=%u\n", count, rejected);
}

static void RunStreamStats(HANDLE device)
{
    AGL_STREAM_STATS stats{};
    ULONG returned = 0;
    if (SendControl(
            device,
            AGL_OP_GET_STREAM_STATS,
            nullptr,
            0,
            &stats,
            sizeof(stats),
            returned))
    {
        wprintf(L"StreamBytes=%llu StreamPackets=%llu\n",
            static_cast<unsigned long long>(stats.Bytes),
            static_cast<unsigned long long>(stats.Packets));
    }
    else
    {
        wprintf(L"Stream stats query failed.\n");
    }
}

static bool OpenDevice(HANDLE& handle)
{
    handle = CreateFileW(
        AGL_WIN32_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
    return handle != INVALID_HANDLE_VALUE;
}

static bool SendControl(
    HANDLE device,
    AGL_OPCODE op,
    const void* input,
    ULONG inputLength,
    void* output,
    ULONG outputLength,
    ULONG& returned)
{
    const ULONG headerSize = sizeof(AGL_CONTROL_HEADER);
    std::vector<uint8_t> inBuffer(headerSize + inputLength, 0);
    std::vector<uint8_t> outBuffer(headerSize + outputLength, 0);
    auto* header = reinterpret_cast<AGL_CONTROL_HEADER*>(inBuffer.data());
    header->StructSize = headerSize;
    header->Version = AGL_PROTOCOL_VERSION;
    header->OpCode = static_cast<ULONG>(op);
    header->InputLength = inputLength;
    if (input && inputLength)
    {
        memcpy(inBuffer.data() + headerSize, input, inputLength);
    }

    DWORD bytes = 0;
    if (!DeviceIoControl(
            device,
            AGL_CONTROL_IOCTL,
            inBuffer.data(),
            static_cast<DWORD>(inBuffer.size()),
            outBuffer.data(),
            static_cast<DWORD>(outBuffer.size()),
            &bytes,
            nullptr))
    {
        return false;
    }

    if (output && outputLength && bytes > headerSize)
    {
        ULONG copy = (bytes - headerSize) < outputLength ? (bytes - headerSize) : outputLength;
        memcpy(output, outBuffer.data() + headerSize, copy);
        returned = copy;
    }
    else
    {
        returned = 0;
    }
    return true;
}

static bool ReadFileBytes(const wchar_t* path, std::vector<uint8_t>& bytes)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
    {
        return false;
    }
    file.seekg(0, std::ios::end);
    std::streamoff size = file.tellg();
    file.seekg(0, std::ios::beg);
    if (size <= 0)
    {
        return false;
    }
    bytes.resize(static_cast<size_t>(size));
    file.read(reinterpret_cast<char*>(bytes.data()), size);
    return file.good() || file.eof();
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        PrintUsage();
        return 2;
    }

    HANDLE device = INVALID_HANDLE_VALUE;
    if (!OpenDevice(device))
    {
        wprintf(L"Failed to open AgentLensKernel device.\n");
        return 1;
    }

    ULONG returned = 0;
    if (lstrcmpiW(argv[1], L"--version") == 0)
    {
        AGL_VERSION_INFO info{};
        if (SendControl(device, AGL_OP_GET_VERSION, nullptr, 0, &info, sizeof(info), returned))
        {
            wprintf(L"ProtocolVersion=%u\n", info.ProtocolVersion);
        }
    }
    else if (lstrcmpiW(argv[1], L"--stats") == 0)
    {
        AGL_STATS stats{};
        if (SendControl(device, AGL_OP_GET_STATS, nullptr, 0, &stats, sizeof(stats), returned))
        {
            wprintf(L"Written=%llu Read=%llu Dropped=%llu\n",
                static_cast<unsigned long long>(stats.EventsWritten),
                static_cast<unsigned long long>(stats.EventsRead),
                static_cast<unsigned long long>(stats.EventsDropped));
            wprintf(L"CriticalDropped=%llu\n",
                static_cast<unsigned long long>(stats.CriticalDropped));
            wprintf(L"RingUsed=%llu RingTotal=%llu\n",
                static_cast<unsigned long long>(stats.RingBytesUsed),
                static_cast<unsigned long long>(stats.RingBytesTotal));
        }
    }
    else if (lstrcmpiW(argv[1], L"--subscribe") == 0)
    {
        SendControl(device, AGL_OP_SUBSCRIBE_EVENTS, nullptr, 0, nullptr, 0, returned);
    }
    else if (lstrcmpiW(argv[1], L"--unsubscribe") == 0)
    {
        SendControl(device, AGL_OP_UNSUBSCRIBE_EVENTS, nullptr, 0, nullptr, 0, returned);
    }
    else if (lstrcmpiW(argv[1], L"--policy") == 0 && argc >= 3)
    {
        std::vector<uint8_t> policy;
        if (!ReadFileBytes(argv[2], policy))
        {
            wprintf(L"Failed to read policy file: %s\n", argv[2]);
            CloseHandle(device);
            return 1;
        }
        if (SendControl(device, AGL_OP_LOAD_POLICY, policy.data(), static_cast<ULONG>(policy.size()), nullptr, 0, returned))
        {
            wprintf(L"Policy loaded (%zu bytes).\n", policy.size());
        }
        else
        {
            wprintf(L"Policy load failed.\n");
        }
    }
    else if (lstrcmpiW(argv[1], L"--text-policy") == 0 && argc >= 3)
    {
        std::vector<uint8_t> policy;
        std::wstring error;
        if (!CompileTextPolicy(argv[2], policy, error))
        {
            wprintf(L"Failed to compile policy: %s\n", error.c_str());
            CloseHandle(device);
            return 1;
        }
        if (SendControl(device, AGL_OP_LOAD_POLICY, policy.data(), static_cast<ULONG>(policy.size()), nullptr, 0, returned))
        {
            wprintf(L"Text policy compiled and loaded (%zu bytes).\n", policy.size());
        }
        else
        {
            wprintf(L"Policy load failed.\n");
        }
    }
    else if (lstrcmpiW(argv[1], L"--clear-policy") == 0)
    {
        SendControl(device, AGL_OP_CLEAR_POLICY, nullptr, 0, nullptr, 0, returned);
    }
    else if (lstrcmpiW(argv[1], L"--driver-stop") == 0)
    {
        int rc = _wsystem(L"sc.exe stop AgentLensKernel");
        wprintf(L"sc stop returned %d\n", rc);
    }
    else if (lstrcmpiW(argv[1], L"--driver-start") == 0)
    {
        int rc = _wsystem(L"sc.exe start AgentLensKernel");
        wprintf(L"sc start returned %d\n", rc);
    }
    else if (lstrcmpiW(argv[1], L"--driver-restart") == 0)
    {
        _wsystem(L"sc.exe stop AgentLensKernel");
        _wsystem(L"sc.exe start AgentLensKernel");
    }
    else if (lstrcmpiW(argv[1], L"--selftest") == 0)
    {
        RunSelftest(device);
    }
    else if (lstrcmpiW(argv[1], L"--fuzz-ioctl") == 0 && argc >= 3)
    {
        RunFuzzIoctl(device, static_cast<ULONG>(_wtoi(argv[2])));
    }
    else if (lstrcmpiW(argv[1], L"--fuzz-policy") == 0 && argc >= 3)
    {
        RunFuzzPolicy(device, static_cast<ULONG>(_wtoi(argv[2])));
    }
    else if (lstrcmpiW(argv[1], L"--stream-stats") == 0)
    {
        RunStreamStats(device);
    }
    else
    {
        PrintUsage();
    }

    CloseHandle(device);
    return 0;
}
