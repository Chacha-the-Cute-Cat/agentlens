# AgentLens

AgentLens is a Windows 10/11 runtime security project for observing, correlating, and controlling process, thread, image, file, registry, object, and network activity.

The project follows the architecture described in `docs/agentlens/ARCHITECTURE.html`. The current implementation is a single-driver design:

- `AgentLensKernel.sys` combines the control driver, minifilter, and WFP callout modules.
- `AgentLensService.exe` consumes kernel events and exposes the JSON event stream.
- `AgentLensAgent.dll` runs inside a target process and provides process, command, environment, and image context.
- `AgentLensTools.exe` provides the control and diagnostic CLI.
- `AgentLensEtw.exe` is a standalone ETW consumer for validation and debugging.

## Current Status

The repository contains a compilable, loadable, observable, and partially controllable kernel security framework. Test signing is used for development; production signing and deployment are not yet complete.

## Implemented

### Kernel

- Control device `\Device\AgentLensControl`
- Non-paged event ring with a kernel-owned consumer index and IOCTL event consumption
- Named event notification
- Process monitoring with `PsSetCreateProcessNotifyRoutineEx`
- Thread monitoring with `PsSetCreateThreadNotifyRoutine`
- Image load monitoring with `PsSetLoadImageNotifyRoutine`
- Registry monitoring with `CmRegisterCallbackEx`
- Object handle monitoring with `ObRegisterCallbacks`
- File monitoring through a minifilter instance
- Network monitoring through WFP ALE callouts
- WFP stream callouts for byte and packet counters
- Network flow context with send/receive statistics
- ETW event emission
- Control device DACL and request validation

### Events

Observed event categories include:

- Process create and exit
- Thread create and exit
- Image load
- File open, read, write, rename, delete, close, query, security, and directory operations
- Registry open, query, set value, enum key, enum value, delete key, and delete value
- Object handle operations
- Network connect, flow established, and flow closed

The event ring uses versioned records and JSON Lines output with correlation IDs.
File read and write events are emitted without sampling; ring overflow is
reported through the `Dropped` and `CriticalDropped` statistics.

### Context

- Process context
- Thread context
- Image context
- Network flow context
- Registry key context
- Correlation ID and parent correlation ID
- Agent session ID
- PID plus create-time validation
- Tombstone-based deferred cleanup
- Token SID hash, integrity level, and privilege hash
- Current directory and environment hash
- Real file SHA-256 and signer state from user-mode verification

### Policy

- Text policy compiler
- Binary policy format
- Event type index
- Priority-sorted rules
- RuleSet and access mask matching
- Process, path, image hash, user SID hash, and command-line matching
- Case-insensitive path prefix tree
- Immutable copy-on-write snapshots
- Epoch-based deferred reclamation for hot policy updates
- File, registry, process, and network deny controls

### User Mode

- `AgentLensService.exe`
  - Control device client
  - Event ring reader
  - JSON Lines output
  - Event filtering and replay
  - Named pipe server for `AgentLensAgent`
  - DNS ETW association for network events

- `AgentLensAgent.dll`
  - Current directory and environment hash collection
  - Image SHA-256 calculation
  - WinVerifyTrust signer-state verification
  - Agent context reporting

- `AgentLensTools.exe`
  - Version and stats
  - Subscribe and unsubscribe
  - Policy loading
  - Self-test
  - Driver start, stop, and restart

- `AgentLensEtw.exe`
  - Real-time ETW consumer
  - DNS Client ETW parsing
  - Kernel ETW event display

## Build

Requirements:

- Visual Studio 2022
- Windows SDK
- Windows Driver Kit (WDK)
- MSVC Spectre-mitigated libraries (Visual Studio Installer, individual components)

Build the complete solution:

```cmd
msbuild AgentLens.sln /t:Build /p:Configuration=Debug /p:Platform=x64 /m
```

Or use the provided wrapper:

```cmd
build.cmd Debug
```

Release build:

```cmd
msbuild AgentLens.sln /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

The projects enable `/WX` and `/sdl` by default and automatically enable
Spectre mitigation when the toolset provides the Spectre-mitigated libraries.
CI forces the mitigation on. To require or disable it explicitly:

```cmd
msbuild AgentLens.sln /t:Build /p:Configuration=Debug /p:Platform=x64 /p:AgentLensSpectreMitigation=true /m
msbuild AgentLens.sln /t:Build /p:Configuration=Debug /p:Platform=x64 /p:AgentLensSpectreMitigation=false /m
```

CI (`.github/workflows/build.yml`), CodeQL (`.github/workflows/codeql.yml`),
and the SDV entry point (`tests\run_sdv.cmd`) cover the static-analysis gates.

## Run

The kernel driver must be loaded in a test environment with test signing enabled.

Run the service as administrator:

```cmd
AgentLensService.exe --console
AgentLensService.exe --console --policy <binary-policy-file>
```

Without `--policy`, the service tries to load `AgentLens.policy` from its
working directory; a missing default file is ignored, while an explicitly
specified policy that cannot be read fails startup.

Use the control CLI to inspect state:

```cmd
AgentLensTools.exe --version
AgentLensTools.exe --stats
```

## Policy CLI

```cmd
AgentLensTools.exe --policy <binary-policy-file>
AgentLensTools.exe --text-policy <text-policy-file>
AgentLensTools.exe --clear-policy
```

## Policy Matching

Text policy `path`, `process`, and `command` attributes use case-insensitive
prefix matching. Wildcards (`*`, `?`) are not supported and are rejected by the
compiler. For `process`, specify the full image path prefix, for example
`C:\Program Files\AgentLens\agent.exe`. DOS drive-letter paths in text policies
are normalized to native `\Device\HarddiskVolumeN\...` paths at compile time,
so the text policy should be compiled on the system where it will be loaded.

## Install, Sign, and Test

See:

- `installer/README.md`
- `tests/README.md`

Common development scripts:

```cmd
installer\install.cmd Debug
installer\uninstall.cmd
installer\create_test_cert.cmd
installer\sign_driver.cmd Debug
installer\generate_catalog.cmd
installer\sign_catalog.cmd
```

## Not Yet Complete

- Production signing
- Production installer and catalog validation
- Real Driver Verifier, fuzz, and long-running VM validation
- Full event persistence and replay backend
- Advanced AgentLensAgent call-stack and script context
- Performance baselines and counters
- Windows kernel static-analysis and SDV/CodeQL validation in a dedicated environment

## Security Note

AgentLens is still under development. Do not load unsigned or unverified driver builds on production systems. Use an isolated test VM.
