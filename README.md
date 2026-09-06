# AgentLens v0.1

AgentLens is a Windows runtime security project for observing, correlating, and controlling process, file, registry, and network behavior.

This implementation is a Visual Studio 2022 scaffold based on `docs/agentlens/ARCHITECTURE.md`.

## Implemented

- `AgentLensKernel.sys`
  - Control device `\Device\AgentLensControl`
  - Event ring
  - Shared memory event mapping
  - Process / thread / image monitors
  - Registry monitor
  - Object monitor
  - File system minifilter monitor
  - WFP ALE callouts
  - Policy loading
  - File / registry / process / network policy controls

- `AgentLensService.exe`
  - Control channel client
  - Event reader and JSON output
  - Named pipe server for `AgentLensAgent`
  - Policy loading

- `AgentLensAgent.dll`
  - User-mode agent with basic process context collection

- `AgentLensTools.exe`
  - Control and diagnostic CLI

## Not Implemented Yet

- Full ETW integration
- Production driver signing
- Production installer
- Long-running Driver Verifier validation
- Advanced command context and correlation

## Build

```cmd
msbuild AgentLens.sln /t:Build /p:Configuration=Debug /p:Platform=x64 /m
```

Or:

```cmd
build.cmd Debug
```

## Run

1. Load `AgentLensKernel.sys` in a test environment.
2. Run the service as administrator:

```cmd
AgentLensService.exe --console
```

3. Observe process, thread, image, file, registry, and network events.

## Install / Sign

See `installer/README.md`.

## Control CLI

```cmd
AgentLensTools.exe --version
AgentLensTools.exe --stats
AgentLensTools.exe --policy <binary-policy-file>
AgentLensTools.exe --text-policy <text-policy-file>
AgentLensTools.exe --clear-policy
AgentLensTools.exe --selftest
AgentLensTools.exe --driver-stop
AgentLensTools.exe --driver-start
AgentLensTools.exe --driver-restart
```
