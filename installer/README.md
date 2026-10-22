# Install / Sign

## Install

```cmd
install.cmd Debug
```

`install.cmd` stages the driver and `config\AgentLensKernel.inf` into
`build\install` and installs the kernel service through the INF, so the INF is
the single definition of the driver service. Generate and sign the catalog
first when the test environment requires it.

It also installs `AgentLensService` with a dependency on `AgentLensKernel`
and delayed automatic startup. The default event log is:

```text
%ProgramData%\AgentLens\events.jsonl
```

Service diagnostics are appended to:

```text
%ProgramData%\AgentLens\service.log
```

For interactive testing, stop the installed service and run:

```cmd
sc.exe stop AgentLensService
..\build\AgentLensService\x64\Release\AgentLensService.exe --console
```

Console mode mirrors status messages and event JSON to the screen while also
appending them to the two default log files above.

To override only the JSONL path:

```cmd
..\build\AgentLensService\x64\Release\AgentLensService.exe --console --output C:\agentlens-events.jsonl
```

## Uninstall

```cmd
uninstall.cmd
```

## Test Signing

Run in an elevated Developer Command Prompt:

```cmd
create_test_cert.cmd
sign_driver.cmd Debug
sign_all.cmd Debug
```

## Generate and Sign Catalog

```cmd
generate_catalog.cmd Debug
sign_catalog.cmd
```

## ETW Manifest

```cmd
cd ..\etw
build_manifest.cmd
```
