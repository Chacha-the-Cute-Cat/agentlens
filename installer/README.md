# Install / Sign

## Install

```cmd
install.cmd Debug
```

`install.cmd` stages the driver and `config\AgentLensKernel.inf` into
`build\install` and installs the kernel service through the INF, so the INF is
the single definition of the driver service. Generate and sign the catalog
first when the test environment requires it.

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
