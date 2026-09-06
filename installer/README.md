# Install / Sign

## Install

```cmd
install.cmd Debug
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
```

## ETW Manifest

```cmd
cd ..\etw
build_manifest.cmd
```
