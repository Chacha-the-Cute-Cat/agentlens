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
sign_all.cmd Debug
```

## Generate and Sign Catalog

```cmd
generate_catalog.cmd
sign_catalog.cmd
```

## ETW Manifest

```cmd
cd ..\etw
build_manifest.cmd
```
