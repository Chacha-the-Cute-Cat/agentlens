# Driver Verification

These scripts are for a dedicated test VM only.

## Reload

```cmd
reload_driver.cmd
```

## Self Test

```cmd
run_selftest.cmd
```

## Stress Reload

```cmd
stress_reload.cmd
```

## IOCTL Fuzzing

```cmd
stress_ioctl.cmd
```

## Driver Verifier

```cmd
enable_driver_verifier.cmd
```

Then reboot and run stress/load tests. To disable:

```cmd
disable_driver_verifier.cmd
```

Expected checks:

- driver load/unload without leak
- process/file/registry events
- policy deny paths
- event ring overflow behavior
- WFP callout register/unregister
