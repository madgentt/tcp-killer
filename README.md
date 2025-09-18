# tcp-killer

The utility is intended for legitimate security research: it can identify and forcibly terminate TCP connections of specified processes, effectively allowing you to selectively halt any of their network activity on the host. In controlled and authorized settings, this can temporarily stop the transmission of telemetry and other outbound data by information security products.

## Features
- Close ESTABLISHED TCP connections by PID of the target process.
- Whitelists for IP addresses and ports to skip critical connections.
- Continuous monitoring mode with polling interval and verbose logging.

- Low-level operation via \\.\Nsi using a custom SetAllParameters IOCTL (IoCode = 16).


## Usage - local admin required  

```
tcp_killer.exe [options] <process_names.exe>


Options

-v, --verbose — verbose logs.
-c, --continuous — continuous monitoring mode.
-i, --interval <ms> — polling interval (default: 1000 ms).
-w, --whitelist-ip <ip> — add IP to allowlist (repeatable).
-p, --whitelist-port <port> — add port to allowlist (repeatable).
-h, --help — show help.
``` 
## Examples
```
tcp_killer.exe -v chrome.exe firefox.exe
tcp_killer.exe -c -i 500 -w 192.168.1.1 -p 443 malware.exe
```

## How it Works (high level)

Target processes are resolved by exact image name via CreateToolhelp32Snapshot / Process32First/Next.

The TCP table is read via GetTcpTable2, then filtered by PID and ESTABLISHED state.

To terminate connections, an IPv4 parameter structure is constructed and a low-level NSI call is made to \\.\Nsi with the internal SetAllParameters action (IoCode = 16). NT functions (NtDeviceIoControlFile, NtWaitForSingleObject, RtlNtStatusToDosError) are loaded dynamically from ntdll.dll.

## Limitations & Notes

- IPv4 only (parameters are built for AF_INET).
- Only ESTABLISHED connections are terminated; other states are ignored.
- Process matching is by exact filename (e.g., chrome.exe), no wildcards.
- IP/port whitelists prevent termination of protected connections.


## Research Source & Thanks

The attached PDF — “Uncovering the network outages of digital security products: from SetTcpEntry to NsiSetAllParameters” — is the primary research source for this utility. 


Big thanks to vx-underground for curating Windows networking research: https://vx-underground.org/Papers/Windows/Networking