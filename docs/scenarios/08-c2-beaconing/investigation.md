# C2 beaconing — investigation

## What is C2 beaconing?

Malware on a device checks in with its controller (command and control, C2) on a timer to pick up commands. A single connection looks normal; the **pattern over time** gives it away.

A timer-driven pattern shows that some software calls out on a schedule. It doesn't show that the software is malicious: decide that on the process and the destination.

What to do, in order, is in the [playbook](playbook.md). This page explains what you are looking at and how to scope it.

T0 = the first connection from the device to the C2 destination, or the earliest malicious event before it, in UTC. Advanced Hunting holds 30 days of native data; older activity needs Sentinel retention.

---

## What MDE can and can't show you

| You want | In MDE? |
|----------|---------|
| Connection time, remote IP, port, URL or host name | Yes: `DeviceNetworkEvents` (`Timestamp`, `RemoteIP`, `RemotePort`, `RemoteUrl`) |
| Which process made the connection | Yes: `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessSHA1`, `InitiatingProcessId`, `InitiatingProcessCreationTime`, `InitiatingProcessParentFileName`. `InitiatingProcessSHA256` is usually empty; use SHA1 |
| Whether that process is signed | Look up `InitiatingProcessSHA1` in `DeviceFileCertificateInfo` (`Signer`, `IsTrusted`). The `VersionInfo` columns are file metadata and don't show a signature |
| Bytes sent or received | No. `DeviceNetworkEvents` has no byte-count column. Needs proxy or firewall logs |
| HTTP user agent | No column for it. Needs proxy logs |
| Full URL path of an HTTPS connection | Don't rely on it. For HTTPS, expect `RemoteUrl` to hold a host name at most (VERIFY (tenant)) |
| Whether a connection is open now | Not from the logs. Use Live Response `connections` ("Shows all the active connections") or the investigation package's Network connections folder |

---

## The five signals

| Signal | What it tells you | Limits |
|--------|-------------------|--------|
| Many connections to one destination | A short timer. A 60-second sleep gives about 1,440 connections a day; a 60-minute sleep gives 24 | Browsers and SaaS apps also hit the same CDN or service IPs thousands of times. A slow beacon stays under any count threshold. C2 spread over several IPs splits the count |
| Regular gaps between connections | Timer-driven software | Defender and other agents, Teams, Windows Time (NTP), CRL/OCSP checks and RMM agents are timer-driven too. Regular doesn't mean malicious |
| Uniform byte sizes | A fixed heartbeat | Not in MDE; needs proxy or firewall logs. Cobalt Strike's `data_jitter` option pads responses to random lengths |
| Connections at night | Nobody is driving the traffic | Weak. Servers and devices left on overnight make night traffic legitimately; a beacon on a laptop stops while the laptop sleeps |
| Unexpected initiating process | The strongest signal | Check the folder path, SHA1 and signer, not the name: a fake `svchost.exe` in AppData has the same file name as the real one. A beacon can also run inside a signed program (injection or DLL side-loading) |

---

## Cobalt Strike defaults

Default profile values from the Cobalt Strike Malleable C2 reference (Fortra). Operators usually change them, and other C2 frameworks have their own. Don't clear an alert because the values don't match.

| Setting | Default | What it means for you |
|---------|---------|-----------------------|
| `sleeptime` | 60000 ms (60 seconds) | Profiles change it. The `sleep` option accepts values such as `1d 13h 34m 45s 25j`, so sleeps of hours or days are possible |
| `jitter` | 0% | A fixed interval. A fixed interval can't tell an RMM heartbeat from a default beacon |
| `useragent` | "Internet Explorer (Random)" | A profile can override it, and MDE doesn't record user agents. Not a check you can make in MDE |
| `pipename` (SMB Beacon) | `msagent_##` | Each `#` is a random hex character. Also `status_##` (SMB stager) and `postex_ssh_####` (SSH sessions) |
| `tcp_port` (TCP Beacon) | 4444 | The port a TCP Beacon listens on |
| `data_jitter` | 0 | When set, appends random-length data to responses, which defeats byte-size checks |

---

## Log examples

The IPs below are documentation addresses, not real C2.

**Classic 60s beacon** (network events for one process):
```
Timestamp  RemoteIP      RemotePort  Process path
02:00:00   203.0.113.45  443         C:\Users\jsmith\AppData\Local\Temp\svchost.exe
02:01:00   203.0.113.45  443         C:\Users\jsmith\AppData\Local\Temp\svchost.exe
02:02:00   203.0.113.45  443         C:\Users\jsmith\AppData\Local\Temp\svchost.exe
```
The real `svchost.exe` lives in the Windows folder, not in a user profile. Same name, wrong folder.

**Jittered beacon (~100s mean, 20% jitter):**
```
09:14:03  198.51.100.12  gap: —
09:15:51  198.51.100.12  gap: +108s
09:17:29  198.51.100.12  gap: +98s
09:19:12  198.51.100.12  gap: +103s
```
Irregular to the eye, but every gap is within a few seconds of 100. The interval regularity query scores this high, as long as every check-in goes to one IP and there are no long gaps (see its limits below).

---

## Investigate the alerted beacon

### 1. Which process is it?

From the alert evidence, or the network events to the destination in the Device timeline, record `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessSHA1`, `InitiatingProcessId`, `InitiatingProcessCreationTime`, `InitiatingProcessParentFileName` and the account. Look up the SHA1 in `DeviceFileCertificateInfo`: `Signer` and `IsTrusted`.

Treat it as suspicious if it:
- isn't signed, has `IsTrusted` false, or is signed by someone other than the vendor of the product it claims to be;
- runs from a user-writable folder (`AppData`, `Temp`, `Downloads`, `C:\Users\Public`);
- is a Windows binary that loads DLLs (`rundll32.exe`, `dllhost.exe`, `regsvr32.exe`) and makes the connections itself;
- is an RMM tool (AnyDesk, ScreenConnect and similar) that isn't on the customer's approved list, or was installed outside a change record. ATT&CK T1219: "An adversary may use legitimate remote access tools to establish an interactive command and control channel".

### 2. Is it still connecting?

The logs show the past. Live Response `connections` lists the device's active connections and `processes` the running processes. The investigation package records the same at collection time (Network connections and Processes folders). Isolation keeps the device connected to the Defender service, so you can collect these after isolating.

### 3. Is someone driving it?

- **Child processes of the beaconing process:** `DeviceProcessEvents` on this device where `InitiatingProcessId` is the beacon PID and `InitiatingProcessCreationTime` is its start time (PIDs are reused, so match both). Shells (`cmd.exe`, `powershell.exe`) or recon commands (`whoami`, `net`, `nltest`, `ipconfig`, `systeminfo`) mean someone is working through the beacon.
- **Reverse shell:** `cmd.exe` or `powershell.exe` itself making outbound connections.
- **Named pipes:** a pipe name that matches the Cobalt Strike defaults above, in the alert or the Device timeline. Pipe names are configurable, so not finding one proves nothing. The hunting `ActionType` for named-pipe events is VERIFY (tenant).
- **Connection rate:** a sudden rise in connections to the same destination can mean the operator shortened the sleep to work interactively. This is a pattern to look for, not a documented rule.

### 4. Is it hiding in a legitimate program?

A signed process is no proof that the traffic is benign. ATT&CK T1574.001: "Adversaries may execute their own malicious payloads by side-loading DLLs." If the beaconing process is signed (a vendor app or a Windows binary):
- Check `DeviceImageLoadEvents` for that process on this device since T0. Look for DLLs not signed by the vendor or Microsoft (look up each `SHA1` in `DeviceFileCertificateInfo`) and DLLs loaded from the program's own folder or a user-writable folder.
- Check the device's alerts for process injection.

### 5. How did it get there, and what keeps it there?

- Process chain: the [process guide](../02-suspicious-process/investigation.md). The implant file's creation event in `DeviceFileEvents` carries `FileOriginUrl` for a web download; see "How did it arrive?" in the [malware alert investigation](../01-malware-alert/investigation.md#step-4--check-for-spread).
- RMM tool: when, and by which account, was it installed? Find the installer in `DeviceFileEvents` and `DeviceProcessEvents` and compare with the customer's change record.
- Persistence: the [persistence playbook](../04-persistence-detected/playbook.md), the package's Autoruns, Scheduled tasks and Services, or Live Response `persistence`, `scheduledtasks` and `services`.

### 6. What is the destination?

- Search the IP or domain in the Defender portal. The IP page shows related alerts and which devices connected to it. The URL/domain page also shows the Microsoft verdict.
- Enrich it with the [threat intel enrichment guide](../../reference/threat-intel-enrichment.md). Look the IP and domain up; don't upload the implant or submit internal URLs to public services.
- A clean reputation or an old domain doesn't clear it. ATT&CK T1102: cloud services used for C2 "may give a significant amount of cover". If the C2 runs over a cloud or web service, use the [LOTS & cloud C2 investigation](../09-lots-cloud-c2/investigation.md).

---

## Scope

Spread is a reason to scope wider, never evidence that the traffic is benign.

- **Other devices talking to the destination.** IP page: "IP prevalence in the organization" (how many devices, first and last seen; default 30 days) and "IP activity observed in the organization" (up to 100 devices). URL/domain page: the Devices tab (first and last event per device; default 30 days, up to six months). The high connection count query below also runs estate-wide, but only shows pairs above its threshold.
- **The implant on other devices.** Run the hash sweep in the [malware alert investigation](../01-malware-alert/investigation.md#step-4--check-for-spread) with the implant's SHA1, and with any DLL SHA1 from section 4 above. Zero rows doesn't prove no spread.
- **T0.** This device's first event on the URL/domain page (Devices tab), or its earliest event to the IP in the Device timeline. The IP page's first-seen time covers the whole organization. If it is before your T0, move T0 and link it to how the implant arrived (section 5 above).
- **After a block.** Network protection blocks appear in `DeviceEvents` with `ActionType` `ExploitGuardNetworkProtectionBlocked`. A device in those events is still trying to reach the destination: it is in scope.

---

## KQL queries

These are estate-wide hunts over the 24 hours before T0, and each ends in a threshold. They can't give you a score for the alerted device: a device and destination pair below the threshold returns nothing, and that doesn't mean it isn't beaconing. Use them to find other devices and destinations, not to clear one.

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

Limits:
- It counts per `RemoteIP` and `RemoteUrl`, so C2 spread over several IPs splits the count.
- A beacon that sleeps longer than about 45 minutes may not reach 30 connections a day.
- `Processes` lists at most 3 file names, not paths. Check the path and SHA1 in the Device timeline.

### Interval regularity
```kql
// C2 beaconing detection — interval regularity (catches jittered beacons)
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1071.001
// Calculates standard deviation of gaps between connections to the same destination
// Low StdDev relative to MeanInterval = mechanical timer = beaconing
// Regularity score: 95%+ = almost certainly beaconing, 70-90% = investigate
// Covers the 24h before T0 (24h keeps the per-day thresholds meaningful); for a daily hunt set T0 to now()
// Ref: docs/scenarios/08-c2-beaconing/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. T0)
| where RemoteIPType != "Private"
| sort by DeviceName, RemoteIP, Timestamp asc
| extend PrevTime = prev(Timestamp, 1)
| extend PrevDevice = prev(DeviceName, 1)
| extend PrevIP = prev(RemoteIP, 1)
| where DeviceName == PrevDevice and RemoteIP == PrevIP
| extend IntervalSec = datetime_diff('second', Timestamp, PrevTime)
| where IntervalSec between (5 .. 3600)
| summarize
    ConnCount = count(),
    MeanInterval = round(avg(IntervalSec), 1),
    StdDev = round(stdev(IntervalSec), 1),
    MinGap = min(IntervalSec),
    MaxGap = max(IntervalSec)
    by DeviceName, RemoteIP, RemoteUrl
| where ConnCount > 20
| extend Regularity = round(
    (1 - (StdDev / MeanInterval)) * 100, 1)
| where Regularity > 70
| order by Regularity desc
```

Read a high score as "timer-driven", not "malicious" (the query comment overstates it). Defender, Teams, NTP and RMM agents score high too; decide on the process and the destination. A low score doesn't clear a destination either:
- Gaps over an hour are dropped and the query needs more than 20 kept gaps, so a beacon that sleeps longer than 60 minutes can't appear.
- A few long gaps (the laptop slept, the lid was closed) push the score of a perfectly regular beacon down, even below zero. A small `MinGap` with a large `MaxGap` is that case.
- Gaps are computed per `RemoteIP`. A beacon whose domain resolves to several IPs (a CDN, for example) gives irregular per-IP gaps and a low score.
- It has no `ActionType` filter, so every network event counts, not only successful outbound connections.

### Combined suspicion score
```kql
// C2 beaconing detection — combined suspicion score
// Runs in: Defender XDR Advanced Hunting (also works in Sentinel when the table is streamed)
// MITRE: T1071.001
// Combines connection count, after-hours activity, and single-port consistency
// Score >= 5 warrants investigation; tune threshold for your environment
// Run this daily as a hunt query
// Covers the 24h before T0 (24h keeps the per-day thresholds meaningful); for a daily hunt set T0 to now()
// Ref: docs/scenarios/08-c2-beaconing/investigation.md

// REPLACE: incident time (T0, UTC) on the next line before running
let T0 = datetime(PASTE_TIME_UTC);
DeviceNetworkEvents
| where Timestamp between ((T0 - 24h) .. T0)
| where RemoteIPType != "Private"
| where RemoteIP != ""
| summarize
    TotalConns = count(),
    NightConns = countif(hourofday(Timestamp) between (0 .. 6)),
    DistinctPorts = dcount(RemotePort),
    Processes = make_set(InitiatingProcessFileName, 3)
    by DeviceName, RemoteIP, RemoteUrl
| extend
    CountScore = case(
        TotalConns > 100, 4,
        TotalConns > 50,  3,
        TotalConns > 20,  2,
        1),
    NightScore = case(
        NightConns > 20, 3,
        NightConns > 5,  2,
        0),
    PortScore = iff(DistinctPorts == 1, 2, 0)
| extend SuspicionScore = CountScore + NightScore + PortScore
| where SuspicionScore >= 5
| project DeviceName, RemoteIP, RemoteUrl,
    TotalConns, NightConns, SuspicionScore, Processes
| order by SuspicionScore desc
```

Read this score as a connection count. `PortScore` is 2 for almost any HTTPS destination (one port), and the score has no regularity, path or signer term. A score of 5 or more therefore means more than 50 connections in 24 hours, or more than 5 between 00:00 and 06:59 UTC. Busy SaaS endpoints score high; slow beacons score low. The night window is UTC, not the customer's local time. Like the regularity query, it has no `ActionType` filter.

---

## What these queries can't see

- **Internal beacons.** Cobalt Strike's SMB Beacon "uses named pipes to communicate through a parent Beacon" and "also works across the network"; the TCP Beacon listens on a port (default 4444). Every query here drops private destinations, so device-to-device C2 is invisible to them. It looks like lateral movement: see [lateral movement network signals](../03-suspicious-network-activity/investigation.md#lateral-movement--network-signals).
- **Slow beacons.** Sleeps longer than about 45 to 60 minutes fall under the thresholds (see each query's limits).
- **C2 spread over several IPs** (CDN or fronted domains): per-IP counts and gaps break up.
- **DNS and DNS-over-HTTPS C2.** These queries don't look at DNS. DNS over HTTPS hides lookups inside HTTPS. For DNS signals see [DNS beaconing](../03-suspicious-network-activity/investigation.md#dns-beaconing).
- **C2 over cloud services** (Graph API, cloud storage, code hosting): see [LOTS & cloud C2](../09-lots-cloud-c2/investigation.md).
- **Explicit proxies.** If clients send web traffic through an explicit proxy, `RemoteIP` may be the proxy rather than the C2, and a private proxy address is filtered out (VERIFY (tenant)). Use the proxy logs to find the real destination.

---

## False positives

Software that commonly beacons on a timer: OneDrive, Defender and other security agents, Teams and Zoom, Windows Time (NTP), CRL/OCSP checks, RMM agents. Being on this list is not enough to close an alert.

These tests don't separate benign software from C2, so don't close on them:
- **A known app from a standard path.** Attackers install real RMM tools, and inject beacons into or side-load them from signed programs. The initiating process then is a known app.
- **A long-established vendor domain.** C2 can run over cloud services, and attackers can buy expired domains that are already trusted.
- **A fixed interval.** Cobalt Strike's default jitter is 0%, so a fixed interval fits a default beacon as well as an RMM heartbeat.
- **The same pattern on many devices.** That can be spread. Scope it as a possible campaign.

To close as a false positive, every condition in [Closing as a false positive](playbook.md#closing-as-a-false-positive) in the playbook must hold.
