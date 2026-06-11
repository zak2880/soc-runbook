# Threat intel enrichment

## The enrichment workflow

```
IOC identified
    ↓
What type? Hash / IP / Domain / URL
    ↓
Run through appropriate tools
    ↓
Answer four questions:
  1. Is it known malicious?
  2. How widespread is it?
  3. How old is it?
  4. What does it do / who uses it?
    ↓
Document and add to incident report
```

---

## File hashes

### VirusTotal
- Detection ratio — above 5/72 = treat as malicious
- First seen — new = targeted/fresh. Old = established campaign
- Malware family labels
- Behaviour tab — sandbox detonation, what it drops, what it connects to
- Relations tab — files it drops, domains/IPs it contacts

> 0/72 does not mean clean. New or targeted malware often has zero detections. Check first-seen date and context.

### MalwareBazaar — bazaar.abuse.ch
Better for malware family attribution and tags (`emotet`, `asyncrat`, `cobalt_strike`).

### Defender XDR file page
- Tenant prevalence — how many of your customer devices have this file
- Global prevalence — worldwide Microsoft telemetry
- Verdict and signer

---

## IP addresses

### VirusTotal
- Detection ratio, associated domains, communicating files

### AbuseIPDB — abuseipdb.com
- Abuse confidence score (above 50% = treat as malicious)
- Report count and reason (scanning, brute force, C2)
- ISP / ASN

**Common suspicious ASNs:**
```
AS20473  Choopa/Vultr
AS14061  DigitalOcean
AS16276  OVH
AS9009   M247
AS60068  Datacamp Limited
```

### Shodan — shodan.io
- Open ports and banners — confirm C2 infrastructure
- TLS certificate details — self-signed on port 443 = suspicious
- Pivot to other domains on the same IP

---

## Domains

### VirusTotal
Detection ratio, resolved IPs, subdomains, associated files

### URLScan.io
- What the page looks like without visiting it
- Redirects, DOM content, screenshots
- Historical scans

### Domain age (WHOIS)
**Key question: how old is the domain?**
Newly registered domains (days/weeks) in phishing or C2 = strong red flag.
Check: registration date, registrar, name servers.

### Defender Threat Intelligence (built into Defender XDR)
- Threat intelligence → Intel explorer
- Search any IP, domain, or hash
- Related infrastructure, WHOIS, passive DNS, attribution articles
- No separate subscription needed with Defender XDR P2

---

## URLs

### URLScan.io — primary tool
Submit for fresh scan or search historical. Follows redirects safely.

### Unshortening links
Never click shortened links. Use: unshorten.me, expandurl.net, or URLScan.

---

## Enrichment documentation template

```
IOC: [value]
Type: Hash / IP / Domain / URL
Source: Where found (email attachment, network connection, registry)

VirusTotal:
  Detection ratio: X/72
  First seen: YYYY-MM-DD
  Malware family: [name or Unknown]
  Notable findings:

Secondary source:
  Tool: AbuseIPDB / MalwareBazaar / URLScan
  Key findings:

Defender XDR:
  Tenant prevalence: X devices
  Global prevalence: X devices
  Verdict:

Assessment: Confirmed malicious / Suspicious / Likely FP
```

---

## Quick reference

| IOC type | Primary | Secondary | Tertiary |
|----------|---------|-----------|----------|
| File hash | VirusTotal | MalwareBazaar | Defender XDR file page |
| IP address | VirusTotal | AbuseIPDB | Shodan |
| Domain | VirusTotal | URLScan.io | Defender TI |
| URL | URLScan.io | VirusTotal | Unshortener |
