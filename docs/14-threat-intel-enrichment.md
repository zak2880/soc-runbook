# Threat intel enrichment

## What is enrichment?

Enrichment is the process of taking a raw IOC — a hash, IP address, domain, or URL — and building context around it. A SHA256 on its own tells you nothing. The same hash with a VirusTotal detection ratio, a malware family name, a first-seen date, and global prevalence data tells you whether you're dealing with commodity malware or a targeted tool, how old the campaign is, and whether other organisations have been hit.

Good enrichment makes the difference between a vague "suspicious file detected" report and a clear, evidenced incident summary.

---

## The enrichment workflow

```
IOC identified
    ↓
What type? Hash / IP / Domain / URL
    ↓
Run through appropriate tools (see below)
    ↓
Answer four questions:
  1. Is it known malicious?
  2. How widespread is it?
  3. How old is it?
  4. What does it do / who uses it?
    ↓
Document findings and add to incident report
```

---

## File hashes (MD5 / SHA1 / SHA256)

### VirusTotal — virustotal.com

Primary tool for hash enrichment. Key fields to check:

| Field | What it tells you |
|-------|------------------|
| Detection ratio (e.g. 45/72) | How many vendors flag it — above 5/72 = treat as malicious |
| First seen in the wild | Old first-seen = established malware. Brand new = targeted or fresh campaign |
| File names | What the file has been named across submissions — look for disguise patterns |
| Malware family labels | What the malware actually is (Emotet, AsyncRAT, Cobalt Strike beacon, etc.) |
| Behaviour tab | Sandbox detonation — what it does, what it connects to, what it drops |
| Relations tab | Files it drops, domains/IPs it contacts, files that drop it |
| Community tab | Analyst notes — often contains MITRE mapping or campaign attribution |

> A detection ratio of 0/72 does not mean clean. New or targeted malware often has zero detections initially. Check first-seen date and file prevalence — a file first seen today with zero detections that came from a phishing email is still suspicious.

### MalwareBazaar — bazaar.abuse.ch

Good secondary source. Focuses on malware samples — better than VT for finding:
- Malware family attribution
- Tags (e.g. `emotet`, `asyncrat`, `cobalt_strike`)
- Download the sample if you need to analyse it further

### Defender XDR file page

For hashes seen in your estate, the Defender file page gives you:
- **Tenant prevalence** — how many devices in your customers' environments have this file
- **Global prevalence** — how many machines Microsoft has seen it on worldwide
- **Verdict** — Microsoft's own classification
- **File details** — signer, PE metadata, import hash

Low global prevalence + no legitimate signer + detected on your customer's device = strong malicious indicator.

---

## IP addresses

### VirusTotal — virustotal.com/gui/ip-address/[IP]

- Detection ratio — how many vendors flag the IP
- Associated domains — what domains have resolved to this IP
- Communicating files — malware samples that have contacted this IP
- Community tab — analyst notes, campaign tags

### AbuseIPDB — abuseipdb.com

Crowdsourced abuse reports. Key fields:
- **Abuse confidence score** — 0–100%, above 50% = treat as malicious
- **Report count** — how many times it's been reported and for what (scanning, brute force, C2, etc.)
- **ISP / ASN** — is it a residential IP, a VPS provider, Tor exit node, or bulletproof hosting?

Common suspicious ASNs to recognise:
```
AS20473  — Choopa/Vultr (popular VPS for C2)
AS14061  — DigitalOcean
AS16276  — OVH (bulletproof hosting used frequently)
AS9009   — M247 (frequently seen in C2 infrastructure)
AS60068  — Datacamp Limited
```

### Shodan — shodan.io

Check what's running on the IP — open ports, banners, certificates. Useful for:
- Confirming C2 infrastructure (Cobalt Strike default port 50050, Metasploit default 4444)
- Identifying the hosting provider and country
- Finding other domains hosted on the same IP (pivoting)
- Checking TLS certificate details — self-signed certs on port 443 = suspicious

### IPinfo / ipinfo.io

Quick lookup for:
- Country, city, ASN, org
- Whether it's a known VPN, proxy, Tor exit, or hosting provider
- Useful for impossible travel checks in Entra ID investigations

---

## Domains

### VirusTotal — virustotal.com/gui/domain/[domain]

- Detection ratio
- Resolved IPs — what IPs the domain has pointed to
- Subdomains
- Associated files — malware that has contacted this domain
- WHOIS data

### URLScan.io — urlscan.io

Passive and active scanning of URLs/domains. Key uses:
- See what a URL/page looks like without visiting it
- Check redirects — phishing links often redirect through multiple hops
- Screenshot of the page at scan time
- DOM content, external resources loaded, cookies set
- Historical scans — did this domain look different 3 months ago?

### WHOIS / domain age

**Key question: how old is the domain?**

Newly registered domains (days or weeks old) used in phishing or C2 are a strong red flag. Legitimate business infrastructure is almost always months or years old.

Tools:
- `whois [domain]` in terminal
- who.is
- domaintools.com

Fields to check:
- Registration date
- Registrar — some registrars are heavily abused (Namecheap, GoDaddy, Porkbun for throwaway domains)
- Registrant details — privacy-protected is normal, but combined with new registration = suspicious
- Name servers — free DNS providers (Cloudflare, namecheap DNS) used on a new domain = suspicious in context

### Passive DNS — SecurityTrails / RiskIQ (Microsoft Defender TI)

Passive DNS shows you the full history of what IPs a domain has resolved to over time, and what other domains have shared the same IP. Essential for:
- Pivoting from one malicious domain to a whole C2 infrastructure
- Finding related domains in the same campaign
- Confirming whether a domain has recently changed infrastructure

**Defender Threat Intelligence (built into Defender XDR):**
- Available under Threat intelligence → Intel explorer
- Search any IP, domain, or hash
- Shows related infrastructure, WHOIS, passive DNS, associated articles
- No separate subscription needed if you have Defender XDR P2

---

## URLs

### URLScan.io — urlscan.io

Best tool for URLs. Submit for a fresh scan or search historical scans.

### VirusTotal — virustotal.com/gui/url/[url]

Quick detection ratio check. Note: VT URL scanning is less reliable than URLScan for full page analysis.

### Unshortening links

Phishing links often go through URL shorteners (bit.ly, tinyurl, t.co) or redirectors. Never click. Use:
- unshorten.me
- expandurl.net
- URLScan (will follow redirects safely)

---

## Putting it together — enrichment template

Use this structure when documenting IOCs in an incident report:

```
IOC: [value]
Type: Hash / IP / Domain / URL
Source: Where it was found (email attachment, network connection, registry value)

VirusTotal:
  Detection ratio: X/72
  First seen: YYYY-MM-DD
  Malware family: [name or Unknown]
  Notable: [anything from behaviour/community tabs]

Secondary source (AbuseIPDB / MalwareBazaar / URLScan):
  [key findings]

Defender XDR:
  Tenant prevalence: X devices
  Global prevalence: X devices
  Verdict: [Malicious / Suspicious / Unknown]

Assessment: [Confirmed malicious / Suspicious - investigate further / Likely FP]
```

---

## Quick reference — tool by IOC type

| IOC type | Primary | Secondary | Tertiary |
|----------|---------|-----------|----------|
| File hash | VirusTotal | MalwareBazaar | Defender XDR file page |
| IP address | VirusTotal | AbuseIPDB | Shodan |
| Domain | VirusTotal | URLScan.io | SecurityTrails / Defender TI |
| URL | URLScan.io | VirusTotal | Unshortener |
| Email sender | VirusTotal (domain) | MXToolbox | Defender TI |

---

## Enrichment shortcuts in Defender XDR

Right-click any IOC in Advanced Hunting results or on the incident page:
- **Go hunt** — runs a pre-built query across your estate for that IOC
- **Investigate** — opens the entity page (file, IP, domain, user, device)
- **Add indicator** — blocks the IOC across your tenant immediately

The entity pages for IPs and domains in Defender XDR now pull in Microsoft Threat Intelligence data automatically — check these before going external, especially for domains and IPs, as Microsoft often has attribution and campaign data that isn't on VirusTotal yet.

---

## Enrichment checklist

- [ ] Hash checked on VirusTotal — detection ratio, first seen, malware family
- [ ] Hash checked on Defender XDR file page — tenant and global prevalence
- [ ] IP checked on VirusTotal and AbuseIPDB — abuse confidence, ASN, reports
- [ ] Domain age checked — newly registered domains are a red flag
- [ ] URL scanned on URLScan.io — redirects, page content, screenshot
- [ ] Passive DNS checked for related infrastructure
- [ ] Findings documented using enrichment template
- [ ] IOCs blocked in Tenant Allow/Block List if confirmed malicious
