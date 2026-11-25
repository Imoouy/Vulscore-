# vulnscore: risk-based vulnerability prioritization

Sorting a patch backlog by CVSS alone sends teams after the highest theoretical severity, not the highest risk. A 9.8 bug that nobody exploits, sitting on an isolated lab box, outranks a 7.5 bug that ransomware crews use on an internet-facing gateway. `vulnscore` ranks each (asset, CVE) pair by combining four signals: how severe the bug is, whether it is being exploited in the wild, how reachable the asset is, and how much the asset matters.

## How it works

Data sources (both public and free):

- **CISA Known Exploited Vulnerabilities (KEV) catalog**: evidence of real-world exploitation, including whether a CVE is known to be used in ransomware campaigns.
- **NVD CVE API 2.0**: CVSS base score and attack vector.

The asset list (`assets.csv`) is hand-built for this demo: seven assets, each with an exposure level, a criticality rating, and the CVEs present on it.

### Scoring

```
score = 100 × (CVSS/10) × threat × exposure × criticality / max_possible
```

| Signal | Values | Reasoning |
|---|---|---|
| Severity | CVSS base score / 10 | How bad the outcome is if the bug is exploited. |
| Threat | 1.0 not in KEV, 2.0 in KEV, 2.5 in KEV with known ransomware use | Confirmed exploitation outweighs theoretical severity. |
| Exposure | internet 1.0, tier0 0.9, internal 0.6, isolated 0.3 | Reachability decides who can attempt the exploit. |
| Criticality | 1–5, mapped to 0.2–1.0 | Business impact of losing the asset. |

The factors are **multiplied, not added**. With a weighted sum, one large factor can compensate for a near-zero one, so a 10.0 CVSS on a throwaway isolated box would still rank high. Multiplication means any factor near zero pulls the whole score down.

**Attack-vector cap:** if the CVSS attack vector is LOCAL or PHYSICAL, exposure is capped at the internal level. Internet exposure is irrelevant when the attacker needs a foothold on the box first.

## Results

Final ranking:

| # | Score | Asset | CVE | CVSS | KEV | Exposure | Crit |
|---|---|---|---|---|---|---|---|
| 1 | 94.0 | vpn01 | CVE-2023-4966 (Citrix Bleed) | 9.4 | Yes, ransomware | internet | 5 |
| 2 | 90.0 | dc01 | CVE-2020-1472 (Zerologon) | 10.0 | Yes, ransomware | tier0 | 5 |
| 3 | 80.0 | web01 | CVE-2021-44228 (Log4Shell) | 10.0 | Yes, ransomware | internet | 4 |
| 4 | 78.4 | web01 | CVE-2021-41773 (Apache path traversal) | 9.8 | Yes, ransomware | internet | 4 |
| 5 | 67.5 | dc01 | CVE-2021-42278 (sAMAccountName spoofing) | 7.5 | Yes, ransomware | tier0 | 5 |
| 6 | 63.4 | dc01 | CVE-2022-26923 (Certifried) | 8.8 | Yes | tier0 | 5 |
| 7 | 48.0 | web01 | CVE-2023-44487 (HTTP/2 Rapid Reset) | 7.5 | Yes | internet | 4 |
| 8 | 27.0 | lt-fin-07 | CVE-2023-36884 | 7.5 | Yes, ransomware | internal | 3 |
| 9 | 21.1 | print01 | CVE-2021-34527 (PrintNightmare) | 8.8 | Yes, ransomware | internal | 2 |
| 10 | 18.0 | lt-gen-12 | CVE-2023-36884 | 7.5 | Yes, ransomware | internal | 2 |
| 11 | 6.0 | dev-lab | CVE-2021-44228 (Log4Shell) | 10.0 | Yes, ransomware | isolated | 1 |
| 12 | 2.4 | dev-lab | CVE-2023-38545 (curl SOCKS5) | 9.8 | No | isolated | 1 |

### Risk-based vs CVSS-only

| Rank | By CVSS alone | By vulnscore |
|---|---|---|
| 1 | Zerologon on dc01 (10.0) | Citrix Bleed on vpn01 |
| 2 | Log4Shell on web01 (10.0) | Zerologon on dc01 |
| 3 | Log4Shell on dev-lab (10.0) | Log4Shell on web01 |
| 4 | Apache path traversal on web01 (9.8) | Apache path traversal on web01 |
| 5 | curl SOCKS5 on dev-lab (9.8) | sAMAccountName spoofing on dc01 |

Two of the CVSS-only top five are on an isolated, criticality-1 dev box. vulnscore ranks both last (#11 and #12). Meanwhile Citrix Bleed, on the internet-facing remote-access gateway and actively used by ransomware crews, drops to #6 under CVSS sorting but is correctly #1 here. The same Log4Shell CVE scores 80.0 on the public web server and 6.0 on the isolated box: the vulnerability is identical, the risk is not.

## Two flaws found and fixed

### 1. Model flaw: domain controllers were underweighted

The first version had only three exposure levels, so the domain controller was scored as `internal` (0.6). That is wrong for a DC: nearly every host in the domain can reach it, so a single phished laptop is enough to attempt Zerologon, which needs only network access to Netlogon and ends in full domain compromise.

**Fix:** added a `tier0` exposure level (0.9) for assets reachable from almost everywhere internally whose compromise means owning the environment (DCs, AD CS, SCCM). It is 0.9 rather than 1.0 because the attacker still needs an internal foothold first. The alternative, automatically raising exposure for criticality-5 assets, was rejected because it mixes two separate factors and would wrongly inflate critical assets that really are segmented.

### 2. Data flaw: the NVD returned conflicting scores

After adding `tier0`, Zerologon did not move. It was still scored **5.5 with a LOCAL attack vector**, and the LOCAL cap held its exposure at 0.6.

The NVD record for CVE-2020-1472 contains two CVSS v3.1 entries, **both marked `Secondary`**:

- `secure@microsoft.com`: 5.5, `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`
- `nvd@nist.gov`: 10.0, `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`

The script preferred the `Primary` entry. With none present, it fell back to the first-listed entry, which was the vendor's 5.5. The result depended on the order the NVD happened to list its sources in, and it silently disabled the tier0 fix.

**Fix:** when sources disagree, take the highest score (plan for the worse case), and record the chosen source in `cvss_source` and the rejected scores in `other_scores`. Four of the ten CVEs had conflicting scores. Zerologon's rank across the fixes:

| Version | Zerologon rank | Score |
|---|---|---|
| Original (internal, vendor score 5.5/LOCAL) | #7 | 33.0 |
| tier0 only | #7 | 33.0 (the LOCAL cap cancels the fix) |
| tier0 + highest-score rule | #2 | 90.0 |

**Trade-off:** taking the maximum is deliberately conservative and can inflate scores. Citrix Bleed rose from NIST's 7.5 to Citrix's own 9.4 under this rule. For prioritization, over-ranking a real exploited bug is the cheaper mistake.

## Limitations and next steps

- **Weights are judgment calls.** The threat, exposure and criticality values are defensible but not calibrated against real incident data.
- **Unscored CVEs default to 5.0 silently.** The NVD has had a scoring backlog since 2024, so recent CVEs often have no score. These should be flagged as "unknown" rather than treated as medium.
- **Add EPSS.** FIRST's Exploit Prediction Scoring System gives a 30-day exploitation probability, which would rank CVEs that are not yet in KEV.
- **Real inventory.** Replace the hand-built CSV with a scanner export (Nessus, OpenVAS) or an asset inventory.

## Usage

Requires Python 3.8+, standard library only.

```bash
# Optional but recommended: free NVD API key (50 requests/30s instead of 5)
export NVD_API_KEY=your-key          # Linux/macOS
set NVD_API_KEY=your-key             # Windows cmd (no quotes)

python vulnscore.py assets.csv
```

Output: a ranked table in the terminal and `prioritized.csv`. The KEV feed is saved to `kev.json` and NVD responses to `nvd_cache/`, so reruns make no API calls.

`assets.csv` format: `asset,role,exposure,criticality,cves`, with CVEs separated by `;`. Exposure is one of `internet`, `tier0`, `internal`, `isolated`; criticality is 1–5.
