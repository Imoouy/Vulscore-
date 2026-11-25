#!/usr/bin/env python3
"""
vulnscore.py - risk-based vulnerability prioritization.

Combines four signals per (asset, CVE) pair:
  1. Severity    - CVSS base score from the NVD (how bad if exploited)
  2. Threat      - is it in CISA's Known Exploited Vulnerabilities catalog?
                   (is anyone actually exploiting it), with a bump for ransomware use
  3. Exposure    - how reachable the asset is (internet / internal / isolated),
                   adjusted by the CVE's CVSS attack vector
  4. Criticality - how much the business loses if this asset is compromised (1-5)

score = 100 * (cvss/10) * threat * exposure * criticality / MAX
Multiplicative on purpose: a near-zero factor (isolated box, throwaway asset)
should drag the whole score down instead of being averaged away.

Standard library only. Usage:
  python3 vulnscore.py assets.csv
  python3 vulnscore.py assets.csv --nvd-key YOUR_KEY       # faster NVD lookups
  python3 vulnscore.py assets.csv --kev-file kev.json      # use a saved KEV feed
"""
import argparse, csv, json, os, sys, time, urllib.request, urllib.error

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"

# ---- Tunable weights: these are your judgment calls, defend them in the writeup ----
THREAT = {"kev_ransomware": 2.5, "kev": 2.0, "none": 1.0}
EXPOSURE = {
    "internet": 1.0,   # reachable by anyone on the internet
    "tier0": 0.9,      # internal, but reachable from nearly every internal host (DCs, AD CS, SCCM)
    "internal": 0.6,   # reachable only from parts of the internal network
    "isolated": 0.3,   # segmented lab / air-gapped
}
# Criticality 1-5 maps to 0.2-1.0
MAX_RAW = 1.0 * THREAT["kev_ransomware"] * EXPOSURE["internet"] * 1.0


def fetch_json(url, headers=None, retries=3):
    req = urllib.request.Request(url, headers={"User-Agent": "vulnscore/1.0", **(headers or {})})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            # NVD returns 403/429 when you exceed the rate limit; back off and retry
            if e.code in (403, 429, 503) and attempt < retries - 1:
                time.sleep(10 * (attempt + 1))
                continue
            hint = ""
            if e.code == 404 and "apiKey" in (headers or {}):
                hint = ("\n  NVD returns 404 for an invalid API key. Check the key is activated "
                        "and has no quotes or spaces in it.")
            sys.exit(f"HTTP {e.code} fetching {url}{hint}")


def load_kev(path=None):
    """Return {cve_id: kev_record}. Downloads once, caches to kev.json."""
    if path and os.path.exists(path):
        data = json.load(open(path))
    else:
        data = fetch_json(KEV_URL)
        json.dump(data, open("kev.json", "w"))
    return {v["cveID"]: v for v in data["vulnerabilities"]}


def pick_cvss(metrics):
    """
    Prefer CVSS v3.1 > v3.0 > v4.0 > v2. Within a version, the NVD can list several
    scores from different sources (NIST, the vendor CNA, CISA-ADP) that disagree.
    Take the HIGHEST: when scorers disagree, plan for the worse case.
    (Example: one source scores Zerologon 5.5/LOCAL, another 10.0/NETWORK.)
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = max(entries, key=lambda m: float(m["cvssData"]["baseScore"]))
        d = entry["cvssData"]
        av = d.get("attackVector") or d.get("accessVector") or "UNKNOWN"
        others = sorted({float(m["cvssData"]["baseScore"]) for m in entries} - {float(d["baseScore"])})
        return (float(d["baseScore"]), av.upper(), key.replace("cvssMetric", ""),
                entry.get("source", "?"), "/".join(str(s) for s in others))
    return None, "UNKNOWN", None, "", ""


def load_nvd(cve_ids, api_key=None, cache_dir="nvd_cache"):
    """Return {cve_id: (score, attack_vector, version)}. Caches each CVE to disk."""
    os.makedirs(cache_dir, exist_ok=True)
    # NVD limits: 5 requests / 30s without a key, 50 / 30s with one
    delay = 0.7 if api_key else 6.5
    headers = {"apiKey": api_key} if api_key else {}
    out = {}
    for i, cve in enumerate(sorted(cve_ids)):
        cache = os.path.join(cache_dir, f"{cve}.json")
        if os.path.exists(cache):
            data = json.load(open(cache))
        else:
            print(f"  NVD lookup {i+1}/{len(cve_ids)}: {cve}", file=sys.stderr)
            data = fetch_json(NVD_URL.format(cve), headers)
            json.dump(data, open(cache, "w"))
            time.sleep(delay)
        vulns = data.get("vulnerabilities", [])
        out[cve] = pick_cvss(vulns[0]["cve"].get("metrics", {})) if vulns else (None, "UNKNOWN", None, "", "")
    return out


def effective_exposure(asset_exposure, attack_vector):
    """
    Internet exposure only matters if the bug is reachable over the network.
    A LOCAL or PHYSICAL vector on an internet-facing box needs a foothold first,
    so treat it like an internal asset.
    """
    base = EXPOSURE[asset_exposure]
    if attack_vector in ("LOCAL", "PHYSICAL"):
        return min(base, EXPOSURE["internal"])
    return base


def score_row(asset, cve, nvd, kev):
    cvss, av, ver, src, others = nvd.get(cve, (None, "UNKNOWN", None, "", ""))
    if cvss is None:
        cvss = 5.0  # no score published yet: assume medium, and flag it
    k = kev.get(cve)
    if k and k.get("knownRansomwareCampaignUse", "").lower() == "known":
        threat_key = "kev_ransomware"
    elif k:
        threat_key = "kev"
    else:
        threat_key = "none"
    exp = effective_exposure(asset["exposure"], av)
    crit = int(asset["criticality"]) / 5
    raw = (cvss / 10) * THREAT[threat_key] * exp * crit
    return {
        "score": round(100 * raw / MAX_RAW, 1),
        "asset": asset["asset"],
        "role": asset["role"],
        "cve": cve,
        "cvss": cvss,
        "cvss_ver": ver or "none",
        "cvss_source": src,
        "other_scores": others,
        "attack_vector": av,
        "kev": {"kev_ransomware": "YES (ransomware)", "kev": "YES", "none": "no"}[threat_key],
        "kev_due": k["dueDate"] if k else "",
        "exposure": asset["exposure"],
        "criticality": asset["criticality"],
        "name": k["vulnerabilityName"] if k else "",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("assets", help="CSV: asset,role,exposure,criticality,cves (cves ;-separated)")
    ap.add_argument("--nvd-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--kev-file", help="local KEV JSON instead of downloading")
    ap.add_argument("--nvd-cache", default="nvd_cache")
    ap.add_argument("--out", default="prioritized.csv")
    args = ap.parse_args()
    if args.nvd_key:
        # Windows cmd keeps quotes as part of the value: set X="abc" stores "abc" with quotes
        args.nvd_key = args.nvd_key.strip().strip('"').strip("'").strip()
        print(f"Using NVD API key ending in ...{args.nvd_key[-4:]}", file=sys.stderr)

    assets = list(csv.DictReader(open(args.assets)))
    for a in assets:
        if a["exposure"] not in EXPOSURE:
            sys.exit(f"{a['asset']}: exposure must be one of {list(EXPOSURE)}")
        if not 1 <= int(a["criticality"]) <= 5:
            sys.exit(f"{a['asset']}: criticality must be 1-5")
    all_cves = {c.strip() for a in assets for c in a["cves"].split(";") if c.strip()}

    print("Loading CISA KEV...", file=sys.stderr)
    kev = load_kev(args.kev_file)
    print(f"  {len(kev)} known exploited CVEs in catalog", file=sys.stderr)
    print("Loading NVD scores...", file=sys.stderr)
    nvd = load_nvd(all_cves, args.nvd_key, args.nvd_cache)

    rows = [score_row(a, c.strip(), nvd, kev) for a in assets for c in a["cves"].split(";") if c.strip()]
    rows.sort(key=lambda r: r["score"], reverse=True)

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    print(f"\n{'#':>2}  {'SCORE':>5}  {'ASSET':<10} {'CVE':<15} {'CVSS':>4}  {'AV':<8} {'KEV':<17} {'EXPOSURE':<9} CRIT")
    for i, r in enumerate(rows, 1):
        print(f"{i:>2}  {r['score']:>5}  {r['asset']:<10} {r['cve']:<15} {r['cvss']:>4}  "
              f"{r['attack_vector'][:8]:<8} {r['kev']:<17} {r['exposure']:<9} {r['criticality']}")
    print(f"\nWrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
