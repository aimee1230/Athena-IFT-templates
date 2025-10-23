#!/usr/bin/env python3
"""
Auto-fill CVE templates using data from PostgreSQL.
Automatically detects which placeholders a template requires.
"""

import json
import argparse
from pathlib import Path
from typing import List, Dict, Any

from query_postgre import run_query as pg_run_query

# Paths
TEMPLATES_PATH = Path("templates/IFT_CVE.jsonl")
OUTPUT_DIR = Path("filled_templates")

# Helper Functions
def load_templates(path: Path) -> List[Dict[str, Any]]:
    """Read JSONL templates file and return list of template dicts."""
    templates = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                templates.append(json.loads(line))
    return templates

def fill_template_text(template_text: str, placeholders: Dict[str, str]) -> str:
    """Replace {placeholders} in template_text with actual values."""
    out = template_text
    for k, v in placeholders.items():
        out = out.replace(f"{{{k}}}", v if v is not None else "")
    return out

# Data Extraction
def get_cve_data(limit: int = None) -> List[Dict[str, Any]]:
    """Fetch CVE data from PostgreSQL (only 2024 & 2025 CVEs by default)."""
    q = """
    SELECT cve_id, descriptions, impacts, metrics
    FROM cve_vulnerabilities
    WHERE cve_id LIKE 'CVE-2025-%' OR cve_id LIKE 'CVE-2024-%'
    ORDER BY cve_id
    """
    if limit:
        q += f" LIMIT {limit}"
    return pg_run_query(q, return_dict=True)

def safe_json_load(s):
    """Try loading JSON safely, handling common PostgreSQL formatting quirks."""
    if not s:
        return None
    if isinstance(s, (dict, list)):
        return s

    try:
        # Clean newlines, tabs, stray spaces (but avoid aggressive quote replacement)
        cleaned = (
            str(s)
            .replace("\r", "")
            .replace("\t", "")
            .strip()
        )
        # Remove literal newlines inside string (they may split tokens)
        cleaned = cleaned.replace("\n", " ")
        # Attempt first parse
        data = json.loads(cleaned)
        # If the result is a stringified JSON (double encoded), parse again
        if isinstance(data, str) and data.strip().startswith("["):
            data = json.loads(data)
        return data
    except Exception as e:
        # Second attempt: try replacing single quotes with double quotes (best-effort)
        try:
            repaired = cleaned.replace("'", '"')
            data = json.loads(repaired)
            if isinstance(data, str) and data.strip().startswith("["):
                data = json.loads(data)
            return data
        except Exception:
            # Give up quietly (caller will handle None)
            return None

def extract_cvss_metrics(metrics_json: str) -> Dict[str, str]:
    """
    Extract CVSSv3.1 baseScore and vectorString from metrics JSON.
    Supports several common layouts:
      - [{"cvssV3_1": {...}}]
      - {"metrics": {"cvssV3_1": {...}}}
      - {"cvssMetricV31": [{"cvssData": {...}}]}  (NVD)
      - and variations
    Returns dict with keys: cvss_score (string) and attack_vector (vectorString).
    """
    data = safe_json_load(metrics_json)
    if not data:
        return {"cvss_score": "", "attack_vector": ""}

    # Normalize to iterable list
    entries = data if isinstance(data, list) else [data]

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        # Direct keys
        if "cvssV3_1" in entry and isinstance(entry["cvssV3_1"], dict):
            cvss = entry["cvssV3_1"]
            return {
                "cvss_score": str(cvss.get("baseScore", "")),
                "attack_vector": cvss.get("vectorString", "") or cvss.get("vector_string", "")
            }

        if "cvssV3" in entry and isinstance(entry["cvssV3"], dict):
            cvss = entry["cvssV3"]
            return {
                "cvss_score": str(cvss.get("baseScore", "")),
                "attack_vector": cvss.get("vectorString", "") or cvss.get("vector_string", "")
            }

        # nested under "metrics"
        metrics = entry.get("metrics")
        if isinstance(metrics, dict):
            for key in ("cvssV3_1", "cvssV3"):
                if key in metrics and isinstance(metrics[key], dict):
                    cvss = metrics[key]
                    return {
                        "cvss_score": str(cvss.get("baseScore", "")),
                        "attack_vector": cvss.get("vectorString", "") or cvss.get("vector_string", "")
                    }

        # NVD-like: cvssMetricV31 -> list of {cvssData: {...}}
        if "cvssMetricV31" in entry and isinstance(entry["cvssMetricV31"], list) and entry["cvssMetricV31"]:
            first = entry["cvssMetricV31"][0]
            cvss_data = first.get("cvssData") or first.get("cvssV3_1") or {}
            if isinstance(cvss_data, dict):
                return {
                    "cvss_score": str(cvss_data.get("baseScore", "")),
                    "attack_vector": cvss_data.get("vectorString", "") or cvss_data.get("vector_string", "")
                }

    # Not found
    return {"cvss_score": "", "attack_vector": ""}

def extract_description(desc_raw: str) -> str:
    """Extract English-language description text from JSON or raw text."""
    desc_json = safe_json_load(desc_raw)
    description = ""

    if isinstance(desc_json, list):
        for d in desc_json:
            if isinstance(d, dict):
                # common patterns: {"lang":"en","value":"..."} or {"value":"...","lang":"en"}
                if d.get("lang") == "en" and d.get("value"):
                    description = d.get("value")
                    break
                # sometimes the object itself is the text
                if d.get("value") and not d.get("lang"):
                    description = d.get("value")
                    break
    elif isinstance(desc_json, dict):
        # support nested keys
        if "value" in desc_json:
            description = desc_json.get("value", "")
        else:
            # fallback stringify
            description = json.dumps(desc_json)
    else:
        description = str(desc_raw)

    # Normalize whitespace / newlines into single spaces
    return " ".join(description.split())

def extract_impact(imp_raw: str) -> str:
    """
    Extract human-readable impact from various impact JSON formats.
    Handles:
      - [{"capecId": "...", "descriptions": [{"lang": "en", "value": "..."}]}]
    Returns plain text (e.g. "CAPEC-233 Privilege Escalation" or "CWE-287 Improper Authentication").
    """
    imp_json = safe_json_load(imp_raw)
    if not imp_json:
        return ""

    # impact is a list of objects (CAPEC or CWE)
    if isinstance(imp_json, list):
        results = []
        for item in imp_json:
            if not isinstance(item, dict):
                continue

            # CAPEC-style
            if "capecId" in item:
                descs = item.get("descriptions", [])
                for d in descs:
                    if isinstance(d, dict) and d.get("lang") == "en" and d.get("value"):
                        results.append(d["value"].strip())

            # Fallback
            elif item.get("description"):
                results.append(item["description"].strip())

        if results:
            return "; ".join(results)

    # Fallback: return raw string
    return str(imp_raw).strip()



# Core Logic
def build_filled_entries(templates: List[Dict[str, Any]], cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    filled = []

    for cve in cves:
        cve_id = cve.get("cve_id", "")
        desc_raw = cve.get("descriptions", "")
        imp_raw = cve.get("impacts", "")
        metrics_raw = cve.get("metrics", "")

        # Optional debug (uncomment if you want to inspect raw DB values)
        # print("[DEBUG] metrics_raw:", metrics_raw)
        # print("[DEBUG] desc_raw:", desc_raw)
        # print("[DEBUG] imp_raw:", imp_raw)

        description = extract_description(desc_raw)
        impact = extract_impact(imp_raw)

        cvss_data = extract_cvss_metrics(metrics_raw)
        cvss_score = cvss_data.get("cvss_score", "")
        attack_vector = cvss_data.get("attack_vector", "")

        placeholders_base = {
            "cve_id": cve_id,
            "vulnerability_description": description,
            "potential_impact": impact,
            "cve_description": description,
            "cvss_score": cvss_score,
            "attack_vector": attack_vector,
        }

        for tmpl in templates:
            instr = tmpl.get("instruction", "")
            inp = tmpl.get("input", "")
            out = tmpl.get("output", "")

            # detect which placeholders are used (input OR output)
            placeholders = {
                k: v for k, v in placeholders_base.items()
                if f"{{{k}}}" in inp or f"{{{k}}}" in out
            }

            filled.append({
                "instruction": instr,
                "input": fill_template_text(inp, placeholders),
                "output": fill_template_text(out, placeholders),
            })

    return filled

# Main
def main():
    parser = argparse.ArgumentParser(description="Fill CVE templates using PostgreSQL.")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of CVEs")
    parser.add_argument("--templates", type=str, default=str(TEMPLATES_PATH))
    parser.add_argument("--outdir", type=str, default=str(OUTPUT_DIR))
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    templates = load_templates(Path(args.templates))
    cves = get_cve_data(limit=args.limit)
    if not cves:
        print("No CVEs found.")
        return

    filled_entries = build_filled_entries(templates, cves)
    print(f"Built {len(filled_entries)} filled CVE template entries.")

    outpath = outdir / f"filled_cve_templates_{args.limit or 'all'}.jsonl"
    with outpath.open("w", encoding="utf-8") as fh:
        for entry in filled_entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"Saved filled templates to: {outpath.resolve()}")

if __name__ == "__main__":
    main()
