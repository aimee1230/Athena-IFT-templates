#!/usr/bin/env python3
"""
Fill MITRE ATT&CK templates using helper modules `query_postgre` and `query_neo4j`.
Outputs JSONL files to filled_templates/.
"""

import os
import json
import argparse
import datetime
from pathlib import Path
from typing import List, Dict, Any

from query_postgre import run_query as pg_run_query
from query_neo4j import run_query_dict as neo4j_run_query_dict

# Paths
TEMPLATES_PATH = Path("templates/IFT_MITRE.jsonl")
OUTPUT_DIR = Path("filled_templates")

# Helper Functions
def load_templates(path: Path) -> List[Dict[str, Any]]:
    """Read JSONL templates file and return list of template dicts."""
    if not path.exists():
        raise FileNotFoundError(f"Templates file not found: {path}")
    templates = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                templates.append(json.loads(line))
    return templates

def safe_to_list(field_value) -> List[str]:
    """Normalize field to list of strings."""
    if not field_value:
        return []
    if isinstance(field_value, list):
        return [str(x) for x in field_value]
    if isinstance(field_value, str):
        try:
            parsed = json.loads(field_value)
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        except Exception:
            pass
        return [s.strip() for s in field_value.split(",") if s.strip()]
    return [str(field_value)]

def fill_template_text(template_text: str, placeholders: Dict[str, str]) -> str:
    """Replace {placeholders} in template_text with actual values."""
    out = template_text
    for k, v in placeholders.items():
        out = out.replace(f"{{{k}}}", v if v is not None else "")
    return out

# Data Extraction
def get_techniques(limit: int = None) -> List[Dict[str, Any]]:
    """Fetch techniques from PostgreSQL."""
    q = "SELECT mitre_id, name, description, x_mitre_data_sources, x_mitre_platforms, kill_chain_phases FROM techniques ORDER BY mitre_id"
    if limit:
        q += f" LIMIT {limit}"
    return pg_run_query(q, return_dict=True)


def get_tactic_by_shortname(shortname: str) -> Dict[str, Any]:
    """
    Robust lookup for tactic details by shortname.
    Tries multiple columns commonly used to store the tactic short-name:
      - shortname
      - name
      - mitre_id

    Returns a dict with keys: mitre_id, name, description (possibly empty strings).
    """
    if not shortname:
        return {"mitre_id": "", "name": "", "description": ""}

    # sanitize single-quote inside shortname
    safe_short = shortname.replace("'", "''")

    q = f"""
    SELECT mitre_id, name, description
    FROM tactics
    WHERE shortname = '{safe_short}'
    LIMIT 1;
    """
    try:
        res = pg_run_query(q, return_dict=True)
    except Exception as e:
        print(f"[get_tactic_by_shortname] query error: {e}")
        return {"mitre_id": "", "name": shortname, "description": ""}

    if res:
        # ensure keys exist
        row = res[0]
        return {
            "mitre_id": row.get("mitre_id", "") or "",
            "name": row.get("name", "") or "",
            "description": row.get("description", "") or ""
        }

    # fallback: not found in DB — return shortname in 'name' so templates still meaningful
    # (use empty mitre_id/description)
    # helpful debug print:
    print(f"[get_tactic_by_shortname] no tactic found for shortname='{shortname}'")
    return {"mitre_id": "", "name": shortname, "description": ""}

def get_subtechniques(technique_id: str) -> List[str]:
    """Fetch subtechniques for a technique from Neo4j, get their names from PostgreSQL."""
    query = f"""
    MATCH (st:Technique)-[:CHILD_OF]->(t:Technique)
    WHERE t.mitre_id = '{technique_id}'
    RETURN st.mitre_id AS mitre_id
    ORDER BY st.mitre_id
    """
    subtechs = neo4j_run_query_dict(query, keys=["mitre_id"])

    if not subtechs:
        return ["None"]

    subtech_ids = [st["mitre_id"] for st in subtechs if st.get("mitre_id")]

    if not subtech_ids:
        return ["None"]

    # Fetch subtechnique names from PostgreSQL
    ids_str = ", ".join([f"'{sid}'" for sid in subtech_ids])
    q = f"SELECT mitre_id, name FROM techniques WHERE mitre_id IN ({ids_str});"
    res = pg_run_query(q, return_dict=True)

    if not res:
        return ["None"]

    return [f"{r['name']} ({r['mitre_id']})" for r in res]

def build_filled_entries(templates: List[Dict[str, Any]], techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    filled = []

    for t in techniques:
        mitre_id = t.get("mitre_id")
        name = t.get("name", "")
        description = t.get("description", "")
        data_sources = ", ".join(safe_to_list(t.get("x_mitre_data_sources")))
        platforms = ", ".join(safe_to_list(t.get("x_mitre_platforms")))

        placeholders_base = {
            "technique_name": name,
            "technique_id": mitre_id,
            "brief_description_of_technique": description,
            "x_mitre_data_sources": data_sources,
            "platform_list": platforms
        }

        subtech_list = ", ".join(get_subtechniques(mitre_id))
        placeholders_base["subtechnique_list"] = subtech_list

        # normalize kill_chain_phases
        phases_raw = t.get("kill_chain_phases") or []
        try:
            phases = json.loads(phases_raw) if isinstance(phases_raw, str) else phases_raw
        except Exception:
            phases = [{"phase_name": p.strip()} for p in str(phases_raw).split(",") if p.strip()]

        for tmpl in templates:
            instr = tmpl.get("instruction", "")
            inp = tmpl.get("input", "")
            out_template = tmpl.get("output", "")

            # tactic template
            if "{tactic_name}" in out_template or "{tactic_purpose}" in out_template:
                if not phases:
                    placeholders = placeholders_base.copy()
                    placeholders.update({"tactic_name": "", "tactic_purpose": ""})
                    filled.append({
                        "instruction": instr,
                        "input": fill_template_text(inp, placeholders),
                        "output": fill_template_text(out_template, placeholders),
                    })
                else:
                    for ph in phases:
                        phase_name = ph.get("phase_name") if isinstance(ph, dict) else str(ph)
                        tactic = get_tactic_by_shortname(phase_name)
                        placeholders = placeholders_base.copy()
                        placeholders.update({
                            "tactic_name": tactic.get("name", ""),
                            "tactic_purpose": tactic.get("description", ""),
                            "tactic_id": tactic.get("mitre_id", "")
                        })
                        filled.append({
                            "instruction": instr,
                            "input": fill_template_text(inp, placeholders),
                            "output": fill_template_text(out_template, placeholders),
                        })
            else:
                placeholders = placeholders_base.copy()
                filled.append({
                    "instruction": instr,
                    "input": fill_template_text(inp, placeholders),
                    "output": fill_template_text(out_template, placeholders),
                })

    return filled

# Main
def main():
    parser = argparse.ArgumentParser(description="Fill MITRE templates using helpers.")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of techniques")
    parser.add_argument("--templates", type=str, default=str(TEMPLATES_PATH))
    parser.add_argument("--outdir", type=str, default=str(OUTPUT_DIR))
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    templates = load_templates(Path(args.templates))
    techniques = get_techniques(limit=args.limit)
    if not techniques:
        print("No techniques found.")
        return

    filled_entries = build_filled_entries(templates, techniques)
    print(f"Built {len(filled_entries)} filled template entries.")

    #ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    fname = f"filled_mitre_templates_{args.limit or 'all'}.jsonl"
    outpath = outdir / fname

    with outpath.open("w", encoding="utf-8") as fh:
        for entry in filled_entries:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")

    print(f"Saved filled templates to: {outpath.resolve()}")

if __name__ == "__main__":
    main()
