#!/usr/bin/env python3
"""
Fill MITRE ATT&CK templates (Techniques + Tools) using helper modules
`query_postgre` and `query_neo4j`.
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

# ---------------------- Helper Functions ----------------------

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


# ---------------------- Data Extraction ----------------------

def get_techniques(limit: int = None) -> List[Dict[str, Any]]:
    """Fetch techniques from PostgreSQL."""
    q = "SELECT mitre_id, name, description, x_mitre_data_sources, x_mitre_platforms, kill_chain_phases FROM techniques ORDER BY mitre_id"
    if limit:
        q += f" LIMIT {limit}"
    return pg_run_query(q, return_dict=True)


def get_tools(limit: int = None) -> List[Dict[str, Any]]:
    """Fetch tools from PostgreSQL."""
    q = "SELECT mitre_id, name, description FROM tools ORDER BY mitre_id"
    if limit:
        q += f" LIMIT {limit}"
    return pg_run_query(q, return_dict=True)


def get_tactic_by_shortname(shortname: str) -> Dict[str, Any]:
    """Lookup tactic details by shortname."""
    if not shortname:
        return {"mitre_id": "", "name": "", "description": ""}

    safe_short = shortname.replace("'", "''")
    q = f"SELECT mitre_id, name, description FROM tactics WHERE shortname = '{safe_short}' LIMIT 1;"
    try:
        res = pg_run_query(q, return_dict=True)
    except Exception as e:
        print(f"[get_tactic_by_shortname] query error: {e}")
        return {"mitre_id": "", "name": shortname, "description": ""}

    if res:
        row = res[0]
        return {
            "mitre_id": row.get("mitre_id", ""),
            "name": row.get("name", ""),
            "description": row.get("description", "")
        }

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

    ids_str = ", ".join([f"'{sid}'" for sid in subtech_ids])
    q = f"SELECT mitre_id, name FROM techniques WHERE mitre_id IN ({ids_str});"
    res = pg_run_query(q, return_dict=True)

    if not res:
        return ["None"]

    return [f"{r['name']} ({r['mitre_id']})" for r in res]


def get_techniques_by_tool(tool_id: str) -> List[str]:
    """Fetch technique names for a tool using Neo4j + PostgreSQL."""
    query = f"""
    MATCH (t:Tool)-[:USES]->(tech:Technique)
    WHERE t.mitre_id = '{tool_id}'
    RETURN tech.mitre_id AS mitre_id
    ORDER BY tech.mitre_id
    """
    techs = neo4j_run_query_dict(query, keys=["mitre_id"])

    if not techs:
        return ["None"]

    technique_ids = [t["mitre_id"] for t in techs if t.get("mitre_id")]
    if not technique_ids:
        return ["None"]

    ids_str = ", ".join([f"'{tid}'" for tid in technique_ids])
    q = f"SELECT mitre_id, name FROM techniques WHERE mitre_id IN ({ids_str});"
    res = pg_run_query(q, return_dict=True)

    if not res:
        return [tid for tid in technique_ids]

    return [f"{r['name']} ({r['mitre_id']})" for r in res if r.get("name")]

def get_campaigns(limit: int = None) -> List[Dict[str, Any]]:
    """Fetch campaigns from PostgreSQL."""
    q = "SELECT mitre_id, name, description FROM campaigns ORDER BY mitre_id"
    if limit:
        q += f" LIMIT {limit}"
    return pg_run_query(q, return_dict=True)


def get_tools_by_campaign(campaign_id: str) -> List[str]:
    """Fetch tools linked to a campaign from Neo4j, get names from PostgreSQL."""
    query = f"""
    MATCH (c:Campaign)-[:USES]->(t:Tool)
    WHERE c.mitre_id = '{campaign_id}'
    RETURN t.mitre_id AS mitre_id
    ORDER BY t.mitre_id
    """
    tools = neo4j_run_query_dict(query, keys=["mitre_id"])

    if not tools:
        return ["None"]

    tool_ids = [t["mitre_id"] for t in tools if t.get("mitre_id")]
    if not tool_ids:
        return ["None"]

    ids_str = ", ".join([f"'{tid}'" for tid in tool_ids])
    q = f"SELECT mitre_id, name FROM tools WHERE mitre_id IN ({ids_str});"
    res = pg_run_query(q, return_dict=True)

    if not res:
        return [tid for tid in tool_ids]

    return [f"{r['name']} ({r['mitre_id']})" for r in res if r.get("name")]


def get_techniques_by_campaign(campaign_id: str) -> List[str]:
    """Fetch techniques linked to a campaign from Neo4j, get names from PostgreSQL."""
    query = f"""
    MATCH (c:Campaign)-[:USES]->(tech:Technique)
    WHERE c.mitre_id = '{campaign_id}'
    RETURN tech.mitre_id AS mitre_id
    ORDER BY tech.mitre_id
    """
    techs = neo4j_run_query_dict(query, keys=["mitre_id"])

    if not techs:
        return ["None"]

    technique_ids = [t["mitre_id"] for t in techs if t.get("mitre_id")]
    if not technique_ids:
        return ["None"]

    ids_str = ", ".join([f"'{tid}'" for tid in technique_ids])
    q = f"SELECT mitre_id, name FROM techniques WHERE mitre_id IN ({ids_str});"
    res = pg_run_query(q, return_dict=True)

    if not res:
        return [tid for tid in technique_ids]

    return [f"{r['name']} ({r['mitre_id']})" for r in res if r.get("name")]

def get_malware(limit: int = None) -> List[Dict[str, Any]]:
    """Fetch malware entries from PostgreSQL."""
    q = "SELECT mitre_id, name, description FROM malware ORDER BY mitre_id"
    if limit:
        q += f" LIMIT {limit}"
    return pg_run_query(q, return_dict=True)


def get_techniques_by_malware(malware_id: str) -> List[str]:
    """Fetch technique IDs linked to malware from Neo4j."""
    query = f"""
    MATCH (m:Malware)-[:USES]->(tech:Technique)
    WHERE m.mitre_id = '{malware_id}'
    RETURN tech.mitre_id AS mitre_id
    ORDER BY tech.mitre_id
    """
    techs = neo4j_run_query_dict(query, keys=["mitre_id"])

    if not techs:
        return ["None"]

    technique_ids = [t["mitre_id"] for t in techs if t.get("mitre_id")]
    return technique_ids if technique_ids else ["None"]


# ---------------------- Template Filling ----------------------

def build_filled_entries_techniques(templates: List[Dict[str, Any]], techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fill technique-related templates."""
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

        # Handle tactic
        phases_raw = t.get("kill_chain_phases") or []
        try:
            phases = json.loads(phases_raw) if isinstance(phases_raw, str) else phases_raw
        except Exception:
            phases = [{"phase_name": p.strip()} for p in str(phases_raw).split(",") if p.strip()]

        for tmpl in templates:
            if "{technique_id}" not in tmpl.get("input", ""):
                continue  # skip non-technique templates

            instr = tmpl["instruction"]
            inp = tmpl["input"]
            out_template = tmpl["output"]

            # tactic template
            if "{tactic_name}" in out_template or "{tactic_purpose}" in out_template:
                if not phases:
                    placeholders = placeholders_base.copy()
                    placeholders.update({"tactic_name": "", "tactic_purpose": ""})
                    filled.append({
                        "instruction": instr,
                        "input": fill_template_text(inp, placeholders),
                        "output": fill_template_text(out_template, placeholders)
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
                            "output": fill_template_text(out_template, placeholders)
                        })
            else:
                placeholders = placeholders_base.copy()
                filled.append({
                    "instruction": instr,
                    "input": fill_template_text(inp, placeholders),
                    "output": fill_template_text(out_template, placeholders)
                })
    return filled


def build_filled_entries_tools(templates: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fill tool-related templates."""
    filled = []
    for tool in tools:
        tool_id = tool.get("mitre_id", "")
        tool_name = tool.get("name", "")
        tool_desc = tool.get("description", "")

        technique_list = ", ".join(get_techniques_by_tool(tool_id))

        placeholders = {
            "tool_id": tool_id,
            "tool_name": tool_name,
            "tool_description": tool_desc,
            "technique_list": technique_list
        }

        for tmpl in templates:
            if "{tool_id}" not in tmpl.get("input", ""):
                continue  # skip non-tool templates

            filled.append({
                "instruction": tmpl["instruction"],
                "input": fill_template_text(tmpl["input"], placeholders),
                "output": fill_template_text(tmpl["output"], placeholders)
            })

    return filled

def build_filled_entries_campaigns(templates: List[Dict[str, Any]], campaigns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fill campaign-related templates (templates 9 and 10)."""
    filled = []
    for camp in campaigns:
        camp_id = camp.get("mitre_id", "")
        camp_name = camp.get("name", "")
        camp_desc = camp.get("description", "")

        tool_list = ", ".join(get_tools_by_campaign(camp_id))
        technique_list = ", ".join(get_techniques_by_campaign(camp_id))

        placeholders = {
            "campaign_id": camp_id,
            "campaign_name": camp_name,
            "campaign_description": camp_desc,
            "tool_list": tool_list,
            "technique_list": technique_list
        }

        for tmpl in templates:
            if "{campaign_id}" not in tmpl.get("input", ""):
                continue  # skip non-campaign templates

            filled.append({
                "instruction": tmpl["instruction"],
                "input": fill_template_text(tmpl["input"], placeholders),
                "output": fill_template_text(tmpl["output"], placeholders)
            })

    return filled

def build_filled_entries_malware(templates: List[Dict[str, Any]], malware_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Fill malware-related templates."""
    filled = []
    for mw in malware_list:
        mw_id = mw.get("mitre_id", "")
        mw_name = mw.get("name", "")
        mw_desc = mw.get("description", "")

        technique_list = ", ".join(get_techniques_by_malware(mw_id))

        placeholders = {
            "malware_id": mw_id,
            "malware_name": mw_name,
            "malware_description": mw_desc,
            "technique_list": technique_list
        }

        for tmpl in templates:
            if "{malware_id}" not in tmpl.get("input", ""):
                continue  # skip non-malware templates

            filled.append({
                "instruction": tmpl["instruction"],
                "input": fill_template_text(tmpl["input"], placeholders),
                "output": fill_template_text(tmpl["output"], placeholders)
            })

    return filled

# ---------------------- Main ----------------------

def main():
    parser = argparse.ArgumentParser(description="Fill MITRE templates using helpers.")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of items")
    parser.add_argument("--templates", type=str, default=str(TEMPLATES_PATH))
    parser.add_argument("--outdir", type=str, default=str(OUTPUT_DIR))
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    templates = load_templates(Path(args.templates))

    filled_all = []

    # ---- Techniques ----
    techniques = get_techniques(limit=args.limit)
    if techniques:
        filled_techniques = build_filled_entries_techniques(templates, techniques)
        filled_all.extend(filled_techniques)
        print(f"✅ Built {len(filled_techniques)} technique entries")

    # ---- Tools ----
    tools = get_tools(limit=args.limit)
    if tools:
        filled_tools = build_filled_entries_tools(templates, tools)
        filled_all.extend(filled_tools)
        print(f"✅ Built {len(filled_tools)} tool entries")

    # ---- Campaigns ----
    campaigns = get_campaigns(limit=args.limit)
    if campaigns:
        filled_campaigns = build_filled_entries_campaigns(templates, campaigns)
        filled_all.extend(filled_campaigns)
        print(f"✅ Built {len(filled_campaigns)} campaign entries")
    
    # ---- Malware ----
    malware_list = get_malware(limit=args.limit)
    if malware_list:
        filled_malware = build_filled_entries_malware(templates, malware_list)
        filled_all.extend(filled_malware)
        print(f"✅ Built {len(filled_malware)} malware entries")

    # ---- Single Combined Output ----
    if filled_all:
        outpath = outdir / f"filled_mitre_templates_{args.limit or 'all'}.jsonl"
        with outpath.open("w", encoding="utf-8") as fh:
            for entry in filled_all:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"🎯 Combined {len(filled_all)} total entries → {outpath}")
    else:
        print("⚠️ No entries were generated.")


if __name__ == "__main__":
    main()
