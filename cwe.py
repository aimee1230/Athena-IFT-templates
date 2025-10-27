import json
import os
import re
from typing import Any
from query_postgre import run_query
from query_neo4j import run_query_dict

TEMPLATE_PATH = "templates/IFT_CWE.jsonl"
OUTPUT_DIR = "filled_templates"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def get_capec_attack_patterns(cwe_id: str) -> str:
    """
    Fetch CAPEC attack pattern names and IDs related to a CWE from Neo4j.
    Returns a nicely formatted string, or a fallback message if none found.
    """
    query = f"""
    MATCH (c:CAPEC)-[:EXPLOITS]->(w:CWE {{cwe_id: '{cwe_id}'}})
    RETURN c.capec_id AS id, c.name AS name
    """
    results = run_query_dict(query, keys=["id", "name"])
    if not results:
        return "None found"
    
    formatted_patterns = [f"{r['name']} ({r['id']})" for r in results if r.get("name") and r.get("id")]
    return ", ".join(formatted_patterns) if formatted_patterns else "no related attack patterns found"


def format_background_details(details) -> str:
    if not details:
        return ""
    if isinstance(details, list):
        return " ".join(d.strip() for d in details)  # no numbering
    if isinstance(details, str):
        try:
            parsed = json.loads(details)
            if isinstance(parsed, list):
                return " ".join(d.strip() for d in parsed)
            return str(parsed)
        except Exception:
            return details
    return str(details)


def format_detection_methods(methods) -> str:
    if not methods:
        return "no detection methods available"
    sentences = []
    for i, m in enumerate(methods, start=1):
        desc = m.get("description", "").strip()
        name = m.get("method", "").strip()
        sentences.append(f"{i}. {name}: {desc}")
    return "\n".join(sentences)


def format_mitigations(mitigations) -> str:
    if not mitigations:
        return "no mitigations available"
    sentences = []
    for i, m in enumerate(mitigations, start=1):
        phase = m.get("phase", "")
        desc = m.get("description", "").strip()
        sentences.append(f"{i}. ({phase}) {desc}")
    return "\n".join(sentences)

def _ensure_list(x: Any):
    if x is None:
        return []
    if isinstance(x, str):
        try:
            parsed = json.loads(x)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            # not JSON list — try split by newlines/semicolons, else return single string
            parts = [p.strip() for p in re.split(r'[\n;]+', x) if p.strip()]
            return parts if parts else [x.strip()]
    if isinstance(x, (list, tuple)):
        return list(x)
    return [x]

def format_modes(modes: Any) -> str:
    modes_list = _ensure_list(modes)
    if not modes_list:
        return "unknown"

    clauses = []
    for m in modes_list:
        if isinstance(m, str):
            phase = m.strip()
            note = ""
        elif isinstance(m, dict):
            phase = str(m.get("phase") or "").strip()
            note = " ".join(str(m.get("note") or "").split()).strip()
        else:
            # fallback - stringify
            phase = str(m).strip()
            note = ""

        if not phase and not note:
            continue

        if phase and note:
            clauses.append(f"{phase} ({note})")
        elif phase:
            clauses.append(f"{phase}")
        elif note:
            # if phase missing but note exists, include note as a parenthetical clause
            clauses.append(f"({note})")

    if not clauses:
        return "unknown"

    # join with commas & final 'and' for natural English
    if len(clauses) == 1:
        joined = clauses[0]
    elif len(clauses) == 2:
        joined = f"{clauses[0]} and {clauses[1]}"
    else:
        joined = f"{', '.join(clauses[:-1])}, and {clauses[-1]}"

    return f"commonly introduced during {joined}"


def format_related_weaknesses(weaknesses) -> str:
    if not weaknesses:
        return "none"
    sentences = []
    for w in weaknesses:
        cwe = w.get("cwe_id", "")
        nature = w.get("nature", "")
        ordinal = w.get("ordinal", "")
        sentences.append(f"{cwe} ({nature}, {ordinal})")
    return ", ".join(sentences)


def format_observed_examples(examples) -> str:
    if not examples:
        return "no examples available"
    sentences = []
    for i, e in enumerate(examples, start=1):
        ref = e.get("reference", "")
        desc = e.get("description", "").strip()
        sentences.append(f"{i}. {ref}: {desc}")
    return "\n".join(sentences)

def format_common_consequences(consequences) -> str:
    if not consequences:
        return "No known consequences have been reported."

    # Parse JSON if necessary
    if isinstance(consequences, str):
        try:
            consequences = json.loads(consequences)
        except Exception:
            return consequences.strip()

    lines = []
    for i, item in enumerate(consequences, start=1):
        if isinstance(item, dict):
            note = item.get("note", "").strip()
            impact = item.get("impact", "").strip()
            scopes = ", ".join(item.get("scopes", []))

            # Build natural-language sentence
            sentence = f"{i}. {note}"
            if impact and scopes:
                sentence += f" This primarily impacts {scopes.lower()} through {impact.lower()}."
            elif impact:
                sentence += f" This results in {impact.lower()}."
            elif scopes:
                sentence += f" This affects {scopes.lower()}."
        else:
            sentence = f"{i}. {item}"
        lines.append(sentence)

    return "\n".join(lines)


def get_output_path(limit: int) -> str:
    return os.path.join(OUTPUT_DIR, f"filled_cwe_templates_{limit}.jsonl")


def fill_templates(limit: int = 5):
    # Load templates
    with open(TEMPLATE_PATH, "r") as f:
        templates = [json.loads(line) for line in f]

    # Fetch CWE data
    query = f"""
        SELECT cwe_id, name, description, extended_description,
               background_details, common_consequences,
               detection_methods, potential_mitigations,
               modes_of_introduction, related_weaknesses, observed_examples
        FROM cwe_weaknesses
        LIMIT {limit};
    """
    cwe_rows = run_query(query)

    filled_data = []

    for row in cwe_rows:
        (
            cwe_id, name, description, extended_description,
            background_details, common_consequences,
            detection_methods, potential_mitigations,
            modes_of_introduction, related_weaknesses, observed_examples
        ) = row

        # Format fields properly
        detection_methods_text = format_detection_methods(detection_methods)
        mitigations_text = format_mitigations(potential_mitigations)
        modes_text = format_modes(modes_of_introduction)
        weaknesses_text = format_related_weaknesses(related_weaknesses)
        examples_text = format_observed_examples(observed_examples)
        attack_patterns_text = get_capec_attack_patterns(cwe_id)
        background_details_text = format_background_details(background_details)
        common_consequences_text = format_common_consequences(common_consequences)

        for template in templates:
            output = template["output"].format(
                name=name or "",
                cwe_id=cwe_id or "",
                description=description or "",
                extended_description=extended_description or "",
                detection_methods=detection_methods_text,
                background_details=background_details_text,
                potential_mitigations=mitigations_text,
                common_consequences=common_consequences_text,
                modes_of_introduction=modes_text,
                related_weaknesses=weaknesses_text,
                related_attack_patterns=attack_patterns_text,
                observed_examples=examples_text
            )

            filled_data.append({
                "instruction": template["instruction"],
                "input": template["input"].format(name=name, cwe_id=cwe_id),
                "output": output
            })

    # Write output
    output_path = get_output_path(limit)
    with open(output_path, "w") as out:
        for entry in filled_data:
            json.dump(entry, out, ensure_ascii=False)
            out.write("\n")

    print(f"✅ Filled {len(filled_data)} templates saved to {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fill CWE templates")
    parser.add_argument("--limit", type=int, default=5, help="Number of CWEs to process")
    args = parser.parse_args()
    fill_templates(limit=args.limit)
