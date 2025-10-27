import json
import os
import re
from typing import Any
from query_postgre import run_query

TEMPLATE_PATH = "templates/IFT_CAPEC.jsonl"
OUTPUT_DIR = "filled_templates"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def format_execution_flow(flow: Any) -> str:
    """
    Convert execution flow into multi-line, bulleted step form for readability.
    """
    if not flow:
        return "None"

    # If flow is a JSON string, try to parse it to a list
    if isinstance(flow, str):
        try:
            parsed = json.loads(flow)
            if isinstance(parsed, list):
                flow = parsed
        except Exception:
            # return stripped string (single-line) as fallback
            return flow.strip()

    blocks = []
    for step_obj in (flow or []):
        step_no = step_obj.get("step") or step_obj.get("ste p") or ""
        phase = step_obj.get("phase") or ""
        techniques = step_obj.get("techniques") or []
        desc = (step_obj.get("description") or "").strip()

        # Normalize techniques into a list
        if isinstance(techniques, str):
            # attempt to split comma/semicolon separated strings
            techs = [t.strip() for t in re.split(r"[;,]\s*", techniques) if t.strip()]
        elif isinstance(techniques, list):
            techs = [str(t).strip() for t in techniques if t is not None and str(t).strip()]
        else:
            techs = [str(techniques).strip()] if techniques else []

        # Build step header
        header = f"Step {step_no}: During the {phase} phase, the attacker uses:"
        # Build bullets for techniques/resources used
        if techs:
            tech_lines = "\n".join(f"- {t}" for t in techs)
        else:
            tech_lines = "- (no specific techniques listed)"

        # Description line (single paragraph)
        desc_line = f"Description: {desc}" if desc else "Description: None."

        # Combine with a blank line at end of step block
        block = f"{header}\n{tech_lines}\n{desc_line}"
        blocks.append(block)

    # Join steps with a blank line between them
    return "\n".join(blocks)

def format_prerequisites(prereqs) -> str:
    """Return prerequisites as one bullet per line."""
    if not prereqs:
        return "- None"
    # if prereqs is a JSON string, try to parse
    if isinstance(prereqs, str):
        try:
            parsed = json.loads(prereqs)
            if isinstance(parsed, list):
                prereqs = parsed
        except Exception:
            # fallback: split by newline or semicolon or comma
            prereqs = [p.strip() for p in re.split(r"[\n;,]\s*", prereqs) if p.strip()]
    return "\n".join(f"- {p}" for p in prereqs)


def format_skills(skills) -> str:
    """Return skills as one bullet per line with level and description."""
    if not skills:
        return "- None"
    # accept list of dicts or JSON string
    if isinstance(skills, str):
        try:
            parsed = json.loads(skills)
            if isinstance(parsed, list):
                skills = parsed
        except Exception:
            # fallback: treat as single-line description
            return f"- {skills.strip()}"
    lines = []
    for s in skills:
        # s might be a dict or a string
        if isinstance(s, dict):
            level = s.get("level", "").strip()
            desc = s.get("description", "").strip()
            if level and desc:
                lines.append(f"- {level}: {desc}")
            elif desc:
                lines.append(f"- {desc}")
            elif level:
                lines.append(f"- {level}")
        else:
            lines.append(f"- {str(s).strip()}")
    return "\n".join(lines)


def format_resources(resources) -> str:
    """Return resources as bullets."""
    if not resources:
        return "- None"
    if isinstance(resources, str):
        try:
            parsed = json.loads(resources)
            if isinstance(parsed, list):
                resources = parsed
        except Exception:
            resources = [r.strip() for r in re.split(r"[\n;,]\s*", resources) if r.strip()]
    return "\n".join(f"- {r}" for r in resources)


def format_consequences(cons) -> str:
    if not cons:
        return "None"

    lines = []
    for c in cons:
        impact = c.get("impact", "").strip()
        scopes = c.get("scopes", [])
        if scopes:
            scope_str = ", ".join(scopes)
            lines.append(f"- {impact} impacts {scope_str}.")
        elif impact:
            lines.append(f"- {impact} impact.")

    return "\n".join(lines)


def format_mitigations(mitigations) -> str:
    if not mitigations:
        return "No mitigations found"
    return "\n".join(f"{m}" for m in mitigations)


def format_examples(examples) -> str:
    if not examples:
        return "No examples available"
    return "\n".join(f"- {e}" for e in examples)


def format_related_weaknesses(weaknesses) -> str:
    if not weaknesses:
        return "No related weaknesses found"
    return ", ".join(weaknesses)


def format_taxonomy_mappings(mappings) -> str:
    """
    Format taxonomy_mappings into a single readable sentence.
    Accepts list of dicts or JSON string.
    Example output:
    'the taxonomy entry "Hijack Execution Flow: ServicesFile Permissions Weakness" (ID: 1574.010, Taxonomy: ATTACK)'
    """
    if not mappings:
        return "None"

    # parse JSON string if needed
    if isinstance(mappings, str):
        try:
            mappings = json.loads(mappings)
        except Exception:
            return mappings.strip()

    formatted = []
    for m in mappings:
        entry_id = m.get("entry_id", "").strip()
        entry_name = m.get("entry_name", "").strip()
        taxonomy_name = m.get("taxonomy_name", "").strip()
        if entry_name or entry_id or taxonomy_name:
            formatted.append(f'"{entry_name}" (ID: {entry_id}, Taxonomy: {taxonomy_name})')

    if not formatted:
        return "None"

    # join multiple entries with commas and 'and' before the last one
    if len(formatted) == 1:
        return f'the taxonomy entry {formatted[0]}'
    else:
        return f'the taxonomy entries {", ".join(formatted[:-1])}, and {formatted[-1]}'


def get_output_path(limit: int) -> str:
    return os.path.join(OUTPUT_DIR, f"filled_capec_templates_{limit}.jsonl")


def fill_capec_templates(limit: int = 5):
    # Load templates
    with open(TEMPLATE_PATH, "r") as f:
        templates = [json.loads(line) for line in f]

    # Fetch CAPEC data from PostgreSQL
    query = f"""
        SELECT capec_id, name, description, abstraction, status,
               typical_severity, likelihood_of_attack,
               execution_flow, prerequisites, skills_required,
               resources_required, consequences, mitigations,
               example_instances, related_weaknesses, taxonomy_mappings
        FROM capec_patterns
        LIMIT {limit};
    """
    capec_rows = run_query(query)
    filled_data = []

    for row in capec_rows:
        (
            capec_id, name, description, abstraction, status,
            typical_severity, likelihood_of_attack,
            execution_flow, prerequisites, skills_required,
            resources_required, consequences, mitigations,
            example_instances, related_weaknesses, taxonomy_mappings
        ) = row

        # Format fields
        execution_flow_text = format_execution_flow(execution_flow)
        prerequisites_text = format_prerequisites(prerequisites)
        skills_text = format_skills(skills_required)
        resources_text = format_resources(resources_required)
        consequences_text = format_consequences(consequences)
        mitigations_text = format_mitigations(mitigations)
        examples_text = format_examples(example_instances)
        weaknesses_text = format_related_weaknesses(related_weaknesses)
        taxonomy_text = format_taxonomy_mappings(taxonomy_mappings)

        for template in templates:
            output = template["output"].format(
                name=name or "",
                capec_id=capec_id or "",
                description=description or "",
                abstraction=abstraction or "",
                status=status or "",
                typical_severity=typical_severity or "",
                likelihood_of_attack=likelihood_of_attack or "",
                execution_flow=execution_flow_text,
                prerequisites=prerequisites_text,
                skills_required=skills_text,
                resources_required=resources_text,
                consequence=consequences_text,
                mitigations=mitigations_text,
                example_instances=examples_text,
                related_weaknesses=weaknesses_text,
                taxonomy_mappings=taxonomy_text
            )

            filled_data.append({
                "instruction": template["instruction"],
                "input": template["input"].format(name=name, capec_id=capec_id),
                "output": output
            })

    # Write output
    output_path = get_output_path(limit)
    with open(output_path, "w") as out:
        for entry in filled_data:
            json.dump(entry, out, ensure_ascii=False)
            out.write("\n")

    print(f"✅ Filled {len(filled_data)} CAPEC templates saved to {output_path}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Fill CAPEC templates")
    parser.add_argument("--limit", type=int, default=5, help="Number of CAPEC rows to process")
    args = parser.parse_args()
    fill_capec_templates(limit=args.limit)
