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
    Convert execution flow into sentence form for readability.
    """
    if not flow:
        return "None"

    # Parse JSON string if needed
    if isinstance(flow, str):
        try:
            parsed = json.loads(flow)
            if isinstance(parsed, list):
                flow = parsed
        except Exception:
            return flow.strip()

    sentences = []
    for step_obj in (flow or []):
        step_no = step_obj.get("step") or step_obj.get("ste p") or ""
        phase = step_obj.get("phase") or ""
        techniques = step_obj.get("techniques") or []
        desc = step_obj.get("description") or ""

        if isinstance(techniques, list):
            tech_str = ", ".join(techniques)
        else:
            tech_str = str(techniques)

        sentence = f"Step {step_no}: During the {phase} phase, the attacker uses {tech_str}. Description: {desc}."
        sentences.append(sentence)

    return " ".join(sentences)



def format_prerequisites(prereqs) -> str:
    if not prereqs:
        return "None"
    return " ".join(f"- {p}" for p in prereqs)


def format_skills(skills) -> str:
    if not skills:
        return "None"
    lines = []
    for s in skills:
        level = s.get("level", "")
        desc = s.get("description", "")
        lines.append(f"- {level}: {desc}")
    return "\n".join(lines)


def format_resources(resources) -> str:
    if not resources:
        return "None"
    return "\n".join(f"- {r}" for r in resources)


def format_consequences(cons) -> str:
    if not cons:
        return "None"
    lines = []
    for c in cons:
        impact = c.get("impact", "")
        scopes = ", ".join(c.get("scopes", []))
        if impact and scopes:
            lines.append(f"{impact} impact on {scopes}")
        elif impact:
            lines.append(f"{impact} impact")
        elif scopes:
            lines.append(f"Affecting: {scopes}")
    return "; ".join(lines)


def format_mitigations(mitigations) -> str:
    if not mitigations:
        return "No mitigations found"
    return " ".join(f"{m}" for m in mitigations)


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
