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
    Format execution_flow so each step prints compactly as:
    Step <n> | Phase: <phase> | Techniques: <tech1>, <tech2>, ... | Description: <description>

    Accepts a list, or a JSON string representing a list.
    Handles small key typos like "ste p".
    """
    if not flow:
        return "None"

    # If flow is a JSON string, try to parse it
    if isinstance(flow, str):
        try:
            parsed = json.loads(flow)
            if isinstance(parsed, list):
                flow = parsed
        except Exception:
            return flow.strip()  # fallback to raw string

    lines = []
    for step_obj in (flow or []):
        # tolerate keys like "ste p" or "step"
        step_no = step_obj.get("step") if isinstance(step_obj, dict) else None
        if step_no is None:
            for k in ("ste p", "st ep", "stp", "s"):
                if isinstance(step_obj, dict) and k in step_obj:
                    step_no = step_obj.get(k)
                    break
        step_no = str(step_no).strip() if step_no is not None else ""

        phase = (step_obj.get("phase") if isinstance(step_obj, dict) else "") or ""
        phase = str(phase).strip()

        # techniques may be list or a single string
        techniques = step_obj.get("techniques") if isinstance(step_obj, dict) else None
        if isinstance(techniques, str):
            try:
                tparsed = json.loads(techniques)
                if isinstance(tparsed, list):
                    techniques = tparsed
            except Exception:
                techniques = [t.strip() for t in re.split(r'[\n;]+', techniques) if t.strip()]
        techniques = techniques or []

        desc = (step_obj.get("description") if isinstance(step_obj, dict) else "") or ""
        desc = " ".join(str(desc).split())  # remove line breaks, extra spaces

        tech_str = ", ".join(" ".join(str(t).split()) for t in techniques) if techniques else "None"

        # Compose single line per step
        step_line = f"Step {step_no}" if step_no else "Step"
        if phase:
            step_line += f" \nPhase: {phase}"
        step_line += f" \nTechniques: {tech_str}"
        step_line += f"\nDescription: {desc}"

        lines.append(step_line)

    return "\n".join(lines)


def format_prerequisites(prereqs) -> str:
    if not prereqs:
        return "None"
    return "\n".join(f"- {p}" for p in prereqs)


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
    return "".join(f"{m}" for m in mitigations)


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
    Format taxonomy_mappings into readable bullets.
    Accepts list of dicts or JSON string.
    """
    if not mappings:
        return "None found."

    # parse JSON string if needed
    if isinstance(mappings, str):
        try:
            mappings = json.loads(mappings)
        except Exception:
            return mappings.strip()

    lines = []
    for m in mappings:
        entry_id = m.get("entry_id", "").strip()
        entry_name = m.get("entry_name", "").strip()
        taxonomy_name = m.get("taxonomy_name", "").strip()
        lines.append(f"- ID: {entry_id}, Name: {entry_name}, Taxonomy: {taxonomy_name}")
    return "\n".join(lines)


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
