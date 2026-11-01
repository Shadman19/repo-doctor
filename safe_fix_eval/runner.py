"""Run the whole safe auto-fix benchmark and write the metrics report.

For every toy project:
  1. Scan requirements.txt against the frozen advisory snapshot.
  2. Run the project's tests on the ORIGINAL (vulnerable) pins, so we know the
     tests passed before any fix. A later failure is then a real regression.
  3. For each proposer (rule-based, mocked LLM), propose a bump for every
     vulnerable package and send it through the safety gates.
Then:
  4. Prompt-injection check: confirm that no text from requirements.txt
     comments ever appeared in a request sent to the (mocked) LLM.
  5. Count outcomes and write results.json plus a Markdown metrics table.

Every number in the report is computed here from these real runs.

Usage:
    python -m safe_fix_eval.runner
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from safe_fix_eval.advisories import AdvisoryDB, parse_requirements, render_requirements
from safe_fix_eval.gates import GATE_ORDER, evaluate_fix, run_project_tests
from safe_fix_eval.proposers import LLMProposer, RuleBasedProposer, scripted_benchmark_client

HERE = Path(__file__).parent
PROJECTS_DIR = HERE / "benchmark" / "projects"
RESULTS_JSON = HERE / "benchmark" / "results.json"
REPORT_MD = HERE / "benchmark" / "metrics.md"


def load_projects() -> list[dict]:
    projects = []
    for folder in sorted(p for p in PROJECTS_DIR.iterdir() if p.is_dir()):
        text = (folder / "requirements.txt").read_text()
        projects.append({"name": folder.name, "dir": folder, "requirements": text,
                         "pins": parse_requirements(text)})
    return projects


def comment_texts(requirements_text: str) -> list[str]:
    """All comment strings in a requirements file (used by the injection check)."""
    return [line.split("#", 1)[1].strip() for line in requirements_text.splitlines()
            if "#" in line and line.split("#", 1)[1].strip()]


def metrics(outcomes: list[dict], vulnerable_count: int) -> dict:
    decisions = Counter(o["decision"] for o in outcomes)
    rejections = {gate: decisions.get(f"rejected_at_{gate}", 0) for gate in GATE_ORDER[:-1]}
    safe = decisions.get("safe_to_auto_apply", 0)
    major = decisions.get("human_review_major_bump", 0)
    return {
        "vulnerable_dependencies": vulnerable_count,
        "safe_to_auto_apply": safe,
        "fix_success_rate": round(safe / vulnerable_count, 3) if vulnerable_count else 0.0,
        "rejections_per_gate": rejections,
        "regressions_caught": sum(1 for o in outcomes
                                  if o["decision"] == "rejected_at_c_tests_pass" and o["baseline_tests_passed"]),
        "routed_to_human_review_major_bump": major,
        "total_needing_a_human": vulnerable_count - safe,
    }


def run() -> dict:
    db = AdvisoryDB.load()
    projects = load_projects()

    # Steps 1 and 2: scan, and run the baseline tests once per project.
    for project in projects:
        project["scan"] = {pkg: ids for pkg, ids in db.scan(project["pins"]).items() if ids}
        passed, summary = run_project_tests(project["dir"], project["requirements"])
        project["baseline"] = {"passed": passed, "summary": summary}
        print(f"[baseline] {project['name']}: {'pass' if passed else 'FAIL'} ({summary})")

    # The mocked LLM's scripted answers start from the rule-based answers.
    rule = RuleBasedProposer(db)
    rule_answers = {}
    for project in projects:
        for pkg, ids in project["scan"].items():
            version = project["pins"][pkg]
            rule_answers[(pkg, version)] = rule.propose(pkg, version, ids)["new_version"]
    client = scripted_benchmark_client(rule_answers)
    proposers = [rule, LLMProposer(db, client)]

    # Step 3: propose and gate.
    runs = {}
    vulnerable_count = sum(len(p["scan"]) for p in projects)
    for proposer in proposers:
        outcomes = []
        for project in projects:
            for pkg, ids in project["scan"].items():
                proposal = proposer.propose(pkg, project["pins"][pkg], ids)
                outcome = evaluate_fix(db, project["dir"], project["requirements"], pkg, proposal)
                record = asdict(outcome)
                record.update(project=project["name"], original_advisories=sorted(ids),
                              baseline_tests_passed=project["baseline"]["passed"],
                              ignored_extra_keys=proposal.get("ignored_extra_keys", []))
                if outcome.decision == "safe_to_auto_apply":
                    record["patched_requirements"] = render_requirements(
                        project["requirements"], pkg, outcome.new_version)
                outcomes.append(record)
                print(f"[{proposer.name}] {project['name']}: {pkg} {outcome.old_version} -> "
                      f"{outcome.new_version}: {outcome.decision}")
        runs[proposer.name] = {"outcomes": outcomes, "metrics": metrics(outcomes, vulnerable_count)}

    # Step 4: prompt-injection check.
    sent_to_llm = json.dumps(client.requests)
    leaked = [c for p in projects for c in comment_texts(p["requirements"]) if c in sent_to_llm]
    injection_project = next(p for p in projects if p["name"] == "p12_prompt_injection")
    injection_outcomes = [o for r in runs.values() for o in r["outcomes"]
                          if o["project"] == injection_project["name"]]
    injection = {
        "llm_requests_checked": len(client.requests),
        "comment_strings_checked": sum(len(comment_texts(p["requirements"])) for p in projects),
        "comment_text_leaked_to_llm": leaked,
        "injection_project_outcomes": [
            {"proposer": o["proposer"], "package": o["package"], "new_version": o["new_version"],
             "decision": o["decision"],
             # Parse the patched file (comments dropped) and look for the injected package.
             "evil_helper_installed": "evil-helper" in parse_requirements(o.get("patched_requirements", ""))}
            for o in injection_outcomes
        ],
    }

    results = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "advisory_snapshot": {"source": db.snapshot["source"], "downloaded_at": db.snapshot["downloaded_at"]},
        "llm": "MOCKED Bedrock Converse client (ScriptedBedrockClient). No live Bedrock call was made.",
        "projects": [{"name": p["name"], "pins": p["pins"],
                      "vulnerable": {k: sorted(v) for k, v in p["scan"].items()},
                      "baseline_tests": p["baseline"]} for p in projects],
        "runs": runs,
        "prompt_injection_check": injection,
    }
    RESULTS_JSON.write_text(json.dumps(results, indent=2) + "\n")
    REPORT_MD.write_text(render_report(results))
    print(f"Wrote {RESULTS_JSON} and {REPORT_MD}")
    return results


def render_report(results: dict) -> str:
    rule = results["runs"]["rule-based"]["metrics"]
    llm = results["runs"]["llm-mocked"]["metrics"]
    lines = [
        "# Safe auto-fix evaluation: metrics from the latest run",
        "",
        f"Generated {results['generated_at']} by `python -m safe_fix_eval.runner`.",
        f"Advisory data: {results['advisory_snapshot']['source']}, downloaded "
        f"{results['advisory_snapshot']['downloaded_at']}.",
        "",
        "| Metric | Rule-based proposer | Mocked LLM (3 injected faults) |",
        "|---|---:|---:|",
        f"| Vulnerable dependencies | {rule['vulnerable_dependencies']} | {llm['vulnerable_dependencies']} |",
        f"| Safe to auto-apply | {rule['safe_to_auto_apply']} | {llm['safe_to_auto_apply']} |",
        f"| Fix success rate | {rule['fix_success_rate']:.3f} | {llm['fix_success_rate']:.3f} |",
    ]
    for gate in GATE_ORDER[:-1]:
        lines.append(f"| Rejected at {gate} | {rule['rejections_per_gate'][gate]} | "
                     f"{llm['rejections_per_gate'][gate]} |")
    lines += [
        f"| Regressions caught (tests passed before, failed after) | {rule['regressions_caught']} | "
        f"{llm['regressions_caught']} |",
        f"| Routed to human review (major bump) | {rule['routed_to_human_review_major_bump']} | "
        f"{llm['routed_to_human_review_major_bump']} |",
        f"| Total needing a human | {rule['total_needing_a_human']} | {llm['total_needing_a_human']} |",
        "",
        "## Per-fix decisions",
        "",
        "| Project | Package | From | Rule-based | Mocked LLM |",
        "|---|---|---|---|---|",
    ]
    llm_by_key = {(o["project"], o["package"]): o for o in results["runs"]["llm-mocked"]["outcomes"]}
    for o in results["runs"]["rule-based"]["outcomes"]:
        m = llm_by_key[(o["project"], o["package"])]
        lines.append(f"| {o['project']} | {o['package']} | {o['old_version']} | "
                     f"{o['new_version']}: {o['decision']} | {m['new_version']}: {m['decision']} |")
    inj = results["prompt_injection_check"]
    lines += [
        "",
        "## Prompt-injection check",
        "",
        f"- LLM requests inspected: {inj['llm_requests_checked']}",
        f"- Comment strings from requirements files checked: {inj['comment_strings_checked']}",
        f"- Comment text found in any LLM request: {len(inj['comment_text_leaked_to_llm'])}",
    ]
    for o in inj["injection_project_outcomes"]:
        lines.append(f"- p12 ({o['proposer']}): {o['package']} -> {o['new_version']}, {o['decision']}, "
                     f"evil-helper added: {o['evil_helper_installed']}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    run()
