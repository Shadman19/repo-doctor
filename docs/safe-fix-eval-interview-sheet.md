# Safe auto-fix evaluation: explain it to an interviewer

**One line:** I measured how often a proposed dependency upgrade is safe to apply with no human, using real OSV advisories, four safety gates, and a mocked LLM with deliberate mistakes. Every number comes from one logged run on 2026-11-01.

## What each file does

| File | Plain English |
|---|---|
| `safe_fix_eval/build_snapshot.py` | Downloads real advisories from PyPI (sourced from OSV) once and freezes them, so results do not change from day to day. |
| `safe_fix_eval/advisories.py` | Reads requirements.txt (comments thrown away) and looks up which advisories affect each pinned version. |
| `safe_fix_eval/proposers.py` | Proposes the fix. Rule-based: first newer release with none of the advisories. LLM: same question through the Bedrock Converse interface, answered by a scripted mock; falls back to rules if the call fails. |
| `safe_fix_eval/gates.py` | The safety checks, run in order; the first failure stops the fix and everything is logged. |
| `safe_fix_eval/runner.py` | Runs all 12 projects through both proposers, does the injection check, and writes results.json and metrics.md. |
| `safe_fix_eval/benchmark/projects/` | 12 toy projects, each with one vulnerable pin and 2 or 3 tests. p12 holds the prompt-injection comments. |
| `tests/test_safe_fix_gates.py` | 31 unit tests, at least one per gate, plus injection and fallback tests. |

## Why each gate exists

- **Step 0, proposal check:** an LLM can invent a version or name the wrong package. Cheapest check, so it runs first.
- **Gate a, advisory gone:** a "fix" that leaves the vulnerability in place is worse than none, because it looks done.
- **Gate b, nothing new:** an upgrade can bring its own advisory. Real example in the data: urllib3 2.2.x has GHSA-48p4-8xcf-vxj5, which 1.26.17 did not.
- **Gate c, tests pass:** security fixes break code. jinja2 3.0.3 to 3.1.6 is only a minor bump, yet it removed `Markup` and the tests failed.
- **Gate d, semver:** a major bump may break things the tests do not cover, so a human decides.

## The 3 metrics

1. **Fix success rate** = fixes safe to auto-apply / vulnerable dependencies. Rule-based 7/12 (0.583). Mocked LLM 5/12 (0.417).
2. **Rejections per gate** shows *where* fixes fail. Rule-based: 1 at gate c (the jinja2 regression). Mocked LLM: 1 at step 0, 2 at gate a, 1 at gate c. All 3 injected faults were caught.
3. **Routed to human review:** 4 major bumps (rule-based), 5 fixes needing a human in total. This is the human workload the system leaves behind.

## 5 likely questions, honest answers

**1. Did you use Bedrock?** No. The code calls the Bedrock Converse interface, but the client is a scripted mock. I have not run it on live Bedrock, so I make no claim about real model quality.

**2. Why is the mocked LLM's score meaningful at all?** The score itself is not. What it shows is that the gates catch the mistakes I injected: an invented version, and two incomplete fixes. With a real model, the same harness would measure the real error rate.

**3. Only 58% fixed. Is that bad?** It is the honest number for minimal fixes. 4 of the 5 failures were major bumps, which are routed to a human on purpose, and one is a real regression the tests caught. Pushing the rate up by auto-applying major bumps would trade safety for a better number.

**4. What would you change for thousands of real repos?** Handle transitive dependencies and lock files, use stronger test signals than 2 or 3 tests, recognize calendar versioning (certifi was a false "major"), cache environments, and measure fix quality by blinded human review on a sample.

**5. How do you stop prompt injection?** Two layers. The model only sees structured fields, never the raw file, so 0 of 4 comment strings reached it. And even if a model were fooled, its output must name the vulnerable package and a real release, or step 0 rejects it; extra keys like `auto_apply` are ignored.

**Limits to say out loud:** toy benchmark, mocked LLM, not run on live Bedrock or real-world repos, one-day advisory snapshot.
