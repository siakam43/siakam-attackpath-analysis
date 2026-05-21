# Step 3: False-Positive Elimination

## Key Principle

**Better to miss some theoretical issues than flood the report with false positives.**

Every finding you confirm should be something a security engineer would confidently raise in a PR review.

## Operational Rules

- Do NOT run commands to reproduce findings.
- Do NOT use the Bash tool.
- You write the updated `_vuls.md` file directly. After writing, return a completion report to the main agent.

## Context Isolation

> Use ONLY the input files specified in this document. Do not rely on conclusions or judgments from previous analysis phases. Re-examine from first principles. You are seeing this finding for the first time.
>
> **Tool constraint:** All review work must be done by reading source code with Read tools and applying LLM reasoning. Do NOT write or execute scripts.

## Your Input

You receive ALL findings for one entry:
- The full `<uid>_vuls.md` file containing every finding for this entry, each in a `<!-- SECTION: finding -->` block with Step 2 identification (severity, confidence, category, description, exploitation scenario, remediation) and an empty `### Review (Step 3)` table.
- The full `<uid>_attack_path.md` file — the Phase 1 output with all attack paths, the complete Function Index, and per-function labels (source/active/pass-through/leaf).
- `PROJECT_DIR`: Absolute path to the project root, for locating source files.
- `EXCLUSIONS`: List of excluded files/directories.

You do NOT receive: other entries' findings or vuln files. This isolation prevents cross-entry bias.

**Reading source code for context:** For each finding, use Read tools to examine functions in its attack path chain. Start with the vulnerability function and its immediate caller. If the immediate caller does not provide enough context to verify reachability, data flow, or protective mechanisms, read the next caller up the chain. You may read up to the entry function if needed. Do NOT read functions outside the attack path chain.

## Your Task

Review every finding in the `<uid>_vuls.md` file. For each finding, apply the three-layer protocol below. Then write the updated `_vuls.md` file with all `### Review (Step 3)` tables filled in.

You may also identify that two or more findings share the same root cause. If so, merge them into a single finding (keeping the lowest finding number) and note the merge in the completion report.

### Layer 1: Hard Exclusion Rules

Check the finding against this list. If it matches ANY rule, return FALSE_POSITIVE immediately with the rule as the reason. Do not proceed to Layer 2.

**HARD EXCLUSIONS — Findings matching these are automatically false positives:**

1. **Denial of Service (DOS) or resource exhaustion WITHOUT memory corruption or an attacker-triggered crash/panic.** An attacker causing the system to hang, loop, or consume resources (CPU, memory, file descriptors) without corrupting memory, crashing the system, gaining control, or escalating privilege is NOT a vulnerability in this analysis. Pure resource exhaustion is an operational concern, not a security vulnerability.
   - **Explicitly NOT excluded — crashes and panics**: NULL pointer dereferences, double-frees, or kernel panics that are reachable from attacker-controlled input are NOT "just DoS." A reachable crash IS a security vulnerability regardless of what caused the NULL or bad state: memory corruption (UAF, heap overflow, double-free), logic bugs (stale state flag, missing NULL check after an operation that can fail), or any other mechanism. The crash is the security impact; memory corruption in the causal chain is an additional escalation path but is not required to confirm the finding.
   - **Explicitly NOT excluded — race conditions**: Race conditions or TOCTOU that lead to memory corruption or privilege escalation — even if the most likely outcome is a crash, the corruption path is the vulnerability.
2. **Secrets/credentials stored on disk**, if the disk/filesystem is otherwise secured by OS permissions or disk encryption.
3. **Rate limiting concerns or service overload scenarios.**
4. **Memory consumption or CPU exhaustion** without a concrete path to code execution or privilege escalation.
5. **Lack of input validation on non-security-critical fields** without proven security impact. For example: a debug print that logs an unvalidated string; a configuration value that only affects cosmetic behavior.
6. **Lack of hardening measures.** Code is not expected to implement every security best practice. Only flag concrete vulnerabilities, not missing defense-in-depth.
7. **Purely theoretical race conditions without a concrete exploitation path.** HOWEVER, DO report race conditions with: (a) a clear TOCTOU pattern with an exploitable window, (b) shared state accessed without synchronization in multi-threaded code, (c) a demonstrable data race with security impact.
8. **Vulnerabilities in outdated third-party libraries.** These are managed separately.
9. **Files that are unit tests or test-only code.** Do not include findings in test files.
10. **Log spoofing.** Outputting un-sanitized user input to logs is not a vulnerability.
11. **User-controlled content in AI system prompts** is not a vulnerability.
12. **Regex injection.** Injecting untrusted content into a regex is not a vulnerability.
13. **Insecure documentation.** Do not report findings in markdown files, comments, or docstrings.
14. **Lack of audit logs** is not a vulnerability.

### Layer 2: Context Re-Verification

For each check below, read the source code with fresh eyes. Do NOT rely on the Step 2 description — verify independently.

| Check | How to Verify | Result |
|-------|--------------|--------|
| **Reachability** | Is the call path from entry to this function real? Read each function in the chain (starting from the vulnerability function, moving up) and verify the call exists in the source. For direct calls: confirm the callee name appears in the caller's source. For indirect calls (function pointers): find the assignment (e.g., `ops->handler = &func`) and confirm it resolves to the callee. If you cannot find the call in the caller's source, that is a FAIL. | PASS / FAIL / UNCERTAIN |
| **Data-flow validity** | Does entry data really reach the vulnerable parameter or state? Read the source of functions in the attack path chain, tracing the data from entry parameters through assignments, struct fields, and function arguments. Do not assume Step 2 was correct. If the chain is deeper than 3 levels, trace at least 3 levels up from the vulnerability function. | PASS / FAIL / UNCERTAIN |
| **Protective mechanisms** | Are there bounds checks, lock acquisitions, permission checks, or NULL checks that protect the vulnerable operation? Check the vulnerability function AND its callers up the chain. A bounds check in any caller that sanitizes data before the call is valid protection — you must read far enough up the chain to confirm. | PASS / FAIL / UNCERTAIN |
| **Exploit condition realism** | Are the exploit preconditions actually satisfiable in the target's runtime environment? For example: can the attacker control the physical memory layout? Does the DMA buffer actually come from an external source? Is the race window genuinely exploitable (nanoseconds in kernel context vs. user-triggerable)? | PASS / FAIL / UNCERTAIN |
| **Compensating controls** | Do compiler mitigations (stack canary, ASLR, W^X, RELRO) or hardware protections (SMMU, MPU, TZASC, IOMMU) eliminate or significantly downgrade the vulnerability? Note: these do NOT make a vulnerability disappear, but they may lower severity from HIGH to MEDIUM or MEDIUM to LOW. | PASS / FAIL / UNCERTAIN |
| **Code misinterpretation** | Did Step 2 misunderstand the code semantics? Common misinterpretations: a variable that appears unvalidated was actually checked in an inline function or macro; a `void*` cast that Step 2 thought was type confusion is actually a known pattern; a "missing" check is actually performed by the hardware. | PASS / FAIL / UNCERTAIN |

**Decision matrix:**
- All PASS → Proceed to Layer 3.
- Any FAIL → Return FALSE_POSITIVE. State which check failed and why.
- Any UNCERTAIN, rest PASS → Keep the finding but lower confidence by 0.1. Proceed to Layer 3 (if confidence still ≥ 0.7).

### Layer 3: Independent Judgment

You have verified the technical facts. Now apply your security judgment.

1. **Read the finding description and exploitation scenario from Step 2.** Do you agree with the severity and confidence?
2. **Is this really exploitable?** Given everything you verified in Layer 2, could a real attacker (with realistic capabilities) exploit this? Or is this a "lab vulnerability" — interesting in theory but unreachable in practice?
3. **Would you raise this in a PR review?** If a colleague submitted this code, would you flag this specific issue? If not, it should not be in the final report.

**Return your verdict:**

- **CONFIRMED**: The vulnerability is real, reachable, and exploitable (or has clear security impact). Include your confidence (may be revised from Step 2).
- **FALSE_POSITIVE**: The vulnerability is not real, not reachable, or not exploitable. Include the specific reason and which Layer 2 check(s) failed.
- **DISPUTED**: You believe there is a vulnerability, but you disagree with Step 2's severity, confidence, categorization, or description. Include:
  - What you agree with
  - What you disagree with and why
  - Your recommended revision

## Writing the Updated Vuln File

After reviewing all findings, write the updated `<uid>_vuls.md`. For each finding, fill in the `### Review (Step 3)` table:

```
### Review (Step 3)
| Field | Value |
|-------|-------|
| Reviewed | yes |
| Result | CONFIRMED / FALSE_POSITIVE |
| Reviewer | <your sub-agent identifier> |
| Revised Confidence | <only if changed from Step 2, e.g. 0.85> |
| Exclusion Reason | <only if FALSE_POSITIVE: which rule or check failed> |
```

Also update the `## Summary` table with the final confirmed/false-positive counts.

## Completion Report

After writing the file, return a completion report in this format:

```
ENTRY: <entry_name>
FINDINGS REVIEWED: <N>

Finding-001: CONFIRMED
Finding-002: FALSE_POSITIVE (Layer 2 - Data-flow validity: entry data does not reach the vulnerable parameter)
Finding-003: CONFIRMED (confidence revised 0.90 → 0.80, compensating controls: IOMMU enabled)
Finding-004: DISPUTED (disagree with HIGH severity — requires physical access, should be MEDIUM)
...
MERGES: Finding-005 merged into Finding-002 (same root cause)
```

## Edge Cases

- **Finding references code in an excluded file**: If the vulnerability function's source file matches an EXCLUSION pattern, mark FALSE_POSITIVE. Reason: "File excluded by .siakamignore."
- **Source file cannot be found/read**: Mark DISPUTED. Reason: "Cannot verify — source file not accessible." The main agent will decide.
- **No findings to review**: If `_vuls.md` has zero findings, write the file unchanged and report `FINDINGS REVIEWED: 0`.
