# Step 3: False-Positive Elimination

## Key Principle

**Better to miss some theoretical issues than flood the report with false positives.**

Every finding you confirm should be something a security engineer would confidently raise in a PR review.

## Operational Rules

- Do NOT run commands to reproduce findings.
- Do NOT use the Bash tool.
- Do NOT write files. You are a reviewer. Return your verdict to the main agent.
- The main agent will update the `_vuls.md` files based on your verdict.

## Context Isolation

> Use ONLY the input files specified in this document. Do not rely on conclusions or judgments from previous analysis phases. Re-examine from first principles. You are seeing this finding for the first time.
>
> **Tool constraint:** All review work must be done by reading source code with Read tools and applying LLM reasoning. Do NOT write or execute scripts.

## Your Input

You receive exactly ONE finding to review:
- The finding's `<!-- SECTION: finding -->` block from `<uid>_vuls.md` (containing the Step 2 identification, severity, confidence, description, code snippet)
- The vulnerability function's complete source code (read fresh from `<PROJECT_DIR>/<file>`)
- The immediate caller's source code (the function that calls the vulnerability function in the attack path)

You do NOT receive: other findings from the same entry, the attack_path.md file, or any Phase 1 data. This isolation prevents pattern bias.

## Your Task

Apply the three-layer protocol below. Return one of: CONFIRMED, FALSE_POSITIVE (with reason), or DISPUTED (with reason).

### Layer 1: Hard Exclusion Rules

Check the finding against this list. If it matches ANY rule, return FALSE_POSITIVE immediately with the rule as the reason. Do not proceed to Layer 2.

**HARD EXCLUSIONS — Findings matching these are automatically false positives:**

1. **Denial of Service (DOS) or resource exhaustion.** An attacker causing the system to hang, loop, or consume resources without gaining control or escalating privilege is NOT a vulnerability in this analysis.
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
| **Reachability** | Is the call path from entry to this function real? Can you trace the exact sequence of calls? If any step uses an indirect call (function pointer), has the pointer assignment been confirmed in the source? | PASS / FAIL / UNCERTAIN |
| **Data-flow validity** | Does entry data really reach the vulnerable parameter or state? Trace independently — follow the data from entry parameters through assignments, struct fields, and function arguments. Do not assume Step 2 was correct. | PASS / FAIL / UNCERTAIN |
| **Protective mechanisms** | Are there bounds checks, lock acquisitions, permission checks, or NULL checks that protect the vulnerable operation? Check the vulnerability function AND its callers. A check in the caller that sanitizes data before the call is still valid protection. | PASS / FAIL / UNCERTAIN |
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

## Verdict Format

Return your verdict in this exact format:

```
VERDICT: <CONFIRMED | FALSE_POSITIVE | DISPUTED>

REASON: <If FALSE_POSITIVE: state which check failed and why. If DISPUTED: state what you disagree with. If CONFIRMED: brief confirmation.>

REVISED_CONFIDENCE: <Only if different from Step 2. Use 0.XX format.>

LAYER_1_RESULT: <PASS | FAIL - rule name>
LAYER_2_RESULTS:
  - Reachability: <PASS | FAIL | UNCERTAIN>
  - Data-flow validity: <PASS | FAIL | UNCERTAIN>
  - Protective mechanisms: <PASS | FAIL | UNCERTAIN>
  - Exploit condition realism: <PASS | FAIL | UNCERTAIN>
  - Compensating controls: <PASS | FAIL | UNCERTAIN>
  - Code misinterpretation: <PASS | FAIL | UNCERTAIN>
```

## Edge Cases

- **Finding references code in an excluded file**: If the vulnerability function's source file matches an EXCLUSION pattern, return FALSE_POSITIVE. Reason: "File excluded by .siakamignore."
- **Source file cannot be found/read**: Return DISPUTED. Reason: "Cannot verify — source file not accessible." The main agent will decide.
