---
name: siakam-attackpath-analysis
description: Use when analyzing C codebases (Linux kernel drivers, boot chain firmware, mobile co-processor firmware) for security vulnerabilities from externally-exposed entry functions
---

# siakam-attackpath-analysis

Analyze C codebases for attack paths and security vulnerabilities.

## Usage

```
/siakam-attackpath-analysis <project_dir>
```

- `project_dir` defaults to the current working directory if omitted.
- Reads `.siakamignore` (same syntax as `.gitignore`) to exclude files/directories.

## Configurable Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `MAX_CALL_DEPTH` | 10 | Maximum nodes in an attack path (entry to leaf) |
| `MAX_INFECTED_FUNCTIONS` | 50 | Maximum infected functions per entry before truncation |
| `PHASE1_TIMEOUT_MS` | 600000 | Max time (ms) for one Phase 1 sub-agent (call graph + data flow) |
| `PHASE2_TIMEOUT_MS` | 600000 | Max time (ms) for one Phase 2 sub-agent (vulnerability analysis) |
| `PHASE3_TIMEOUT_MS` | 240000 | Max time (ms) for one Phase 3 reviewer (single finding review) |

To change a parameter, edit the value in this file and in `steps/step1_attack_path.md`.

## Terminology

| Term | Definition |
|------|------------|
| Entry | An externally-exposed function listed in `apis.json` that can receive attacker-controlled data |
| Infected function | A function whose parameters can be traced back to an entry's external input |
| Attack path | A root-to-leaf chain of infected functions in the pruned call graph |
| Pruned attack graph | The call graph filtered to only infected nodes and their edges |
| Leaf node | An infected function with no infected callees; data flow terminus |
| Finding | A potential vulnerability discovered in Phase 2, pending Phase 3 review |
| CONFIRMED | Finding verified as a real vulnerability after Phase 3 review |
| FALSE_POSITIVE | Finding determined to be non-exploitable after Phase 3 review |

## Constraints

**All analysis MUST be performed by LLM reasoning alone.** You and your sub-agents read source code using codebase exploration tools (Read, Grep, Glob) and analyze it through reasoning. Do NOT write, generate, or execute any scripts or code to assist analysis.

**No exceptions:**
- Do NOT write Python/Shell/Perl scripts to parse C code or extract information
- Do NOT use Bash to run grep/awk/sed pipelines as analysis shortcuts — use the Read and Grep tools instead
- Do NOT generate helper programs to automate reasoning steps
- The ONLY permitted executable is `tools/cg_helper.py` for Phase 1 callgraph queries. Locate it at `<skill_root>/tools/cg_helper.py` where `<skill_root>` is the directory containing this SKILL.md file. Always invoke it with the explicit `--callgraph-path` flag pointing to `<PROJECT_DIR>/.siakam_out/callgraph.json`.

**Violating this rule means the analysis is invalid.** The skill's value comes from LLM judgment applied to source code, not from automated tooling.

## Execution Instructions

You are the orchestrator. Follow these steps in order. Do not skip, reorder, or deviate.

### Phase 0: Initialization

1. **Parse the project directory.**
   - If the user provided a path argument, use it as `PROJECT_DIR`.
   - Otherwise, use the current working directory as `PROJECT_DIR`.
   - Resolve `PROJECT_DIR` to an absolute path.

2. **Read exclusion patterns.**
   - If `<PROJECT_DIR>/.siakamignore` exists, read it. Apply the same exclusion rules as `.gitignore`: excluded files and directories are skipped entirely — do not read them, do not analyze them, and exclude any functions from excluded files that appear in callgraph.json edges.
   - If the file does not exist, no exclusions apply.

3. **Verify apis.json.**
   - Check if `<PROJECT_DIR>/.siakam_out/SII/apis.json` exists.
   - If it does NOT exist, tell the user: "apis.json not found at `<PROJECT_DIR>/.siakam_out/SII/apis.json`. Please specify the path to apis.json." Wait for the user to provide a path. If they cannot, abort.
   - If it exists, read it. If the `interfaces` array is empty, warn: "No entry functions found in apis.json. Check SII analysis results." and exit.
   - Ignore the `failures`, `errors`, and `warnings` fields — they are informational only.

4. **Check for callgraph.json.**
   - Check if `<PROJECT_DIR>/.siakam_out/callgraph.json` exists.
   - If it exists, set `HAS_CALLGRAPH = true`. (The skill does not generate callgraph.json — it is pre-built by external Siakam framework modules.)
   - If it does not exist, set `HAS_CALLGRAPH = false`.

5. **Determine entry list and file naming.**
   - Extract all entries from `apis.json` `interfaces` array.
   - For each entry, compute the `<uid>`:
     - Default: `<entry.name>`
     - If duplicate names exist across different files: `<entry.name>_<source_file_basename>`
     - If still duplicate (same file, different lines): `<entry.name>_<source_file_basename>_<line>`
   - The identity string for cross-references is `<entry.name> @ <entry.file>:<entry.line>`.

6. **Initialize output directories and task tracker.**
   - Create `<PROJECT_DIR>/.siakam_out/SAA/attack_path/`
   - Create `<PROJECT_DIR>/.siakam_out/SAA/vulns/`
   - Create the task tracker at `<PROJECT_DIR>/.siakam_out/SAA/tasks.md`:

```markdown
# Task Tracker
**Project**: <PROJECT_DIR>
**Started**: <current timestamp>
**Last Updated**: <current timestamp>

## Phase 1: Attack Path Identification
- [ ] <uid_1> @ <file>:<line>
- [ ] <uid_2> @ <file>:<line>
...

## Phase 2: Vulnerability Discovery
- [ ] <uid_1> @ <file>:<line>
- [ ] <uid_2> @ <file>:<line>
...

## Phase 3: False-Positive Elimination
(to be populated after Phase 2)
```

7. **Check for resume.**
   - If `tasks.md` already existed before you created it (from a previous interrupted run):
     - Read it. Identify tasks marked `[x]` as complete.
     - Verify that the corresponding output files exist on disk. If a task is marked `[x]` but the output file is missing, mark it as `[ ]` and re-run it.
     - Skip completed tasks in subsequent phases.
     - Keep the existing `Started` timestamp, update `Last Updated`.

### Phase 1: Attack Path Identification

1. **Read the step document.**
   - Read `steps/step1_attack_path.md` in full. Follow its instructions exactly.

2. **Launch parallel sub-agents (timeout: PHASE1_TIMEOUT_MS ms each).**
   - Determine `CG_HELPER_PATH`: the absolute path to `tools/cg_helper.py`. This file is located at `<skill_root>/tools/cg_helper.py` where `<skill_root>` is the directory containing this SKILL.md file.
   - For each entry in the task tracker that is NOT marked `[x]`:
     - Dispatch a sub-agent with the prompt from `step1_attack_path.md`. Set its timeout to `PHASE1_TIMEOUT_MS` ms.
     - The sub-agent receives: `ENTRY_NAME`, `ENTRY_FILE`, `ENTRY_LINE`, `PROJECT_DIR`, `HAS_CALLGRAPH`, `MAX_CALL_DEPTH`, `MAX_INFECTED_FUNCTIONS`, `EXCLUSIONS`, and `CG_HELPER_PATH`.
     - The sub-agent writes its output to `<PROJECT_DIR>/.siakam_out/SAA/attack_path/<uid>_attack_path.md`.
   - Launched sub-agents run concurrently.

3. **Monitor and track.**
   - As each sub-agent completes successfully, mark its task `[x]` in tasks.md and update `Last Updated`.
   - If a sub-agent fails, classify the failure:
     - **Timeout**: Mark `FAILED (timeout)` in tasks.md. The sub-agent exceeded `PHASE1_TIMEOUT_MS` ms.
     - **Malformed output**: Mark `FAILED (malformed)` in tasks.md. The output file is missing, empty, or does not match the required format.
     - **Error**: Mark `FAILED (error)` with the error message.

4. **Retry failures.**
   - After all sub-agents complete, collect all FAILED entries.
   - For timeout failures: retry once with `PHASE1_TIMEOUT_MS * 1.5` ms (extended timeout) and a fresh sub-agent. The first run may have timed out due to an unusually large call graph.
   - For malformed/error failures: retry once with the same timeout and a fresh sub-agent.
   - If the retry succeeds, mark it `[x]`. If it fails again, mark it `FAILED (retry exhausted)` and record the entry with its failure reason in a failures manifest string for the final report.

5. **Gate check.**
   - If ALL entries failed, skip to Phase 4 (Consolidation) — generate a report with only failed entries.
   - Otherwise, proceed to Phase 2.

### Phase 2: Vulnerability Discovery

1. **Read the step document.**
   - Read `steps/step2_vuln_analysis.md` in full. Follow its instructions exactly.

2. **Determine sub-agent grouping.**
   - For each entry with a successful Phase 1 output:
     - Read its `<uid>_attack_path.md` and check the `## Function Index`.
     - If the entry has 10 or fewer attack paths: assign the entire entry to one sub-agent.
     - If the entry has more than 10 attack paths: group the infected functions (from the Function Index) into groups of roughly equal size, each group to one sub-agent. Group by function, not by path, to avoid multi-agent re-analysis of the same function.
   - Update tasks.md Phase 2 section with the assigned tasks (one per sub-agent assignment).

3. **Instruct sub-agents to write partial results on exhaustion.**
   - Tell each Phase 2 sub-agent: if you are running out of capacity (token limit, timeout approaching) before completing all assigned functions, write your output file immediately with what you have:
     - Add `<!-- STATUS: partial -->` below the header.
     - In the Summary table, note `Functions analyzed: <N> of <M> (partial)`.
     - List unanalyzed functions under a `## Unanalyzed Functions` section so the main agent can reassign them.
   - Full output (all functions analyzed) uses `<!-- STATUS: complete -->`.

4. **Launch parallel sub-agents (timeout: PHASE2_TIMEOUT_MS ms each).**
   - For each assignment, dispatch a sub-agent with the prompt from `step2_vuln_analysis.md`. Set its timeout to `PHASE2_TIMEOUT_MS` ms.
   - The sub-agent receives: the assignment (entry or function group), the attack_path.md file(s), PROJECT_DIR, and the exclusion list.
   - The sub-agent writes its output to `<PROJECT_DIR>/.siakam_out/SAA/vulns/<uid>_vuls.md`. If the entry was split into groups, use group identifiers: `<uid>_group_<N>_vuls.md`.

5. **Monitor, track, and retry.**
   - For each completing sub-agent, check the output file's status marker (`<!-- STATUS: complete -->` or `<!-- STATUS: partial -->`).
   - **Format validation** (before marking success): verify that each `_vuls.md` file contains:
     - `<!-- SECTION: finding -->` markers wrapping each finding
     - `## Finding-001:` format (NOT `VULN-N` or other schemes)
     - `### Review (Step 3)` tables with `*to be filled in Step 3*` in ALL value fields
   - If any format check fails, mark the output `FAILED (malformed)` — do NOT accept it.
   - Mark `[x]` on success (complete + format-valid), `PARTIAL` on partial output, `FAILED` with classification (`timeout`, `malformed`, `format-violation`, `error`) on failure.
   - For partial outputs: collect the unanalyzed functions from `## Unanalyzed Functions` and launch a new sub-agent with `PHASE2_TIMEOUT_MS` ms to cover them (smaller assignment, should complete faster).
   - For total failures: classify and retry once. Timeout failures get `PHASE2_TIMEOUT_MS * 1.5` ms extended timeout. If the retry also fails, mark `FAILED (retry exhausted)`.
   - Record exhausted failures in a failures manifest string for the final report.

6. **Merge split outputs (if any).**
   - If an entry's findings were split across multiple group files (some complete, some partial, some failed), merge the complete and partial outputs into a single `<uid>_vuls.md`. The merge concatenates findings from all groups and renumbers them sequentially.
   - If any group produced partial output that still has unanalyzed functions after retry, note them under a `## Gaps` section in the merged file:
     ```markdown
     ## Gaps
     | Function | File:Line | Reason |
     |----------|-----------|--------|
     | func_x   | src/x.c:10 | Group 2 sub-agent exhausted; analysis incomplete |
     ```
   - If any group failed entirely, note all its assigned functions in the Gaps section.
   - Do NOT merge files from different entries — only same-entry group files.

7. **Gate check.**
   - If ALL Phase 2 tasks failed, skip to Phase 4 with whatever data exists.
   - Otherwise, populate the Phase 3 section of tasks.md with all findings from all successful and partial `<uid>_vuls.md` files. Do NOT create Phase 3 tasks for findings from the Gaps section.

### Phase 3: False-Positive Elimination

1. **Read the step document.**
   - Read `steps/step3_false_positive.md` in full. Follow its instructions exactly.

2. **Assign reviewers.**
   - For each finding across all `<uid>_vuls.md` files, assign it to exactly one reviewer sub-agent.
   - **Constraint**: No sub-agent may review a finding it discovered. Track which sub-agent discovered each finding (recorded in the finding's metadata). Assign reviewers such that discoverer != reviewer.
   - Update tasks.md Phase 3 section with the assignments.

3. **Launch parallel sub-agents (timeout: PHASE3_TIMEOUT_MS ms each).**
   - For each finding, dispatch a reviewer sub-agent with the prompt from `step3_false_positive.md`. Set its timeout to `PHASE3_TIMEOUT_MS` ms.
   - The reviewer receives:
     - The individual finding context (the `<!-- SECTION: finding -->` block from the vuln report).
     - The attack path chain with edge annotations: the sequence of functions from entry to vulnerability function, with file:line and edge type/confidence between hops (e.g., `entry @ src/a.c:10 → [direct] mid @ src/b.c:20 → [indirect, confidence: high] vuln @ src/c.c:30`). No Step 1/2 analysis — bare chain + edge metadata only.
     - `PROJECT_DIR` and `EXCLUSIONS` for locating source files.
   - The reviewer reads source code themselves using Read tools, starting with the vulnerability function and immediate caller. They may read any function in the attack path chain for context (up to the entry). Do NOT send pre-read source code — let the reviewer read fresh.
   - The reviewer returns: CONFIRMED / FALSE_POSITIVE (with reason) / DISPUTED (with reason).
   - Reviewers do NOT write files. They return their verdict to you (the main agent).

4. **Collect and apply reviews.**
   - Each `_vuls.md` file may have findings from multiple reviewers. Since reviewers return verdicts asynchronously, apply each verdict one at a time:
     1. **Re-read** the current `<uid>_vuls.md` file to get its exact state including any prior review updates already applied.
     2. Locate the matching `<!-- SECTION: finding -->` block by finding number (`Finding-XXX`).
     3. Verify the finding block has `Reviewed` → `no` (not yet reviewed). If already reviewed, skip — this is a duplicate verdict.
     4. Update the `### Review (Step 3)` block. **Critical: when using the Edit tool, the old_string MUST include the finding's header line** (e.g., `## Finding-001: Buffer Overflow in WRITE ioctl...`) to guarantee the match is unique. Never use a generic string like `Reviewed | *to be filled in Step 3*` alone — it matches all unreviewed findings and will create duplicates.
        - `Reviewed` → yes
        - `Result` → CONFIRMED / FALSE_POSITIVE
        - `Reviewer` → sub-agent identifier
        - `Revised Confidence` → only if the reviewer changed the confidence score
        - `Exclusion Reason` → only if FALSE_POSITIVE
     5. Update the per-file `## Summary` table with the new confirmed/false-positive counts.
     6. Write the file and mark the task `[x]` in tasks.md.
   - This read-verify-update-write cycle prevents stale overwrites when multiple verdicts target the same file.

5. **Resolve DISPUTED findings.**
   - For any finding where the reviewer returned DISPUTED, you (the main agent) make the final call.
   - Read the finding, the original analysis, and the reviewer's dispute reason. Decide CONFIRMED or FALSE_POSITIVE.
   - Update the finding's Review block accordingly.

6. **Retry failures.**
   - For any reviewer that failed, classify the failure (timeout, malformed verdict, error).
   - Timeout failures: retry once with a different sub-agent and `PHASE3_TIMEOUT_MS * 1.5` ms extended timeout.
   - Other failures: retry once with a different sub-agent using the same `PHASE3_TIMEOUT_MS` ms.
   - If still failing, leave the finding as unreviewed (`Reviewed` → no) and record it in the failures manifest with the failure reason.

### Phase 4: Consolidation

1. **Scan all `<uid>_vuls.md` files.**
   - **Deduplication check**: Scan for duplicate finding numbers within each `_vuls.md` file and across files. If `Finding-XXX` appears more than once in the same file, keep only the first occurrence (the one closest to the file top) and discard later duplicates. If duplicates differ in their Review verdict, use the first occurrence's verdict. Count discarded duplicates separately — report them in a `## Data Integrity Notes` section of Vul_report.md:
     ```markdown
     ## Data Integrity Notes
     | File | Finding | Issue | Resolution |
     |------|---------|-------|------------|
     | driver_ioctl_vuls.md | Finding-005 | Duplicate finding (2 occurrences) | Kept first occurrence (FALSE_POSITIVE); discarded duplicate (CONFIRMED) |
     ```
   - Extract every finding with `Result: CONFIRMED`.
   - Also identify findings where `Reviewed` is still `no` (reviewer failed, verdict never applied). Flag these as **unreviewed** — do NOT include them in confirmed vulnerabilities. List them in the `## Unreviewed Findings` section of Vul_report.md.
   - Count total unreviewed findings and report them in the Summary table.

2. **Compile `Vul_report.md`.**
   - Write to `<PROJECT_DIR>/.siakam_out/SAA/Vul_report.md`:

```markdown
<!-- SECTION: header -->
# Vulnerability Report: <project_name>
**Analysis Date**: <YYYY-MM-DD>
**Project**: <PROJECT_DIR>
<!-- /SECTION: header -->

<!-- SECTION: summary -->
## Summary
| Metric | Count |
|--------|-------|
| Entries analyzed | <N_success> |
| Entries failed | <N_failed> |
| Entries with gaps | <N_gaps> |
| Confirmed vulnerabilities | <N_confirmed> |
| HIGH / MEDIUM / LOW | <H> / <M> / <L> |
| Unreviewed findings | <N_unreviewed> |

### By Category
| Category | HIGH | MEDIUM | LOW | Total |
|----------|------|--------|-----|-------|
| A. Input Validation | <count> | <count> | <count> | <total> |
| B. Memory Safety | <count> | <count> | <count> | <total> |
| C. System Security | <count> | <count> | <count> | <total> |
| D. Cryptographic | <count> | <count> | <count> | <total> |
| E. Firmware/Embedded | <count> | <count> | <count> | <total> |
| F. Concurrency | <count> | <count> | <count> | <total> |
<!-- /SECTION: summary -->

<!-- SECTION: failures -->
## Failed Entries
(Only include if there are failures)
| Entry | Reason |
|-------|--------|
| <entry> @ <file>:<line> | <failure reason> |
<!-- /SECTION: failures -->

<!-- SECTION: unreviewed -->
## Unreviewed Findings
(Only include if there are unreviewed findings)
| Finding | Entry | Severity | Reason Unreviewed |
|---------|-------|----------|-------------------|
| Finding-XXX: <title> | <entry> @ <file>:<line> | HIGH / MEDIUM / LOW | Reviewer sub-agent failed; verdict not applied |
<!-- /SECTION: unreviewed -->

<!-- SECTION: integrity -->
## Data Integrity Notes
(Only include if duplicates or other data issues were found and resolved)
| File | Finding | Issue | Resolution |
|------|---------|-------|------------|
| <file> | <finding> | <issue description> | <resolution> |
<!-- /SECTION: integrity -->

<!-- SECTION: vulns -->
## Confirmed Vulnerabilities

### VULN-001: <Title>
| Field | Value |
|-------|-------|
| Severity | HIGH / MEDIUM / LOW |
| Confidence | 0.XX |
| Category | <A-F> |
| Entry | <entry_name> @ <file>:<line> |
| Attack Path | entry → ... → vuln_func |
| Function | <func> @ <file>:<line> |

**Description**: ...
**Exploitation Scenario**: ...
**Remediation**: ...

(sorted by severity (HIGH first), then confidence (descending))
<!-- /SECTION: vulns -->
```

   - **Edge cases**:
     - If no confirmed vulnerabilities: Generate the report with Summary all zeros and note "No confirmed vulnerabilities found." Do NOT omit the report.
     - If all entries failed: Generate the report with `## Failed Entries` listing all failures, Summary showing 0 confirmed.
     - If there are unreviewed findings: Include them in `## Unreviewed Findings` with the reason (reviewer failure). They are NOT counted as confirmed.
     - If an entry has gaps (functions analyzed were partial): Count it in the `Entries with gaps` summary row. The gaps are detailed in the per-entry `_vuls.md` file.

### Phase 5: Cleanup

1. Remove the temporary directory: `<PROJECT_DIR>/.siakam_out/SAA/.step1_state/` (if it exists).
2. Keep `tasks.md` for audit. (Delete it only if the user has configured automatic cleanup.)

---

**Execution complete.** Report the path to `Vul_report.md` to the user.
