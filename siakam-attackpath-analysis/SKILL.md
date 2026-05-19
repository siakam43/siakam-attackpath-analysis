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

2. **Launch parallel sub-agents.**
   - For each entry in the task tracker that is NOT marked `[x]`:
     - Dispatch a sub-agent with the prompt from `step1_attack_path.md`.
     - The sub-agent receives: entry name, file, line, PROJECT_DIR, HAS_CALLGRAPH, MAX_CALL_DEPTH, MAX_INFECTED_FUNCTIONS, and the exclusion list.
     - The sub-agent writes its output to `<PROJECT_DIR>/.siakam_out/SAA/attack_path/<uid>_attack_path.md`.
   - Launched sub-agents run concurrently.

3. **Monitor and track.**
   - As each sub-agent completes successfully, mark its task `[x]` in tasks.md and update `Last Updated`.
   - If a sub-agent fails (timeout, malformed output, error), mark it as `FAILED` in tasks.md with the reason.

4. **Retry failures.**
   - After all sub-agents complete, collect all FAILED entries.
   - For each failed entry, launch one retry with a fresh sub-agent.
   - If the retry succeeds, mark it `[x]`. If it fails again, mark it `FAILED (retry exhausted)` and record the entry in a failures manifest string for the final report.

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

3. **Launch parallel sub-agents.**
   - For each assignment, dispatch a sub-agent with the prompt from `step2_vuln_analysis.md`.
   - The sub-agent receives: the assignment (entry or function group), the attack_path.md file(s), PROJECT_DIR, and the exclusion list.
   - The sub-agent writes its output to `<PROJECT_DIR>/.siakam_out/SAA/vulns/<uid>_vuls.md`. If the entry was split into groups, use group identifiers: `<uid>_group_<N>_vuls.md`.

4. **Monitor, track, and retry.**
   - Same pattern as Phase 1: mark `[x]` on success, `FAILED` on failure, retry once, record exhausted failures.

5. **Merge split outputs (if any).**
   - If an entry's findings were split across multiple group files, merge them into a single `<uid>_vuls.md`. The merge is a simple concatenation of findings (renumbered sequentially).

6. **Gate check.**
   - If ALL Phase 2 tasks failed, skip to Phase 4 with whatever data exists.
   - Otherwise, populate the Phase 3 section of tasks.md with all findings from all successful `<uid>_vuls.md` files.

### Phase 3: False-Positive Elimination

1. **Read the step document.**
   - Read `steps/step3_false_positive.md` in full. Follow its instructions exactly.

2. **Assign reviewers.**
   - For each finding across all `<uid>_vuls.md` files, assign it to exactly one reviewer sub-agent.
   - **Constraint**: No sub-agent may review a finding it discovered. Track which sub-agent discovered each finding (recorded in the finding's metadata). Assign reviewers such that discoverer != reviewer.
   - Update tasks.md Phase 3 section with the assignments.

3. **Launch parallel sub-agents.**
   - For each finding, dispatch a reviewer sub-agent with the prompt from `step3_false_positive.md`.
   - The reviewer receives ONLY: the individual finding context (the `<!-- SECTION: finding -->` block from the vuln report + the vulnerability function's source code + the caller's source code). Do NOT send other findings from the same entry.
   - The reviewer returns: CONFIRMED / FALSE_POSITIVE (with reason) / DISPUTED (with reason).
   - Reviewers do NOT write files. They return their verdict to you (the main agent).

4. **Collect and apply reviews.**
   - As each reviewer returns, update the corresponding finding's `### Review (Step 3)` block in `<uid>_vuls.md`:
     - `Reviewed` → yes
     - `Result` → CONFIRMED / FALSE_POSITIVE
     - `Reviewer` → sub-agent identifier
     - `Revised Confidence` → only if the reviewer changed the confidence score
     - `Exclusion Reason` → only if FALSE_POSITIVE
   - Update the per-file `## Summary` table with confirmed/false-positive counts.
   - Mark the task `[x]` in tasks.md.

5. **Resolve DISPUTED findings.**
   - For any finding where the reviewer returned DISPUTED, you (the main agent) make the final call.
   - Read the finding, the original analysis, and the reviewer's dispute reason. Decide CONFIRMED or FALSE_POSITIVE.
   - Update the finding's Review block accordingly.

6. **Retry failures.**
   - For any reviewer that failed, retry once with a different sub-agent. If still failing, leave the finding as unreviewed (`Reviewed` → no) and record it in the failures manifest.

### Phase 4: Consolidation

1. **Scan all `<uid>_vuls.md` files.**
   - Extract every finding with `Result: CONFIRMED`.

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
| Confirmed vulnerabilities | <N_confirmed> |
| HIGH / MEDIUM / LOW | <H> / <M> / <L> |

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

### Phase 5: Cleanup

1. Remove the temporary directory: `<PROJECT_DIR>/.siakam_out/SAA/.step1_state/` (if it exists).
2. Keep `tasks.md` for audit. (Delete it only if the user has configured automatic cleanup.)

---

**Execution complete.** Report the path to `Vul_report.md` to the user.
