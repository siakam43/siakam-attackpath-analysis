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
| `PHASE1_TIMEOUT_MS` | 1200000 | Max time (ms) for one Phase 1 sub-agent (call graph + data flow) |
| `PHASE2_TIMEOUT_BASE_MS` | 600000 | Base time (ms) for Phase 2 sub-agent setup, file I/O, and report writing |
| `PHASE2_TIMEOUT_PER_FUNC_MS` | 120000 | Additional time (ms) per infected function in the entry |
| `PHASE3_TIMEOUT_MS` | 1200000 | Max time (ms) for one Phase 3 reviewer (all findings for one entry) |
| `MAX_CONCURRENT_SUBAGENTS` | 2 | Maximum sub-agents running concurrently in any phase |

A Phase 2 sub-agent's timeout = `PHASE2_TIMEOUT_BASE_MS + (num_infected_functions * PHASE2_TIMEOUT_PER_FUNC_MS)`.
To change a parameter, edit the value in this file. `MAX_CALL_DEPTH` and `MAX_INFECTED_FUNCTIONS` must also be updated in `steps/step1_attack_path.md`.

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

4. **Verify callgraph.json.**
   - Check if `<PROJECT_DIR>/.siakam_out/callgraph.json` exists.
   - If it does NOT exist, tell the user: "callgraph.json not found at `<PROJECT_DIR>/.siakam_out/callgraph.json`. The Siakam framework must generate this file before SAA analysis." and abort.
   - If it exists, the file is ready for use. (callgraph.json is pre-built by external Siakam framework modules — this skill does not generate it.)

5. **Determine entry list and file naming.**
   - Extract all entries from `apis.json` `interfaces` array.
   - For each entry, compute the `<uid>`:
     - Default: `<entry.name>`
     - If duplicate names exist across different files: `<entry.name>_<source_file_basename>`
     - If still duplicate (same file, different lines): `<entry.name>_<source_file_basename>_<line>`
   - The identity string for cross-references is `<entry.name> @ <entry.file>:<entry.line>`.

6. **Check for resume.**
   - If `<PROJECT_DIR>/.siakam_out/SAA/tasks.md` already exists (from a previous interrupted run):
     - Read it. Verify the task list structure has Phase 1, Phase 2, and Phase 3 sections.
     - Identify tasks marked `[x]` as complete.
     - Verify that the corresponding output files exist on disk. If a task is marked `[x]` but the output file is missing, mark it as `[ ]` and re-run it.
     - If new entries exist in `apis.json` that are not in the task tracker, append them as `[ ]` under the appropriate phase.
     - Skip completed tasks in subsequent phases.
     - Keep the existing `Started` timestamp, update `Last Updated`.
     - Proceed to Phase 1 (do NOT re-create the task tracker).

7. **Initialize output directories and task tracker (first run only).**
   - If `tasks.md` does NOT exist (no resume), create the directories and the task tracker:
   - Create `<PROJECT_DIR>/.siakam_out/SAA/attack_path/`
   - Create `<PROJECT_DIR>/.siakam_out/SAA/vulns/`
   - Create `<PROJECT_DIR>/.siakam_out/SAA/tasks.md`:

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

### Phase 1: Attack Path Identification

1. **Read the step document.**
   - Read `steps/step1_attack_path.md` in full. Follow its instructions exactly.

2. **Launch sub-agents in batches and track (timeout: PHASE1_TIMEOUT_MS ms each, max concurrent: MAX_CONCURRENT_SUBAGENTS).**
   - Determine `CG_HELPER_PATH`: the absolute path to `tools/cg_helper.py`. This file is located at `<skill_root>/tools/cg_helper.py` where `<skill_root>` is the directory containing this SKILL.md file.
   - Collect all entries in the task tracker that are NOT marked `[x]` into a pending list.
   - While the pending list is not empty:
     - Take the first `MAX_CONCURRENT_SUBAGENTS` entries as the current batch.
     - For each entry in the batch, dispatch a sub-agent with the prompt from `step1_attack_path.md`. Set its timeout to `PHASE1_TIMEOUT_MS` ms.
     - The sub-agent receives: `ENTRY_NAME`, `ENTRY_FILE`, `ENTRY_LINE`, `PROJECT_DIR`, `MAX_CALL_DEPTH`, `MAX_INFECTED_FUNCTIONS`, `EXCLUSIONS`, and `CG_HELPER_PATH`.
     - The sub-agent writes its output to `<PROJECT_DIR>/.siakam_out/SAA/attack_path/<uid>_attack_path.md`.
     - Wait for all sub-agents in the current batch to complete (success or failure).
     - As sub-agents complete, classify the result and update tasks.md:
       - Success: mark `[x]` and update `Last Updated`.
       - **Timeout**: Mark `FAILED (timeout)`. The sub-agent exceeded `PHASE1_TIMEOUT_MS` ms.
       - **Malformed output**: Mark `FAILED (malformed)`. The output file is missing, empty, or does not match the required format.
       - **Error**: Mark `FAILED (error)` with the error message.
     - Remove the batch entries from the pending list.

3. **Retry failures (in batches, respecting MAX_CONCURRENT_SUBAGENTS).**
   - After all batches complete, collect all FAILED entries into a retry list.
   - While the retry list is not empty:
     - Take the first `MAX_CONCURRENT_SUBAGENTS` entries as the current retry batch.
     - For each entry in the batch, dispatch a fresh sub-agent:
       - Timeout failures: retry once with `PHASE1_TIMEOUT_MS * 1.5` ms (extended timeout).
       - Malformed/error failures: retry once with the same timeout.
     - Wait for all retry sub-agents in the current batch to complete.
     - As retry sub-agents complete, apply the same classification as above.
     - If a retry succeeds, mark it `[x]`. If it fails again, mark it `FAILED (retry exhausted)` and record the entry with its failure reason in a failures manifest string for the final report.
     - Remove the batch entries from the retry list.

4. **Gate check.**
   - If ALL entries failed, skip to Phase 4 (Consolidation) — generate a report with only failed entries.
   - Otherwise, proceed to Phase 2.

### Phase 2: Vulnerability Discovery

1. **Read the step document.**
   - Read `steps/step2_vuln_analysis.md` in full. Follow its instructions exactly.

2. **Assign one sub-agent per entry.**
   - For each entry with a successful Phase 1 output:
     - Read its `<uid>_attack_path.md` and count infected functions from the `## Function Index`.
     - Assign one sub-agent for that entry. Each sub-agent receives the full `<uid>_attack_path.md` file, which contains all attack paths and the complete Function Index.
     - Compute the sub-agent's timeout: `PHASE2_TIMEOUT_BASE_MS + (num_infected_functions * PHASE2_TIMEOUT_PER_FUNC_MS)`.
   - Update tasks.md Phase 2 section with one task per entry.

3. **Instruct sub-agents to write partial results on exhaustion.**
   - Tell each Phase 2 sub-agent: if you are running out of capacity (token limit, timeout approaching) before completing all assigned functions, write your output file immediately with what you have:
     - Add `<!-- STATUS: partial -->` below the header.
     - In the Summary table, note `Functions analyzed: <N> of <M> (partial)`.
     - List unanalyzed functions under a `## Unanalyzed Functions` section so the main agent can reassign them.
   - Full output (all functions analyzed) uses `<!-- STATUS: complete -->`.

4. **Launch sub-agents in batches and track (dynamic timeout per entry, max concurrent: MAX_CONCURRENT_SUBAGENTS).**
   - Collect all entries into a pending list.
   - While the pending list is not empty:
     - Take the first `MAX_CONCURRENT_SUBAGENTS` entries as the current batch.
     - For each entry in the batch, dispatch a sub-agent with the prompt from `step2_vuln_analysis.md`. Set its timeout to the computed value from step 2.
     - The sub-agent receives: the entry name, the full `<uid>_attack_path.md` file, `PROJECT_DIR`, and the exclusion list.
     - The sub-agent writes its output to `<PROJECT_DIR>/.siakam_out/SAA/vulns/<uid>_vuls.md`.
     - Wait for all sub-agents in the current batch to complete.
     - As sub-agents complete, classify the result and update tasks.md:
       - Check the output file's status marker (`<!-- STATUS: complete -->` or `<!-- STATUS: partial -->`).
       - **Format validation** (before marking success): verify that the `_vuls.md` file contains:
         - `<!-- SECTION: finding -->` markers wrapping each finding
         - `## Finding-001:` format (NOT `VULN-N` or other schemes)
         - `### Review (Step 3)` tables with `*to be filled in Step 3*` in ALL value fields
       - If any format check fails, mark `FAILED (malformed)` — do NOT accept it.
       - Mark `[x]` on success (complete + format-valid), `PARTIAL` on partial output, `FAILED` with classification (`timeout`, `malformed`, `format-violation`, `error`) on failure.
     - Remove the batch entries from the pending list.

5. **Handle partial outputs and retry failures.**
   - **Partial outputs**: For entries marked `PARTIAL`, collect the unanalyzed functions from `## Unanalyzed Functions`. Launch a new sub-agent with the computed timeout to cover them (smaller assignment, should complete faster). If multiple partial entries need reassignment, batch them respecting `MAX_CONCURRENT_SUBAGENTS`. Append the new findings to the same `<uid>_vuls.md` file and renumber sequentially.
   - **Total failures**: Collect all FAILED entries into a retry list. While the retry list is not empty, take the first `MAX_CONCURRENT_SUBAGENTS` entries as the current retry batch, dispatch fresh sub-agents, and wait for all to complete. Timeout failures get `PHASE2_TIMEOUT_BASE_MS + (num_infected_functions * PHASE2_TIMEOUT_PER_FUNC_MS * 1.5)` ms extended timeout. If the retry also fails, mark `FAILED (retry exhausted)`. Remove the batch entries from the retry list.
   - Record exhausted failures in a failures manifest string for the final report.

6. **Gate check.**
   - If ALL Phase 2 tasks failed, skip to Phase 4 with whatever data exists.
   - Otherwise, populate the Phase 3 section of tasks.md with all findings from all successful and partial `<uid>_vuls.md` files.

### Phase 3: False-Positive Elimination

1. **Read the step document.**
   - Read `steps/step3_false_positive.md` in full. Follow its instructions exactly.

2. **Assign one reviewer per entry.**
   - For each entry with Phase 2 findings (successful or partial), assign one reviewer sub-agent.
   - Each reviewer will receive ALL findings from one `<uid>_vuls.md` file, plus the full attack path context for each finding.
   - Update tasks.md Phase 3 section with one task per entry.

3. **Launch reviewer sub-agents in batches and track (timeout: PHASE3_TIMEOUT_MS ms each, max concurrent: MAX_CONCURRENT_SUBAGENTS).**
   - Collect all entries into a pending list.
   - While the pending list is not empty:
     - Take the first `MAX_CONCURRENT_SUBAGENTS` entries as the current batch.
     - For each entry in the batch, dispatch a reviewer sub-agent with the prompt from `step3_false_positive.md`. Set its timeout to `PHASE3_TIMEOUT_MS` ms.
     - The reviewer receives:
       - The full `<uid>_vuls.md` file (all findings for that entry).
       - The full `<uid>_attack_path.md` file (all attack paths, the Function Index, and per-function labels from Phase 1).
       - `PROJECT_DIR` and `EXCLUSIONS` for locating source files.
     - The reviewer reads source code themselves using Read tools to independently verify the attack path chain, data flow, and protective mechanisms for each finding.
     - The reviewer writes the updated `<uid>_vuls.md` directly: filling in each finding's `### Review (Step 3)` table and updating the `## Summary` table.
     - The reviewer returns a brief completion report listing the verdict for each finding.
     - Wait for all reviewers in the current batch to complete.
     - As reviewers complete, verify their output and update tasks.md:
       - Read the updated `<uid>_vuls.md` and verify:
         - Every finding's `Reviewed` field is now `yes` (not `*to be filled in Step 3*`).
         - No duplicate or missing review blocks.
       - If verification passes, mark the task `[x]` in tasks.md.
       - If verification fails (some findings left unreviewed, malformed updates), mark `PARTIAL` and note which findings need re-review.
     - Remove the batch entries from the pending list.

4. **Retry failures (in batches, respecting MAX_CONCURRENT_SUBAGENTS).**
   - For any reviewer that failed (timeout, malformed output, error), classify and collect into a retry list.
   - While the retry list is not empty:
     - Take the first `MAX_CONCURRENT_SUBAGENTS` entries as the current retry batch.
     - For each entry in the batch, dispatch a fresh sub-agent:
       - Timeout failures: retry with `PHASE3_TIMEOUT_MS * 1.5` ms extended timeout.
       - Other failures: retry with the same `PHASE3_TIMEOUT_MS` ms.
     - Wait for all retry sub-agents in the current batch to complete.
     - If the retry also fails, leave all findings in that entry as unreviewed (`Reviewed` → no) and record it in the failures manifest.
     - Remove the batch entries from the retry list.

### Phase 4: Consolidation

1. **Scan all `<uid>_vuls.md` files.**
   - **Duplicate number check** (mechanical integrity): Scan for duplicate `Finding-XXX` numbers within each file. The same finding number should never appear twice within a file — if it does, it indicates a write collision or merge error. Keep the first occurrence and discard later duplicates. Report any discarded duplicates in `## Data Integrity Notes`.
   - **Reviewer merge verification**: For each reviewer completion report that declared `MERGES:`, verify the merged file reflects the merge: the merged-into finding remains, the merged-from finding is removed. Number gaps from reviewer merges are expected — note them in `## Data Integrity Notes` as informational, not errors.
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
(Only include if duplicate numbers or reviewer merges were found)
| File | Finding | Issue | Resolution |
|------|---------|-------|------------|
| <file> | Finding-XXX | Duplicate finding number | Kept first occurrence; discarded duplicate |
| <file> | Finding-XXX | Reviewer merged Finding-YYY into Finding-XXX | Number gap at Finding-YYY (expected) |
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

1. Keep `tasks.md` for audit. (Delete it only if the user has configured automatic cleanup.)

---

**Execution complete.** Report the path to `Vul_report.md` to the user.
