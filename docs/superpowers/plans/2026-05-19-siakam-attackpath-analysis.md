# siakam-attackpath-analysis Skill Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Claude Code skill (markdown prompts + cg_helper.py) that analyzes C codebases for attack paths, discovers vulnerabilities along those paths, and eliminates false positives through a three-layer review protocol.

**Architecture:** Five production files + test fixture. SKILL.md (with proper YAML frontmatter) orchestrates a 3-phase pipeline. Step documents (step1/step2/step3) contain LLM analysis prompts, templates, and rules. cg_helper.py provides call-graph queries. State passes between phases via filesystem. A test fixture C project with known vulnerabilities enables TDD-style verification (RED-GREEN-REFACTOR).

**Tech Stack:** Markdown (LLM prompts), Python 3 (cg_helper.py), Claude Code sub-agents for parallel execution, C (test fixture)

**Spec reference:** `docs/superpowers/specs/2026-05-19-siakam-attackpath-analysis-design.md`

---

## File Map

| File | Responsibility |
|------|---------------|
| `tools/cg_helper.py` | Query callgraph.json for caller/callee edges |
| `SKILL.md` | Entry point: arg parsing, env verification, phase orchestration, glossary, resume |
| `steps/step1_attack_path.md` | Attack path identification: BFS call graph construction, data-flow tracing, pruned graph output |
| `steps/step2_vuln_analysis.md` | Vulnerability discovery: per-function 8-method review, category system, severity/confidence scoring |
| `steps/step3_false_positive.md` | False-positive elimination: 3-layer protocol (hard exclusions, context re-verification, cross-review), consolidation |
| `test_fixture/` | Minimal C project with known vulnerabilities for RED-GREEN testing |

---

### Task 1: Create directory structure and cg_helper.py

**Files:**
- Create: `tools/cg_helper.py`
- Create: `steps/` (empty directory)
- Verify: `callgraph.json` (sample already exists at repo root)

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/tools
mkdir -p /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/steps
```

- [ ] **Step 2: Write cg_helper.py**

```python
#!/usr/bin/env python3
"""cg_helper.py - Query callgraph.json for caller/callee relationships.

Usage:
    python3 cg_helper.py <FUNC> caller   # List all functions that call FUNC
    python3 cg_helper.py <FUNC> callee   # List all functions called by FUNC

Reads callgraph.json from the current working directory.
Outputs JSON array of matching edges to stdout.
"""

import json
import sys
import os


def load_callgraph(path="callgraph.json"):
    if not os.path.exists(path):
        print(json.dumps({"error": f"callgraph.json not found at {path}"}))
        sys.exit(1)
    with open(path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            print(json.dumps({"error": f"Malformed callgraph.json: {e}"}))
            sys.exit(1)


def query_caller(cg, func_name):
    results = []
    for edge in cg.get("edges", []):
        if edge.get("callee") == func_name:
            results.append(edge)
    return results


def query_callee(cg, func_name):
    results = []
    for edge in cg.get("edges", []):
        if edge.get("caller") == func_name:
            results.append(edge)
    return results


def main():
    if len(sys.argv) != 3:
        print(json.dumps({"error": "Usage: cg_helper.py <FUNC> caller|callee"}))
        sys.exit(1)

    func_name = sys.argv[1]
    mode = sys.argv[2]

    if mode not in ("caller", "callee"):
        print(json.dumps({"error": f"Invalid mode '{mode}'. Use 'caller' or 'callee'."}))
        sys.exit(1)

    cg = load_callgraph()

    if mode == "caller":
        results = query_caller(cg, func_name)
    else:
        results = query_callee(cg, func_name)

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Test cg_helper.py with the sample callgraph.json**

```bash
cd /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/tools && \
cp ../../callgraph.json . && \
python3 cg_helper.py main callee
```

Expected: JSON array of 4 edges where caller is "main" (driver_setup, set_worker, execute_work, printf).

```bash
python3 cg_helper.py driver_setup caller
```

Expected: JSON array with 1 edge (main → driver_setup).

```bash
python3 cg_helper.py nonexistent_func callee
```

Expected: `[]` (empty array).

```bash
rm callgraph.json
python3 cg_helper.py main callee
```

Expected: `{"error": "callgraph.json not found at callgraph.json"}`.

```bash
cp ../../callgraph.json .
```

- [ ] **Step 4: Verify cg_helper.py standalone contract matches spec**

Verify against spec section "cg_helper.py Contract":
- [x] Accepts `<FUNC> caller|callee` arguments
- [x] Returns JSON array of edge objects with caller, callee, type, file, line, uid, confidence
- [x] uid and confidence present only for indirect edges
- [x] Returns `[]` for no matches
- [x] Returns `{"error": "..."}` for missing/malformed callgraph.json

---

### Task 2: Write SKILL.md (entry point orchestrator)

**Files:**
- Create: `SKILL.md`

- [ ] **Step 1: Write SKILL.md**

File: `siakam-attackpath-analysis/SKILL.md`

```markdown
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
```

- [ ] **Step 2: Review SKILL.md against spec section "SKILL.md Entry Point"**

Checklist:
- [x] Parse arguments (default current dir)
- [x] Read .siakamignore
- [x] Verify apis.json at `.siakam_out/SII/apis.json`
- [x] Check callgraph.json at `.siakam_out/callgraph.json`
- [x] Empty interfaces → warn and exit
- [x] Ignore failures/errors/warnings in apis.json
- [x] Create directory structure and task tracker
- [x] Resume/checkpoint logic
- [x] Phase 1: read step1, launch parallel sub-agents, retry-once, gate check
- [x] Phase 2: read step2, function-grouping for >10 paths, launch, retry, merge
- [x] Phase 3: read step3, assign reviewers (discoverer != reviewer), collect verdicts, update files, resolve DISPUTED
- [x] Phase 4: consolidate Vul_report.md with category cross-table and failed entries
- [x] Phase 5: cleanup temp dirs
- [x] Programmatic linear-instruction style
- [x] Terminology glossary included
- [x] Configurable parameters at top

---

### Task 3: Write step1_attack_path.md

**Files:**
- Create: `steps/step1_attack_path.md`

- [ ] **Step 1: Write steps/step1_attack_path.md**

```markdown
# Step 1: Attack Path Identification

## Configurable Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `MAX_CALL_DEPTH` | 10 | Maximum nodes in an attack path (entry to leaf) |
| `MAX_INFECTED_FUNCTIONS` | 50 | Maximum infected functions per entry before truncation |

## Abbreviated Glossary

| Term | Definition |
|------|------------|
| Entry | The externally-exposed function you are analyzing |
| Infected function | A function whose parameters trace back to the entry's external input |
| Attack path | A root-to-leaf chain of infected functions |
| Pruned attack graph | Call graph with only infected nodes and their edges |

## Context Isolation

> Use ONLY the input files specified in this document. Do not rely on conclusions or judgments from any previous analysis. Analyze from first principles.

## Your Input

You receive:
- `ENTRY_NAME`: The entry function name
- `ENTRY_FILE`: Path to the source file (relative to PROJECT_DIR)
- `ENTRY_LINE`: Line number of the function definition
- `PROJECT_DIR`: Absolute path to the project root
- `HAS_CALLGRAPH`: "true" or "false"
- `MAX_CALL_DEPTH`: Maximum depth (default 10)
- `MAX_INFECTED_FUNCTIONS`: Infected function limit (default 50)
- `EXCLUSIONS`: List of excluded files/directories from `.siakamignore`

## Your Task

For the given entry function, construct a pruned call graph and identify all attack paths. Write the result to `<PROJECT_DIR>/.siakam_out/SAA/attack_path/<uid>_attack_path.md`.

## Step 1.0: Pre-Scan for Custom Data-Transfer Functions

Before building the call graph, scan the source files in PROJECT_DIR (respecting EXCLUSIONS) for custom data-transfer functions. These are functions that move data and serve as propagation conduits.

Identify functions matching these patterns:
- **Custom memory copy**: Name contains copy/mem/move/transfer AND body contains memcpy/memmove/strcpy/strncpy calls
- **Hardware data read**: Reads from DMA buffer, FIFO, MMIO registers (look for mmio_read*, dma_read*, fifo_get*, ioread*)
- **Serialization**: Packs/unpacks data structures (parse_*, pack_*, marshal_*, unmarshal_*, deserialize_*)
- **IPC/shared-memory transfer**: Cross-core communication, shared memory writes (ipc_send*, shmem_write*, mbox_*)

Record these function names. They propagate data just like standard memcpy: if F transfers data from location X to Y, and G can read from Y, then G is infected.

## Step 1.1: Build the Call Graph

### If HAS_CALLGRAPH is true:

1. Use `cg_helper.py` to load the graph from `<PROJECT_DIR>/.siakam_out/callgraph.json`.
2. BFS from the entry function:
   - Query callees: `python3 <skill_dir>/tools/cg_helper.py <FUNC> callee`
   - For each callee, if it is a standard library/kernel function (see terminal list below), mark as leaf and stop expansion.
   - If it is a non-terminal function, add it to the queue for the next level.
   - Stop when depth exceeds MAX_CALL_DEPTH or infected function count exceeds MAX_INFECTED_FUNCTIONS.
3. **Indirect edge verification**:
   - `high` confidence edges: accept directly. The edge generator has already verified the function pointer assignment.
   - `medium` and `low` confidence edges: read the caller's source code. Look for the function pointer assignment (e.g., `ops->process = my_handler`, `ctx->callback = &func`). Verify the assignment is reachable from the call site. Even if uncertain, keep the edge but annotate it with the confidence level.
4. Resolve each callee's `file` path relative to PROJECT_DIR to get the source location.

### If HAS_CALLGRAPH is false:

Use iterative BFS with intermediate state files. Write intermediate results to `<PROJECT_DIR>/.siakam_out/SAA/.step1_state/<uid>_layer_<N>.json`.

1. **Layer 0**: The entry function is layer 0. Read its source body from `<PROJECT_DIR>/<ENTRY_FILE>`.
2. **For each layer** (repeat until no more infected functions or depth exceeds MAX_CALL_DEPTH):
   a. For each function in the current layer, read its source body.
   b. Identify all function calls within the body:
      - Direct calls: `func(args)` — extract the function name
      - Indirect calls: `ptr->callback(args)`, `ops.func(args)` — trace the function pointer assignment
      - Function pointer assignments: `struct.field = &func` — record as a potential callee
   c. Filter out standard library/kernel terminal functions.
   d. For each callee, locate its source file by searching PROJECT_DIR (respect EXCLUSIONS).
   e. Write the layer's results to the state file: list of `{caller, callee, file, line, type, confidence}`.
   f. Queue callees for the next layer.
3. After all layers, compile the complete edge list from all state files.

### Terminal Functions (do not expand past these):

`malloc`, `free`, `kmalloc`, `kfree`, `copy_from_user`, `copy_to_user`, `printk`, `printf`, `sprintf`, `snprintf`, `memcpy`, `memmove`, `memset`, `strcpy`, `strncpy`, `strlen`, `strcmp`, `strncmp`, `strcat`, `strncat`, `memset`, `kzalloc`, `kcalloc`, `vfree`, `vmalloc`, `ioremap`, `iounmap`, `readl`, `writel`, `readb`, `writeb`, `__raw_readl`, `__raw_writel`, `spin_lock`, `spin_unlock`, `mutex_lock`, `mutex_unlock`, `assert`, `BUG`, `WARN`, `BUG_ON`, `WARN_ON`.

Also terminate on any function whose name starts with `__builtin_`, `__atomic_`, or `__sync_`.

### Cycle Detection:

Maintain a visited set per path. If a function appears that is already in the current path's ancestor chain, terminate that branch and annotate: `[terminated at cycle: <func>]`. The branch is still a valid path up to the point before the cycle.

### Header File Entries:

If the entry function is in a `.h` file, analyze it normally. However, do not deeply expand function-like macros — treat `#define` macros that contain control flow as opaque.

## Step 1.2: Data Flow Tracing

For each function in the call graph, determine whether it is "infected" by attacker data.

### Fundamental Principle

**Reception = Infection.** If a function's parameter can be traced back to the entry's external input, the function is infected, regardless of whether it actively reads or uses the data.

### Tracing Rules (apply in priority order)

For each function F that has caller C:

1. **Direct pass**: C passes one of its infected parameters directly to F as an argument → F is infected.
2. **Local assignment**: C assigns an infected parameter/expression to a local variable, then passes that variable to F → F is infected.
3. **Struct field propagation**: C writes an infected value to a struct field, passes the struct to F, and F reads that field → F is infected.
4. **Pointer alias propagation**: C has a pointer P pointing to infected data. C computes `Q = P + offset` or `Q = (cast_type)P` and passes Q to F → F is infected.
5. **Memory copy propagation**: C copies infected data via memcpy/strcpy or a custom data-transfer function (from Step 1.0), then passes the destination buffer to F → F is infected.
6. **Control-flow influence**: C uses an infected parameter in a branch condition (`if`, `switch`), and F is called within the controlled branch → F is infected (indirect influence).
7. **Comparison-only exclusion**: C uses an infected parameter ONLY in a comparison (`if (arg == CONSTANT)`) and the comparison result does NOT determine whether F is called → F is NOT infected.

### Termination

Data flow terminates when the infected data no longer participates in any function call's argument computation.

Example: if infected data is only used as `printf("value: %d", arg)`, the data does not propagate further — `printf` is a terminal function.

### Classification

For each infected function, assign one label:

| Label | Criteria |
|-------|----------|
| `source` | The entry function itself |
| `active` | The function reads, parses, dereferences, or makes control-flow decisions based on the infected data |
| `pass-through` | The function forwards the infected data to callees without reading or acting on it |
| `leaf` | The function is infected but has no infected callees (data flow terminus) |

A function can be both `active` and `leaf` (if it uses the data but doesn't pass it on).

## Step 1.3: Prune and Identify Paths

1. **Prune**: Remove all non-infected functions from the call graph. Keep only infected nodes and edges between them.
2. **Identify leaves**: Find all infected nodes with out-degree 0 in the pruned graph.
3. **Extract paths**: Each root-to-leaf traversal is an attack path.
   - If the entry has no infected callees, the entry itself is the sole leaf → 1 attack path of length 1.
4. **Truncation**: If infected function count exceeds MAX_INFECTED_FUNCTIONS during construction, stop and annotate the report with a truncation warning. Do not continue expanding.

## Step 1.4: Write Output

Write to `<PROJECT_DIR>/.siakam_out/SAA/attack_path/<uid>_attack_path.md`.

The output MUST use the following exact format. Use the structural markers (`<!-- SECTION: ... -->`) exactly as shown.

```markdown
<!-- SECTION: header -->
# Attack Path Analysis: <entry_name>
**Entry**: <entry_name> @ <file>:<line>
**Analysis Date**: <YYYY-MM-DD>
**Confidence**: <high|medium>
<!-- /SECTION: header -->

<!-- SECTION: summary -->
## Call Graph Summary
- Total nodes in pruned graph: <N>
- Attack paths: <M>
- Max depth: <D>
<!-- /SECTION: summary -->

<!-- SECTION: paths -->
## Attack Paths

### Path 1: <entry> → ... → <leaf>
(A single-node path if entry is its own leaf; otherwise show full chain)

| Step | Function | File:Line | Data Flow Mechanism | Label |
|------|----------|-----------|---------------------|-------|
| 1    | entry    | file.c:10 | source              | source |
| 2    | func_a   | file.c:20 | arg passed directly | active |
| 3    | func_b   | file.c:30 | struct field read   | leaf   |

**Risk Summary**: <1-2 sentences on why the terminal function is security-relevant. What attacker-controlled data reaches it? What operations does it perform?>

### Path 2: ...
(Repeat for each path)
<!-- /SECTION: paths -->

<!-- SECTION: function-index -->
## Function Index
| Function | File:Line | Label | Path IDs |
|----------|-----------|-------|----------|
| entry    | file.c:10 | source | 1, 2, 3 |
| func_a   | file.c:20 | active | 1, 3 |
| func_b   | file.c:30 | leaf   | 1 |
<!-- /SECTION: function-index -->
```

### Truncation Warning (if applicable)

If analysis was truncated, add this after the summary section:

```
**WARNING**: Analysis truncated at <N> infected functions (limit: MAX_INFECTED_FUNCTIONS = 50).
<M> functions were not analyzed. Consider reducing scope or increasing MAX_INFECTED_FUNCTIONS.
```

### Edge Cases

- **No infected callees**: The report has 1 path (entry only), 1 node in the pruned graph. The entry function's own code MUST still be analyzed for vulnerabilities. The entry is both source and leaf.
- **Cycle detected**: The path ends at the function before the cycle with annotation `[terminated at cycle: <func>]`. The cycle function is still listed in the Function Index.
- **Indirect edge uncertain**: Annotate the edge in the path table with a superscript note: `(indirect, confidence: low)` in the Data Flow Mechanism column.

## Step 1.5: Report Completion

After writing the output file, report to the main agent:
- Number of paths found
- Number of infected functions
- Whether truncation occurred
- Path to the output file
```

- [ ] **Step 2: Review step1_attack_path.md against spec sections**

Checklist:
- [x] Configurable parameters (MAX_CALL_DEPTH, MAX_INFECTED_FUNCTIONS)
- [x] Abbreviated glossary
- [x] Context isolation directive
- [x] Custom data-transfer function pre-scan (Step 1.0)
- [x] Dual BFS strategy (HAS_CALLGRAPH true/false)
- [x] Terminal function list
- [x] Cycle detection
- [x] Header file handling
- [x] Data flow tracing rules (7 rules + pointer alias)
- [x] Node classification labels (source/active/pass-through/leaf)
- [x] Pruning and path identification
- [x] Truncation warning
- [x] Output template with SECTION markers and Function Index
- [x] Edge case handling (no callees, cycle, uncertain indirect)
- [x] Intermediate state files for no-callgraph mode

---

### Task 4: Write step2_vuln_analysis.md

**Files:**
- Create: `steps/step2_vuln_analysis.md`

- [ ] **Step 1: Write steps/step2_vuln_analysis.md**

```markdown
# Step 2: Vulnerability Discovery

## Abbreviated Glossary

| Term | Definition |
|------|------------|
| Entry | The externally-exposed function being analyzed |
| Attack path | A root-to-leaf chain of infected functions from Step 1 |
| Infected function | A function whose parameters trace back to entry's external input |
| Finding | A potential vulnerability discovered in this phase |

## Context Isolation

> Use ONLY the input files specified in this document. Do not rely on conclusions or judgments from any previous analysis. Analyze each function from its source code.

## Your Input

You receive:
- `ASSIGNMENT`: Either an entry name (and you analyze all its attack paths) or a list of infected functions (a group from a large entry)
- `ATTACK_PATH_FILES`: Paths to one or more `<uid>_attack_path.md` files
- `PROJECT_DIR`: Absolute path to the project root
- `EXCLUSIONS`: List of excluded files/directories

## Your Task

Review every infected function in your assignment for security vulnerabilities. Write findings to `<PROJECT_DIR>/.siakam_out/SAA/vulns/<uid>_vuls.md` (or `<uid>_group_<N>_vuls.md` for groups).

## Step 2.1: Collect and Deduplicate Functions

1. Read each attack_path.md file assigned to you.
2. Extract all functions from the `## Function Index` section.
3. Deduplicate: same function name + same file = same function. Keep the union across all assigned paths.
4. Sort by call-graph depth (from the Path table; entry = depth 1). Analyze shallowest first.

## Step 2.2: For Each Function, Apply the 8-Method Review

For each function in your sorted, deduplicated list:

### Step 2.2a: Read the Function Source

1. Locate the function definition in `<PROJECT_DIR>/<file>` at the given line.
2. Read the complete function body (from opening `{` to closing `}`).
3. Also read any called functions that are within the same file and relevant to understanding the logic (use your judgment — do not expand beyond 3 levels of local helper calls).

### Step 2.2b: Determine Applicability

Scan the function body. For each of the 8 methods below, determine if the method is APPLICABLE:

| Method | Applicability Check |
|--------|---------------------|
| Source-to-sink tracking | Applicable if the function calls any memory operation (memcpy, strcpy, sprintf, copy_to_user, mmio_write, etc.) or passes data to such a function |
| Bounds-check completeness | Applicable if the function uses array indexing, pointer arithmetic, or calls memcpy/strcpy with a variable length argument |
| Integer safety | Applicable if the function performs arithmetic on variables that could be tainted, especially before memory operations or size calculations |
| Lifetime analysis | Applicable if the function calls malloc/free/kmalloc/kfree or uses dynamically allocated memory |
| Synchronization check | Applicable if the function accesses global/static variables or shared data structures (especially in multi-threaded contexts like drivers with IRQ handlers, tasklets, workqueues) |
| Authorization gating | Applicable if the function performs security-sensitive operations: physical memory access, register writes, DMA mapping, privilege changes |
| Secret pattern matching | Applicable if the function contains string literals or static arrays that could be keys, or calls cryptographic APIs |
| Cross-trust-boundary checks | Applicable if the function reads from shared memory, IPC buffers, hardware registers, or data from a different privilege level (EL1→EL3, non-secure→secure world) |

### Step 2.2c: Execute Applicable Methods

For each method marked APPLICABLE, perform the analysis:

**1. Source-to-Sink Tracking**
- Identify taint sources: entry parameters that reach this function.
- Identify dangerous sinks: memcpy, strcpy, sprintf, sscanf, copy_to_user, copy_from_user, mmio_write, iowrite*, writel, outb, etc.
- For each source-sink pair, trace whether the tainted value can reach the sink without sanitization.
- Record as PASS (no issue), FAIL (vulnerability found), or N/A.

**2. Bounds-Check Completeness**
- For each memcpy(dst, src, len), array[idx], ptr[offset]: trace backward to find where len/idx/offset was last set.
- Check whether there is a bounds check (if statement, ASSERT, BUG_ON) on len/idx/offset before use.
- Check whether the bounds check covers the full valid range (not off-by-one).
- Check whether the check is on the correct variable (not a stale copy).
- Record as PASS, FAIL, or N/A.

**3. Integer Safety**
- Identify arithmetic operations on tainted values: +, -, *, /, %, <<, >>, casts.
- Check for overflow: addition that could wrap, multiplication that could overflow, shift from signed types.
- Check whether the result is used in a size calculation (malloc, memcpy length) or array index.
- Check for signed/unsigned confusion (negative values interpreted as large unsigned).
- Record as PASS, FAIL, or N/A.

**4. Lifetime Analysis**
- Identify all malloc/kmalloc/kzalloc calls and their corresponding free/kfree calls.
- Check pairing: every allocation has exactly one free on all code paths (including error paths).
- Check use-after-free: the pointer is not dereferenced after free.
- Check double-free: the pointer is set to NULL after free, or guarded against re-free.
- Record as PASS, FAIL, or N/A.

**5. Synchronization Check**
- Identify accesses to global/static variables or shared heap objects.
- Check whether each access is protected by a lock (spin_lock, mutex_lock, RCU).
- Check for TOCTOU: read-check-write patterns where the value can change between check and use.
- Check for missing barriers (smp_rmb, smp_wmb) when accessing shared lock-free data.
- Record as PASS, FAIL, or N/A.

**6. Authorization Gating**
- Identify security-sensitive operations: ioremap, DMA API (dma_alloc_*, dma_map_*), register writes, SMC calls, TZASC configuration.
- Check whether there is a capability/permission/caller-ID check before the operation.
- Check whether the check can be bypassed (e.g., through a different code path that skips the gate).
- Record as PASS, FAIL, or N/A.

**7. Secret Pattern Matching**
- Search for hardcoded patterns: hex strings of 16+ bytes, base64 strings, strings named *key*, *secret*, *password*, *token*, *certificate*, *iv*, *nonce*.
- Check whether a fixed IV/nonce is used (all-zeros, sequential counter without randomness).
- Check whether weak algorithms are referenced: DES, RC4, MD4, MD5 (in security context), SHA1 (for signatures), RSA with < 2048 bits.
- Record as PASS, FAIL, or N/A.

**8. Cross-Trust-Boundary Checks**
- Identify reads from shared memory (ioremap'd regions, shared buffers, IPC rings).
- Check whether the data has an integrity check before use: CRC, checksum, magic number, signature verification.
- Check whether the data size/format is validated before parsing (length field validated against buffer size).
- Record as PASS, FAIL, or N/A.

### Step 2.2d: Record the Checklist

After analyzing a function, output the 8-method checklist inline in your analysis (not in the final report). This is for your own tracking:

```
Function: <name> @ <file>:<line>
| Method | Applicable? | Result | Notes |
|--------|-------------|--------|-------|
| Source-to-sink tracking | YES | FAIL | memcpy uses tainted len without check |
| Bounds-check completeness | YES | FAIL | len from user without bounds |
| Integer safety | YES | PASS | no arithmetic on len |
| Lifetime analysis | NO | N/A | no dynamic allocation |
| Synchronization check | NO | N/A | no shared state |
| Authorization gating | NO | N/A | no security-sensitive ops |
| Secret pattern matching | NO | N/A | no crypto material |
| Cross-trust-boundary checks | YES | PASS | shared mem has magic number check |
```

## Step 2.3: Create Findings

For each method where the result is FAIL, create a finding.

### Finding Consolidation Rule

When multiple FAIL results share the same root cause, create a **single composite finding**. For example:
- Integer overflow leading to insufficient bounds check leading to buffer overflow → 1 finding, not 3.
- Missing NULL check leading to NULL pointer dereference → 1 finding.

The Description must explain the full causal chain. Each finding should be something a security engineer would confidently raise in a PR review.

### Severity Assignment

- **HIGH**: Directly exploitable — leads to RCE, privilege escalation, or authentication bypass. Attacker can control the exploit payload. No significant mitigating factors.
- **MEDIUM**: Requires specific conditions (race window, specific configuration, attacker with limited control) but has significant impact (information disclosure, denial of service in security context, limited memory corruption).
- **LOW**: Defense-in-depth issues. A missing check that could theoretically be exploited but has strong compensating controls. Hardcoded non-critical keys.

When in doubt between HIGH and MEDIUM, choose MEDIUM. A false HIGH is worse than a missed upgrade.

### Confidence Scoring

- **0.9-1.0**: Certain. All exploit preconditions are clearly met. Data flow is unambiguous. No speculation needed.
- **0.8-0.9**: Clear pattern. The vulnerability class is well-understood and exploitation methods are known. Minor assumptions about runtime environment.
- **0.7-0.8**: Suspicious pattern. A real concern, but exploitation requires conditions that cannot be fully confirmed from static analysis alone.
- **Below 0.7**: Do NOT report. Better to miss a theoretical issue than to flood the report with speculative findings.

## Step 2.4: Write Output

Write to `<PROJECT_DIR>/.siakam_out/SAA/vulns/<uid>_vuls.md`.

Use the exact format below. The `### Review (Step 3)` fields MUST be left as shown — they will be filled by Phase 3. Do not write anything in those fields.

```markdown
<!-- SECTION: header -->
# Vulnerability Analysis: <entry_name>
**Entry**: <entry_name> @ <file>:<line>
**Analysis Date**: <YYYY-MM-DD>
<!-- /SECTION: header -->

<!-- SECTION: summary -->
## Summary
| Status | Count |
|--------|-------|
| Total findings | <N> |
| Confirmed | *to be filled in Step 3* |
| False positive | *to be filled in Step 3* |
<!-- /SECTION: summary -->

---
<!-- SECTION: finding -->
## Finding-001: <Brief Descriptive Title>

### Identification (Step 2)
| Field | Value |
|-------|-------|
| Severity | HIGH / MEDIUM / LOW |
| Confidence | 0.XX |
| Category | <A-F> |
| Function | <func_name> @ <file>:<line> |
| Attack Path | entry → ... → <vuln_func> |

**Description**:
<Detailed description of the vulnerability.>
<What is the root cause? What is the causal chain if composite?>
<Include the key code lines as a markdown code block:>
```c
// <file>:<line_start>-<line_end>
<relevant code snippet>
```

**Exploitation Scenario**:
<How would an attacker exploit this? What capabilities do they need? What is the impact?>

**Remediation**:
<Specific, actionable fix. If possible, show corrected code.>

### Review (Step 3)
| Field | Value |
|-------|-------|
| Reviewed | *to be filled in Step 3* |
| Result | *to be filled in Step 3* |
| Reviewer | *to be filled in Step 3* |
| Revised Confidence | *to be filled, if changed* |
| Exclusion Reason | *to be filled if false positive* |
<!-- /SECTION: finding -->
```

Repeat the `<!-- SECTION: finding -->` block for each finding. Number them sequentially (Finding-001, Finding-002, ...).

### Edge Cases

- **No vulnerabilities found in a function**: The function's 8-method checklist shows all PASS or N/A. Move to the next function. Do NOT create an empty finding.
- **No vulnerabilities found in the entire assignment**: Still generate the `_vuls.md` file. Summary shows "Total findings: 0". The file is still required as a contract for Phase 3.

## Step 2.5: Report Completion

Report to the main agent:
- Number of functions analyzed
- Number of findings created
- Per-function checklist summary (function name, methods passed, methods failed)
```

- [ ] **Step 2: Review step2_vuln_analysis.md against spec sections**

Checklist:
- [x] Abbreviated glossary
- [x] Context isolation directive
- [x] Function collection and deduplication from Function Index
- [x] Sort by call-graph depth
- [x] 8 analysis methods with detailed execution instructions
- [x] Applicability gating (scan first, apply only applicable)
- [x] Per-function checklist output
- [x] Finding consolidation rule (composite findings)
- [x] Severity and confidence scoring guidelines
- [x] Output template with SECTION markers
- [x] Review fields left as "*to be filled in Step 3*"
- [x] Edge case: no findings → still generate file
- [x] Vulnerability category system (A-F) referenced in output

---

### Task 5: Write step3_false_positive.md

**Files:**
- Create: `steps/step3_false_positive.md`

- [ ] **Step 1: Write steps/step3_false_positive.md**

```markdown
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
```

- [ ] **Step 2: Review step3_false_positive.md against spec sections**

Checklist:
- [x] Key principle and operational rules
- [x] Context isolation directive (only the one finding + source)
- [x] Layer 1: 14 hard exclusion rules
- [x] Layer 2: 6 verification checks with methods and decision matrix
- [x] Layer 3: independent security judgment
- [x] Verdict format (CONFIRMED/FALSE_POSITIVE/DISPUTED with structured output)
- [x] Edge cases (excluded file, missing source)
- [x] Do NOT write files (return verdict to main agent)
- [x] Do NOT use Bash

---

### Task 6: Integration Verification

**Files:**
- Verify: All 5 files exist and are consistent with each other and the spec

- [ ] **Step 1: Verify file structure**

```bash
ls -la /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/
ls -la /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/steps/
ls -la /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/tools/
```

Expected: SKILL.md, steps/ with 3 files, tools/ with cg_helper.py.

- [ ] **Step 2: Cross-document consistency check**

1. **SKILL.md references step documents**: Read SKILL.md and confirm it says "Read `steps/step1_attack_path.md`" (and step2, step3). The file paths must match the actual file locations exactly.

2. **Terminology consistency**: Check that the following terms are used consistently across all 4 markdown files:
   - "entry" / "entry function" (not "interface" or "endpoint")
   - "infected function" / "infected node" (not "tainted function" or "dirty node")
   - "attack path" (not "attack chain" or "vulnerability path")
   - "finding" (not "issue" or "defect" or "vulnerability" until confirmed)
   - "CONFIRMED" / "FALSE_POSITIVE" / "DISPUTED" (all caps, exactly these strings)

3. **Output template consistency**: The `<!-- SECTION: ... -->` markers used in SKILL.md Phase 4 (Vul_report.md template) must match what step3 expects to read from `<uid>_vuls.md` files.

4. **File path consistency**: 
   - SKILL.md writes to `.siakam_out/SAA/attack_path/<uid>_attack_path.md` → step1 outputs to same path
   - SKILL.md writes to `.siakam_out/SAA/vulns/<uid>_vuls.md` → step2 outputs to same path
   - SKILL.md reads from `.siakam_out/SAA/vulns/<uid>_vuls.md` → step3 reviews from same path
   - SKILL.md writes to `.siakam_out/SAA/Vul_report.md` → final output

- [ ] **Step 3: Spec traceability check**

Map each spec section to the file that implements it:

| Spec Section | Implemented In |
|-------------|----------------|
| Terminology Glossary | SKILL.md |
| Configurable Parameters | SKILL.md, step1_attack_path.md |
| Usage / invocation | SKILL.md |
| apis.json handling | SKILL.md Phase 0 |
| callgraph.json handling | SKILL.md Phase 0, step1 Step 1.1 |
| .siakamignore handling | SKILL.md Phase 0 |
| cg_helper.py contract | tools/cg_helper.py |
| File naming convention | SKILL.md Phase 0 |
| Output format stability (SECTION markers) | step1, step2 (templates), SKILL.md Phase 4 |
| Step 1: Call graph construction (both modes) | step1 Step 1.1 |
| Step 1: Data flow tracing rules | step1 Step 1.2 |
| Step 1: Custom data-transfer functions | step1 Step 1.0 |
| Step 1: Pruned attack graph / paths | step1 Step 1.3 |
| Step 1: Node classification labels | step1 Step 1.2 |
| Step 1: Truncation | step1 Step 1.3 |
| Step 1: Output template + Function Index | step1 Step 1.4 |
| Step 1: Parallel execution | SKILL.md Phase 1 |
| Step 2: Execution model (function grouping) | SKILL.md Phase 2, step2 Step 2.1 |
| Step 2: 8-method review protocol | step2 Step 2.2 |
| Step 2: Vulnerability category system | step2 Step 2.2 (method details reference categories) |
| Step 2: Finding consolidation rule | step2 Step 2.3 |
| Step 2: Scoring (severity/confidence) | step2 Step 2.3 |
| Step 2: Output template | step2 Step 2.4 |
| Step 3: Layer 1 (hard exclusions) | step3 Layer 1 |
| Step 3: Layer 2 (context re-verification) | step3 Layer 2 |
| Step 3: Layer 3 (cross-review) | step3 Layer 3 |
| Step 3: Parallel execution / reviewer assignment | SKILL.md Phase 3 |
| Step 3: Output (updated _vuls.md) | SKILL.md Phase 3 |
| Final consolidation Vul_report.md | SKILL.md Phase 4 |
| Edge cases (empty, all-failed) | SKILL.md Phase 4 |
| Resume/checkpoint | SKILL.md Phase 0 step 7 |
| Task tracking | SKILL.md (tasks.md format in Phase 0) |
| Sub-agent failure handling (retry once) | SKILL.md Phases 1, 2, 3 |
| Cleanup | SKILL.md Phase 5 |

- [ ] **Step 4: Quick content scan**

Run grep to verify no TBD/TODO/placeholder remains:

```bash
grep -rn "TBD\|TODO\|to be determined\|fill in later\|implement later" \
  /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/
```

Expected: Only intentional Step 3 placeholder fields in step2 output template ("*to be filled in Step 3*"). These are correct — they are filled by the main agent in Phase 3.

The grep should match only lines containing `*to be filled in Step 3*`. Any other match is a defect.

- [ ] **Step 5: cg_helper.py final verification**

```bash
cd /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/tools
cp ../../callgraph.json .
python3 cg_helper.py main callee | python3 -m json.tool > /dev/null && echo "PASS: valid JSON output"
python3 cg_helper.py nonexistent callee | python3 -m json.tool > /dev/null && echo "PASS: empty array valid JSON"
rm callgraph.json
python3 cg_helper.py main callee 2>&1
```

Expected: Third command prints error JSON to stdout. All json.tool validations pass.
```

---

### Task 7: Create Test Fixture Project (RED Phase)

**Files:**
- Create: `test_fixture/src/driver.c`
- Create: `test_fixture/src/ops.c`
- Create: `test_fixture/.siakam_out/SII/apis.json`
- Create: `test_fixture/.siakam_out/callgraph.json`

This is the RED phase of TDD for skills. Before writing the skill documents, create a minimal C project with known vulnerabilities. After writing the skill, run it against this fixture and verify detection.

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/test_fixture/src
mkdir -p /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/test_fixture/.siakam_out/SII
```

- [ ] **Step 2: Write test fixture C source — src/driver.c**

```c
/* test_fixture/src/driver.c - Fake kernel driver with known vulnerabilities */

#include <linux/types.h>
#include <linux/slab.h>

#define MAX_DATA_SIZE 256
#define HARDCODED_KEY "deadbeefcafebabedeadbeefcafebabe"

struct driver_data {
    void *buffer;
    size_t buf_size;
    int is_initialized;
};

static struct driver_data *g_drv = NULL;
static int g_config_value = 0;

/* Entry function: ioctl handler exposed to userspace */
int driver_ioctl(unsigned int cmd, unsigned long arg)
{
    struct driver_data *drv;
    void *user_buf;
    size_t user_len;
    int ret = 0;

    if (!g_drv) {
        g_drv = kmalloc(sizeof(struct driver_data), GFP_KERNEL);
        if (!g_drv)
            return -1;
        g_drv->is_initialized = 0;
    }
    drv = g_drv;

    switch (cmd) {
    case 0x01: /* SETUP */
        user_len = *(size_t *)arg;
        /* VULNERABILITY: No upper bound check on user_len */
        drv->buffer = kmalloc(user_len, GFP_KERNEL);
        if (!drv->buffer)
            return -1;
        drv->buf_size = user_len;
        drv->is_initialized = 1;
        break;

    case 0x02: /* WRITE */
        user_buf = (void *)(*(unsigned long *)(arg + 8));
        user_len = *(size_t *)arg;
        /* VULNERABILITY: user_len not checked against drv->buf_size */
        if (!drv->is_initialized) {
            ret = -1;
            break;
        }
        memcpy(drv->buffer, user_buf, user_len);  /* VULNERABILITY: buffer overflow */
        break;

    case 0x03: /* READ_CONFIG */
        user_buf = (void *)(*(unsigned long *)(arg + 8));
        /* VULNERABILITY: g_config_value read without lock in multi-threaded context */
        *(int *)user_buf = g_config_value;
        break;

    case 0x04: /* VALIDATE */
        user_buf = (void *)(*(unsigned long *)(arg + 8));
        /* VULNERABILITY: use-after-free — drv freed but pointer accessible */
        kfree(drv->buffer);
        drv->buffer = NULL;
        /* VULNERABILITY: uses freed buffer */
        if (*(int *)user_buf > 0)
            drv->buf_size = *(size_t *)user_buf;  /* VULNERABILITY: writes to freed struct */
        break;

    case 0x05: /* AUTH */
        /* VULNERABILITY: No authentication check before privileged operation */
        /* Direct physical memory access without capability check */
        ioremap(*(unsigned long *)arg, PAGE_SIZE);
        break;

    case 0x06: /* RESET */
        kfree(drv->buffer);
        drv->buffer = NULL;
        /* Missing: drv->is_initialized = 0 — stale state */
        break;

    default:
        ret = -1;
        break;
    }

    return ret;
}

/* Helper functions in the call chain */

int validate_input(void *data, size_t len)
{
    /* Pass-through — simply forwards user data to process_input */
    return process_input(data, len);
}

int process_input(void *data, size_t len)
{
    /* VULNERABILITY: Missing validation — data from external source used directly */
    /* Also: no integrity check on shared-memory-style buffer */
    return 0;
}

int send_response(void *data, size_t len)
{
    /* Sink function — writes data out */
    if (len > MAX_DATA_SIZE)
        return -1;
    /* copy_to_user or similar would go here */
    return 0;
}
```

- [ ] **Step 3: Write test fixture C source — src/ops.c**

```c
/* test_fixture/src/ops.c - Additional functions referenced via callgraph */

#include <linux/types.h>

extern int g_config_value;

/* Called from driver_ioctl's call chain */
void update_config(int new_value)
{
    /* VULNERABILITY: No synchronization on shared global */
    g_config_value = new_value;  /* race condition with driver_ioctl READ_CONFIG */
}

int get_config(void)
{
    /* Read path — infected by new_value from update_config */
    return g_config_value;
}

/* Indirect call target */
int default_handler(void *data, size_t len)
{
    /* VULNERABILITY: No bounds check on len before memcpy-like operation */
    if (data && len > 0)
        return 0;
    return -1;
}
```

- [ ] **Step 4: Write apis.json**

```bash
cat > /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/test_fixture/.siakam_out/SII/apis.json << 'JSONEOF'
{
  "project": "test_fixture",
  "analysis_date": "2026-05-19",
  "total_candidates": 1,
  "confirmed_interfaces": 1,
  "summary": {
    "high_confidence": 1,
    "medium_confidence": 0,
    "exclusion_reasons": {}
  },
  "interfaces": [
    {
      "name": "driver_ioctl",
      "file": "src/driver.c",
      "line": 19,
      "confidence": "high",
      "analysis": "Primary ioctl handler exposed to userspace. Receives cmd and arg from untrusted userspace."
    }
  ],
  "failures": [],
  "errors": [],
  "warnings": []
}
JSONEOF
```

- [ ] **Step 5: Write callgraph.json**

```bash
cat > /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis/siakam-attackpath-analysis/test_fixture/.siakam_out/callgraph.json << 'JSONEOF'
{
  "nodes": [
    {"name": "driver_ioctl", "file": "src/driver.c", "line_start": 19, "has_body": true, "body_file": "src/driver.c", "body_line_start": 19, "body_line_end": 90},
    {"name": "validate_input", "file": "src/driver.c", "line_start": 93, "has_body": true, "body_file": "src/driver.c", "body_line_start": 93, "body_line_end": 97},
    {"name": "process_input", "file": "src/driver.c", "line_start": 99, "has_body": true, "body_file": "src/driver.c", "body_line_start": 99, "body_line_end": 105},
    {"name": "send_response", "file": "src/driver.c", "line_start": 107, "has_body": true, "body_file": "src/driver.c", "body_line_start": 107, "body_line_end": 113},
    {"name": "update_config", "file": "src/ops.c", "line_start": 8, "has_body": true, "body_file": "src/ops.c", "body_line_start": 8, "body_line_end": 12},
    {"name": "get_config", "file": "src/ops.c", "line_start": 14, "has_body": true, "body_file": "src/ops.c", "body_line_start": 14, "body_line_end": 19},
    {"name": "default_handler", "file": "src/ops.c", "line_start": 22, "has_body": true, "body_file": "src/ops.c", "body_line_start": 22, "body_line_end": 28}
  ],
  "edges": [
    {"caller": "driver_ioctl", "callee": "kmalloc", "type": "direct", "file": "src/driver.c", "line": 32},
    {"caller": "driver_ioctl", "callee": "kmalloc", "type": "direct", "file": "src/driver.c", "line": 40},
    {"caller": "driver_ioctl", "callee": "memcpy", "type": "direct", "file": "src/driver.c", "line": 50},
    {"caller": "driver_ioctl", "callee": "kfree", "type": "direct", "file": "src/driver.c", "line": 63},
    {"caller": "driver_ioctl", "callee": "kfree", "type": "direct", "file": "src/driver.c", "line": 83},
    {"caller": "driver_ioctl", "callee": "ioremap", "type": "direct", "file": "src/driver.c", "line": 73},
    {"caller": "driver_ioctl", "callee": "validate_input", "type": "direct", "file": "src/driver.c", "line": 37},
    {"caller": "driver_ioctl", "callee": "update_config", "type": "direct", "file": "src/driver.c", "line": 56},
    {"caller": "driver_ioctl", "callee": "get_config", "type": "direct", "file": "src/driver.c", "line": 55},
    {"caller": "validate_input", "callee": "process_input", "type": "direct", "file": "src/driver.c", "line": 95},
    {"caller": "driver_ioctl", "callee": "default_handler", "type": "indirect", "uid": "a1b2c3d4", "confidence": "high"}
  ]
}
JSONEOF
```

- [ ] **Step 6: Define expected results**

The test fixture contains these **known vulnerabilities** that the skill MUST detect:

| # | Category | Location | Description |
|---|----------|----------|-------------|
| 1 | A. Input Validation | driver_ioctl (cmd 0x02) → memcpy | `user_len` from userspace not validated against `drv->buf_size` before memcpy |
| 2 | B. Memory Safety | driver_ioctl (cmd 0x02) → memcpy | Classic buffer overflow: `user_len` can exceed `drv->buf_size` |
| 3 | B. Memory Safety | driver_ioctl (cmd 0x01) | No upper bound on `user_len` from `*(size_t *)arg`, integer controlled allocation |
| 4 | B. Memory Safety | driver_ioctl (cmd 0x04) | Use-after-free: `drv->buf_size` written to freed struct, followed by field access |
| 5 | F. Concurrency | driver_ioctl (cmd 0x03) / update_config | TOCTOU / data race on `g_config_value` (no lock protection) |
| 6 | C. System Security | driver_ioctl (cmd 0x05) | ioremap called without capability/permission check |
| 7 | A. Input Validation | process_input | Missing validation on data from external source; no integrity check on shared-memory buffer |
| 8 | D. Cryptographic | driver_ioctl | Hardcoded key `HARDCODED_KEY` at line 8 |

Findings 1 and 2 share the same root cause (unvalidated user_len) and should be reported as a single composite finding per the consolidation rule.

### Task 8: Run Skill Against Test Fixture (GREEN Phase)

**Files:**
- Use: All skill files + test_fixture/
- Verify: Output in `test_fixture/.siakam_out/SAA/`

- [ ] **Step 1: Run the skill against the test fixture**

```bash
cd /home/admin/cc/wksp/siakam_security_skills/siakam_attackpath_analysis && \
/siakam-attackpath-analysis siakam-attackpath-analysis/test_fixture
```

Note: This step is manual — invoke the skill in the Claude Code session and observe.

- [ ] **Step 2: Verify Phase 1 output**

Check that `test_fixture/.siakam_out/SAA/attack_path/driver_ioctl_attack_path.md` exists and contains:
- [ ] Entry `driver_ioctl @ src/driver.c:19`
- [ ] At least 5 infected functions in pruned graph (expect: driver_ioctl, validate_input, process_input, update_config, get_config, default_handler)
- [ ] At least 2 attack paths (different leaf nodes)
- [ ] Function Index listing all infected functions
- [ ] `<!-- SECTION: ... -->` markers present

- [ ] **Step 3: Verify Phase 2 output**

Check that `test_fixture/.siakam_out/SAA/vulns/driver_ioctl_vuls.md` exists and contains:
- [ ] All 7 composite findings (8 individual → 7 after consolidation of #1+#2)
- [ ] Each finding has: Step 2 identification table, Description with code snippet, Exploitation Scenario, Remediation
- [ ] Review (Step 3) fields are all `*to be filled in Step 3*`
- [ ] Severity and confidence scored per spec guidelines
- [ ] 8-method checklist inline in analysis (not in final output)

- [ ] **Step 4: Verify Phase 3 output**

Check that findings have been reviewed:
- [ ] `Reviewed` → yes for all findings
- [ ] `Result` → CONFIRMED for genuine vulnerabilities
- [ ] Reviewer is a different sub-agent from discoverer (check no self-review)
- [ ] At least 1 finding should be FALSE_POSITIVE by Layer 1 (the hardcoded key — "Secrets/credentials stored on disk (if disk is otherwise secured)")
- [ ] Per-file Summary table updated with confirmed/false-positive counts

- [ ] **Step 5: Verify final consolidation**

Check `test_fixture/.siakam_out/SAA/Vul_report.md`:
- [ ] Summary table with correct counts
- [ ] Category × Severity cross-table populated
- [ ] Only CONFIRMED vulnerabilities listed
- [ ] False positives NOT in final report
- [ ] Vulnerabilities sorted by severity (HIGH → MEDIUM → LOW), then confidence (descending)

- [ ] **Step 6: RED-GREEN assessment**

After running the skill against the test fixture, assess:

| Metric | Target | Actual |
|--------|--------|--------|
| Known vulnerabilities detected | ≥ 6 of 8 | ___ |
| False positives in final report | 0 | ___ |
| Composite finding rule applied | Yes (findings 1+2 merged) | ___ |
| Phase 1 Function Index present | Yes | ___ |
| Phase 2 8-method checklist executed | Yes | ___ |
| Phase 3 cross-review (no self-review) | Yes | ___ |
| Vul_report.md generated | Yes | ___ |

**RED items** (target not met): Fix the relevant skill document and re-run.
**GREEN items** (target met): Mark as done.

- [ ] **Step 7: Document rationalizations (REFACTOR material)**

During testing, record any LLM rationalizations where the skill was NOT followed:
- What did the agent do instead?
- What reasoning did it give?
- Which pressure triggered the deviation?

Document these in a `test_fixture/RATIONALIZATIONS.md` file for future skill refinement.

---

## Self-Review

### 1. Spec Coverage

Every spec section maps to at least one implementation file (see Task 6 Step 3 traceability table). No gaps identified.

**New with Tasks 7-8:** Test fixture covers the full pipeline integration. Task 7 creates a minimal C project with 8 known vulnerabilities across all 6 categories (A-F). Task 8 executes the full 3-phase pipeline against the fixture and verifies: Phase 1 attack path discovery, Phase 2 vulnerability detection, Phase 3 false-positive elimination (verifying hardcoded key is excluded per Layer 1 rules), and consolidation report format.

### 2. Placeholder Scan

The only `*to be filled*` occurrences are the Step 3 review fields in step2's output template — these are intentional design (spec section "Output: `<uid>_vuls.md` (Step 2 generates, Step 3 updates)"). No other TBD/TODO/placeholders exist.

### 3. Type/Name Consistency

- `<!-- SECTION: ... -->` markers are consistent across step1 (output), step2 (output), SKILL.md (Phase 4 reads them)
- Term "infected function" used throughout (not "tainted function")
- Term "finding" used throughout (not "issue" or "defect")
- Verdict values CONFIRMED/FALSE_POSITIVE/DISPUTED used consistently
- File paths `.siakam_out/SAA/attack_path/` and `.siakam_out/SAA/vulns/` used consistently
- `MAX_CALL_DEPTH` and `MAX_INFECTED_FUNCTIONS` referenced in both SKILL.md and step1
- `HAS_CALLGRAPH` flag defined in SKILL.md Phase 0, consumed in step1 Step 1.1
