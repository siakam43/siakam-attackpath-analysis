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
