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

> **Tool constraint:** All source code analysis must be done using Read/Grep/Glob tools. Do NOT write or execute scripts to parse code or automate reasoning. The ONLY executable permitted is `CG_HELPER_PATH` for callgraph queries. Always invoke it with `--callgraph-path <PROJECT_DIR>/.siakam_out/callgraph.json`.

## Your Input

You receive:
- `ENTRY_NAME`: The entry function name
- `ENTRY_FILE`: Path to the source file (relative to PROJECT_DIR)
- `ENTRY_LINE`: Line number of the function definition
- `PROJECT_DIR`: Absolute path to the project root
- `MAX_CALL_DEPTH`: Maximum depth (default 10)
- `MAX_INFECTED_FUNCTIONS`: Infected function limit (default 50)
- `EXCLUSIONS`: List of excluded files/directories from `.siakamignore`
- `CG_HELPER_PATH`: Absolute path to `tools/cg_helper.py` in the skill directory

## Your Task

For the given entry function, construct a pruned call graph and identify all attack paths. Write the result to `<PROJECT_DIR>/.siakam_out/SAA/attack_path/<uid>_attack_path.md`.

## Step 1.0: Custom Data-Transfer Function Recognition

Some projects define their own data-copy wrappers around memcpy/memmove (e.g., `my_memcpy`, `dma_buffer_copy`, `shmem_xfer`). These propagate attacker data through their destination buffers, just like standard memcpy. Identifying them is critical for correct data-flow tracing in Step 1.2.

**Do NOT pre-scan all source files.** Instead, recognize data-transfer functions inline during Step 1.1's BFS expansion, when you encounter each callee that is NOT in the terminal list:

1. Check the callee's **name** against these patterns:
   - **Custom memory copy**: name contains `copy`, `mem`, `move`, `transfer`
   - **Hardware data read**: `mmio_read*`, `dma_read*`, `fifo_get*`, `ioread*`
   - **Serialization**: `parse_*`, `pack_*`, `marshal_*`, `unmarshal_*`, `deserialize_*`
   - **IPC/shared-memory**: `ipc_send*`, `shmem_write*`, `mbox_*`
2. If the name matches, **read its function body** (using Read tool at the resolved source location).
3. If the body contains a call to `memcpy`, `memmove`, `strcpy`, `strncpy`, `memcpy_toio`, `__copy_from_user`, or similar raw memory operations → mark the function as a **data-transfer conduit**.
4. Record the function name. The destination-buffer argument of a data-transfer conduit propagates taint — downstream functions that read from that buffer are infected (see Step 1.2 Rule 5).
5. Whether or not the function is a data-transfer conduit, **continue BFS expansion** past it normally — it is NOT a terminal function.

This approach limits analysis to functions that actually appear on the call graph, avoiding an O(all-files) pre-scan.

## Step 1.1: Build the Call Graph

1. Use `cg_helper.py` to load the graph from `<PROJECT_DIR>/.siakam_out/callgraph.json`.
2. BFS from the entry function:
   - Query callees: `python3 <CG_HELPER_PATH> <FUNC> callee --callgraph-path <PROJECT_DIR>/.siakam_out/callgraph.json`
   - For each callee:
     - If it is a standard library/kernel function (see terminal list below), mark as leaf and stop expansion.
     - If it is NOT in the terminal list, apply the data-transfer recognition check from Step 1.0 before adding it to the BFS queue. Record any confirmed data-transfer conduits for Step 1.2.
     - If it is a non-terminal function, add it to the queue for the next level.
   - Stop when depth exceeds MAX_CALL_DEPTH or infected function count exceeds MAX_INFECTED_FUNCTIONS.
3. Resolve each callee's `file` path relative to PROJECT_DIR to get the source location.

### Terminal Functions (do not expand past these)

**"Terminal" means BFS stops here — the function has no security-relevant callees. This does NOT mean the function is invisible. The CALLER of a terminal function remains in the pruned graph and IS analyzed in Phase 2.** Phase 2 sees every terminal call the infected function makes and evaluates it accordingly.

| Category | Functions | Why Terminal |
|----------|-----------|--------------|
| Memory alloc/free | `malloc`, `free`, `kmalloc`, `kfree`, `kzalloc`, `kcalloc`, `vmalloc`, `vfree`, `devm_kzalloc`, `devm_kmalloc` | No further callees; Phase 2 checks lifetime/size in the caller |
| Memory/string ops | `memcpy`, `memmove`, `memset`, `strcpy`, `strncpy`, `strlen`, `strcmp`, `strncmp`, `strcat`, `strncat` | No further callees; Phase 2 checks bounds/integrity in the caller |
| User-kernel copy | `copy_from_user`, `copy_to_user`, `get_user`, `put_user`, `__copy_from_user`, `__copy_to_user` | No further callees; Phase 2 validates the size/source in the caller |
| MMIO / hardware I/O | `readb`, `readw`, `readl`, `readq`, `writeb`, `writew`, `writel`, `writeq`, `__raw_readl`, `__raw_writel`, `ioread8`, `ioread16`, `ioread32`, `iowrite8`, `iowrite16`, `iowrite32`, `inb`, `outb`, `inl`, `outl` | No further callees; Phase 2 checks register access authorization in the caller |
| DMA API | `dma_alloc_coherent`, `dma_alloc_noncoherent`, `dma_free_coherent`, `dma_map_single`, `dma_unmap_single`, `dma_map_page`, `dma_map_sg`, `dma_sync_single_for_cpu`, `dma_sync_single_for_device` | No further callees; Phase 2 checks DMA buffer validation in the caller |
| Physical memory mapping | `ioremap`, `ioremap_nocache`, `ioremap_wc`, `iounmap`, `devm_ioremap`, `devm_ioremap_resource` | No further callees; Phase 2 checks capability/permission in the caller |
| Kernel logging / format | `printk`, `pr_info`, `pr_warn`, `pr_err`, `pr_debug`, `dev_info`, `dev_warn`, `dev_err`, `printf`, `sprintf`, `snprintf`, `scnprintf`, `vprintk`, `vsprintf`, `vsnprintf` | No further callees; Phase 2 checks format-string vulnerabilities in the caller |
| Locking / synchronization | `spin_lock`, `spin_unlock`, `spin_lock_irqsave`, `spin_unlock_irqrestore`, `mutex_lock`, `mutex_unlock`, `read_lock`, `read_unlock`, `write_lock`, `write_unlock`, `rcu_read_lock`, `rcu_read_unlock` | No further callees; Phase 2 checks concurrency correctness in the caller |
| Assert / panic | `WARN`, `WARN_ON`, `BUG`, `BUG_ON`, `assert`, `panic` | No further callees; not security-relevant |

Also terminate on any function whose name starts with `__builtin_`, `__atomic_`, or `__sync_`.

**Custom wrappers around terminal functions**: If the codebase defines a wrapper around a terminal function (e.g., `my_memcpy()`, `dma_buf_alloc()`), the wrapper is NOT automatically terminal — it must be identified via the Step 1.0 data-transfer recognition check. If the wrapper only calls the terminal function (no further callees), BFS still stops there — but the wrapper is recorded as a data-transfer conduit for Step 1.2 data-flow tracing.

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

## Step 1.5: Report Completion

After writing the output file, report to the main agent:
- Number of paths found
- Number of infected functions
- Whether truncation occurred
- Path to the output file
