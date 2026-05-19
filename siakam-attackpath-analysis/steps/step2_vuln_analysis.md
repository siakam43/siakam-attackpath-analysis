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
>
> **Tool constraint:** All vulnerability analysis must be done by reading source code with Read/Grep/Glob tools and applying LLM reasoning. Do NOT write or execute scripts to parse code, match patterns, or automate analysis. All 9 review methods must be performed manually by reasoning over the source code.

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

## Step 2.2: For Each Function, Apply the 9-Method Review

For each function in your sorted, deduplicated list:

### Step 2.2a: Read the Function Source

1. Locate the function definition in `<PROJECT_DIR>/<file>` at the given line.
2. Read the complete function body (from opening `{` to closing `}`).
3. Also read any called functions that are within the same file and relevant to understanding the logic (use your judgment — do not expand beyond 3 levels of local helper calls).

### Step 2.2b: Determine Applicability

Scan the function body. For each of the 9 methods below, determine if the method is APPLICABLE:

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
| Firmware/hardware security | Applicable if the function configures DMA descriptors, writes to hardware/MMIO registers, configures TrustZone/PMP/MPU regions, performs secure boot operations (image loading/verification), reads from hardware FIFOs or ring buffers, calls ARM SMC/HVC instructions, or configures memory controllers/cache |

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

**9. Firmware/Hardware Security**
- **DMA**: Are DMA buffer addresses and lengths validated against the actual memory layout? Can an attacker control the DMA descriptor (source address, destination, length)? Is the DMA engine properly isolated (IOMMU/SMMU configured and enabled)?
- **Hardware register access**: Are security-critical registers (debug, memory controller, TZASC, clock/reset) writable after boot? Is there a lock-after-write pattern for write-once registers? Are debug registers (ETM, CTI, DAP) left enabled in production?
- **Secure boot**: Are boot images cryptographically verified (signature, hash) before execution? Is there anti-rollback protection (version check, monotonic counter)? Are failed verification paths handled securely (not falling through to boot)?
- **TrustZone/PMP/MPU**: Are memory region permissions correctly configured? Is non-secure access to secure memory blocked? Are PMP entries locked after configuration?
- **Hardware FIFO/ring buffer**: Is there underflow/overflow protection on hardware queues? Are FIFO status registers checked before read/write operations?
- **SMC/HVC calls**: Are SMC call arguments validated? Is the SMC caller ID (non-secure vs secure) checked where appropriate?
- Record as PASS, FAIL, or N/A.

### Step 2.2d: Record the Checklist

After analyzing a function, output the 9-method checklist inline in your analysis (not in the final report). This is for your own tracking:

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
| Firmware/hardware security | NO | N/A | no hardware configuration |
```

## Step 2.3: Vulnerability Category System

Assign every finding to exactly one category. If a finding fits multiple categories, assign it to the category that best matches the root cause.

**A. Input Validation**
- Missing or insufficient validation on external inputs (interface parameters, files, IPC, shared memory)
- Shared memory data read without integrity/safety checks
- Trust boundary violations (trusting data from untrusted sources)
- Missing bounds checking on data from external sources
- Type confusion from unvalidated input
- Deserialization of untrusted data without validation
- Missing validation on inter-process communication (IPC) data
- Environment variable injection from external sources

**B. Memory Safety**
- Stack-based or heap-based buffer overflow
- Out-of-bounds read/write (array index vulnerabilities)
- Use-after-free (UAF)
- Double free
- Null pointer dereference
- Uninitialized memory access
- Integer overflow/underflow leading to memory corruption
- Format string vulnerabilities

**C. System Security**
- Authentication bypass logic
- Privilege escalation paths
- Remote code execution
- Dynamic code execution

**D. Cryptographic Security**
- Hardcoded API keys, passwords, or tokens
- Weak cryptographic algorithms or implementations (DES, RC4, MD4, MD5 for security, SHA1 for signatures, RSA < 2048 bits)
- Improper key storage or management
- Cryptographic randomness issues (fixed IV/nonce, predictable RNG)
- Certificate validation bypasses

**E. Firmware/Embedded-Specific**
- DMA attack surface (unvalidated DMA buffers)
- Improper MMIO access control
- Physical memory mapping security (ioremap without capability check)
- Secure boot bypass
- Improper hardware register exposure
- TrustZone/PMP boundary violations
- Cross-world (EL1→EL3, non-secure→secure) trust boundary violations

**F. Concurrency**
- TOCTOU with clear exploitable window
- Shared state accessed without synchronization in multi-threaded code
- Demonstrable data race with security impact

## Step 2.4: Create Findings

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

## Step 2.5: Write Output

Write to `<PROJECT_DIR>/.siakam_out/SAA/vulns/<uid>_vuls.md`.

**If you complete all assigned functions**: use the complete output format below. Include `<!-- STATUS: complete -->` after the header.

**If you run out of capacity (token limit, timeout approaching) before finishing all functions**: write immediately with:
- `<!-- STATUS: partial -->` after the header.
- Summary notes: `Functions analyzed: <N> of <M> (partial)`.
- List unanalyzed functions under `## Unanalyzed Functions`:
  ```markdown
  ## Unanalyzed Functions
  | Function | File:Line | Reason |
  |----------|-----------|--------|
  | <func>   | <file>:<line> | Sub-agent capacity exhausted |
  ```
- Include all findings for functions you DID complete. The main agent will reassign unanalyzed functions.

Use the exact format below. The `### Review (Step 3)` fields MUST be left as shown — they will be filled by Phase 3. Do not write anything in those fields.

```markdown
<!-- SECTION: header -->
<!-- STATUS: complete -->
# Vulnerability Analysis: <entry_name>
**Entry**: <entry_name> @ <file>:<line>
**Analysis Date**: <YYYY-MM-DD>
<!-- /SECTION: header -->

<!-- SECTION: summary -->
## Summary
| Status | Count |
|--------|-------|
| Total findings | <N> |
| Functions analyzed | <N> of <M> |
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

- **No vulnerabilities found in a function**: The function's 9-method checklist shows all PASS or N/A. Move to the next function. Do NOT create an empty finding.
- **No vulnerabilities found in the entire assignment**: Still generate the `_vuls.md` file. Summary shows "Total findings: 0". The file is still required as a contract for Phase 3.

## Step 2.6: Report Completion

Report to the main agent:
- Number of functions analyzed
- Number of findings created
- Per-function checklist summary (function name, methods passed, methods failed)
