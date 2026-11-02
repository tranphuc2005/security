# C/C++ SAST False Positive Triaging Guide (OpenLiteSpeed Case Study)

When reviewing SAST reports (Semgrep, AFR, CodeQL, Flawfinder) on large C/C++ native enterprise codebases, deterministic pattern matching generates massive false positive rates (~80-90%). Use this guide to triage high-severity findings quickly.

## 1. CWE-78 (OS Command Injection / system() sink)
- **Check Sink Parameters**:
  - If `snprintf(cmd, sizeof(cmd), "... %d ...", int_var)` uses purely integer specifiers (`%d`, `%u`, `%ld`), command injection is mathematically impossible regardless of whether `int_var` is user-influenced.
  - Check caller source: In multi-process architectures (e.g. LiteSpeed `lscgid`), parameters like `uid`, `gid`, `pid` are passed via IPC Unix socket by privileged parent processes based on server configuration (`suexec` target user), not HTTP headers or query parameters.
  - Admin/maintenance scripts (`system("rm -rf ...")` or `awstats.pl`): Parameters often come from internal vhost config (`pName`, `pWorking`), not user traffic. Mark as informational/hardening (avoid `system()`, use `execve`), not exploitable CVSS 10.0 RCE.

## 2. CWE-835 / CWE-670 (Loop or Recursion Does Not Terminate / Control Flow)
- **Parser Loop Bounds Check**:
  - For dual-pointer scans: `for (; pHBegin <= pHEnd; pHEnd--)` terminates because `pHEnd` is decremented each step until it drops below `pHBegin`.
  - Watch out for LLM/SAST description hallucinations (e.g., claiming `i != n; ++n` when the code actually decrements `pHEnd`). Always diff the snippet with the real line.

## 3. CWE-825 / CWE-562 (Reference Outlives Object / Return Stack Address)
- **Reference Passing in C++ RAII Wrappers**:
  - `MtLock(ls_mutex_t &lock) : m_lock(&lock)` takes a reference `&`, taking the address of an existing object allocated in caller frame/heap. It is NOT taking the address of a pass-by-value copy.
  - Verify caller lifetime vs RAII guard lifetime.

## 4. CWE-806 / CWE-120 (Copy Sized by Wrong Operand / Buffer Overflows)
- **Swap / Buffer idiom**:
  - `char buf[sizeof(T)]; memmove(buf, &rhs, sizeof(buf)); memmove(&rhs, this, sizeof(buf)); memmove(this, buf, sizeof(buf));`
  - The length operand `sizeof(buf)` matches the allocated stack temporary. This is a canonical type-agnostic swap pattern, not an unbound source copy.

## 5. CWE-480 / CWE-783 (Operator Precedence / Bitwise vs Modulo)
- **Modulo Power of Two**:
  - `flag % (1 << N)` where `(1 << N)` is power-of-two behaves identically to bitmasking `flag & ((1 << N) - 1)` for positive numbers. Stylistic oddity != vulnerability.

## 6. Dead Code & Test Fixtures
- Always check if vulnerable pattern is inside:
  - `#ifdef notdef` or `#if 0` blocks
  - Unit tests / fixtures (`test/`, `addon/example/`)
  - Test keys/certs (`server.key`, `phpinfo.php`)
  - Uncalled utility functions (e.g. Go `validOffAndLen` defined but never invoked across the module)

## 7. Genuine C/C++ Findings to Watch
- **Realloc pointer leakage on OOM (CWE-401)**:
  `ptr = (Type *)realloc(ptr, new_size); if (!ptr) return FAIL;` -> Old memory leaked on allocation failure.
- **Insecure PRNG for predictable resources (CWE-335)**:
  `srand(time(NULL)); rand() % 1000;` used for temporary socket paths or port binding -> Local DoS / collision risk.
