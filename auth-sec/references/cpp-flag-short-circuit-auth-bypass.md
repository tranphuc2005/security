# C++ Source Audit: Flag Short-Circuit Auth Bypass (OpenLiteSpeed 1.9.2 pattern)

Session-verified finding: state-flag carry-over between contexts lets a stale
"auth already checked" flag skip authentication on a remapped context.

## Bug class

When per-request state flags (e.g. CONTEXT_AUTH_CHECKED) are set during auth of
context A, and a rewrite/remap later swaps m_pContext to protected context B,
the flag must be cleared on context change. Any path that swaps context WITHOUT
clearing the flag = auth bypass.

## Verified trace (openlitespeed-1.9.2)

1. `postRewriteProcess()` (src/http/httpreq.cpp:2145-2187) — dead-code bug:
```c
2154:    m_pContext = pNewCtx;              // assigned FIRST
2158:    if (pNewCtx != m_pContext)          // ALWAYS FALSE — self-compare
2160:        m_iContextState &= ~CONTEXT_AUTH_CHECKED;  // DEAD CODE
```
Comment says "if new context is same as previous one skip authentication" but
assignment before comparison makes the guard tautological.

2. Exploit flow (src/http/httpsession.cpp):
- Request hits public context A -> `processContextAuth()` (line 2385) sets
  CONTEXT_AUTH_CHECKED (line 2394). Anonymous passes public context.
- Re-processing pass (HSF_URI_PROCESSED, hook re-entry):
  `processContextRewrite` runs rewrite that remaps URI to protected context B
  via `matchLocation` -> `postRewriteProcess` sets m_pContext = B, flag stays
  set, returns 0.
- Return 0 -> caller takes `HSPS_HKPT_URI_MAP` -> FILE_MAP -> CHECK_AUTH_ACCESS.
- `processContextAuth()` line 2391: `if (!getContextState(CONTEXT_AUTH_CHECKED |
  KEEP_AUTH_INFO))` — flag set -> short-circuits entire auth block of context B.

Result: protected resources served unauthenticated.

## Audit checklist for similar C++ http servers

- Grep for the flag: all write sites (`&= ~FLAG`) and the read site
  (`if (!state(FLAG))`). Any context/handler swap that misses a write site = bug.
- Look for compare-after-assign dead code: `if (newPtr != m_pX)` immediately
  after `m_pX = newPtr` — always false.
- Trace the state machine: which return values route to which process states
  (e.g. postRewriteProcess return 0 vs 1 -> HSPS_HKPT_URI_MAP vs
  HSPS_CHECK_AUTH_ACCESS).
- Note correct-clearing paths too: `processContext()` line 2257-2258
  (`if (m_pContext != pOldCtx) clear flag`) — exploit only works via the
  matchLocation branch, so rewrite must land a file-path that reverse-maps
  into a protected context.

## Fix pattern

```c
const HttpContext *pOldCtx = m_pContext;
m_pContext = pNewCtx;
...
if (pNewCtx != pOldCtx)          // compare with OLD context
    m_iContextState &= ~CONTEXT_AUTH_CHECKED;
```
