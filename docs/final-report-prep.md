# Final Report Prep

This document is the repo-side checklist for turning the scanner into the final written report.

## What Changed After Feedback

- The access-control detector now treats treasury-style configuration writes as privileged surfaces, so `setTreasury(...)` is no longer just a caveat in the presentation demo; it is an actual regression-tested detection path.
- The unchecked external call write-up now needs to emphasize the difference between a return value that is merely stored and a return value that actually gates failure.
- Benchmark outputs are now saved under `reports/final-report/` and summarized in `reports/final-report/summary.{json,md}` so the final report can cite detector-by-detector, benchmark-by-benchmark numbers instead of relying on aggregate prose.

## Report-Ready Artifacts

- Access control / SmartBugs: `reports/final-report/access-control-smartbugs.json`
- Access control / NSSC: `reports/final-report/access-control-nssc.json`
- Access control / SWC Registry: `reports/final-report/access-control-swc-registry.json`
- Unchecked external calls: `reports/final-report/unchecked-calls.json`
- Arithmetic / SmartBugs: `reports/final-report/arithmetic-smartbugs.json`
- Reentrancy / SmartBugs exploratory CSV: `reports/final-report/reentrancy-smartbugs.csv`
- Consolidated benchmark summary: `reports/final-report/summary.md`

## Stored But Not Used

For SWC-104, the load-bearing claim is not “we matched `.call(...)` syntax.” The claim is:

1. A low-level call is vulnerable when failure can happen and execution still continues.
2. Assigning `bool success = target.call(...)` does not make the code safe by itself.
3. The success value only counts as handled if it gates control flow, for example with `require(success)`, `assert(success)`, or `if (!success) revert`.

That is why the detector distinguishes:

```solidity
(bool success, ) = target.call(data);
emit Attempted(success);
balances[msg.sender] += 1;
```

from:

```solidity
(bool success, ) = target.call(data);
require(success, "call failed");
balances[msg.sender] += 1;
```

The first case is “stored but not used as a failure gate.” The second is checked.

Code and tests:

- `src/scanner/ast/unchecked_calls.py`
- `tests/test_unchecked_external_calls.py`
- `docs/unchecked-external-calls.md`

## Threat-Model Expansion Worked Example

The `setTreasury(...)` miss matters because it shows that detector scope is a design decision, not just a bug list.

Initial detector scope:

- ownership transfer
- admin-role changes
- unguarded privileged transfers

Expanded scope after review:

- security-sensitive configuration writes such as treasury redirects

Concrete repo evidence:

- vulnerable example: `contracts/src/demo/DemoAccessControlVulnerable.sol`
- guarded counterpart: `contracts/src/demo/DemoAccessControlSafe.sol`
- regression fixture: `tests/fixtures/ConfigSurface.sol`
- detector logic: `src/scanner/ast/analysis.py`

This is a good final-report example because it explains both a limitation and an improvement:

1. Sensitive configuration was not initially modeled.
2. The threat model was expanded deliberately.
3. The expanded scope is now encoded as detector logic and tests.

## How To Frame Reentrancy Honestly

The reentrancy detector is useful in demos and unit tests, but the current SmartBugs exploratory run is weak on legacy 0.4.x contracts.

Suggested final-report wording:

- The detector demonstrates the checks-effects-interactions ordering signal on curated examples.
- The current implementation is not yet benchmark-strong on the legacy SmartBugs reentrancy bucket.
- Therefore, reentrancy should be presented as a scoped prototype detector rather than one of the strongest evaluation results.

## Definition Of Done

You are ready to write the final report when:

- every number cited in the paper comes from a saved artifact under `reports/final-report/`
- the report cites benchmarks separately by detector and dataset
- the SWC-104 section includes the stored-vs-gated distinction
- the access-control section includes the `setTreasury` threat-model expansion story
- reentrancy is framed honestly as exploratory on legacy SmartBugs
