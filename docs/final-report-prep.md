# Final Report Prep

This document is the repo-side checklist for turning the scanner into the final written report.

## What Changed After Feedback

- The access-control detector now treats treasury-style configuration writes as privileged surfaces, so `setTreasury(...)` is no longer just a caveat in the presentation demo; it is an actual regression-tested detection path.
- The unchecked external call write-up now needs to emphasize the difference between a return value that is merely stored and a return value that actually gates failure.
- Benchmark outputs are now saved under `reports/final-report/` and summarized in `reports/final-report/summary.{json,md}` so the final report can cite detector-by-detector, benchmark-by-benchmark numbers instead of relying on aggregate prose.
- External baseline outputs are now saved in `reports/final-report/baselines.json`, and the consolidated summary folds those comparisons into the report-ready markdown.

## Report-Ready Artifacts

- Access control / SmartBugs: `reports/final-report/access-control-smartbugs.json`
- Access control / NSSC: `reports/final-report/access-control-nssc.json`
- Access control / SWC Registry: `reports/final-report/access-control-swc-registry.json`
- Unchecked external calls: `reports/final-report/unchecked-calls.json`
- Arithmetic / SmartBugs: `reports/final-report/arithmetic-smartbugs.json`
- Reentrancy / SmartBugs CSV: `reports/final-report/reentrancy-smartbugs.csv`
- External + heuristic baselines: `reports/final-report/baselines.json`
- Consolidated benchmark summary: `reports/final-report/summary.md`

## Baseline Story

The repo now has a real baseline comparison rather than only internal metrics:

- `Slither 0.11.5` is the main external tool baseline.
- It is compared on the overlapping slices where the comparison is technically fair:
  - SmartBugs reentrancy
  - SmartBugs access control (with an explicit partial-scope caveat)
  - SmartBugs, NSSC, and scoped SolidiFI unchecked external calls
- A naive SWC-104 syntax baseline is also generated, but it should be framed as a cautionary contrast rather than a serious semantic competitor because these public subsets are mostly positive examples.

Suggested wording:

- Slither is a credible industry-standard static-analysis baseline for overlapping detector classes.
- Our scanner outperforms the Slither baseline on the access-control slice and on the harder scoped SolidiFI unchecked-call subset.
- Reentrancy should be framed more carefully: Slither is extremely strong where it compiles, while our detector compiles across the full cached SmartBugs subset in this environment and still achieves near-perfect line overlap.

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

The reentrancy detector is now much stronger on the SmartBugs subset than the
earlier prototype version. The current saved artifact reports:

- `31/31` contracts detected with at least one finding
- `30/31` line overlap at `+/-3` lines

Suggested final-report wording:

- The detector now covers legacy low-level call chains, storage-alias state writes, helper-triggered external interaction, and modifier-carried external interaction.
- SmartBugs results are strong enough to present as a real benchmark result, not just a demo-only detector.
- One residual mismatch remains in `spank_chain_payment.sol`, so the report should still present reentrancy as heuristic static analysis rather than a proof-oriented analysis.

## Definition Of Done

You are ready to write the final report when:

- every number cited in the paper comes from a saved artifact under `reports/final-report/`
- the report cites benchmarks separately by detector and dataset
- the report includes the generated baseline comparison from `reports/final-report/summary.md`
- the SWC-104 section includes the stored-vs-gated distinction
- the access-control section includes the `setTreasury` threat-model expansion story
- reentrancy is framed honestly as strong but still heuristic on SmartBugs
