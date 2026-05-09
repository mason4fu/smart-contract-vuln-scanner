# Baseline Comparison Section

This file is a paste-ready section for the final report. All numbers below come
from the saved artifacts under `reports/final-report/`, especially
`reports/final-report/summary.md` and `reports/final-report/baselines.json`.

## Baseline Comparison

We compared our scanner against `Slither 0.11.5`, a widely used static-analysis
tool for Solidity, on the benchmark slices where the comparison was technically
fair. We used Slither as the main external baseline for overlapping detector
classes, and we also included a naive pattern baseline for SWC-104 to show why
semantic return-value handling matters more than syntax matching alone.

The comparison should be interpreted per detector rather than as a single
overall score. Access control is only a partial apples-to-apples comparison,
because our detector models a broader set of privileged surfaces under the
SWC-105 family, while Slither exposes several narrower authentication-related
checks rather than one unified SWC-105-equivalent rule. Reentrancy should also
be interpreted carefully: Slither is very strong on the contracts it compiles,
while our detector compiled across the full cached SmartBugs subset in this
environment.

### Access Control Baseline

On the SmartBugs access-control subset, our scanner outperformed the Slither
baseline by a large margin. Our approach achieved perfect precision and recall
on the compiled contracts, while the Slither baseline reached precision `0.700`
and recall `0.368`. This gap is consistent with the design of the two systems:
our detector explicitly models broader privileged behaviors such as ownership
mutation, constructor-like initialization, missing authorization on sensitive
surfaces, and treasury-style configuration writes, whereas the Slither baseline
is composed of narrower rules such as `tx-origin`, `protected-vars`,
`suicidal`, `unprotected-upgrade`, `arbitrary-send-eth`, and
`controlled-delegatecall`.

| Tool | Benchmark | Compiled | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---:|---:|---:|---:|---:|---:|
| Our scanner | SmartBugs access control | 15/18 | 16 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Slither 0.11.5 | SmartBugs access control | 17/18 | 7 | 3 | 12 | 0.700 | 0.368 | 0.483 |

### Unchecked External Call Baseline

For SWC-104, Slither was a strong baseline on the smaller hand-curated subsets:
both tools achieved perfect precision and recall on the SmartBugs and
Not-So-Smart-Contracts samples. The more informative comparison came from the
scoped SolidiFI `Unhandled-Exceptions` subset, where our detector achieved
recall `0.898` versus Slither's `0.695` while both maintained precision
`1.000`. This result supports the core project claim that unchecked-call
detection benefits from reasoning about whether a success value actually gates
failure, not just whether a low-level call syntactically appears in the code.

| Tool | Benchmark | Compiled | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---:|---:|---:|---:|---:|---:|
| Our scanner | SmartBugs unchecked calls | 5/5 | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Slither 0.11.5 | SmartBugs unchecked calls | 5/5 | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Our scanner | NSSC unchecked calls | 1/1 | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Slither 0.11.5 | NSSC unchecked calls | 1/1 | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Our scanner | SolidiFI scoped subset | 3/3 | 53 | 0 | 6 | 1.000 | 0.898 | 0.946 |
| Slither 0.11.5 | SolidiFI scoped subset | 3/3 | 41 | 0 | 18 | 1.000 | 0.695 | 0.820 |

The repository also includes a naive syntax baseline for SWC-104 that flags
nearly every low-level call or `send` occurrence. That baseline appears strong
on these mostly positive-only public subsets, with aggregate precision `0.986`
and recall `1.000`, but it is not a semantic competitor: it does not encode the
load-bearing distinction between a return value that is merely stored and one
that actually gates failure. For that reason, we treat it as a cautionary
comparison rather than as the main baseline.

### Reentrancy Baseline

For reentrancy, both tools performed strongly on SmartBugs, but the tradeoff is
different from the other detector classes. Our detector compiled and analyzed
all `31/31` cached SmartBugs reentrancy contracts, achieving contract recall
`1.000` and line-overlap recall `0.968`. Slither achieved perfect contract and
line recall on the `29/31` contracts it compiled in this environment. We
therefore present the result as complementary rather than absolute: Slither is
extremely strong where it compiles, while our detector was more portable across
the full cached subset and still achieved near-perfect line overlap.

| Tool | Benchmark | Compiled | Contract Recall | Line Recall |
|---|---|---|---:|---:|
| Our scanner | SmartBugs reentrancy | 31/31 | 1.000 | 0.968 |
| Slither 0.11.5 | SmartBugs reentrancy | 29/31 | 1.000 | 1.000 |

### Takeaway

Overall, the baseline comparison supports three claims. First, our access
control detector adds real value beyond a standard off-the-shelf tool on the
broader SWC-105-style scope we care about. Second, our unchecked-call detector
is competitive with Slither on curated subsets and stronger on the harder
scoped SolidiFI subset because it reasons about success-value usage rather than
pattern matching alone. Third, our reentrancy detector is now benchmark-credible
on SmartBugs and compares reasonably to a strong external baseline, even though
Slither remains stronger on the contracts it compiles successfully.
