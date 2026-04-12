# Evaluation

## Overview
The access control scanner is evaluated against three independent datasets:

- SmartBugs Curated access-control subset (line-level matching)
- Not-So-Smart-Contracts subset (function-level matching)
- SWC Registry pinned subset fetched from upstream markdown samples (contract-level matching)

The unchecked external call scanner is evaluated against three small public
subsets with line-level matching:

- SmartBugs Curated unchecked low-level calls subset
- SolidiFI-benchmark Unchecked-Send and Unhandled-Exceptions injected samples
- Not-So-Smart-Contracts unchecked_external_call example

## Datasets

### SmartBugs Curated
- **Source**: https://github.com/smartbugs/smartbugs-curated
- **Subset**: `dataset/access_control/` — 18 contracts
- **Annotations**: `@vulnerable_at_lines` header annotations + inline `// <yes> ACCESS_CONTROL` markers
- **Evaluation method**: Line-level matching with tolerance=5 lines

**Results** (as of current scanner version):
| Metric | Value |
|--------|-------|
| Compiled successfully | 13/18 |
| Total findings | 21 |
| True Positives | 14 |
| False Positives | 0 |
| False Negatives | 0 |
| Precision | 100% |
| Recall | 100% |
| F1 | 1.000 |

**Why SmartBugs Curated?**
It is the most widely-cited curated dataset for Solidity vulnerability research, with contracts annotated by vulnerability category and line numbers. The `access_control` category directly matches our detector scope.

### Not-So-Smart-Contracts
- **Source**: https://github.com/crytic/not-so-smart-contracts
- **Subset**: `unprotected_function/`, `wrong_constructor_name/` — 3 contracts
- **Annotations**: manually defined ground truth (known vulnerable function names)
- **Evaluation method**: Function-level matching

**Results** (as of current scanner version):
| Metric | Value |
|--------|-------|
| Compiled successfully | 3/3 |
| Total findings | 5 |
| True Positives | 3 |
| False Positives | 0 |
| False Negatives | 0 |
| Precision | 100% |
| Recall | 100% |
| F1 | 1.000 |

### SWC Registry (Pinned Subset)
- **Source**: https://github.com/SmartContractSecurity/SWC-registry
- **Pinning**: commit from `scripts/swc_registry_manifest.json`
- **Subset**: SWC-105, SWC-115, SWC-118 snippets extracted from markdown docs
- **Fetch/cache path**: `datasets/swc-registry/`
- **Evaluation method**: Contract-level vulnerable vs safe matching with optional vulnerable-function checks

**Results** (as of current scanner version):
| Metric | Value |
|--------|-------|
| Compiled successfully | 10/10 |
| Total findings | 9 |
| True Positives | 6 |
| False Positives | 0 |
| False Negatives | 0 |
| True Negatives | 4 |
| Precision | 100% |
| Recall | 100% |
| F1 | 1.000 |

## Running Evaluation

```bash
# SmartBugs evaluation
uv run python scripts/evaluate_smartbugs.py

# Save SmartBugs results to JSON
uv run python scripts/evaluate_smartbugs.py --output results.json

# Fetch and evaluate Not-So-Smart-Contracts
uv run python scripts/fetch_nssc.py
uv run python scripts/evaluate_nssc.py

# Fetch and evaluate pinned SWC subset
uv run python scripts/fetch_swc_registry.py
uv run python scripts/evaluate_swc_registry.py

# Fetch and evaluate unchecked external call datasets
uv run python scripts/fetch_unchecked_call_datasets.py
uv run python scripts/evaluate_unchecked_calls.py --output reports/unchecked-call-eval.json
```

## Unchecked External Calls

### Dataset Pins

- **SmartBugs Curated**: `smartbugs/smartbugs-curated@230e649123477eff332742a59a1c7cc6dc286cab`
- **SolidiFI-benchmark**: `DependableSystemsLab/SolidiFI-benchmark@4b0573e1b3f7031396de6f48f7f3e7380222ad3a`
- **Not-So-Smart-Contracts**: `crytic/not-so-smart-contracts@020dbdbde3e0c2e8de5f3944e7455e438b0995d5`

### Matching Protocol

1. Fetch only the documented small subset into ignored `datasets/unchecked-external-calls/`.
2. Compile each contract with the pragma-derived solc version, coercing pre-0.4.11 pragmas to 0.4.11 because py-solc-x cannot install older versions.
3. Run the unchecked external call detector from compiler output.
4. Match source findings to labeled vulnerable lines with a default `+/-5` line tolerance.
5. Exclude compile failures from TP/FP/FN counts and report them separately.
6. Use source-located findings for line-level PRF; bytecode findings are retained in JSON output as supporting evidence.

### Current Results

| Dataset | Compiled | TP | FP | FN | Precision | Recall | F1 |
|---------|----------|----|----|----|-----------|--------|----|
| SmartBugs Curated unchecked subset | 5/5 | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| SolidiFI unchecked/unhandled subset | 5/6 | 29 | 4 | 71 | 0.879 | 0.290 | 0.436 |
| Not-So-Smart-Contracts unchecked external call | 1/1 | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| Aggregate micro-average | 11/12 | 43 | 4 | 71 | 0.915 | 0.377 | 0.534 |

The aggregate is a micro-average over the same line-level protocol. It should
not be read as a general benchmark score because the three datasets have
different origins and annotation styles.

### Limitations

- The SolidiFI subset uses injected fault logs rather than hand-curated exploit lines.
- Some injected unhandled-exception patterns are outside the current low-level call focus.
- The detector was not tuned to the SolidiFI syntax; misses are kept visible for regression tracking.
- Bytecode-only findings do not participate in line-level precision/recall unless source maps are later added.

## Methodology

### SmartBugs
1. Iterate all `.sol` files in `smartbugs-curated/dataset/access_control/`
2. Parse `@vulnerable_at_lines` annotations for ground truth
3. Detect the pragma solidity version and install the appropriate compiler
4. Compile each contract and run the access control detector
5. Compare findings to annotated lines with a tolerance window of ±5 lines
6. Report TP / FP / FN / precision / recall / F1

### Not-So-Smart-Contracts
1. Fetch target contracts from the upstream repository
2. Run the access control detector on each contract
3. Match findings against manually defined ground-truth function names
4. Report TP / FP / FN / precision / recall / F1

### SWC Registry Subset
1. Load pinned manifest from `scripts/swc_registry_manifest.json`
2. Fetch markdown docs at pinned commit and extract selected `solidity` snippets
3. Cache snippets and ground truth metadata under `datasets/swc-registry/`
4. Compile each cached snippet and run source-level access-control detection
5. Compute contract-level TP / FP / FN / TN and precision / recall / F1

**Note on compile errors**: Many SmartBugs contracts have compilation errors due to outdated syntax or missing imports. These are reported as compile errors and excluded from precision/recall calculations.

## Limitations
- 5/18 SmartBugs contracts fail to compile (legacy Solidity syntax)
- Line tolerance=5 may cause FP/FN near closely-spaced vulnerabilities
- Bytecode analysis does not use the legacy AST, so it works uniformly across Solidity versions
- Some SmartBugs contracts import files not present in the dataset (e.g., SafeMath), causing compilation failures counted as compile errors rather than false negatives
