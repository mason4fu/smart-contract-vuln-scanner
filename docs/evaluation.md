# Dataset Evaluation

## Dataset

**SmartBugs Curated** — a curated collection of vulnerable Solidity smart contracts.

- Source: [github.com/smartbugs/smartbugs-curated](https://github.com/smartbugs/smartbugs-curated)
- Already included at: `smartbugs-curated/dataset/`
- Access control category: `smartbugs-curated/dataset/access_control/` (19 contracts)
- Contracts are annotated with `@vulnerable_at_lines` comments indicating ground truth

**Why SmartBugs Curated?**
It is the most widely-cited curated dataset for Solidity vulnerability research, with contracts annotated by vulnerability category and line numbers. The access_control category directly matches our detector scope.

## Running the Evaluation

```bash
# Full evaluation (source + bytecode)
uv run python scripts/evaluate_smartbugs.py

# Bytecode-only mode
uv run python scripts/evaluate_smartbugs.py --bytecode-only

# Save results to JSON
uv run python scripts/evaluate_smartbugs.py --output evaluation_results.json
```

## Methodology

1. Iterate all `.sol` files in `smartbugs-curated/dataset/access_control/`
2. Parse `@vulnerable_at_lines` annotations for ground truth
3. Detect the pragma solidity version and install the appropriate compiler
4. Compile each contract and run the access control detector
5. Compare findings to annotated lines
6. Report TP/FN/recall

**Note on precision**: Many SmartBugs contracts have compilation errors due to outdated syntax or missing imports. These are reported as compile errors and excluded from precision/recall calculations.

## Known Challenges

- Many SmartBugs contracts use Solidity 0.4.x which has different AST structure (legacy format). Source-level analysis may produce different results than for 0.8.x contracts.
- Some SmartBugs contracts import other files not present in the dataset (e.g., SafeMath), causing compilation failures. These are counted as compile errors, not false negatives.
- Bytecode analysis does not use the legacy AST, so it works uniformly across versions.

## Limitations

- Recall metric: only measures whether any finding was produced, not whether findings correspond to exact vulnerable lines.
- Precision: not calculated here since all SmartBugs access_control contracts are by definition vulnerable — a false positive on a vulnerable contract is not meaningful.
