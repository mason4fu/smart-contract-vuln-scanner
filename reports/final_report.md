# Static Structural Detection of Smart Contract Vulnerabilities in Solidity

**Yu Fu**  
University of Illinois Urbana-Champaign  
yuf7@illinois.edu

**Aman Jain**  
University of Illinois Urbana-Champaign  
aman18@illinois.edu

> Drafting note: bracketed tags such as `[Draft owner: Yu]`, `[Draft owner: Aman]`, and `[Draft owner: Shared]` are internal collaboration markers for revision and should be removed in the final submitted version.

## Abstract

[Draft owner: Shared]

Smart contracts operate in adversarial environments, control real assets, and execute with little tolerance for post-deployment mistakes. This project builds and evaluates a static vulnerability scanner for Solidity that targets four widely studied weakness classes: arithmetic overflow/underflow (`SWC-101`), unchecked low-level external calls (`SWC-104`), access control flaws (`SWC-105` and related authorization mistakes), and reentrancy (`SWC-107`). Our scanner is source-first and AST-driven, with bytecode-oriented fallback heuristics when source is unavailable. Beyond merely flagging patterns, the tool reports severity, confidence, contract/function context, line information, snippets, and remediation guidance, and it can emit text, JSON, and SARIF output. We evaluate the scanner on SmartBugs Curated, Not-So-Smart-Contracts, and a pinned SWC Registry subset where available, and we compare key detectors against Slither as a baseline. The strongest results are perfect precision/recall on the scoped access-control and unchecked-call subsets, strong arithmetic performance on SmartBugs (`P=0.955`, `R=0.913`, `F1=0.933`), and benchmark-credible reentrancy recall on SmartBugs (`31/31` contracts hit, `0.968` line recall). The project’s main contribution is not claiming complete smart contract security coverage, but building a more disciplined structural analyzer whose scope, evidence, and limitations are explicit.

## 1. Introduction

[Draft owner: Shared]

Ethereum smart contracts turn software behavior directly into financial and governance outcomes. In the “code is law” setting described by Buterin’s original Ethereum whitepaper, bugs are not merely correctness issues; they can become irreversible economic events once deployed on-chain [1]. This raises a difficult engineering problem: how can developers catch security-critical mistakes early enough to matter, while still working within the practical constraints of real codebases, compiler versions, and incomplete information?

Static analysis is an attractive answer because it can run before deployment, scale to many contracts, and explain findings in source terms that developers can actually fix. At the same time, static analysis has obvious limits. Some smart contract failures are structural and local, such as an external call before a later state update or a publicly callable ownership transfer. Others are deeply contextual or economic, such as oracle manipulation or flash-loan-driven state distortion, and cannot be soundly resolved by local syntax or AST structure alone.

This report presents our pair project: a Solidity vulnerability scanner designed around that distinction. The scanner focuses on structural weaknesses that are well suited to static detection and explicitly avoids claiming coverage of full runtime, market, or cross-protocol exploit reasoning. The four detector families are:

- arithmetic overflow/underflow and unsafe unchecked arithmetic (`SWC-101`)
- unchecked low-level external calls (`SWC-104`)
- access control and privileged-surface flaws (`SWC-105`, `SWC-106`, `SWC-115`, `SWC-118`)
- reentrancy-oriented checks-effects-interactions violations (`SWC-107`)

The project evolved from a class survey of smart contract vulnerabilities into a benchmarked implementation with detector-specific evaluations, baseline comparisons, richer remediation output, and clearer scope boundaries. A central theme of this report is that detector design is not just about matching syntax. It is also about deciding what counts as evidence, what counts as a privileged action, and what claims a static tool is justified in making.

## 2. Background

[Draft owner: Shared]

### 2.1 Smart Contract Vulnerabilities as Structural Security Problems

Ethereum contracts execute on the EVM, a deterministic stack machine that exposes contracts to adversarial calls, public transaction visibility, and immutable deployed logic [1]. This environment makes several vulnerability classes especially important:

- **Reentrancy** occurs when a contract performs an external interaction before updating internal state, allowing control flow to re-enter vulnerable logic.
- **Arithmetic vulnerabilities** arise when numeric operations silently wrap or bypass expected checks. Solidity `0.8.x` changed the default semantics by checking arithmetic unless code enters an explicit `unchecked` block [2].
- **Unchecked low-level calls** occur when `.call`, `.delegatecall`, `.staticcall`, or `.send` can fail silently but the success result does not actually gate continuation.
- **Access control flaws** arise when privileged functionality is reachable without appropriate authorization, including ownership mutation, role grants, unsafe initialization, or improper use of `tx.origin`.

These classes are widely represented in the Smart Contract Weakness Classification (SWC) Registry [7], in the SmartBugs ecosystem [4][5], and in educational benchmarks such as Not-So-Smart-Contracts [6].

### 2.2 Why Static Analysis Is Useful Here

[Draft owner: Shared]

Static analysis is especially useful when the bug has a recognizable structural signature:

- an external call followed by a later state write
- a public function that mutates privileged state without an auth guard
- a low-level call whose boolean result is ignored or only observed non-terminatingly
- arithmetic on state-sensitive values in contexts where wraparound is possible

In contrast, attacks such as oracle manipulation, sandwiching, and flash-loan-driven price distortion require economic and protocol-level reasoning that is not available to a local AST or bytecode pass. Our project therefore treats static analysis as a precision-oriented structural tool rather than a universal smart contract security oracle.

## 3. Project Overview and Scope

[Draft owner: Shared]

Our scanner is a Python-based command-line tool that accepts Solidity source files, directories of contracts, compiled JSON output, or raw EVM bytecode. The default workflow is source-first:

1. compile or load the target contract
2. build AST and source-location context
3. run the selected detectors
4. optionally corroborate or fall back to bytecode heuristics
5. deduplicate and confidence-filter findings
6. emit reports in text, JSON, or SARIF form

The tool also supports multi-file directory scans, project summary generation, and structured remediation output. The implementation is intentionally modular: detectors share a common finding model, are registered centrally, and can be evaluated independently.

**Figure 1. Scanner pipeline**

```text
Solidity source / compiled JSON / runtime bytecode
        -> compiler or loader
        -> AST analysis and source mapping
        -> detector registry
           -> arithmetic
           -> unchecked low-level calls
           -> access control
           -> reentrancy
        -> optional bytecode corroboration / fallback
        -> deduplication + confidence filtering
        -> text / JSON / SARIF / project-summary output
```

**Table 1. Supported detector families**

| Detector | Primary SWC coverage | Main analysis mode | Key structural idea |
|---|---|---|---|
| Arithmetic | `SWC-101` | AST, with bytecode hints | Flag risky arithmetic in state/value-sensitive paths, with Solidity-version gating |
| Unchecked external calls | `SWC-104` | AST, with bytecode fallback | Distinguish ignored or non-gating low-level call results from properly checked failures |
| Access control | `SWC-105`, `SWC-106`, `SWC-115`, `SWC-118` | AST, with selected bytecode hints | Track privileged surfaces, initialization risks, and weak auth patterns |
| Reentrancy | `SWC-107` | AST, with bytecode corroboration/fallback | Detect external call before later state effect, including helper-call propagation |

Our scope is intentionally limited. We do **not** claim to detect:

- oracle manipulation
- flash-loan-driven economic exploits
- transaction-order dependence in its full mempool or MEV sense
- full exploitability proofs for every flagged structural issue

That scoping is a design choice, not a weakness to hide. It keeps the tool aligned with what a structural static analyzer can legitimately support.

## 4. Design and Implementation

[Draft owner: Shared]

### 4.1 Core Architecture

[Draft owner: Shared]

The scanner is implemented under `src/scanner/` and organized into compiler, AST, bytecode, detector, model, evaluation, and output modules. The CLI loads source or bytecode targets, registers detectors, and writes findings through a shared reporting layer. Findings carry:

- detector name
- title and description
- severity and confidence
- contract and function context
- source location when available
- SWC identifier
- remediation guidance

Recent project improvements also added:

- project-wide summaries for directory scans
- SARIF export for CI-style consumption
- richer remediation fields, including secure patterns and suggested steps
- stronger bytecode-only heuristics for cases where source is missing

### 4.2 Reentrancy Detector

[Draft owner: Yu]

The reentrancy detector focuses on a classic checks-effects-interactions failure mode: a contract performs an external `CALL`-family interaction before it commits a later storage effect. The main detector works over Solidity AST structure and function bodies, not merely surface syntax. In its stronger form by the end of the project, it handles:

- modern call syntax such as `call{value: amount}("")`
- legacy call forms such as `.call.value(...)()`
- helper-call propagation through internal/private functions
- modifier-carried interactions
- storage alias writes such as `var acc = accounts[msg.sender]; acc.balance -= amount`
- source line recovery from compiler `src` offsets

The key design choice is that the detector does not try to prove a full exploit. Instead, it reports a risky ordering pattern that is strongly associated with reentrancy and explains why the pattern violates the intended checks-effects-interactions discipline.

**Listing 1. Reentrancy pattern flagged by the scanner**

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
    balances[msg.sender] -= amount;
}
```

This pattern is structurally risky because control leaves the contract before the internal accounting effect occurs.

### 4.3 Arithmetic Detector

[Draft owner: Yu]

The arithmetic detector targets overflow/underflow-style arithmetic bugs, but its main challenge is semantic drift across Solidity versions. Before Solidity `0.8.0`, arithmetic wraparound was the default. Starting with Solidity `0.8.0`, arithmetic is checked unless code enters `unchecked { ... }` [2]. A naive detector that ignores version semantics will either over-report modern code or under-report deliberately unsafe unchecked sections.

Our implementation therefore makes version-awareness central. It:

- reports risky arithmetic more aggressively on pre-`0.8` contracts
- suppresses ordinary `0.8+` arithmetic unless it appears inside an explicit `unchecked` block
- treats state-sensitive and value-sensitive paths as higher priority
- suppresses common safe patterns such as SafeMath-style wrappers and classic additive guards

This produces a more useful detector than blanket operator matching because it reasons about when arithmetic can actually wrap under the contract’s intended compiler semantics.

**Listing 2. Solidity `0.8.x` arithmetic that becomes risky again inside `unchecked`**

```solidity
function incrementUnchecked(uint256 amount) external {
    unchecked {
        count += amount;
    }
}
```

### 4.4 Access Control Detector

[Draft owner: Aman]

The access-control detector covers several related authorization failures rather than one narrow rule. It identifies:

- missing authorization on sensitive public/external functions
- ownership takeover surfaces
- unguarded role-grant functions
- dangerous constructor-like initialization patterns
- `tx.origin`-based authorization
- uninitialized owner state and selected renounce risks

An important project lesson was that “sensitive function” detection is itself a threat-model decision. Early versions naturally focused on obvious actions such as `setOwner` or `grantAdmin`. Later revisions expanded the privileged surface to include treasury-style configuration writes, which may not transfer funds immediately but can redirect future value flow.

**Listing 3. Worked example of threat-model expansion**

```solidity
function setTreasury(address newTreasury) external {
    treasury = newTreasury;
}
```

The key insight is that a scanner should not treat only direct ownership mutation as privileged. A public `setTreasury` function can be just as security-sensitive if it controls where funds are routed later. This became a central design lesson in the access-control portion of the project.

### 4.5 Unchecked Low-Level External Call Detector

[Draft owner: Aman]

The unchecked-call detector analyzes `.call`, `.delegatecall`, `.staticcall`, and `.send` and asks a more precise question than simple pattern matching: does the success result actually gate failure before the function continues?

This distinction matters because low-level calls return a boolean success value, but contracts often assign that value without using it meaningfully. Our detector therefore distinguishes:

- result ignored entirely
- result stored but not used as a failure gate
- result only logged or observed without terminating control flow
- result properly checked via `require`, `assert`, revert branches, or equivalent helper logic

**Listing 4. “Stored but not used” versus genuinely checked**

```solidity
// Vulnerable: success is assigned but does not gate continuation.
(bool success, bytes memory returnData) = target.call("");
returnData;
notifyCount += 1;

// Safe: success gates continuation.
(bool ok,) = target.call("");
require(ok, "call failed");
notifyCount += 1;
```

This “stored but not used” distinction is the load-bearing argument for why our detector is stronger than a naive return-value pattern check. Merely seeing a boolean assignment is not enough; the question is whether failed external execution can still be silently tolerated while local state changes proceed.

### 4.6 Reporting and Usability Features

[Draft owner: Shared]

To make the scanner more useful as a project artifact rather than just a detector collection, we added:

- text and JSON findings for direct use
- SARIF output for code-scanning workflows
- project-level summary files for directory scans
- structured remediation fields, including secure patterns and example fixes

These additions matter because vulnerability tools are judged not only by whether they find issues, but also by whether their output is interpretable and actionable.

## 5. Evaluation Methodology

[Draft owner: Shared]

Our evaluation uses a detector-by-detector, dataset-by-dataset structure rather than one aggregate score. This follows the project feedback directly: aggregated performance can hide important differences in scope, compilation coverage, and benchmark fit.

### 5.1 Datasets

[Draft owner: Shared]

We evaluated against the following benchmark families where compatible subsets were available in the repository:

- **SmartBugs Curated** [5]: a widely used benchmark dataset of annotated vulnerable Solidity contracts
- **Not-So-Smart-Contracts** [6]: educational but still useful benchmark contracts spanning several classic vulnerability classes
- **Pinned SWC Registry subset** [7]: a locally scripted subset used for specific detector checks
- **SolidiFI supplemental subset**: used as an additional pressure test for unchecked-call detection

Not every detector currently has a scripted subset for every benchmark family. Rather than hiding that mismatch, we mark those cells explicitly as **not evaluated**.

### 5.2 Metrics

[Draft owner: Shared]

Depending on the dataset and detector, we report contract-level, function-level, or line-level matches. For line-level runs, our saved artifacts use small tolerances (for example `+/-5` or `+/-6` lines) to account for compiler/source-map differences while still treating findings as location-sensitive. We report:

- true positives (`TP`)
- false positives (`FP`)
- false negatives (`FN`)
- precision
- recall
- F1
- compile coverage when relevant

### 5.3 Baseline Tool

[Draft owner: Shared]

We implemented a direct baseline comparison against **Slither 0.11.5** [3], a widely used static analysis framework for Ethereum smart contracts. Slither is an appropriate baseline because it is mature, security-oriented, and overlaps significantly with our detector classes. The comparison is not perfectly uniform for every category: in particular, access control is only partially apples-to-apples because Slither exposes multiple narrower auth-related checks rather than one broad `SWC-105`-style detector. We document that caveat instead of overstating parity.

## 6. Evaluation Results

[Draft owner: Shared]

### 6.1 Detector-by-Dataset Results

[Draft owner: Shared]

**Table 2. Primary evaluation matrix**

| Detector | Benchmark | Compiled | Granularity | TP | FP | FN | Precision | Recall | F1 | Notes |
|---|---|---|---|---:|---:|---:|---:|---:|---:|---|
| Access control | SmartBugs Curated | 15/18 | line-level | 16 | 0 | 0 | 1.000 | 1.000 | 1.000 |  |
| Access control | Not-So-Smart-Contracts | 3/3 | function-level | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |  |
| Access control | SWC Registry | 10/10 | contract-level | 6 | 0 | 0 | 1.000 | 1.000 | 1.000 |  |
| Unchecked external calls | SmartBugs Curated | 5/5 | line-level | 10 | 0 | 0 | 1.000 | 1.000 | 1.000 |  |
| Unchecked external calls | Not-So-Smart-Contracts | 1/1 | line-level | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |  |
| Unchecked external calls | SolidiFI (supplemental) | 3/3 | line-level | 53 | 0 | 6 | 1.000 | 0.898 | 0.946 | Supplemental pressure test |
| Unchecked external calls | SWC Registry | 1/1 | line-level | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | Pinned `unchecked_return_value.sol` sample |
| Arithmetic | SmartBugs Curated | 15/15 | line-level | 21 | 1 | 2 | 0.955 | 0.913 | 0.933 |  |
| Arithmetic | Not-So-Smart-Contracts | 1/1 | line-level | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 | `integer_overflow_1.sol` public sample |
| Arithmetic | SWC Registry | 14/14 | line-level | 9 | 1 | 0 | 0.900 | 1.000 | 0.947 | One remaining FP on infeasible safe sample |

Reentrancy is reported separately because our saved artifact uses contract recall and line-overlap recall rather than a simple `TP/FP/FN` table:

- SmartBugs Curated: `31/31` compiled
- contracts with at least one finding: `31/31`
- detected contract recall: `1.000`
- line-overlap recall: `0.968`

This is a much stronger result than our earlier prototype state, where legacy patterns significantly reduced effective recall. The detector is now benchmark-credible on the SmartBugs subset, with one remaining line-overlap miss rather than broad failure.

### 6.2 Baseline Comparison Against Slither

[Draft owner: Shared]

**Table 3. Baseline comparison**

| Tool / Detector | Benchmark | Compiled | Precision | Recall | F1 | Notes |
|---|---|---|---:|---:|---:|---|
| Our scanner / Access control | SmartBugs Curated | 15/18 | 1.000 | 1.000 | 1.000 | Broad privileged-surface model |
| Slither / Access control | SmartBugs Curated | 17/18 | 0.700 | 0.368 | 0.483 | Partial category match only |
| Our scanner / Unchecked calls | SmartBugs Curated | 5/5 | 1.000 | 1.000 | 1.000 |  |
| Slither / Unchecked calls | SmartBugs Curated | 5/5 | 1.000 | 1.000 | 1.000 |  |
| Our scanner / Unchecked calls | Not-So-Smart-Contracts | 1/1 | 1.000 | 1.000 | 1.000 |  |
| Slither / Unchecked calls | Not-So-Smart-Contracts | 1/1 | 1.000 | 1.000 | 1.000 |  |
| Our scanner / Unchecked calls | SolidiFI (supplemental) | 3/3 | 1.000 | 0.898 | 0.946 |  |
| Slither / Unchecked calls | SolidiFI (supplemental) | 3/3 | 1.000 | 0.695 | 0.820 |  |
| Our scanner / Reentrancy | SmartBugs Curated | 31/31 | n/a | 1.000 contract, 0.968 line | n/a | One line-overlap miss |
| Slither / Reentrancy | SmartBugs Curated | 29/31 | n/a | 1.000 contract, 1.000 line on compiled subset | n/a | Better on compiled subset, lower compile coverage |

The baseline comparison supports three main conclusions:

1. Our access-control detector benefits from a broader, more explicit privileged-surface model than the closest Slither configuration on this subset.
2. Our unchecked-call detector is competitive on curated subsets and stronger on the supplemental SolidiFI pressure test, largely because it reasons about whether the success result truly gates failure.
3. Our reentrancy detector became much stronger over the course of the project, reaching full contract recall on the SmartBugs subset while maintaining source-grounded reporting.

### 6.3 Interpreting the Results

[Draft owner: Shared]

The results are strongest where the detector scope, benchmark labels, and structural assumptions align well. Access control and unchecked calls benefited from highly targeted threat models and carefully chosen benchmark subsets. Arithmetic is slightly weaker, but still strong, because version gating and guard recognition improve precision while some benchmark edge cases remain difficult. Reentrancy showed the biggest growth during development: it started as the most obvious weakness in our scanner and became a much more convincing detector after handling legacy syntax, helper propagation, and improved line recovery.

Just as important as the best scores are the explicit **not evaluated** cells. These make the report more honest. A missing benchmark subset is not the same thing as poor detector performance, but it is still a limitation of the evidence we can claim.

## 7. Limitations

[Draft owner: Shared]

Our scanner is intentionally scoped, and several limitations remain.

### 7.1 Static Structural Scope

[Draft owner: Shared]

The scanner reasons about structural code properties. It does **not** model:

- adversarial market dynamics
- oracle integrity
- mempool-level transaction-order manipulation
- flash-loan-backed economic attacks
- dynamic exploitability proofs across full execution traces

As a result, a positive finding means “this structural pattern is risky,” not “this exploit is guaranteed.”

### 7.2 Incomplete Benchmark Coverage

[Draft owner: Shared]

Not every detector has a pinned subset across all three requested benchmark families in the repository. Arithmetic currently has strong SmartBugs evidence but not scripted NSSC or SWC Registry subsets. Unchecked external calls have strong SmartBugs, NSSC, and supplemental SolidiFI results, but no pinned SWC-104 subset in the local evaluation harness. We report those gaps explicitly, but they still limit how comprehensive our evidence can be.

### 7.3 Compilation and Representation Constraints

[Draft owner: Shared]

Some benchmark contracts are hard to compile uniformly across environments, especially older Solidity versions and legacy syntax. We improved this substantially, especially for reentrancy, but baseline comparisons can still be affected by compile coverage differences. Bytecode-only analysis is also necessarily weaker than source-guided analysis because source names, intent, and exact control structure are lost.

### 7.4 Detector Boundary Decisions

[Draft owner: Shared]

A recurring lesson in this project is that detector quality depends on boundary decisions:

- what counts as a sensitive function
- what counts as a sufficient auth guard
- when a low-level call result is truly “checked”
- when arithmetic is meaningfully risky rather than just syntactically present

Those are unavoidable judgment calls. We tried to make them explicit and benchmarked, but they are still design choices rather than universal truths.

## 8. Future Work

[Draft owner: Shared]

The most important future work is to deepen reasoning rather than merely add more detector labels.

### 8.1 Stronger Interprocedural and Multi-Contract Reasoning

[Draft owner: Shared]

The scanner already improved on helper-call and project-wide reasoning, but richer interprocedural analysis could further strengthen:

- cross-function reentrancy modeling
- privilege propagation across helper chains and inheritance
- multi-contract call graph context
- storage-flow reasoning across wrappers and internal abstractions

### 8.2 Better Bytecode-Only Analysis

[Draft owner: Shared]

Bytecode fallback is useful, but still weaker than source-based analysis. Future work could improve:

- recovery of storage-sensitive patterns from runtime bytecode
- confidence calibration for bytecode-only findings
- distinction between corroborating hints and stronger bytecode evidence

### 8.3 Broader and Cleaner Evaluation Harnesses

[Draft owner: Shared]

The report would be stronger still with:

- pinned arithmetic subsets for NSSC and SWC Registry
- a pinned SWC-104 SWC Registry subset
- more negative examples for stress-testing false positives
- broader side-by-side tool comparisons beyond Slither

### 8.4 Workflow and Productization

[Draft owner: Shared]

The project already includes SARIF export and project summaries, but future work could add:

- CI templates for GitHub code scanning
- IDE integrations
- richer machine-readable remediation templates
- differential scanning across commits

## 9. Conclusion

[Draft owner: Shared]

This project began as a survey of common smart contract vulnerability classes and evolved into a static scanner with four detector families, explicit scope boundaries, benchmark-driven evaluation, and baseline comparisons. The final tool is strongest not because it claims to solve all smart contract security, but because it is careful about what it does claim. It performs well on structural vulnerability classes that static analysis can meaningfully support, especially access control, unchecked low-level calls, arithmetic, and reentrancy ordering patterns. It also makes an important methodological point: in smart contract security, detector scope is itself a design decision. The `setTreasury` example and the “stored but not used” distinction both illustrate that meaningful vulnerability detection depends on how carefully those decisions are made.

For us, the most valuable outcome of the project was learning to connect implementation, threat modeling, and evaluation discipline. A detector that merely produces findings is not enough. A useful security tool must also justify its findings, bound its claims, and make clear where its evidence stops.

## References

[Draft owner: Shared]

[1] Vitalik Buterin. *A Next-Generation Smart Contract and Decentralized Application Platform*. 2014. [https://ethereum.org/en/whitepaper/](https://ethereum.org/en/whitepaper/)

[2] Solidity Team. *Solidity 0.8.0 Release Announcement*. December 16, 2020. [https://www.soliditylang.org/blog/2020/12/16/solidity-v0.8.0-release-announcement/](https://www.soliditylang.org/blog/2020/12/16/solidity-v0.8.0-release-announcement/)

[3] Josselin Feist, Gustavo Grieco, and Alex Groce. *Slither: A Static Analysis Framework for Smart Contracts*. 2019 IEEE/ACM 2nd International Workshop on Emerging Trends in Software Engineering for Blockchain (WETSEB), 2019. [https://doi.org/10.1109/WETSEB.2019.00008](https://doi.org/10.1109/WETSEB.2019.00008)

[4] João F. Ferreira, Pedro Cruz, Thomas Durieux, and Rui Abreu. *SmartBugs: A Framework to Analyze Solidity Smart Contracts*. ASE 2020 Tool Demonstrations Track, 2020. [https://doi.org/10.1145/3417929.3417934](https://doi.org/10.1145/3417929.3417934)

[5] smartbugs. *SB Curated: A Curated Dataset of Vulnerable Solidity Smart Contracts*. GitHub repository. [https://github.com/smartbugs/smartbugs-curated](https://github.com/smartbugs/smartbugs-curated)

[6] crytic. *(Not So) Smart Contracts*. GitHub repository. [https://github.com/crytic/not-so-smart-contracts](https://github.com/crytic/not-so-smart-contracts)

[7] Smart Contract Weakness Classification (SWC) Registry. [https://swcregistry.io/](https://swcregistry.io/)

[8] Santiago Palladino. *The Parity Wallet Hack Explained*. OpenZeppelin, July 19, 2017. [https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7](https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack-405a8c12e8f7)

[9] Santiago Palladino. *The Parity Wallet Hack Reloaded*. OpenZeppelin, November 7, 2017. [https://www.openzeppelin.com/news/parity-wallet-hack-reloaded](https://www.openzeppelin.com/news/parity-wallet-hack-reloaded)
