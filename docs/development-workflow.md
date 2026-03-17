# Development Workflow

How to contribute code to this project.

## Branch Strategy

We use a simple feature-branch workflow on top of `master`.

### Branch naming

| Prefix | Use |
|--------|-----|
| `feature/<name>` | New analysis features or detectors |
| `fix/<name>` | Bug fixes |
| `setup/<name>` | Infrastructure / tooling changes |
| `docs/<name>` | Documentation only |
| `test/<name>` | Adding or improving tests |

### Workflow

1. Pull latest master: `git checkout master && git pull`
2. Create your branch: `git checkout -b feature/my-detector`
3. Make focused, small commits
4. Run verification: `pwsh scripts/verify.ps1`
5. Push: `git push -u origin feature/my-detector`
6. Open a Pull Request on GitHub
7. Request a review from at least one teammate
8. Squash-merge or merge after approval

## Commit Messages

- Keep the first line under ~50 characters
- Use imperative mood: "Add X" not "Added X"
- One to two lines max
- No emojis

Examples:
```
Add reentrancy detector for external calls
Fix AST walker missing body nodes
Update CI to cache uv dependencies
```

## Running Checks Locally

Before pushing, always run:

```powershell
pwsh scripts/verify.ps1
```

This runs:
1. `ruff check` – lint errors
2. `ruff format --check` – formatting issues
3. `pytest` – Python tests
4. `forge build` – Solidity compilation
5. `forge test` – Foundry tests

## Adding a New Detector

1. **Create the detector module:**
   ```
   src/scanner/detectors/my_detector.py
   ```

2. **Write the detection logic:**
   - Accept compiler output as input
   - Return `list[Finding]`
   - Use `scanner.ast` or `scanner.bytecode` helpers

3. **Add a fixture contract** (if needed):
   ```
   contracts/src/MyFixture.sol
   ```

4. **Add tests:**
   ```
   tests/test_my_detector.py
   ```

5. **Add a Foundry test** (if the fixture needs behavior validation):
   ```
   contracts/test/MyFixture.t.sol
   ```

## Code Style

- Format with `ruff format`
- Lint with `ruff check`
- Type hints on all public functions
- Docstrings on all public functions and classes
- Keep modules small and focused

## Pre-commit Hooks

Pre-commit runs automatically on `git commit` after setup:
- Trailing whitespace removal
- End-of-file newline
- YAML/TOML validation
- Ruff lint and format

If a hook fails, fix the issue and re-commit.
