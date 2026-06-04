# Contributing

## Setup

git clone https://github.com/Zi-Stonga/Regulatory-Compliance.git
cd Regulatory-Compliance
git checkout -b feature/your-feature
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

## Before every pull request

make all

This runs install, lint, security scan, and the full test suite.
All checks must pass before submitting.

## Test standards

- Every test follows Arrange / Act / Assert structure
- One assertion focus per test function
- New functions require tests covering happy path, edge case, error path
- Mocks must have a comment explaining what they replace and why
- Do not reduce coverage below the current level

## Commit message format

type(scope): short imperative description

Types: feat, fix, refactor, test, docs, chore, perf
Example: feat(engine): add GDPR framework support

One concern per commit. Do not bundle unrelated changes.

## Pull request checklist

- All 110 existing tests pass
- New tests added for new functionality
- ruff lint passes with no errors
- bandit security scan passes
- Relevant docs/specs files updated
- CHANGELOG.md updated

## Code style

Read docs/specs/00_system_overview.md before writing any code.

Key rules:
- snake_case for functions and variables
- SCREAMING_SNAKE_CASE for constants
- PascalCase for classes
- Leading underscore for private methods
- Docstrings on every function: purpose, args, returns, exceptions
- Arrange / Act / Assert in every test
- No bare except clauses
- No print() in src/ files
